use std::any::type_name;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use codex_core::CodexAuth;
use codex_core::CodexConversation;
use codex_core::ConversationManager;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::cross_session::AssistantMessage;
use codex_core::cross_session::CrossSessionHub;
use codex_core::cross_session::SessionEventStream;
use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_protocol::ConversationId;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::de::Error as _;
use serde_json::Value;
use serde_json::json;
use tokio::signal;
use tokio_stream::StreamExt;
use tracing::warn;

use crate::progress::ProgressReporter;
use crate::prompts;
use crate::run_store::RoleMetadata;
use crate::run_store::RunStore;
use crate::session;
use crate::signals::AggregatedVerifierVerdict;
use crate::signals::DirectiveResponse;
use crate::signals::VerifierDecision;
use crate::signals::VerifierReport;
use crate::signals::VerifierVerdict;
use crate::types::FINALIZATION_PROMPT;
use crate::types::RoleConfig;
use crate::types::RoleSession;
use crate::types::RunExecutionOptions;
use crate::types::RunOutcome;
use crate::types::RunParams;
use crate::types::RunSessions;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SolverSignal {
    DirectionRequest {
        #[serde(default)]
        prompt: Option<String>,
    },
    VerificationRequest {
        #[serde(default)]
        claim_path: Option<String>,
        #[serde(default)]
        notes: Option<String>,
    },
    FinalDelivery {
        #[serde(default)]
        deliverable_path: Option<String>,
        #[serde(default)]
        summary: Option<String>,
    },
}

#[derive(Serialize)]
struct DirectionRequestPayload<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    prompt: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    objective: Option<&'a str>,
}

#[derive(Serialize)]
struct VerificationRequestPayload<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    claim_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    objective: Option<&'a str>,
}

struct SessionCleanup {
    conversation_id: ConversationId,
    conversation: Arc<CodexConversation>,
}

impl SessionCleanup {
    fn new(session: &RoleSession) -> Self {
        Self {
            conversation_id: session.conversation_id,
            conversation: Arc::clone(&session.conversation),
        }
    }
}

pub struct InftyOrchestrator {
    hub: Arc<CrossSessionHub>,
    conversation_manager: ConversationManager,
    runs_root: PathBuf,
    progress: Option<Arc<dyn ProgressReporter>>,
}

impl InftyOrchestrator {
    pub fn new(auth: CodexAuth) -> Result<Self> {
        let runs_root = crate::default_runs_root()?;
        Ok(Self::with_runs_root(auth, runs_root))
    }

    pub fn with_runs_root(auth: CodexAuth, runs_root: impl Into<PathBuf>) -> Self {
        Self {
            hub: Arc::new(CrossSessionHub::new()),
            conversation_manager: ConversationManager::with_auth(auth),
            runs_root: runs_root.into(),
            progress: None,
        }
    }

    pub fn runs_root(&self) -> &PathBuf {
        &self.runs_root
    }

    pub fn hub(&self) -> Arc<CrossSessionHub> {
        Arc::clone(&self.hub)
    }

    pub fn with_progress(mut self, reporter: Arc<dyn ProgressReporter>) -> Self {
        self.progress = Some(reporter);
        self
    }

    pub async fn execute_new_run(
        &self,
        params: RunParams,
        options: RunExecutionOptions,
    ) -> Result<RunOutcome> {
        let sessions = self.spawn_run(params).await?;
        self.drive_run(sessions, options).await
    }

    // resumable runs are disabled; execute_existing_run removed

    pub async fn spawn_run(&self, params: RunParams) -> Result<RunSessions> {
        let RunParams {
            run_id,
            run_root,
            solver,
            director,
            verifiers,
        } = params;

        let run_path = run_root.unwrap_or_else(|| self.runs_root.join(&run_id));
        let role_metadata = collect_role_metadata(&solver, &director, &verifiers);
        let mut store = RunStore::initialize(&run_path, &run_id, &role_metadata)?;
        let mut cleanup = Vec::new();

        let solver_session = match self
            .spawn_and_register_role(&run_id, &run_path, &solver, &mut store, &mut cleanup)
            .await
        {
            Ok(session) => session,
            Err(err) => {
                self.cleanup_failed_spawn(cleanup, &run_path).await;
                return Err(err);
            }
        };

        let director_session = match self
            .spawn_and_register_role(&run_id, &run_path, &director, &mut store, &mut cleanup)
            .await
        {
            Ok(session) => session,
            Err(err) => {
                self.cleanup_failed_spawn(cleanup, &run_path).await;
                return Err(err);
            }
        };

        let mut verifier_sessions = Vec::with_capacity(verifiers.len());
        for verifier in verifiers {
            let session = match self
                .spawn_and_register_role(&run_id, &run_path, &verifier, &mut store, &mut cleanup)
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    self.cleanup_failed_spawn(cleanup, &run_path).await;
                    return Err(err);
                }
            };
            verifier_sessions.push(session);
        }

        Ok(RunSessions {
            run_id,
            solver: solver_session,
            director: director_session,
            verifiers: verifier_sessions,
            store,
        })
    }

    // resumable runs are disabled; resume_run removed

    async fn drive_run(
        &self,
        mut sessions: RunSessions,
        options: RunExecutionOptions,
    ) -> Result<RunOutcome> {
        let result = self.inner_drive_run(&mut sessions, &options).await;
        let cleanup = collect_session_cleanup(&sessions);
        self.shutdown_sessions(cleanup).await;
        result
    }

    async fn inner_drive_run(
        &self,
        sessions: &mut RunSessions,
        options: &RunExecutionOptions,
    ) -> Result<RunOutcome> {
        let mut solver_events = self.stream_events(sessions.solver.conversation_id)?;
        let mut waiting_for_signal = false;
        let mut pending_solver_turn_completion = false;
        if let Some(objective) = &options.objective {
            session::post_turn(
                self.hub.as_ref(),
                &sessions.run_id,
                &sessions.solver.role,
                objective.as_str(),
                Some(solver_signal_schema()),
            )
            .await?;
            sessions.store.touch()?;
            waiting_for_signal = true;
            if let Some(progress) = self.progress.as_ref() {
                progress.objective_posted(objective);
                progress.waiting_for_solver();
            }
        }

        let ctrl_c = signal::ctrl_c();
        tokio::pin!(ctrl_c);

        'event_loop: loop {
            tokio::select! {
                maybe_event = solver_events.next() => {
                    let Some(event) = maybe_event else {
                        break 'event_loop;
                    };
                    if let Some(progress) = self.progress.as_ref() {
                        progress.solver_event(&event.event.msg);
                    }
                    match &event.event.msg {
                        EventMsg::AgentMessage(agent_msg) => {
                            if let Some(progress) = self.progress.as_ref() {
                                progress.solver_agent_message(agent_msg);
                            }
                            if let Some(signal) = parse_solver_signal(&agent_msg.message) {
                                waiting_for_signal = false;
                                match signal {
                                    SolverSignal::DirectionRequest { prompt } => {
                                        let prompt = prompt
                                            .and_then(|p| {
                                                let trimmed = p.trim();
                                                if trimmed.is_empty() {
                                                    None
                                                } else {
                                                    Some(trimmed.to_string())
                                                }
                                            })
                                            .ok_or_else(|| {
                                                anyhow!(
                                                    "solver direction_request missing prompt text"
                                                )
                                            })?;
                                        if let Some(progress) = self.progress.as_ref() {
                                            progress.direction_request(&prompt);
                                        }
                                        self.handle_direction_request(
                                            sessions,
                                            &prompt,
                                            options,
                                        )
                                        .await?;
                                        sessions.store.touch()?;
                                        pending_solver_turn_completion = true;
                                    }
                                    SolverSignal::VerificationRequest { claim_path, notes } => {
                                        let claim_path = claim_path
                                            .and_then(|p| {
                                                let trimmed = p.trim();
                                                if trimmed.is_empty() {
                                                    None
                                                } else {
                                                    Some(trimmed.to_string())
                                                }
                                            })
                                            .ok_or_else(|| {
                                                anyhow!(
                                                    "solver verification_request missing claim_path"
                                                )
                                            })?;
                                        if let Some(progress) = self.progress.as_ref() {
                                            progress.verification_request(
                                                &claim_path,
                                                notes.as_deref(),
                                            );
                                        }
                                        let verified = self
                                            .handle_verification_request(
                                                sessions,
                                                &claim_path,
                                                notes.as_deref(),
                                                options,
                                            )
                                            .await?;
                                        sessions.store.touch()?;
                                        if verified {
                                            pending_solver_turn_completion = true;
                                        }
                                    }
                                    SolverSignal::FinalDelivery {
                                        deliverable_path,
                                        summary,
                                    } => {
                                        let deliverable_path = deliverable_path
                                            .and_then(|p| {
                                                let trimmed = p.trim();
                                                if trimmed.is_empty() {
                                                    None
                                                } else {
                                                    Some(trimmed.to_string())
                                                }
                                            })
                                            .ok_or_else(|| {
                                                anyhow!(
                                                    "solver final_delivery missing deliverable_path"
                                                )
                                            })?;
                                        if deliverable_path.is_empty() {
                                            bail!("solver final_delivery provided empty path");
                                        }
                                        let resolved = resolve_deliverable_path(
                                            sessions.store.path(),
                                            &deliverable_path,
                                        )?;
                                        let summary_clean = summary.and_then(|s| {
                                            let trimmed = s.trim();
                                            if trimmed.is_empty() {
                                                None
                                            } else {
                                                Some(trimmed.to_string())
                                            }
                                        });
                                        let summary_ref = summary_clean.as_deref();
                                        if let Some(progress) = self.progress.as_ref() {
                                            progress.final_delivery(&resolved, summary_ref);
                                        }
                                        let verified = self
                                            .run_final_verification(
                                                sessions,
                                                &resolved,
                                                summary_ref,
                                                options,
                                            )
                                            .await?;
                                        if !verified {
                                            pending_solver_turn_completion = true;
                                            continue;
                                        }
                                        sessions.store.touch()?;
                                        return Ok(RunOutcome {
                                            run_id: sessions.run_id.clone(),
                                            deliverable_path: resolved,
                                            summary: summary_clean,
                                            raw_message: agent_msg.message.clone(),
                                        });
                                    }
                                }
                            }
                        }
                        EventMsg::TaskComplete(..) => {
                            if waiting_for_signal {
                                // The solver completed its turn without issuing a signal; ask for one now.
                                self.request_solver_signal(&sessions.run_id, &sessions.solver.role)
                                    .await?;
                            } else if pending_solver_turn_completion {
                                // We handled a signal earlier in the loop; this completion corresponds to it.
                                pending_solver_turn_completion = false;
                            }
                        }
                        _ => {}
                    }
                }
                _ = &mut ctrl_c => {
                    if let Some(progress) = self.progress.as_ref() {
                        progress.run_interrupted();
                    }
                    let cleanup = collect_session_cleanup(sessions);
                    self.shutdown_sessions(cleanup).await;
                    bail!("run interrupted by Ctrl+C");
                }
            }
        }

        Err(anyhow!(
            "run {} ended before emitting final_delivery message",
            sessions.run_id
        ))
    }

    async fn handle_direction_request(
        &self,
        sessions: &RunSessions,
        prompt: &str,
        options: &RunExecutionOptions,
    ) -> Result<()> {
        let request = DirectionRequestPayload {
            kind: "direction_request",
            prompt,
            objective: options.objective.as_deref(),
        };
        let request_text = serde_json::to_string_pretty(&request)?;
        let handle = session::post_turn(
            self.hub.as_ref(),
            &sessions.run_id,
            &sessions.director.role,
            request_text,
            Some(directive_response_schema()),
        )
        .await?;
        let progress = self
            .progress
            .as_deref()
            .map(|reporter| (reporter, "director"));
        let directive = session::await_first_idle(
            self.hub.as_ref(),
            &handle,
            options.director_timeout,
            progress,
        )
        .await?;
        let directive_payload: DirectiveResponse = parse_json_struct(&directive.message.message)
            .context("director response was not valid directive JSON")?;
        if let Some(progress) = self.progress.as_ref() {
            progress.director_response(&directive_payload);
        }
        let directive_text = serde_json::to_string_pretty(&directive_payload)?;
        session::post_turn(
            self.hub.as_ref(),
            &sessions.run_id,
            &sessions.solver.role,
            directive_text,
            Some(solver_signal_schema()),
        )
        .await?;
        Ok(())
    }

    async fn handle_verification_request(
        &self,
        sessions: &mut RunSessions,
        claim_path: &str,
        notes: Option<&str>,
        options: &RunExecutionOptions,
    ) -> Result<bool> {
        let objective = options
            .objective
            .as_deref()
            .map(str::trim)
            .filter(|objective| !objective.is_empty());

        let summary = self
            .collect_verification_summary(sessions, claim_path, notes, objective, options)
            .await?;
        self.emit_verification_summary(&summary);
        self.post_verification_summary_to_solver(sessions, &summary)
            .await?;
        Ok(summary.overall.is_pass())
    }

    async fn run_final_verification(
        &self,
        sessions: &mut RunSessions,
        deliverable_path: &Path,
        summary: Option<&str>,
        options: &RunExecutionOptions,
    ) -> Result<bool> {
        let relative = deliverable_path
            .strip_prefix(sessions.store.path())
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()));
        let claim_path = relative.unwrap_or_else(|| deliverable_path.display().to_string());

        let objective = options
            .objective
            .as_deref()
            .map(str::trim)
            .filter(|objective| !objective.is_empty());

        let summary_result = self
            .collect_verification_summary(
                sessions,
                claim_path.as_str(),
                summary,
                objective,
                options,
            )
            .await?;
        self.emit_verification_summary(&summary_result);
        self.post_verification_summary_to_solver(sessions, &summary_result)
            .await?;
        Ok(summary_result.overall.is_pass())
    }

    async fn request_solver_signal(&self, run_id: &str, solver_role: &str) -> Result<()> {
        let handle = session::post_turn(
            self.hub.as_ref(),
            run_id,
            solver_role,
            FINALIZATION_PROMPT,
            Some(final_delivery_schema()),
        )
        .await?;
        let _ = session::await_first_idle(self.hub.as_ref(), &handle, Duration::from_secs(5), None)
            .await?;
        Ok(())
    }

    async fn collect_verification_summary(
        &self,
        sessions: &mut RunSessions,
        claim_path: &str,
        notes: Option<&str>,
        objective: Option<&str>,
        options: &RunExecutionOptions,
    ) -> Result<AggregatedVerifierVerdict> {
        if sessions.verifiers.is_empty() {
            return Ok(aggregate_verdicts(Vec::new()));
        }

        let request = VerificationRequestPayload {
            kind: "verification_request",
            claim_path,
            notes,
            objective,
        };
        let request_text = serde_json::to_string_pretty(&request)?;
        let mut results: Vec<(String, VerifierVerdict)> =
            Vec::with_capacity(sessions.verifiers.len());
        for verifier in &sessions.verifiers {
            let handle = session::post_turn(
                self.hub.as_ref(),
                &sessions.run_id,
                &verifier.role,
                request_text.clone(),
                Some(verifier_verdict_schema()),
            )
            .await?;
            let progress = self
                .progress
                .as_deref()
                .map(|reporter| (reporter, verifier.role.as_str()));
            let response = session::await_first_idle(
                self.hub.as_ref(),
                &handle,
                options.verifier_timeout,
                progress,
            )
            .await?;
            let verdict: VerifierVerdict = parse_json_struct(&response.message.message)
                .with_context(|| {
                    format!("verifier {} returned invalid verdict JSON", verifier.role)
                })?;
            if let Some(progress) = self.progress.as_ref() {
                progress.verifier_verdict(&verifier.role, &verdict);
            }
            results.push((verifier.role.clone(), verdict));
        }

        // Replace any verifier that passed with a fresh session; keep failures.
        // Build a set of roles to replace to avoid borrowing issues while mutating.
        let to_replace: Vec<String> = results
            .iter()
            .filter_map(|(role, verdict)| {
                if verdict.verdict.is_pass() {
                    Some(role.clone())
                } else {
                    None
                }
            })
            .collect();
        for role in to_replace {
            if let Err(err) = self.replace_verifier_session(sessions, &role).await {
                warn!(role = %role, ?err, "failed to replace verifier session; keeping existing");
            }
        }

        // Aggregate directly from the collected results
        Ok(aggregate_verdicts(results))
    }

    async fn replace_verifier_session(&self, sessions: &mut RunSessions, role: &str) -> Result<()> {
        // Find the existing verifier session index by role
        let idx = sessions
            .verifiers
            .iter()
            .position(|s| s.role == role)
            .ok_or_else(|| anyhow!(format!("verifier role {role} not found")))?;

        // Shut down the old session and unregister it from the hub
        let old = &sessions.verifiers[idx];
        // best-effort shutdown; ignore errors but proceed to unregister
        let _ = old.conversation.submit(Op::Shutdown).await;
        let _ = self
            .conversation_manager
            .remove_conversation(&old.conversation_id)
            .await;

        // Prepare a fresh Config using current user defaults, then apply our autonomous policies
        let config = Config::load_with_cli_overrides(Vec::new(), ConfigOverrides::default())
            .await
            .context("failed to load Codex config for verifier respawn")?;
        // RoleConfig::new applies sandbox + approval; mimic that here via the constructor
        let role_config = crate::types::RoleConfig::new(role.to_string(), config);

        // Spawn a new verifier session and register it
        let mut dummy = Vec::new();
        let run_path = sessions.store.path().to_path_buf();
        let new_session = self
            .spawn_and_register_role(
                &sessions.run_id,
                &run_path,
                &role_config,
                &mut sessions.store,
                &mut dummy,
            )
            .await?;

        sessions.verifiers[idx] = new_session;
        Ok(())
    }

    fn emit_verification_summary(&self, summary: &AggregatedVerifierVerdict) {
        if let Some(progress) = self.progress.as_ref() {
            progress.verification_summary(summary);
        }
    }

    async fn post_verification_summary_to_solver(
        &self,
        sessions: &RunSessions,
        summary: &AggregatedVerifierVerdict,
    ) -> Result<()> {
        let summary_text = serde_json::to_string_pretty(summary)?;
        session::post_turn(
            self.hub.as_ref(),
            &sessions.run_id,
            &sessions.solver.role,
            summary_text,
            Some(solver_signal_schema()),
        )
        .await?;
        Ok(())
    }

    async fn cleanup_failed_spawn(&self, sessions: Vec<SessionCleanup>, run_path: &Path) {
        self.shutdown_sessions(sessions).await;
        if run_path.exists()
            && let Err(err) = fs::remove_dir_all(run_path)
        {
            warn!(
                path = %run_path.display(),
                ?err,
                "failed to remove run directory after spawn failure"
            );
        }
    }

    // resumable runs are disabled; cleanup_failed_resume removed

    async fn shutdown_sessions(&self, sessions: Vec<SessionCleanup>) {
        for session in sessions {
            if let Err(err) = session.conversation.submit(Op::Shutdown).await {
                warn!(
                    %session.conversation_id,
                    ?err,
                    "failed to shutdown session during cleanup"
                );
            }
            let _ = self
                .conversation_manager
                .remove_conversation(&session.conversation_id)
                .await;
        }
    }

    pub fn stream_events(
        &self,
        conversation_id: ConversationId,
    ) -> Result<SessionEventStream, codex_core::cross_session::CrossSessionError> {
        self.hub.stream_events(conversation_id)
    }

    pub async fn call_role(
        &self,
        run_id: &str,
        role: &str,
        text: impl Into<String>,
        timeout: Duration,
        final_output_json_schema: Option<Value>,
    ) -> Result<AssistantMessage> {
        let handle = session::post_turn(
            self.hub.as_ref(),
            run_id,
            role,
            text,
            final_output_json_schema,
        )
        .await?;
        let progress = self.progress.as_deref().map(|reporter| (reporter, role));
        session::await_first_idle(self.hub.as_ref(), &handle, timeout, progress).await
    }

    pub async fn relay_assistant_to_role(
        &self,
        run_id: &str,
        target_role: &str,
        assistant: &AssistantMessage,
        timeout: Duration,
        final_output_json_schema: Option<Value>,
    ) -> Result<AssistantMessage> {
        let handle = session::post_turn(
            self.hub.as_ref(),
            run_id,
            target_role,
            assistant.message.message.clone(),
            final_output_json_schema,
        )
        .await?;
        let progress = self
            .progress
            .as_deref()
            .map(|reporter| (reporter, target_role));
        session::await_first_idle(self.hub.as_ref(), &handle, timeout, progress).await
    }

    async fn spawn_and_register_role(
        &self,
        run_id: &str,
        run_path: &Path,
        role_config: &RoleConfig,
        store: &mut RunStore,
        cleanup: &mut Vec<SessionCleanup>,
    ) -> Result<RoleSession> {
        let session = session::spawn_role(
            Arc::clone(&self.hub),
            &self.conversation_manager,
            run_id,
            run_path,
            role_config.clone(),
            prompts::ensure_instructions,
        )
        .await?;
        cleanup.push(SessionCleanup::new(&session));
        store.update_rollout_path(&session.role, session.rollout_path.clone())?;
        if let Some(path) = role_config.config_path.clone() {
            store.set_role_config_path(&session.role, path)?;
        }
        Ok(session)
    }

    // resumable runs are disabled; resume_and_register_role removed
}

impl InftyOrchestrator {
    /// Test-only helper to run a single verification round against all verifiers,
    /// applying the replacement policy (replace passes, keep failures).
    pub async fn verify_round_for_test(
        &self,
        sessions: &mut RunSessions,
        claim_path: &str,
        options: &RunExecutionOptions,
    ) -> Result<AggregatedVerifierVerdict> {
        self.collect_verification_summary(sessions, claim_path, None, None, options)
            .await
    }
}

fn collect_role_metadata(
    solver: &RoleConfig,
    director: &RoleConfig,
    verifiers: &[RoleConfig],
) -> Vec<RoleMetadata> {
    solver_and_director_metadata(solver, director)
        .into_iter()
        .chain(verifiers.iter().map(|verifier| RoleMetadata {
            role: verifier.role.clone(),
            rollout_path: None,
            config_path: verifier.config_path.clone(),
        }))
        .collect()
}

fn solver_and_director_metadata(solver: &RoleConfig, director: &RoleConfig) -> Vec<RoleMetadata> {
    vec![
        RoleMetadata {
            role: solver.role.clone(),
            rollout_path: None,
            config_path: solver.config_path.clone(),
        },
        RoleMetadata {
            role: director.role.clone(),
            rollout_path: None,
            config_path: director.config_path.clone(),
        },
    ]
}

fn collect_session_cleanup(sessions: &RunSessions) -> Vec<SessionCleanup> {
    let mut cleanup = Vec::with_capacity(2 + sessions.verifiers.len());
    cleanup.push(SessionCleanup::new(&sessions.solver));
    cleanup.push(SessionCleanup::new(&sessions.director));
    cleanup.extend(sessions.verifiers.iter().map(SessionCleanup::new));
    cleanup
}

fn parse_solver_signal(message: &str) -> Option<SolverSignal> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return None;
    }

    serde_json::from_str(trimmed)
        .or_else(|_| {
            strip_json_code_fence(trimmed)
                .map(|inner| serde_json::from_str(inner.trim()))
                .unwrap_or_else(|| Err(serde_json::Error::custom("invalid payload")))
        })
        .ok()
}

fn strip_json_code_fence(text: &str) -> Option<&str> {
    let trimmed = text.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        return rest.strip_suffix("```").map(str::trim);
    }
    if let Some(rest) = trimmed.strip_prefix("```JSON") {
        return rest.strip_suffix("```").map(str::trim);
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        return rest.strip_suffix("```").map(str::trim);
    }
    None
}

fn parse_json_struct<T>(message: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("message was empty"));
    }

    serde_json::from_str(trimmed)
        .or_else(|err| {
            strip_json_code_fence(trimmed)
                .map(|inner| serde_json::from_str(inner))
                .unwrap_or_else(|| Err(err))
        })
        .map_err(|err| anyhow!(err))
        .with_context(|| format!("failed to parse message as {}", type_name::<T>()))
}

fn aggregate_verdicts(items: Vec<(String, VerifierVerdict)>) -> AggregatedVerifierVerdict {
    let mut overall = VerifierDecision::Pass;
    let mut verdicts = Vec::with_capacity(items.len());

    for (role, verdict) in items {
        if !verdict.verdict.is_pass() {
            overall = VerifierDecision::Fail;
        }
        verdicts.push(VerifierReport {
            role,
            verdict: verdict.verdict,
            reasons: verdict.reasons,
            suggestions: verdict.suggestions,
        });
    }

    AggregatedVerifierVerdict {
        kind: "verification_feedback",
        overall,
        verdicts,
    }
}

fn solver_signal_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "type": {
                "type": "string",
                "enum": ["direction_request", "verification_request", "final_delivery"]
            },
            "prompt": { "type": ["string", "null"] },
            "claim_path": { "type": ["string", "null"] },
            "notes": { "type": ["string", "null"] },
            "deliverable_path": { "type": ["string", "null"] },
            "summary": { "type": ["string", "null"] }
        },
        "required": [
            "type",
            "prompt",
            "claim_path",
            "notes",
            "deliverable_path",
            "summary"
        ],
        "additionalProperties": false
    })
}

fn final_delivery_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "deliverable_path", "summary"],
        "properties": {
            "type": { "const": "final_delivery" },
            "deliverable_path": { "type": "string" },
            "summary": { "type": ["string", "null"] }
        },
        "additionalProperties": false
    })
}

fn directive_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["directive", "rationale"],
        "properties": {
            "directive": { "type": "string" },
            "rationale": { "type": ["string", "null"] }
        },
        "additionalProperties": false
    })
}

fn verifier_verdict_schema() -> Value {
    json!({
        "type": "object",
        "required": ["verdict", "reasons", "suggestions"],
        "properties": {
            "verdict": { "type": "string", "enum": ["pass", "fail"] },
            "reasons": { "type": "array", "items": { "type": "string" } },
            "suggestions": { "type": "array", "items": { "type": "string" } }
        },
        "additionalProperties": false
    })
}

fn resolve_deliverable_path(base: &Path, candidate: &str) -> Result<PathBuf> {
    let base_abs = base
        .canonicalize()
        .with_context(|| format!("failed to canonicalize run store {}", base.display()))?;

    let candidate_path = Path::new(candidate);
    let joined = if candidate_path.is_absolute() {
        candidate_path.to_path_buf()
    } else {
        base_abs.join(candidate_path)
    };

    let resolved = joined.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize deliverable path {}",
            joined.display()
        )
    })?;

    if !resolved.starts_with(&base_abs) {
        bail!(
            "deliverable path {} escapes run store {}",
            resolved.display(),
            base_abs.display()
        );
    }

    Ok(resolved)
}

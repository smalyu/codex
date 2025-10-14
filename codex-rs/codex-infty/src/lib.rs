#![deny(clippy::print_stdout, clippy::print_stderr)]

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
use codex_core::CrossSessionSpawnParams;
use codex_core::NewConversation;
use codex_core::config::Config;
use codex_core::cross_session::AssistantMessage;
use codex_core::cross_session::CrossSessionHub;
use codex_core::cross_session::PostUserTurnRequest;
use codex_core::cross_session::RoleOrId;
use codex_core::cross_session::SessionEventStream;
use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_core::protocol::SessionConfiguredEvent;
use codex_protocol::ConversationId;
use dirs::home_dir;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::de::Error as _;
use serde_json::Value;
use serde_json::json;
use tokio_stream::StreamExt;
use tracing::warn;

mod prompts;
mod run_store;

pub use run_store::RoleMetadata;
pub use run_store::RunMetadata;
pub use run_store::RunStore;

#[derive(Clone)]
pub struct RoleConfig {
    pub role: String,
    pub config: Config,
    pub config_path: Option<PathBuf>,
}

impl RoleConfig {
    pub fn new(role: impl Into<String>, config: Config) -> Self {
        Self {
            role: role.into(),
            config,
            config_path: None,
        }
    }

    pub fn with_path(role: impl Into<String>, config: Config, config_path: PathBuf) -> Self {
        Self {
            role: role.into(),
            config,
            config_path: Some(config_path),
        }
    }
}

pub struct RunParams {
    pub run_id: String,
    pub run_root: Option<PathBuf>,
    pub solver: RoleConfig,
    pub director: RoleConfig,
    pub verifiers: Vec<RoleConfig>,
}

pub struct ResumeParams {
    pub run_path: PathBuf,
    pub solver: RoleConfig,
    pub director: RoleConfig,
    pub verifiers: Vec<RoleConfig>,
}

const DEFAULT_DIRECTOR_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_VERIFIER_TIMEOUT: Duration = Duration::from_secs(180);
const FINALIZATION_PROMPT: &str = "Create deliverable/: include compiled artifacts or scripts, usage docs, and tests. Write deliverable/README.md with overview, manifest (paths and sizes), verification steps, and limitations. Remove scratch files. Reply with JSON: {\"type\":\"final_delivery\",\"deliverable_path\":\"<path>\",\"summary\":\"<summary>\"}.";

#[derive(Clone)]
pub struct RunExecutionOptions {
    pub objective: Option<String>,
    pub director_timeout: Duration,
    pub verifier_timeout: Duration,
}

impl Default for RunExecutionOptions {
    fn default() -> Self {
        Self {
            objective: None,
            director_timeout: DEFAULT_DIRECTOR_TIMEOUT,
            verifier_timeout: DEFAULT_VERIFIER_TIMEOUT,
        }
    }
}

pub struct RunOutcome {
    pub run_id: String,
    pub deliverable_path: PathBuf,
    pub summary: Option<String>,
    pub raw_message: String,
}

pub struct RoleSession {
    pub role: String,
    pub conversation_id: ConversationId,
    pub conversation: Arc<CodexConversation>,
    pub session_configured: SessionConfiguredEvent,
    pub rollout_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SolverSignal {
    DirectionRequest {
        #[serde(default)]
        prompt: String,
    },
    VerificationRequest {
        claim_path: String,
        #[serde(default)]
        notes: Option<String>,
    },
    FinalDelivery {
        deliverable_path: String,
        #[serde(default)]
        summary: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
struct DirectiveResponse {
    directive: String,
    #[serde(default)]
    rationale: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VerifierDecision {
    Pass,
    Fail,
}

impl VerifierDecision {
    fn is_pass(self) -> bool {
        matches!(self, VerifierDecision::Pass)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct VerifierVerdict {
    verdict: VerifierDecision,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    suggestions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct VerifierReport {
    role: String,
    verdict: VerifierDecision,
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    suggestions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AggregatedVerifierVerdict {
    #[serde(rename = "type")]
    kind: &'static str,
    overall: VerifierDecision,
    verdicts: Vec<VerifierReport>,
}

#[derive(Serialize)]
struct DirectionRequestPayload<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    prompt: &'a str,
}

#[derive(Serialize)]
struct VerificationRequestPayload<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    claim_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
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

pub struct RunSessions {
    pub run_id: String,
    pub solver: RoleSession,
    pub director: RoleSession,
    pub verifiers: Vec<RoleSession>,
    pub store: RunStore,
}

pub struct InftyOrchestrator {
    hub: Arc<CrossSessionHub>,
    conversation_manager: ConversationManager,
    runs_root: PathBuf,
}

impl InftyOrchestrator {
    pub fn new(auth: CodexAuth) -> Result<Self> {
        let runs_root = default_runs_root()?;
        Ok(Self::with_runs_root(auth, runs_root))
    }

    pub fn with_runs_root(auth: CodexAuth, runs_root: impl Into<PathBuf>) -> Self {
        Self {
            hub: Arc::new(CrossSessionHub::new()),
            conversation_manager: ConversationManager::with_auth(auth),
            runs_root: runs_root.into(),
        }
    }

    pub fn runs_root(&self) -> &PathBuf {
        &self.runs_root
    }

    pub fn hub(&self) -> Arc<CrossSessionHub> {
        Arc::clone(&self.hub)
    }

    pub async fn execute_new_run(
        &self,
        params: RunParams,
        options: RunExecutionOptions,
    ) -> Result<RunOutcome> {
        let sessions = self.spawn_run(params).await?;
        self.drive_run(sessions, options).await
    }

    pub async fn execute_existing_run(
        &self,
        params: ResumeParams,
        options: RunExecutionOptions,
    ) -> Result<RunOutcome> {
        let sessions = self.resume_run(params).await?;
        self.drive_run(sessions, options).await
    }

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

    pub async fn resume_run(&self, params: ResumeParams) -> Result<RunSessions> {
        let ResumeParams {
            run_path,
            solver,
            director,
            verifiers,
        } = params;

        let mut store = RunStore::load(&run_path)?;
        let run_id = store.metadata().run_id.clone();
        let mut cleanup = Vec::new();

        let run_path = store.path().to_path_buf();

        let solver_session = match self
            .resume_and_register_role(&run_id, &run_path, &solver, &mut store, &mut cleanup)
            .await
        {
            Ok(session) => session,
            Err(err) => {
                self.cleanup_failed_resume(cleanup).await;
                return Err(err);
            }
        };

        let director_session = match self
            .resume_and_register_role(&run_id, &run_path, &director, &mut store, &mut cleanup)
            .await
        {
            Ok(session) => session,
            Err(err) => {
                self.cleanup_failed_resume(cleanup).await;
                return Err(err);
            }
        };

        let mut verifier_sessions = Vec::with_capacity(verifiers.len());
        for verifier in verifiers.iter() {
            let session = match self
                .resume_and_register_role(&run_id, &run_path, verifier, &mut store, &mut cleanup)
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    self.cleanup_failed_resume(cleanup).await;
                    return Err(err);
                }
            };
            verifier_sessions.push(session);
        }

        store.touch()?;

        Ok(RunSessions {
            run_id,
            solver: solver_session,
            director: director_session,
            verifiers: verifier_sessions,
            store,
        })
    }

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

        if let Some(objective) = &options.objective {
            self.post_to_role(
                &sessions.run_id,
                &sessions.solver.role,
                objective.as_str(),
                None,
            )
            .await?;
            sessions.store.touch()?;
        }

        while let Some(event) = solver_events.next().await {
            match event.event.msg {
                EventMsg::AgentMessage(agent_msg) => {
                    if let Some(signal) = parse_solver_signal(&agent_msg.message) {
                        match signal {
                            SolverSignal::DirectionRequest { prompt } => {
                                self.handle_direction_request(sessions, &prompt, options)
                                    .await?;
                                sessions.store.touch()?;
                            }
                            SolverSignal::VerificationRequest { claim_path, notes } => {
                                let pass = self
                                    .handle_verification_request(
                                        sessions,
                                        &claim_path,
                                        notes.as_deref(),
                                        options,
                                    )
                                    .await?;
                                sessions.store.touch()?;
                                if pass {
                                    self.post_to_role(
                                        &sessions.run_id,
                                        &sessions.solver.role,
                                        FINALIZATION_PROMPT.to_string(),
                                        Some(final_delivery_schema()),
                                    )
                                    .await?;
                                    sessions.store.touch()?;
                                }
                            }
                            SolverSignal::FinalDelivery {
                                deliverable_path: candidate_path,
                                summary,
                            } => {
                                sessions.store.touch()?;
                                let deliverable_path = resolve_deliverable_path(
                                    sessions.store.path(),
                                    &candidate_path,
                                )
                                .with_context(|| {
                                    format!(
                                        "invalid deliverable path reported by solver: {candidate_path}"
                                    )
                                })?;
                                return Ok(RunOutcome {
                                    run_id: sessions.run_id.clone(),
                                    deliverable_path,
                                    summary,
                                    raw_message: agent_msg.message,
                                });
                            }
                        }
                    }
                }
                EventMsg::ShutdownComplete => {
                    break;
                }
                _ => {}
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
        };
        let request_text = serde_json::to_string_pretty(&request)?;
        let handle = self
            .post_to_role(
                &sessions.run_id,
                &sessions.director.role,
                request_text,
                Some(director_schema()),
            )
            .await?;
        let directive = self
            .await_first_assistant(&handle, options.director_timeout)
            .await?;
        let directive_payload: DirectiveResponse = parse_json_struct(&directive.message.message)
            .context("director response was not valid directive JSON")?;
        let directive_text = serde_json::to_string_pretty(&directive_payload)?;
        let _ = self
            .post_to_role(
                &sessions.run_id,
                &sessions.solver.role,
                directive_text,
                None,
            )
            .await?;
        Ok(())
    }

    async fn handle_verification_request(
        &self,
        sessions: &RunSessions,
        claim_path: &str,
        notes: Option<&str>,
        options: &RunExecutionOptions,
    ) -> Result<bool> {
        if sessions.verifiers.is_empty() {
            let summary = aggregate_verdicts(Vec::new());
            let summary_text = serde_json::to_string_pretty(&summary)?;
            let _ = self
                .post_to_role(&sessions.run_id, &sessions.solver.role, summary_text, None)
                .await?;
            return Ok(true);
        }

        let request = VerificationRequestPayload {
            kind: "verification_request",
            claim_path,
            notes,
        };
        let request_text = serde_json::to_string_pretty(&request)?;
        let mut collected = Vec::with_capacity(sessions.verifiers.len());
        let schema = verifier_schema();
        for verifier in &sessions.verifiers {
            let handle = self
                .post_to_role(
                    &sessions.run_id,
                    &verifier.role,
                    request_text.as_str(),
                    Some(schema.clone()),
                )
                .await?;
            let response = self
                .await_first_assistant(&handle, options.verifier_timeout)
                .await?;
            let verdict: VerifierVerdict = parse_json_struct(&response.message.message)
                .with_context(|| {
                    format!("verifier {} returned invalid verdict JSON", verifier.role)
                })?;
            collected.push((verifier.role.clone(), verdict));
        }

        let summary = aggregate_verdicts(collected);
        let summary_text = serde_json::to_string_pretty(&summary)?;
        let _ = self
            .post_to_role(&sessions.run_id, &sessions.solver.role, summary_text, None)
            .await?;
        Ok(summary.overall.is_pass())
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

    async fn cleanup_failed_resume(&self, sessions: Vec<SessionCleanup>) {
        self.shutdown_sessions(sessions).await;
    }

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

    pub async fn post_to_role(
        &self,
        run_id: &str,
        role: &str,
        text: impl Into<String>,
        final_output_json_schema: Option<Value>,
    ) -> Result<codex_core::cross_session::TurnHandle> {
        let handle = self
            .hub
            .post_user_turn(PostUserTurnRequest {
                target: RoleOrId::RunRole {
                    run_id: run_id.to_string(),
                    role: role.to_string(),
                },
                text: text.into(),
                final_output_json_schema,
            })
            .await?;
        Ok(handle)
    }

    pub async fn await_first_assistant(
        &self,
        handle: &codex_core::cross_session::TurnHandle,
        timeout: Duration,
    ) -> Result<AssistantMessage> {
        let message = self.hub.await_first_assistant(handle, timeout).await?;
        Ok(message)
    }

    pub async fn call_role(
        &self,
        run_id: &str,
        role: &str,
        text: impl Into<String>,
        timeout: Duration,
        final_output_json_schema: Option<Value>,
    ) -> Result<AssistantMessage> {
        let handle = self
            .post_to_role(run_id, role, text, final_output_json_schema)
            .await?;
        self.await_first_assistant(&handle, timeout).await
    }

    pub async fn relay_assistant_to_role(
        &self,
        run_id: &str,
        target_role: &str,
        assistant: &AssistantMessage,
        timeout: Duration,
        final_output_json_schema: Option<Value>,
    ) -> Result<AssistantMessage> {
        let handle = self
            .post_to_role(
                run_id,
                target_role,
                assistant.message.message.clone(),
                final_output_json_schema,
            )
            .await?;
        self.await_first_assistant(&handle, timeout).await
    }

    pub fn stream_events(
        &self,
        conversation_id: ConversationId,
    ) -> Result<SessionEventStream, codex_core::cross_session::CrossSessionError> {
        self.hub.stream_events(conversation_id)
    }

    async fn spawn_and_register_role(
        &self,
        run_id: &str,
        run_path: &Path,
        role_config: &RoleConfig,
        store: &mut RunStore,
        cleanup: &mut Vec<SessionCleanup>,
    ) -> Result<RoleSession> {
        let session = self
            .spawn_role_session(run_id, run_path, role_config.clone())
            .await?;
        cleanup.push(SessionCleanup::new(&session));
        store.update_rollout_path(&session.role, session.rollout_path.clone())?;
        if let Some(path) = role_config.config_path.clone() {
            store.set_role_config_path(&session.role, path)?;
        }
        Ok(session)
    }

    async fn resume_and_register_role(
        &self,
        run_id: &str,
        run_path: &Path,
        role_config: &RoleConfig,
        store: &mut RunStore,
        cleanup: &mut Vec<SessionCleanup>,
    ) -> Result<RoleSession> {
        let session = self
            .resume_role_session(run_id, run_path, role_config, store)
            .await?;
        cleanup.push(SessionCleanup::new(&session));
        store.update_rollout_path(&session.role, session.rollout_path.clone())?;
        if let Some(path) = role_config.config_path.clone() {
            store.set_role_config_path(&session.role, path)?;
        }
        Ok(session)
    }

    async fn spawn_role_session(
        &self,
        run_id: &str,
        run_path: &Path,
        role_config: RoleConfig,
    ) -> Result<RoleSession> {
        let RoleConfig {
            role, mut config, ..
        } = role_config;
        config.cwd = run_path.to_path_buf();
        prompts::ensure_instructions(&role, &mut config);
        let session = self
            .conversation_manager
            .new_conversation_with_cross_session(
                config,
                CrossSessionSpawnParams {
                    hub: Arc::clone(&self.hub),
                    run_id: Some(run_id.to_string()),
                    role: Some(role.clone()),
                },
            )
            .await?;
        Ok(RoleSession::from_new(role, session))
    }

    async fn resume_role_session(
        &self,
        run_id: &str,
        run_path: &Path,
        role_config: &RoleConfig,
        store: &RunStore,
    ) -> Result<RoleSession> {
        let metadata = store
            .role_metadata(&role_config.role)
            .ok_or_else(|| anyhow!("role {} not found in run metadata", role_config.role))?;
        let rollout_path = metadata
            .rollout_path
            .as_ref()
            .ok_or_else(|| anyhow!("missing rollout path for role {}", role_config.role))?;

        let mut config = role_config.config.clone();
        config.cwd = run_path.to_path_buf();
        prompts::ensure_instructions(&role_config.role, &mut config);

        let session = self
            .conversation_manager
            .resume_conversation_with_cross_session(
                config,
                rollout_path.clone(),
                CrossSessionSpawnParams {
                    hub: Arc::clone(&self.hub),
                    run_id: Some(run_id.to_string()),
                    role: Some(role_config.role.clone()),
                },
            )
            .await?;

        Ok(RoleSession::from_new(role_config.role.clone(), session))
    }
}

impl RoleSession {
    fn from_new(role: String, session: NewConversation) -> Self {
        Self {
            role,
            conversation_id: session.conversation_id,
            conversation: session.conversation,
            session_configured: session.session_configured.clone(),
            rollout_path: session.session_configured.rollout_path.clone(),
        }
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

fn director_schema() -> Value {
    json!({
        "type": "object",
        "required": ["directive"],
        "properties": {
            "directive": { "type": "string" },
            "rationale": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn verifier_schema() -> Value {
    json!({
        "type": "object",
        "required": ["verdict"],
        "properties": {
            "verdict": { "type": "string", "enum": ["pass", "fail"] },
            "reasons": { "type": "array", "items": { "type": "string" } },
            "suggestions": { "type": "array", "items": { "type": "string" } }
        },
        "additionalProperties": false
    })
}

fn final_delivery_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "deliverable_path"],
        "properties": {
            "type": { "const": "final_delivery" },
            "deliverable_path": { "type": "string" },
            "summary": { "type": "string" }
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

fn collect_session_cleanup(sessions: &RunSessions) -> Vec<SessionCleanup> {
    let mut cleanup = Vec::with_capacity(2 + sessions.verifiers.len());
    cleanup.push(SessionCleanup::new(&sessions.solver));
    cleanup.push(SessionCleanup::new(&sessions.director));
    cleanup.extend(sessions.verifiers.iter().map(SessionCleanup::new));
    cleanup
}

pub fn default_runs_root() -> Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow!("failed to determine home directory"))?;
    Ok(home.join(".codex").join("infty"))
}

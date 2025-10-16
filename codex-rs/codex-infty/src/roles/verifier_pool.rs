use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use anyhow::Result;
use codex_core::cross_session::CrossSessionHub;

use crate::progress::ProgressReporter;
use crate::roles::Role;
use crate::roles::verifier::VerificationRequestPayload;
use crate::roles::verifier::VerifierRole;
use crate::roles::verifier::aggregate_verdicts;
use crate::signals::AggregatedVerifierVerdict;
use crate::signals::VerifierVerdict;
use crate::types::RunSessions;

pub struct VerificationRound {
    pub summary: AggregatedVerifierVerdict,
    pub passing_roles: Vec<String>,
}

pub struct VerifierPool {
    hub: Arc<CrossSessionHub>,
    run_id: String,
    timeout: Duration,
    progress: Option<Arc<dyn ProgressReporter>>,
    roles: Vec<VerifierRole>,
}

impl VerifierPool {
    pub fn from_sessions(
        hub: Arc<CrossSessionHub>,
        sessions: &RunSessions,
        timeout: Duration,
        progress: Option<Arc<dyn ProgressReporter>>,
    ) -> Self {
        let roles = sessions
            .verifiers
            .iter()
            .map(|v| {
                VerifierRole::new(
                    Arc::clone(&hub),
                    sessions.run_id.clone(),
                    v.role.clone(),
                    timeout,
                    progress.clone(),
                )
            })
            .collect();
        Self {
            hub,
            run_id: sessions.run_id.clone(),
            timeout,
            progress,
            roles,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty()
    }

    pub async fn collect_round(
        &self,
        request: &VerificationRequestPayload<'_>,
    ) -> Result<VerificationRound> {
        let futures = self
            .roles
            .iter()
            .map(|role| async {
                let name = role.role().to_string();
                let verdict = role.call(request).await;
                (name, verdict)
            })
            .collect::<Vec<_>>();
        let joined = futures::future::join_all(futures).await;

        let mut results: Vec<(String, VerifierVerdict)> = Vec::with_capacity(joined.len());
        let mut passing_roles: Vec<String> = Vec::new();
        for (name, verdict_res) in joined.into_iter() {
            let verdict = verdict_res
                .with_context(|| format!("verifier {} returned invalid verdict JSON", name))?;
            if let Some(progress) = self.progress.as_ref() {
                progress.verifier_verdict(&name, &verdict);
            }
            if verdict.verdict.is_pass() {
                passing_roles.push(name.clone());
            }
            results.push((name, verdict));
        }
        let summary = aggregate_verdicts(results);
        Ok(VerificationRound {
            summary,
            passing_roles,
        })
    }

    pub fn replace_role(&mut self, role_name: &str) {
        if let Some(idx) = self.roles.iter().position(|v| v.role() == role_name) {
            self.roles[idx] = VerifierRole::new(
                Arc::clone(&self.hub),
                self.run_id.clone(),
                role_name.to_string(),
                self.timeout,
                self.progress.clone(),
            );
        }
    }
}

use std::path::Path;

use codex_core::protocol::AgentMessageEvent;
use codex_core::protocol::EventMsg;
use codex_infty::AggregatedVerifierVerdict;
use codex_infty::DirectiveResponse;
use codex_infty::ProgressReporter;
use codex_infty::VerifierDecision;
use codex_infty::VerifierVerdict;
use owo_colors::OwoColorize;
use supports_color::Stream;

pub(crate) struct TerminalProgressReporter {
    color_enabled: bool,
}

impl TerminalProgressReporter {
    pub(crate) fn with_color(color_enabled: bool) -> Self {
        Self { color_enabled }
    }

    fn format_decision(&self, decision: VerifierDecision) -> String {
        let label = match decision {
            VerifierDecision::Pass => "pass",
            VerifierDecision::Fail => "fail",
        };
        if !self.color_enabled {
            return label.to_string();
        }
        match decision {
            VerifierDecision::Pass => format!("{}", label.green().bold()),
            VerifierDecision::Fail => format!("{}", label.red().bold()),
        }
    }
}

impl Default for TerminalProgressReporter {
    fn default() -> Self {
        Self::with_color(supports_color::on(Stream::Stdout).is_some())
    }
}

impl ProgressReporter for TerminalProgressReporter {
    fn objective_posted(&self, objective: &str) {
        let line = format!("→ objective sent to solver: {objective}");
        if self.color_enabled {
            println!("{}", line.cyan());
        } else {
            println!("{line}");
        }
    }

    fn waiting_for_solver(&self) {
        if self.color_enabled {
            println!("{}", "Waiting for solver response...".dimmed());
        } else {
            println!("Waiting for solver response...");
        }
    }

    fn solver_event(&self, event: &EventMsg) {
        match serde_json::to_string_pretty(event) {
            Ok(json) => {
                tracing::trace!("[solver:event]\n{json}");
            }
            Err(err) => {
                tracing::warn!("[solver:event] (failed to serialize: {err}) {event:?}");
            }
        }
    }

    fn solver_agent_message(&self, agent_msg: &AgentMessageEvent) {
        let prefix = if self.color_enabled {
            format!("{}", "[solver]".magenta().bold())
        } else {
            "[solver]".to_string()
        };
        println!("{prefix} {}", agent_msg.message);
    }

    fn direction_request(&self, prompt: &str) {
        let line = format!("→ solver requested direction: {prompt}");
        if self.color_enabled {
            println!("{}", line.yellow().bold());
        } else {
            println!("{line}");
        }
    }

    fn director_response(&self, directive: &DirectiveResponse) {
        match directive.rationale.as_deref() {
            Some(rationale) if !rationale.is_empty() => {
                let line = format!(
                    "[director] directive: {} (rationale: {rationale})",
                    directive.directive
                );
                if self.color_enabled {
                    println!("{}", line.blue());
                } else {
                    println!("{line}");
                }
            }
            _ => {
                let line = format!("[director] directive: {}", directive.directive);
                if self.color_enabled {
                    println!("{}", line.blue());
                } else {
                    println!("{line}");
                }
            }
        }
    }

    fn verification_request(&self, claim_path: &str, notes: Option<&str>) {
        let line = format!("→ solver requested verification for {claim_path}");
        if self.color_enabled {
            println!("{}", line.yellow().bold());
        } else {
            println!("{line}");
        }
        if let Some(notes) = notes
            && !notes.is_empty()
        {
            let notes_line = format!("  notes: {notes}");
            if self.color_enabled {
                println!("{}", notes_line.dimmed());
            } else {
                println!("{notes_line}");
            }
        }
    }

    fn verifier_verdict(&self, role: &str, verdict: &VerifierVerdict) {
        let decision = self.format_decision(verdict.verdict);
        let prefix = if self.color_enabled {
            format!("{}", format!("[{role}]").magenta().bold())
        } else {
            format!("[{role}]")
        };
        println!("{prefix} verdict: {decision}");
        if !verdict.reasons.is_empty() {
            let reasons = verdict.reasons.join("; ");
            let line = format!("  reasons: {reasons}");
            if self.color_enabled {
                println!("{}", line.dimmed());
            } else {
                println!("{line}");
            }
        }
        if !verdict.suggestions.is_empty() {
            let suggestions = verdict.suggestions.join("; ");
            let line = format!("  suggestions: {suggestions}");
            if self.color_enabled {
                println!("{}", line.dimmed());
            } else {
                println!("{line}");
            }
        }
    }

    fn verification_summary(&self, summary: &AggregatedVerifierVerdict) {
        println!();
        let decision = self.format_decision(summary.overall);
        let heading = if self.color_enabled {
            format!("{}", "Verification summary".bold())
        } else {
            "Verification summary".to_string()
        };
        println!("{heading}: {decision}");
        for report in &summary.verdicts {
            let report_decision = self.format_decision(report.verdict);
            let line = format!("  {} → {report_decision}", report.role);
            println!("{line}");
            if !report.reasons.is_empty() {
                let reasons = report.reasons.join("; ");
                let reason_line = format!("    reasons: {reasons}");
                if self.color_enabled {
                    println!("{}", reason_line.dimmed());
                } else {
                    println!("{reason_line}");
                }
            }
            if !report.suggestions.is_empty() {
                let suggestions = report.suggestions.join("; ");
                let suggestion_line = format!("    suggestions: {suggestions}");
                if self.color_enabled {
                    println!("{}", suggestion_line.dimmed());
                } else {
                    println!("{suggestion_line}");
                }
            }
        }
    }

    fn final_delivery(&self, deliverable_path: &Path, summary: Option<&str>) {
        println!();
        let line = format!(
            "✓ solver reported final delivery at {}",
            deliverable_path.display()
        );
        if self.color_enabled {
            println!("{}", line.green().bold());
        } else {
            println!("{line}");
        }
        if let Some(summary) = summary
            && !summary.is_empty()
        {
            let hint = "  (final summary will be shown below)";
            if self.color_enabled {
                println!("{}", hint.dimmed());
            } else {
                println!("{hint}");
            }
        }
    }

    fn run_interrupted(&self) {
        let line = "Run interrupted by Ctrl+C. Shutting down sessions…";
        if self.color_enabled {
            println!("{}", line.red().bold());
        } else {
            println!("{line}");
        }
    }
}

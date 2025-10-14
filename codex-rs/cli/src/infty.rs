use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use chrono::SecondsFormat;
use chrono::Utc;
use clap::Parser;
use clap::Subcommand;
use codex_common::CliConfigOverrides;
use codex_common::elapsed::format_duration;
use codex_core::CodexAuth;
use codex_core::auth::read_codex_api_key_from_env;
use codex_core::auth::read_openai_api_key_from_env;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::protocol::AgentMessageEvent;
use codex_core::protocol::EventMsg;
use codex_infty::AggregatedVerifierVerdict;
use codex_infty::DirectiveResponse;
use codex_infty::InftyOrchestrator;
use codex_infty::ProgressReporter;
use codex_infty::ResumeParams;
use codex_infty::RoleConfig;
use codex_infty::RunExecutionOptions;
use codex_infty::RunParams;
use codex_infty::RunStore;
use codex_infty::VerifierDecision;
use codex_infty::VerifierVerdict;
use crossterm::terminal;
use owo_colors::OwoColorize;
use serde::Serialize;
use supports_color::Stream;
use textwrap::Options as WrapOptions;
use textwrap::wrap;

const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Parser)]
pub struct InftyCli {
    #[clap(flatten)]
    pub config_overrides: CliConfigOverrides,

    /// Override the default runs root (`~/.codex/infty`).
    #[arg(long = "runs-root", value_name = "DIR")]
    pub runs_root: Option<PathBuf>,

    #[command(subcommand)]
    command: InftyCommand,
}

#[derive(Debug, Subcommand)]
enum InftyCommand {
    /// Create a new run store and spawn solver/director sessions.
    Create(CreateArgs),

    /// List stored runs.
    List(ListArgs),

    /// Show metadata for a stored run.
    Show(ShowArgs),

    /// Send a message to a role within a run and print the first reply.
    Drive(DriveArgs),
}

#[derive(Debug, Parser)]
struct CreateArgs {
    /// Explicit run id. If omitted, a timestamp-based id is generated.
    #[arg(long = "run-id", value_name = "RUN_ID")]
    run_id: Option<String>,

    /// Optional objective to send to the solver immediately after creation.
    #[arg(long)]
    objective: Option<String>,

    /// Timeout in seconds when waiting for the solver reply to --objective.
    #[arg(long = "timeout-secs", default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,
}

#[derive(Debug, Parser)]
struct ListArgs {
    /// Emit JSON describing the stored runs.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct ShowArgs {
    /// Run id to display.
    run_id: String,

    /// Emit JSON metadata instead of human-readable text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct DriveArgs {
    /// Run id to resume.
    run_id: String,

    /// Role to address (e.g. solver, director).
    role: String,

    /// Message to send to the role.
    message: String,

    /// Timeout in seconds to await the first assistant message.
    #[arg(long = "timeout-secs", default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    run_id: String,
    path: String,
    created_at: String,
    updated_at: String,
    roles: Vec<String>,
}

struct TerminalProgressReporter {
    color_enabled: bool,
}

impl TerminalProgressReporter {
    fn decision_label(decision: VerifierDecision) -> &'static str {
        match decision {
            VerifierDecision::Pass => "pass",
            VerifierDecision::Fail => "fail",
        }
    }

    fn with_color(color_enabled: bool) -> Self {
        Self { color_enabled }
    }

    fn format_decision(&self, decision: VerifierDecision) -> String {
        let label = Self::decision_label(decision);
        if !self.color_enabled {
            return label.to_string();
        }
        match decision {
            VerifierDecision::Pass => format!("{}", label.green().bold()),
            VerifierDecision::Fail => format!("{}", label.red().bold()),
        }
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
        if let Some(notes) = notes {
            if !notes.is_empty() {
                let notes_line = format!("  notes: {notes}");
                if self.color_enabled {
                    println!("{}", notes_line.dimmed());
                } else {
                    println!("{notes_line}");
                }
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
        if let Some(summary) = summary {
            if !summary.is_empty() {
                let hint = "  (final summary will be shown below)";
                if self.color_enabled {
                    println!("{}", hint.dimmed());
                } else {
                    println!("{hint}");
                }
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

impl InftyCli {
    pub async fn run(self) -> Result<()> {
        let InftyCli {
            config_overrides,
            runs_root,
            command,
        } = self;

        match command {
            InftyCommand::Create(args) => {
                run_create(config_overrides, runs_root, args).await?;
            }
            InftyCommand::List(args) => run_list(runs_root, args)?,
            InftyCommand::Show(args) => run_show(runs_root, args)?,
            InftyCommand::Drive(args) => {
                run_drive(config_overrides, runs_root, args).await?;
            }
        }

        Ok(())
    }
}

async fn run_create(
    config_overrides: CliConfigOverrides,
    runs_root_override: Option<PathBuf>,
    args: CreateArgs,
) -> Result<()> {
    let config = load_config(config_overrides).await?;
    let auth = load_auth(&config)?;
    let runs_root = resolve_runs_root(runs_root_override)?;
    let color_enabled = supports_color::on(Stream::Stdout).is_some();

    let mut run_id = if let Some(id) = args.run_id {
        id
    } else {
        generate_run_id()
    };
    run_id = run_id.trim().to_string();
    validate_run_id(&run_id)?;

    let run_path = runs_root.join(&run_id);
    if run_path.exists() {
        bail!("run {run_id} already exists at {}", run_path.display());
    }

    let orchestrator = InftyOrchestrator::with_runs_root(auth, runs_root.clone()).with_progress(
        Arc::new(TerminalProgressReporter::with_color(color_enabled)),
    );
    let run_params = RunParams {
        run_id: run_id.clone(),
        run_root: Some(run_path.clone()),
        solver: RoleConfig::new("solver", config.clone()),
        director: RoleConfig::new("director", config.clone()),
        verifiers: Vec::new(),
    };

    if let Some(objective) = args.objective {
        let mut options = RunExecutionOptions::default();
        options.objective = Some(objective);
        let timeout = Duration::from_secs(args.timeout_secs);
        options.director_timeout = timeout;
        options.verifier_timeout = timeout;

        let start = Instant::now();
        let start_header = format!("Starting run {run_id}");
        if color_enabled {
            println!("{}", start_header.blue().bold());
        } else {
            println!("{start_header}");
        }
        let location_line = format!("  run directory: {}", run_path.display());
        if color_enabled {
            println!("{}", location_line.dimmed());
        } else {
            println!("{location_line}");
        }
        if let Some(objective_text) = options.objective.as_deref() {
            if !objective_text.trim().is_empty() {
                let objective_line = format!("  objective: {objective_text}");
                if color_enabled {
                    println!("{}", objective_line.dimmed());
                } else {
                    println!("{objective_line}");
                }
            }
        }
        println!();

        let objective_snapshot = options.objective.clone();
        let outcome = orchestrator
            .execute_new_run(run_params, options)
            .await
            .with_context(|| format!("failed to execute run {run_id}"))?;
        let duration = start.elapsed();
        print_run_summary_box(
            color_enabled,
            &run_id,
            &run_path,
            &outcome.deliverable_path,
            outcome.summary.as_deref(),
            objective_snapshot.as_deref(),
            duration,
        );
    } else {
        let sessions = orchestrator
            .spawn_run(run_params)
            .await
            .with_context(|| format!("failed to create run {run_id}"))?;

        println!(
            "Created run {run_id} at {}",
            sessions.store.path().display()
        );
    }

    Ok(())
}

fn run_list(runs_root_override: Option<PathBuf>, args: ListArgs) -> Result<()> {
    let runs_root = resolve_runs_root(runs_root_override)?;
    let listings = collect_run_summaries(&runs_root)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&listings)?);
        return Ok(());
    }

    if listings.is_empty() {
        println!("No runs found under {}", runs_root.display());
        return Ok(());
    }

    println!("Runs in {}", runs_root.display());
    for summary in listings {
        println!(
            "{}\t{}\t{}",
            summary.run_id, summary.updated_at, summary.path
        );
    }

    Ok(())
}

fn run_show(runs_root_override: Option<PathBuf>, args: ShowArgs) -> Result<()> {
    validate_run_id(&args.run_id)?;
    let runs_root = resolve_runs_root(runs_root_override)?;
    let run_path = runs_root.join(&args.run_id);
    let store =
        RunStore::load(&run_path).with_context(|| format!("failed to load run {}", args.run_id))?;
    let metadata = store.metadata();

    let summary = RunSummary {
        run_id: metadata.run_id.clone(),
        path: run_path.display().to_string(),
        created_at: metadata
            .created_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        updated_at: metadata
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        roles: metadata
            .roles
            .iter()
            .map(|role| role.role.clone())
            .collect(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    println!("Run: {}", summary.run_id);
    println!("Path: {}", summary.path);
    println!("Created: {}", summary.created_at);
    println!("Updated: {}", summary.updated_at);
    println!("Roles: {}", summary.roles.join(", "));

    Ok(())
}

async fn run_drive(
    config_overrides: CliConfigOverrides,
    runs_root_override: Option<PathBuf>,
    args: DriveArgs,
) -> Result<()> {
    validate_run_id(&args.run_id)?;
    let config = load_config(config_overrides).await?;
    let auth = load_auth(&config)?;
    let runs_root = resolve_runs_root(runs_root_override)?;
    let run_path = runs_root.join(&args.run_id);
    let store =
        RunStore::load(&run_path).with_context(|| format!("failed to load run {}", args.run_id))?;

    let solver_role = store
        .role_metadata("solver")
        .ok_or_else(|| anyhow!("run {} is missing solver role", args.run_id))?;
    let director_role = store
        .role_metadata("director")
        .ok_or_else(|| anyhow!("run {} is missing director role", args.run_id))?;

    let verifiers: Vec<_> = store
        .metadata()
        .roles
        .iter()
        .filter(|role| role.role != solver_role.role && role.role != director_role.role)
        .map(|role| RoleConfig::new(role.role.clone(), config.clone()))
        .collect();

    let orchestrator = InftyOrchestrator::with_runs_root(auth, runs_root)
        .with_progress(Arc::new(TerminalProgressReporter::default()));
    let sessions = orchestrator
        .resume_run(ResumeParams {
            run_path: run_path.clone(),
            solver: RoleConfig::new(solver_role.role.clone(), config.clone()),
            director: RoleConfig::new(director_role.role.clone(), config.clone()),
            verifiers,
        })
        .await
        .with_context(|| format!("failed to resume run {}", args.run_id))?;

    let timeout = Duration::from_secs(args.timeout_secs);
    let reply = orchestrator
        .call_role(&sessions.run_id, &args.role, args.message, timeout, None)
        .await
        .with_context(|| {
            format!(
                "failed to deliver message to role {} in run {}",
                args.role, sessions.run_id
            )
        })?;

    println!("{}", reply.message.message);
    Ok(())
}

fn validate_run_id(run_id: &str) -> Result<()> {
    if run_id.is_empty() {
        bail!("run id must not be empty");
    }
    if run_id.starts_with('.') || run_id.ends_with('.') {
        bail!("run id must not begin or end with '.'");
    }
    if run_id
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        bail!("run id may only contain ASCII alphanumerics, '-', '_', or '.'");
    }
    Ok(())
}

fn generate_run_id() -> String {
    let timestamp = Utc::now().format("run-%Y%m%d-%H%M%S");
    format!("{timestamp}")
}

async fn load_config(cli_overrides: CliConfigOverrides) -> Result<Config> {
    let overrides = cli_overrides
        .parse_overrides()
        .map_err(|err| anyhow!("failed to parse -c overrides: {err}"))?;
    Config::load_with_cli_overrides(overrides, ConfigOverrides::default())
        .await
        .context("failed to load Codex configuration")
}

fn load_auth(config: &Config) -> Result<CodexAuth> {
    if let Some(auth) =
        CodexAuth::from_codex_home(&config.codex_home).context("failed to read auth.json")?
    {
        return Ok(auth);
    }
    if let Some(api_key) = read_codex_api_key_from_env() {
        return Ok(CodexAuth::from_api_key(&api_key));
    }
    if let Some(api_key) = read_openai_api_key_from_env() {
        return Ok(CodexAuth::from_api_key(&api_key));
    }
    bail!("no Codex authentication found. Run `codex login` or set OPENAI_API_KEY.");
}

fn resolve_runs_root(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    Ok(codex_infty::default_runs_root()?)
}

fn collect_run_summaries(root: &Path) -> Result<Vec<RunSummary>> {
    let mut summaries = Vec::new();
    let iter = match fs::read_dir(root) {
        Ok(read_dir) => read_dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(summaries),
        Err(err) => {
            return Err(
                anyhow!(err).context(format!("failed to read runs root {}", root.display()))
            );
        }
    };

    for entry in iter {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let run_path = entry.path();
        let store = match RunStore::load(&run_path) {
            Ok(store) => store,
            Err(err) => {
                eprintln!(
                    "Skipping {}: failed to load run metadata: {err}",
                    run_path.display()
                );
                continue;
            }
        };
        let metadata = store.metadata();
        summaries.push(RunSummary {
            run_id: metadata.run_id.clone(),
            path: run_path.display().to_string(),
            created_at: metadata
                .created_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            updated_at: metadata
                .updated_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            roles: metadata
                .roles
                .iter()
                .map(|role| role.role.clone())
                .collect(),
        });
    }

    summaries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(summaries)
}

impl Default for TerminalProgressReporter {
    fn default() -> Self {
        Self::with_color(supports_color::on(Stream::Stdout).is_some())
    }
}

fn print_run_summary_box(
    color_enabled: bool,
    run_id: &str,
    run_path: &Path,
    deliverable_path: &Path,
    summary: Option<&str>,
    objective: Option<&str>,
    duration: Duration,
) {
    let mut items = Vec::new();
    items.push(("Run ID".to_string(), run_id.to_string()));
    items.push(("Run Directory".to_string(), run_path.display().to_string()));
    if let Some(objective) = objective {
        if !objective.trim().is_empty() {
            items.push(("Objective".to_string(), objective.trim().to_string()));
        }
    }
    items.push((
        "Deliverable".to_string(),
        deliverable_path.display().to_string(),
    ));
    items.push(("Total Time".to_string(), format_duration(duration)));
    if let Some(summary) = summary {
        let trimmed = summary.trim();
        if !trimmed.is_empty() {
            items.push(("Summary".to_string(), trimmed.to_string()));
        }
    }

    let label_width = items
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0)
        .max(12);
    const DEFAULT_MAX_WIDTH: usize = 84;
    const MIN_VALUE_WIDTH: usize = 20;
    let label_padding = label_width + 7;
    let min_total_width = label_padding + MIN_VALUE_WIDTH;
    let available_width = terminal::size()
        .ok()
        .map(|(cols, _)| usize::from(cols).saturating_sub(2))
        .unwrap_or(DEFAULT_MAX_WIDTH);
    let max_width = available_width.min(DEFAULT_MAX_WIDTH);
    let lower_bound = min_total_width.min(available_width);
    let mut total_width = max_width.max(lower_bound).max(label_padding + 1);
    let mut value_width = total_width.saturating_sub(label_padding);
    if value_width < MIN_VALUE_WIDTH {
        value_width = MIN_VALUE_WIDTH;
        total_width = label_padding + value_width;
    }
    let inner_width = total_width.saturating_sub(4);
    let top_border = format!("+{}+", "=".repeat(total_width.saturating_sub(2)));
    let separator = format!("+{}+", "-".repeat(total_width.saturating_sub(2)));
    let title_line = format!(
        "| {:^inner_width$} |",
        "Run Summary",
        inner_width = inner_width
    );

    println!();
    println!("{top_border}");
    if color_enabled {
        println!("{}", title_line.bold());
    } else {
        println!("{title_line}");
    }
    println!("{separator}");

    for (index, (label, value)) in items.iter().enumerate() {
        let mut rows = Vec::new();
        for (idx, paragraph) in value.split('\n').enumerate() {
            let trimmed = paragraph.trim();
            if trimmed.is_empty() {
                if idx > 0 {
                    rows.push(String::new());
                }
                continue;
            }
            let wrapped = wrap(trimmed, WrapOptions::new(value_width).break_words(false));
            if wrapped.is_empty() {
                rows.push(String::new());
            } else {
                rows.extend(wrapped.into_iter().map(|line| line.into_owned()));
            }
        }
        if rows.is_empty() {
            rows.push(String::new());
        }

        for (line_idx, line) in rows.iter().enumerate() {
            let label_cell = if line_idx == 0 { label.as_str() } else { "" };
            let row_line = format!(
                "| {label_cell:<label_width$} | {line:<value_width$} |",
                label_cell = label_cell,
                line = line,
                label_width = label_width,
                value_width = value_width
            );
            if color_enabled {
                match label.as_str() {
                    "Deliverable" => println!("{}", row_line.green()),
                    "Summary" => println!("{}", row_line.bold()),
                    _ => println!("{row_line}"),
                }
            } else {
                println!("{row_line}");
            }
        }

        if index + 1 < items.len() {
            println!("{separator}");
        }
    }

    println!("{top_border}");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn validates_run_ids() {
        assert!(validate_run_id("run-20241030-123000").is_ok());
        assert!(validate_run_id("run.alpha").is_ok());
        assert!(validate_run_id("").is_err());
        assert!(validate_run_id("..bad").is_err());
        assert!(validate_run_id("bad/value").is_err());
    }

    #[test]
    fn generates_timestamped_run_id() {
        let run_id = generate_run_id();
        assert!(run_id.starts_with("run-"));
        assert_eq!(run_id.len(), "run-YYYYMMDD-HHMMSS".len());
    }

    #[test]
    fn collect_summaries_returns_empty_for_missing_root() {
        let temp = TempDir::new().expect("temp dir");
        let missing = temp.path().join("not-present");
        let summaries = collect_run_summaries(&missing).expect("collect");
        assert!(summaries.is_empty());
    }
}

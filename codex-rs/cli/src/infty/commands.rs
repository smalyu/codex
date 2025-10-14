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
use codex_common::CliConfigOverrides;
use codex_core::CodexAuth;
use codex_core::auth::read_codex_api_key_from_env;
use codex_core::auth::read_openai_api_key_from_env;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_infty::InftyOrchestrator;
use codex_infty::ResumeParams;
use codex_infty::RoleConfig;
use codex_infty::RunExecutionOptions;
use codex_infty::RunParams;
use codex_infty::RunStore;
use owo_colors::OwoColorize;
use serde::Serialize;
use supports_color::Stream;

use super::args::CreateArgs;
use super::args::DriveArgs;
use super::args::ListArgs;
use super::args::ShowArgs;
use super::progress::TerminalProgressReporter;
use super::summary::print_run_summary_box;

const DEFAULT_VERIFIER_ROLES: [&str; 3] = ["verifier-alpha", "verifier-beta", "verifier-gamma"];

pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Serialize)]
struct RunSummary {
    run_id: String,
    path: String,
    created_at: String,
    updated_at: String,
    roles: Vec<String>,
}

pub(crate) async fn run_create(
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

    let orchestrator = InftyOrchestrator::with_runs_root(auth, runs_root).with_progress(Arc::new(
        TerminalProgressReporter::with_color(color_enabled),
    ));
    let verifiers: Vec<RoleConfig> = DEFAULT_VERIFIER_ROLES
        .iter()
        .map(|role| RoleConfig::new(role.to_string(), config.clone()))
        .collect();
    let run_params = RunParams {
        run_id: run_id.clone(),
        run_root: Some(run_path.clone()),
        solver: RoleConfig::new("solver", config.clone()),
        director: RoleConfig::new("director", config.clone()),
        verifiers,
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

pub(crate) fn run_list(runs_root_override: Option<PathBuf>, args: ListArgs) -> Result<()> {
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

pub(crate) fn run_show(runs_root_override: Option<PathBuf>, args: ShowArgs) -> Result<()> {
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

pub(crate) async fn run_drive(
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

fn generate_run_id() -> String {
    let timestamp = Utc::now().format("run-%Y%m%d-%H%M%S");
    format!("{timestamp}")
}

pub(crate) fn validate_run_id(run_id: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_verifier_roles_are_stable() {
        assert_eq!(
            DEFAULT_VERIFIER_ROLES,
            ["verifier-alpha", "verifier-beta", "verifier-gamma"]
        );
    }

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

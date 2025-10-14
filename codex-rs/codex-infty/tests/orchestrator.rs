#![cfg(not(target_os = "windows"))]

use std::time::Duration;

use codex_core::CodexAuth;
use codex_core::built_in_model_providers;
use codex_core::config::Config;
use codex_core::protocol::Op;
use codex_infty::InftyOrchestrator;
use codex_infty::ResumeParams;
use codex_infty::RoleConfig;
use codex_infty::RunExecutionOptions;
use codex_infty::RunParams;
use core_test_support::load_default_config_for_test;
use core_test_support::responses;
use core_test_support::skip_if_no_network;
use tempfile::TempDir;
use wiremock::MockServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrator_routes_between_roles_and_records_store() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let bodies = vec![
        responses::sse(vec![
            responses::ev_response_created("solver-resp-1"),
            responses::ev_assistant_message("solver-msg-1", "Need direction"),
            responses::ev_completed("solver-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("director-resp-1"),
            responses::ev_assistant_message("director-msg-1", "Proceed iteratively"),
            responses::ev_completed("director-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("solver-resp-2"),
            responses::ev_assistant_message("solver-msg-2", "Acknowledged"),
            responses::ev_completed("solver-resp-2"),
        ]),
    ];
    let response_mock = responses::mount_sse_sequence(&server, bodies).await;

    let runs_root = TempDir::new()?;
    let orchestrator =
        InftyOrchestrator::with_runs_root(CodexAuth::from_api_key("dummy-key"), runs_root.path());
    let run_id = "run-orchestrator".to_string();

    let solver_config = build_config(&server).await?;
    let director_config = build_config(&server).await?;

    let sessions = orchestrator
        .spawn_run(RunParams {
            run_id: run_id.clone(),
            run_root: Some(runs_root.path().join("runs").join(&run_id)),
            solver: RoleConfig::new("solver", solver_config.clone()),
            director: RoleConfig::new("director", director_config.clone()),
            verifiers: Vec::new(),
        })
        .await?;

    let solver_message = orchestrator
        .call_role(
            &sessions.run_id,
            "solver",
            "kick off plan",
            Duration::from_secs(1),
            None,
        )
        .await?;
    assert_eq!(solver_message.message.message, "Need direction");

    let director_message = orchestrator
        .relay_assistant_to_role(
            &sessions.run_id,
            "director",
            &solver_message,
            Duration::from_secs(1),
            None,
        )
        .await?;
    assert_eq!(director_message.message.message, "Proceed iteratively");

    let solver_reply = orchestrator
        .relay_assistant_to_role(
            &sessions.run_id,
            "solver",
            &director_message,
            Duration::from_secs(1),
            None,
        )
        .await?;
    assert_eq!(solver_reply.message.message, "Acknowledged");

    assert_eq!(response_mock.requests().len(), 3);
    let first_request = response_mock.requests().first().unwrap().body_json();
    let instructions = first_request["instructions"]
        .as_str()
        .expect("request should set instructions");
    assert!(
        instructions.contains("Codex Infty Solver"),
        "missing solver prompt: {instructions}"
    );
    assert!(sessions.store.path().is_dir());
    let solver_meta = sessions.store.role_metadata("solver").unwrap();
    assert!(solver_meta.rollout_path.is_some());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrator_resumes_existing_run() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let bodies = vec![
        responses::sse(vec![
            responses::ev_response_created("solver-resp-1"),
            responses::ev_assistant_message("solver-msg-1", "Need direction"),
            responses::ev_completed("solver-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("director-resp-1"),
            responses::ev_assistant_message("director-msg-1", "Proceed iteratively"),
            responses::ev_completed("director-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("solver-resp-2"),
            responses::ev_assistant_message("solver-msg-2", "Acknowledged"),
            responses::ev_completed("solver-resp-2"),
        ]),
    ];
    for body in bodies {
        responses::mount_sse_once(&server, body).await;
    }

    let runs_root = TempDir::new()?;
    let orchestrator =
        InftyOrchestrator::with_runs_root(CodexAuth::from_api_key("dummy-key"), runs_root.path());
    let run_id = "run-resume".to_string();

    let solver_config = build_config(&server).await?;
    let director_config = build_config(&server).await?;

    let sessions = orchestrator
        .spawn_run(RunParams {
            run_id: run_id.clone(),
            run_root: Some(runs_root.path().join("runs").join(&run_id)),
            solver: RoleConfig::new("solver", solver_config.clone()),
            director: RoleConfig::new("director", director_config.clone()),
            verifiers: Vec::new(),
        })
        .await?;

    sessions.solver.conversation.submit(Op::Shutdown).await.ok();
    sessions
        .director
        .conversation
        .submit(Op::Shutdown)
        .await
        .ok();
    drop(sessions);

    let resume = orchestrator
        .resume_run(ResumeParams {
            run_path: runs_root.path().join("runs").join(&run_id),
            solver: RoleConfig::new("solver", solver_config),
            director: RoleConfig::new("director", director_config),
            verifiers: Vec::new(),
        })
        .await?;

    assert_eq!(resume.run_id, run_id);
    assert!(
        resume
            .store
            .role_metadata("solver")
            .unwrap()
            .rollout_path
            .is_some()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_new_run_drives_to_completion() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let bodies = vec![
        responses::sse(vec![
            responses::ev_response_created("solver-resp-1"),
            responses::ev_assistant_message(
                "solver-msg-1",
                r#"{"type":"direction_request","prompt":"Need directive","claim_path":null,"notes":null,"deliverable_path":null,"summary":null}"#,
            ),
            responses::ev_completed("solver-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("director-resp-1"),
            responses::ev_assistant_message(
                "director-msg-1",
                r#"{"directive":"Proceed","rationale":"Follow the plan"}"#,
            ),
            responses::ev_completed("director-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("solver-resp-2"),
            responses::ev_assistant_message(
                "solver-msg-2",
                r#"{"type":"verification_request","prompt":null,"claim_path":"memory/claims/attempt1.json","notes":null,"deliverable_path":null,"summary":null}"#,
            ),
            responses::ev_completed("solver-resp-2"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("verifier-resp-1"),
            responses::ev_assistant_message(
                "verifier-msg-1",
                r#"{"verdict":"fail","reasons":["Missing tests"],"suggestions":["Add regression tests"]}"#,
            ),
            responses::ev_completed("verifier-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("solver-resp-3"),
            responses::ev_assistant_message(
                "solver-msg-3",
                r#"{"type":"verification_request","prompt":null,"claim_path":"memory/claims/attempt2.json","notes":null,"deliverable_path":null,"summary":null}"#,
            ),
            responses::ev_completed("solver-resp-3"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("verifier-resp-2"),
            responses::ev_assistant_message(
                "verifier-msg-2",
                r#"{"verdict":"pass","reasons":[],"suggestions":[]}"#,
            ),
            responses::ev_completed("verifier-resp-2"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("solver-resp-4"),
            responses::ev_assistant_message(
                "solver-msg-4",
                r#"{"type":"final_delivery","prompt":null,"claim_path":null,"notes":null,"deliverable_path":"deliverable","summary":"done"}"#,
            ),
            responses::ev_completed("solver-resp-4"),
        ]),
    ];
    for body in bodies {
        responses::mount_sse_once(&server, body).await;
    }

    let runs_root = TempDir::new()?;
    let orchestrator =
        InftyOrchestrator::with_runs_root(CodexAuth::from_api_key("dummy-key"), runs_root.path());
    let run_id = "run-auto".to_string();
    let run_root = runs_root.path().join("runs").join(&run_id);

    let solver_config = build_config(&server).await?;
    let director_config = build_config(&server).await?;
    let verifier_config = build_config(&server).await?;

    let options = RunExecutionOptions {
        objective: Some("Implement feature".to_string()),
        ..RunExecutionOptions::default()
    };

    let outcome = orchestrator
        .execute_new_run(
            RunParams {
                run_id: run_id.clone(),
                run_root: Some(run_root.clone()),
                solver: RoleConfig::new("solver", solver_config),
                director: RoleConfig::new("director", director_config),
                verifiers: vec![RoleConfig::new("verifier", verifier_config)],
            },
            options,
        )
        .await?;

    assert_eq!(outcome.run_id, run_id);
    assert_eq!(outcome.summary.as_deref(), Some("done"));
    assert!(outcome.raw_message.contains("final_delivery"));
    let canonical_run_root = std::fs::canonicalize(&run_root)?;
    let canonical_deliverable = std::fs::canonicalize(&outcome.deliverable_path)?;
    assert!(canonical_deliverable.starts_with(&canonical_run_root));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawn_run_cleans_up_on_failure() -> anyhow::Result<()> {
    skip_if_no_network!(Ok(()));

    let server = responses::start_mock_server().await;
    let bodies = vec![
        responses::sse(vec![
            responses::ev_response_created("solver-resp-1"),
            responses::ev_completed("solver-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("director-resp-1"),
            responses::ev_completed("director-resp-1"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("dup-resp"),
            responses::ev_completed("dup-resp"),
        ]),
    ];
    for body in bodies {
        responses::mount_sse_once(&server, body).await;
    }

    let runs_root = TempDir::new()?;
    let orchestrator =
        InftyOrchestrator::with_runs_root(CodexAuth::from_api_key("dummy-key"), runs_root.path());
    let run_id = "run-cleanup".to_string();
    let run_path = runs_root.path().join("runs").join(&run_id);

    let solver_config = build_config(&server).await?;
    let director_config = build_config(&server).await?;

    let result = orchestrator
        .spawn_run(RunParams {
            run_id: run_id.clone(),
            run_root: Some(run_path.clone()),
            solver: RoleConfig::new("solver", solver_config.clone()),
            director: RoleConfig::new("director", director_config.clone()),
            verifiers: vec![RoleConfig::new("solver", solver_config.clone())],
        })
        .await;
    assert!(result.is_err());
    assert!(!run_path.exists(), "failed run should remove run directory");

    let bodies = vec![
        responses::sse(vec![
            responses::ev_response_created("solver-resp-2"),
            responses::ev_completed("solver-resp-2"),
        ]),
        responses::sse(vec![
            responses::ev_response_created("director-resp-2"),
            responses::ev_completed("director-resp-2"),
        ]),
    ];
    for body in bodies {
        responses::mount_sse_once(&server, body).await;
    }

    let sessions = orchestrator
        .spawn_run(RunParams {
            run_id: run_id.clone(),
            run_root: Some(run_path.clone()),
            solver: RoleConfig::new("solver", solver_config),
            director: RoleConfig::new("director", director_config),
            verifiers: Vec::new(),
        })
        .await?;

    sessions.solver.conversation.submit(Op::Shutdown).await.ok();
    sessions
        .director
        .conversation
        .submit(Op::Shutdown)
        .await
        .ok();

    Ok(())
}

async fn build_config(server: &MockServer) -> anyhow::Result<Config> {
    let home = TempDir::new()?;
    let cwd = TempDir::new()?;
    let mut config = load_default_config_for_test(&home);
    config.cwd = cwd.path().to_path_buf();
    let mut provider = built_in_model_providers()["openai"].clone();
    provider.base_url = Some(format!("{}/v1", server.uri()));
    config.model_provider = provider;
    Ok(config)
}

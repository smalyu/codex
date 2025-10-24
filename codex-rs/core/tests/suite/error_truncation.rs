#![cfg(not(target_os = "windows"))]

use anyhow::Result;
use codex_core::model_family::find_family_for_model;
use codex_core::protocol::AskForApproval;
use codex_core::protocol::Op;
use codex_core::protocol::SandboxPolicy;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_sse_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use serde_json::Value;
use serde_json::json;

async fn submit_turn(test: &TestCodex, prompt: &str, sandbox_policy: SandboxPolicy) -> Result<()> {
    let session_model = test.session_configured.model.clone();

    test.codex
        .submit(Op::UserTurn {
            items: vec![UserInput::Text {
                text: prompt.into(),
            }],
            final_output_json_schema: None,
            cwd: test.cwd.path().to_path_buf(),
            approval_policy: AskForApproval::Never,
            sandbox_policy,
            model: session_model,
            effort: None,
            summary: ReasoningSummary::Auto,
        })
        .await?;

    wait_for_event(&test.codex, |event| {
        matches!(event, codex_core::protocol::EventMsg::TaskComplete(_))
    })
    .await;

    Ok(())
}

fn request_bodies(requests: &[wiremock::Request]) -> Result<Vec<Value>> {
    requests
        .iter()
        .map(|req| Ok(serde_json::from_slice::<Value>(&req.body)?))
        .collect()
}

fn find_function_call_output<'a>(bodies: &'a [Value], call_id: &str) -> Option<&'a Value> {
    for body in bodies {
        if let Some(items) = body.get("input").and_then(Value::as_array) {
            for item in items {
                if item.get("type").and_then(Value::as_str) == Some("function_call_output")
                    && item.get("call_id").and_then(Value::as_str) == Some(call_id)
                {
                    return Some(item);
                }
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncate_function_error_trims_respond_to_model() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;
    let mut builder = test_codex().with_config(|config| {
        // Use the test model that wires function tools like grep_files
        config.model = "test-gpt-5-codex".to_string();
        config.model_family =
            find_family_for_model("test-gpt-5-codex").expect("model family for test model");
    });
    let test = builder.build(&server).await?;

    // Construct a very long, non-existent path to force a RespondToModel error with a large message
    let long_path = "a".repeat(20_000);
    let call_id = "grep-huge-error";
    let args = json!({
        "pattern": "alpha",
        "path": long_path,
        "limit": 10
    });
    let responses = vec![
        sse(vec![
            ev_response_created("resp-1"),
            ev_function_call(call_id, "grep_files", &serde_json::to_string(&args)?),
            ev_completed("resp-1"),
        ]),
        sse(vec![
            ev_assistant_message("msg-1", "done"),
            ev_completed("resp-2"),
        ]),
    ];
    mount_sse_sequence(&server, responses).await;

    submit_turn(
        &test,
        "trigger grep_files with long path to test truncation",
        SandboxPolicy::DangerFullAccess,
    )
    .await?;

    let requests = server
        .received_requests()
        .await
        .expect("recorded requests present");
    let bodies = request_bodies(&requests)?;
    let output_item =
        find_function_call_output(&bodies, call_id).expect("function error output present");
    let output = output_item
        .get("output")
        .and_then(Value::as_str)
        .expect("error output string");

    // Expect plaintext with byte-truncation marker and no omitted-lines marker
    assert!(
        serde_json::from_str::<Value>(output).is_err(),
        "expected error output to be plain text",
    );
    assert!(
        output.contains("Total output lines: 1\n\n"),
        "expected total lines header in truncated output: {output}"
    );
    assert!(
        output.contains("[... output truncated to fit 10240 bytes ...]"),
        "missing byte truncation marker: {output}"
    );
    assert!(
        !output.contains("omitted"),
        "line omission marker should not appear when no lines were dropped: {output}"
    );

    Ok(())
}

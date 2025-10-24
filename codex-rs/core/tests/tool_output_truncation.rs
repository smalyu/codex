#![cfg(not(target_os = "windows"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use anyhow::Result;
use codex_core::features::Feature;
use codex_core::model_family::find_family_for_model;
use codex_core::protocol::AskForApproval;
use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_core::protocol::SandboxPolicy;
use codex_protocol::config_types::ReasoningSummary;
use codex_protocol::user_input::UserInput;
use core_test_support::assert_regex_match;
use core_test_support::responses;
use core_test_support::responses::mount_sse_once_match;
use core_test_support::responses::sse;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use escargot::CargoBuild;
use regex_lite::Regex;
use serde_json::Value;
use wiremock::matchers::any;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_call_output_exceeds_limit_truncated_for_model() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let mut builder = test_codex().with_config(|config| {
        config.model = "gpt-5-codex".to_string();
        config.model_family =
            find_family_for_model("gpt-5-codex").expect("gpt-5-codex is a model family");
    });
    let fixture = builder.build(&server).await?;
    let session_model = fixture.session_configured.model.clone();

    let call_id = "shell-too-large";
    let args = serde_json::json!({
        "command": ["/bin/sh", "-c", "seq 1 400"],
        "timeout_ms": 5_000,
    });

    mount_sse_once_match(
        &server,
        any(),
        sse(vec![
            responses::ev_response_created("resp-1"),
            responses::ev_function_call(call_id, "shell", &serde_json::to_string(&args)?),
            responses::ev_completed("resp-1"),
        ]),
    )
    .await;
    let mock2 = mount_sse_once_match(
        &server,
        any(),
        sse(vec![
            responses::ev_assistant_message("msg-1", "done"),
            responses::ev_completed("resp-2"),
        ]),
    )
    .await;

    fixture
        .codex
        .submit(Op::UserTurn {
            items: vec![UserInput::Text {
                text: "trigger big shell output".into(),
            }],
            final_output_json_schema: None,
            cwd: fixture.cwd.path().to_path_buf(),
            approval_policy: AskForApproval::Never,
            sandbox_policy: SandboxPolicy::DangerFullAccess,
            model: session_model,
            effort: None,
            summary: ReasoningSummary::Auto,
        })
        .await?;

    wait_for_event(&fixture.codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    let output = mock2
        .single_request()
        .function_call_output_text(call_id)
        .expect("function_call_output present for shell call");

    assert!(
        serde_json::from_str::<Value>(&output).is_err(),
        "expected truncated shell output to be plain text"
    );
    let truncated_pattern = r#"(?s)^Exit code: 0
Wall time: [0-9]+(?:\.[0-9]+)? seconds
Total output lines: 400
Output:
1
2
3
4
5
6
.*
\[\.{3} omitted \d+ of 400 lines \.{3}\]

.*
396
397
398
399
400
$"#;
    assert_regex_match(truncated_pattern, &output);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn mcp_tool_call_output_exceeds_limit_truncated_for_model() -> Result<()> {
    skip_if_no_network!(Ok(()));

    let server = start_mock_server().await;

    let call_id = "rmcp-truncated";
    let server_name = "rmcp";
    let tool_name = format!("mcp__{server_name}__echo");

    let large_msg = "long-message-with-newlines-".repeat(600);
    let args_json = serde_json::json!({ "message": large_msg });

    mount_sse_once_match(
        &server,
        any(),
        sse(vec![
            responses::ev_response_created("resp-1"),
            responses::ev_function_call(call_id, &tool_name, &args_json.to_string()),
            responses::ev_completed("resp-1"),
        ]),
    )
    .await;
    let mock2 = mount_sse_once_match(
        &server,
        any(),
        sse(vec![
            responses::ev_assistant_message("msg-1", "rmcp echo tool completed."),
            responses::ev_completed("resp-2"),
        ]),
    )
    .await;

    let rmcp_test_server_bin = CargoBuild::new()
        .package("codex-rmcp-client")
        .bin("test_stdio_server")
        .run()?
        .path()
        .to_string_lossy()
        .into_owned();

    let mut builder = test_codex().with_config(move |config| {
        config.features.enable(Feature::RmcpClient);
        config.mcp_servers.insert(
            server_name.to_string(),
            codex_core::config_types::McpServerConfig {
                transport: codex_core::config_types::McpServerTransportConfig::Stdio {
                    command: rmcp_test_server_bin,
                    args: Vec::new(),
                    env: None,
                    env_vars: Vec::new(),
                    cwd: None,
                },
                enabled: true,
                startup_timeout_sec: Some(std::time::Duration::from_secs(10)),
                tool_timeout_sec: None,
                enabled_tools: None,
                disabled_tools: None,
            },
        );
    });
    let fixture = builder.build(&server).await?;
    let session_model = fixture.session_configured.model.clone();

    fixture
        .codex
        .submit(Op::UserTurn {
            items: vec![UserInput::Text {
                text: "call the rmcp echo tool with a very large message".into(),
            }],
            final_output_json_schema: None,
            cwd: fixture.cwd.path().to_path_buf(),
            approval_policy: AskForApproval::Never,
            sandbox_policy: SandboxPolicy::ReadOnly,
            model: session_model,
            effort: None,
            summary: ReasoningSummary::Auto,
        })
        .await?;

    wait_for_event(&fixture.codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    let output = mock2
        .single_request()
        .function_call_output_text(call_id)
        .expect("function_call_output present for rmcp call");

    assert!(
        serde_json::from_str::<Value>(&output).is_err(),
        "expected truncated MCP output to be plain text"
    );
    assert!(
        output.starts_with("Total output lines: 1\n\n{"),
        "expected total line header and JSON head, got: {output}"
    );
    let byte_marker = Regex::new(r"\[\.\.\. output truncated to fit 10240 bytes \.\.\.\]")
        .expect("compile regex");
    assert!(
        byte_marker.is_match(&output),
        "expected byte truncation marker, got: {output}"
    );

    Ok(())
}

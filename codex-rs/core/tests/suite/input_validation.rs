use codex_core::protocol::EventMsg;
use codex_core::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::start_mock_server;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event_with_timeout;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupt_tool_records_history_entries() {
    let server = start_mock_server().await;

    let fixture = test_codex().build(&server).await.unwrap();
    let codex = Arc::clone(&fixture.codex);

    let wait_timeout = Duration::from_millis(100);

    let input_300_tokens = "token ".repeat(300_000);

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: input_300_tokens,
            }],
        })
        .await
        .unwrap();

    let error_event =
        wait_for_event_with_timeout(&codex, |ev| matches!(ev, EventMsg::Error(_)), wait_timeout)
            .await;
    let EventMsg::Error(error_event) = error_event else {
        unreachable!("wait_for_event_with_timeout returned unexpected payload");
    };
    assert_eq!(error_event.message, "invalid input: input too large");
}

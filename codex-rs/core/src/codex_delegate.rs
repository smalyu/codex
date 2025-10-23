use std::sync::Arc;

use async_channel::Receiver;
use async_channel::Sender;
use codex_async_utils::OrCancelExt;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::SessionSource;
use codex_protocol::user_input::UserInput;
use tokio_util::sync::CancellationToken;

use crate::AuthManager;
use crate::codex::Codex;
use crate::codex::CodexSpawnOk;
use crate::config::Config;
use crate::error::CodexErr;
use codex_protocol::protocol::InitialHistory;

pub(crate) async fn run_codex_conversation(
    config: Config,
    auth_manager: Arc<AuthManager>,
    input: Vec<UserInput>,
    cancel_token: CancellationToken,
) -> Result<Receiver<EventMsg>, CodexErr> {
    let (tx_sub, rx_sub) = async_channel::unbounded();
    let CodexSpawnOk { codex, .. } = Codex::spawn(
        config,
        auth_manager,
        InitialHistory::New,
        SessionSource::SubAgent,
    )
    .await?;

    codex.submit(Op::UserInput { items: input }).await?;

    let cancel_token = cancel_token.clone();
    tokio::spawn(async move {
        let _ = forward_events(codex, tx_sub).or_cancel(&cancel_token).await;
    });

    Ok(rx_sub)
}

async fn forward_events(codex: Codex, tx_sub: Sender<EventMsg>) {
    while let Ok(event) = codex.next_event().await {
        if matches!(event.msg, EventMsg::SessionConfigured(_)) {
            continue;
        }
        if tx_sub.send(event.msg).await.is_err() {
            return;
        }
    }
}

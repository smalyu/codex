use core::fmt;
use std::sync::Arc;

use codex_protocol::ConversationId;
use codex_protocol::items::TurnItem;
use codex_protocol::protocol::Event;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ItemCompletedEvent;
use codex_protocol::protocol::ItemStartedEvent;
use tracing::error;

use crate::codex::Session;

pub(crate) struct TurnEvents {
    thread_id: ConversationId,
    sub_id: String,
    turn_id: String,
    session: Arc<Session>,
}

impl fmt::Debug for TurnEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TurnEvents {{ thread_id: {}, sub_id: {}, turn_id: {} }}",
            self.thread_id, self.sub_id, self.turn_id
        )
    }
}

impl TurnEvents {
    pub fn new(
        session: Arc<Session>,
        thread_id: ConversationId,
        sub_id: String,
        turn_id: String,
    ) -> TurnEvents {
        TurnEvents {
            thread_id,
            sub_id,
            turn_id,
            session,
        }
    }

    pub async fn started(&self, item: TurnItem) {
        let err = self
            .session
            .get_tx_event()
            .send(Event {
                id: self.turn_id.clone(),
                msg: EventMsg::ItemStarted(ItemStartedEvent {
                    thread_id: self.thread_id,
                    turn_id: self.turn_id.clone(),
                    item,
                }),
            })
            .await;
        if let Err(e) = err {
            error!("failed to send item started event: {e}");
        }
    }

    pub async fn completed(&self, item: TurnItem) {
        let err = self
            .session
            .get_tx_event()
            .send(Event {
                id: self.turn_id.clone(),
                msg: EventMsg::ItemCompleted(ItemCompletedEvent {
                    thread_id: self.thread_id,
                    turn_id: self.turn_id.clone(),
                    item,
                }),
            })
            .await;
        if let Err(e) = err {
            error!("failed to send item completed event: {e}");
        }
    }

    pub async fn started_completed(&self, item: TurnItem) {
        self.started(item.clone()).await;
        self.completed(item).await;
    }

    pub async fn legacy(&self, msg: EventMsg) {
        let event = Event {
            id: self.sub_id.clone(),
            msg,
        };
        self.session.send_event(event).await;
    }
}

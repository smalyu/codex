use std::sync::Arc;

use async_trait::async_trait;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ExitedReviewModeEvent;
use codex_protocol::protocol::ReviewOutputEvent;
use codex_protocol::protocol::TaskCompleteEvent;
use tokio_util::sync::CancellationToken;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex_delegate::run_codex_conversation;
// use crate::config::Config; // no longer needed directly; use session.base_config()
use crate::review_format::format_review_findings_block;
use crate::state::TaskKind;
use codex_protocol::user_input::UserInput;

use super::SessionTask;
use super::SessionTaskContext;

#[derive(Clone, Copy, Default)]
pub(crate) struct ReviewTask;

#[async_trait]
impl SessionTask for ReviewTask {
    fn kind(&self) -> TaskKind {
        TaskKind::Review
    }

    async fn run(
        self: Arc<Self>,
        session: Arc<SessionTaskContext>,
        ctx: Arc<TurnContext>,
        input: Vec<UserInput>,
        cancellation_token: CancellationToken,
    ) -> Option<String> {
        let receiver = match start_review_conversation(
            session.clone(),
            ctx.clone(),
            input,
            cancellation_token.clone(),
        )
        .await
        {
            Some(receiver) => receiver,
            None => return None,
        };

        let exit_emitted = process_review_events(session.clone(), ctx.clone(), receiver).await;

        if !exit_emitted && !cancellation_token.is_cancelled() {
            // Ensure the parent session leaves review mode even if the sub-agent
            // finished without emitting a TaskComplete event (for example, when
            // cancellation interrupts the stream before completion parsing).
            emit_review_exit_on_abort(session.clone_session(), ctx.clone()).await;
        }

        None
    }

    async fn abort(&self, session: Arc<SessionTaskContext>, ctx: Arc<TurnContext>) {
        // Ensure ExitedReviewMode is emitted before generic TurnAborted.
        emit_review_exit_on_abort(session.clone_session(), ctx).await;
    }
}

async fn start_review_conversation(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    input: Vec<UserInput>,
    cancellation_token: CancellationToken,
) -> Option<async_channel::Receiver<EventMsg>> {
    let config = ctx.client.get_config().await;
    let mut sub_agent_config = config.as_ref().clone();
    sub_agent_config.user_instructions = None;
    sub_agent_config.project_doc_max_bytes = 0;
    sub_agent_config.base_instructions = Some(crate::REVIEW_PROMPT.to_string());
    match run_codex_conversation(
        sub_agent_config,
        session.auth_manager(),
        input,
        session.clone_session(),
        ctx.clone(),
        cancellation_token,
    )
    .await
    {
        Ok(receiver) => Some(receiver),
        Err(_) => {
            exit_review_mode(session.clone_session(), None, ctx).await;
            None
        }
    }
}

async fn process_review_events(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    receiver: async_channel::Receiver<EventMsg>,
) -> bool {
    let mut exit_emitted = false;
    let mut prev_agent_message: Option<EventMsg> = None;
    while let Ok(event) = receiver.recv().await {
        match event.clone() {
            EventMsg::AgentMessage(_) => {
                if let Some(prev) = prev_agent_message.take() {
                    session.clone_session().send_event(ctx.as_ref(), prev).await;
                }
                prev_agent_message = Some(event);
            }
            EventMsg::TaskComplete(task_complete) => {
                finalize_review_completion(&session, &ctx, task_complete).await;
                exit_emitted = true;
                break;
            }
            EventMsg::TurnAborted(_) => {
                exit_emitted = false;
                break;
            }
            other => {
                session
                    .clone_session()
                    .send_event(ctx.as_ref(), other)
                    .await;
            }
        }
    }
    exit_emitted
}

async fn finalize_review_completion(
    session: &Arc<SessionTaskContext>,
    ctx: &Arc<TurnContext>,
    task_complete: TaskCompleteEvent,
) {
    let review_output = task_complete
        .last_agent_message
        .as_deref()
        .map(parse_review_output_event);

    exit_review_mode(session.clone_session(), review_output, ctx.clone()).await;
}

/// Emits an ExitedReviewMode Event with optional ReviewOutput,
/// and records a developer message with the review output.
pub(crate) async fn exit_review_mode(
    session: Arc<Session>,
    review_output: Option<ReviewOutputEvent>,
    ctx: Arc<TurnContext>,
) {
    let mut user_message = String::new();
    if let Some(out) = review_output.clone() {
        let mut findings_str = String::new();
        let text = out.overall_explanation.trim();
        if !text.is_empty() {
            findings_str.push_str(text);
        }
        if !out.findings.is_empty() {
            let block = format_review_findings_block(&out.findings, None);
            findings_str.push_str(&format!("\n{block}"));
        }
        user_message.push_str(&format!(
            r#"<user_action>
  <context>User initiated a review task. Here's the full review output from reviewer model. User may select one or more comments to resolve.</context>
  <action>review</action>
  <results>
  {findings_str}
  </results>
</user_action>
"#));
    } else {
        user_message.push_str(r#"<user_action>
  <context>User initiated a review task, but was interrupted. If user asks about this, tell them to re-initiate a review with `/review` and wait for it to complete.</context>
  <action>review</action>
  <results>
  None.
  </results>
</user_action>
"#);
    }

    session
        .record_conversation_items(&[ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::InputText { text: user_message }],
        }])
        .await;
    session
        .send_event(
            ctx.as_ref(),
            EventMsg::ExitedReviewMode(ExitedReviewModeEvent { review_output }),
        )
        .await;
}

pub(crate) async fn emit_review_exit_on_abort(session: Arc<Session>, ctx: Arc<TurnContext>) {
    exit_review_mode(session, None, ctx).await;
}

/// Parse the review output; when not valid JSON, build a structured
/// fallback that carries the plain text as the overall explanation.
///
/// Returns: a ReviewOutputEvent parsed from JSON or a fallback populated from text.
fn parse_review_output_event(text: &str) -> ReviewOutputEvent {
    // Try direct parse first
    if let Ok(ev) = serde_json::from_str::<ReviewOutputEvent>(text) {
        return ev;
    }
    // If wrapped in markdown fences or extra prose, attempt to extract the first JSON object
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}'))
        && start < end
        && let Some(slice) = text.get(start..=end)
        && let Ok(ev) = serde_json::from_str::<ReviewOutputEvent>(slice)
    {
        return ev;
    }
    // Not JSON – return a structured ReviewOutputEvent that carries
    // the plain text as the overall explanation.
    ReviewOutputEvent {
        overall_explanation: text.to_string(),
        ..Default::default()
    }
}

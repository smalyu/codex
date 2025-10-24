use std::sync::Arc;

use async_trait::async_trait;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ExitedReviewModeEvent;
use codex_protocol::protocol::ReviewOutputEvent;
use tokio_util::sync::CancellationToken;

use crate::codex::Session;
use crate::codex::TurnContext;
use crate::codex_delegate::AgentEvent;
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
            cancellation_token,
        )
        .await
        {
            Some(receiver) => receiver,
            None => return None,
        };

        process_review_events(session.clone(), ctx.clone(), receiver).await;

        Some("".to_string())
    }

    async fn abort(&self, session: Arc<SessionTaskContext>, ctx: Arc<TurnContext>) {
        exit_review_mode(session.clone_session(), None, ctx).await;
    }
}

async fn start_review_conversation(
    session: Arc<SessionTaskContext>,
    ctx: Arc<TurnContext>,
    input: Vec<UserInput>,
    cancellation_token: CancellationToken,
) -> Option<async_channel::Receiver<AgentEvent>> {
    let config = ctx.client.get_config().await;
    match run_codex_conversation(
        config.as_ref().clone(),
        session.auth_manager(),
        input,
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
    receiver: async_channel::Receiver<AgentEvent>,
) {
    while let Ok(agent_event) = receiver.recv().await {
        handle_review_agent_event(&session, &ctx, agent_event).await;
    }
}

async fn handle_review_agent_event(
    session: &Arc<SessionTaskContext>,
    ctx: &Arc<TurnContext>,
    agent_event: AgentEvent,
) {
    match agent_event {
        AgentEvent::EventMsg(event) => {
            match event {
                EventMsg::AgentMessage(_) => {
                    // The structured review output is surfaced through ExitedReviewMode.
                    // Suppress the raw AgentMessage to avoid leaking implementation details.
                }
                EventMsg::TaskComplete(task_complete) => {
                    let review_output = task_complete
                        .last_agent_message
                        .as_deref()
                        .map(parse_review_output_event);
                    exit_review_mode(session.clone_session(), review_output, ctx.clone()).await;
                    session
                        .clone_session()
                        .send_event(ctx.as_ref(), EventMsg::TaskComplete(task_complete))
                        .await;
                }
                EventMsg::AgentMessageDelta(_)
                | EventMsg::TokenCount(_)
                | EventMsg::Error(_)
                | EventMsg::TaskStarted(_)
                | EventMsg::UserMessage(_)
                | EventMsg::AgentReasoning(_)
                | EventMsg::AgentReasoningDelta(_)
                | EventMsg::AgentReasoningRawContent(_)
                | EventMsg::AgentReasoningRawContentDelta(_)
                | EventMsg::AgentReasoningSectionBreak(_)
                | EventMsg::SessionConfigured(_)
                | EventMsg::McpToolCallBegin(_)
                | EventMsg::McpToolCallEnd(_)
                | EventMsg::WebSearchBegin(_)
                | EventMsg::WebSearchEnd(_)
                | EventMsg::ExecCommandBegin(_)
                | EventMsg::ExecCommandOutputDelta(_)
                | EventMsg::ExecCommandEnd(_)
                | EventMsg::ViewImageToolCall(_)
                | EventMsg::ExecApprovalRequest(_)
                | EventMsg::ApplyPatchApprovalRequest(_)
                | EventMsg::BackgroundEvent(_)
                | EventMsg::StreamError(_)
                | EventMsg::PatchApplyBegin(_)
                | EventMsg::PatchApplyEnd(_)
                | EventMsg::TurnDiff(_)
                | EventMsg::GetHistoryEntryResponse(_)
                | EventMsg::McpListToolsResponse(_)
                | EventMsg::ListCustomPromptsResponse(_)
                | EventMsg::PlanUpdate(_)
                | EventMsg::TurnAborted(_)
                | EventMsg::ShutdownComplete
                | EventMsg::ConversationPath(_)
                | EventMsg::EnteredReviewMode(_)
                | EventMsg::ExitedReviewMode(_)
                | EventMsg::ItemStarted(_)
                | EventMsg::ItemCompleted(_) => {
                    session
                        .clone_session()
                        .send_event(ctx.as_ref(), event)
                        .await;
                }
            }
        }
        AgentEvent::ExecApprovalRequest(event, tx) => {
            let decision = session
                .clone_session()
                .request_command_approval(
                    ctx.as_ref(),
                    event.call_id.clone(),
                    event.command.clone(),
                    event.cwd.clone(),
                    event.reason.clone(),
                )
                .await;
            let _ = tx.send(decision);
        }
        AgentEvent::PatchApprovalRequest(event, tx) => {
            session
                .clone_session()
                .send_event(ctx.as_ref(), EventMsg::ApplyPatchApprovalRequest(event))
                .await;
            let _ = tx.send(codex_protocol::protocol::ReviewDecision::Denied);
        }
    }
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

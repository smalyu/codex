use codex_protocol::models::ResponseInputItem;
use codex_protocol::models::ResponseItem;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use tracing::warn;

static SYNTHETIC_TOOL_OUTPUTS: AtomicU64 = AtomicU64::new(0);

use crate::state::TaskKind;

/// Transcript of conversation history
#[derive(Debug, Clone, Default)]
pub(crate) struct ConversationHistory {
    /// The oldest items are at the beginning of the vector.
    items: Vec<ResponseItem>,
    review_thread_history: Vec<ResponseItem>,
}

impl ConversationHistory {
    pub(crate) fn new() -> Self {
        Self {
            items: Vec::new(),
            review_thread_history: Vec::new(),
        }
    }

    /// Returns a clone of the contents in the transcript.
    pub(crate) fn contents(&self) -> Vec<ResponseItem> {
        self.items.clone()
    }

    pub(crate) fn review_thread_contents(&self) -> Vec<ResponseItem> {
        self.review_thread_history.clone()
    }

    pub(crate) fn clear_review_thread(&mut self) {
        self.review_thread_history.clear();
    }

    /// `items` is ordered from oldest to newest.
    pub(crate) fn record_items<I>(&mut self, items: I, task_kind: TaskKind)
    where
        I: IntoIterator<Item = ResponseItem>,
    {
        for item in items {
            if !is_api_message(&item) {
                continue;
            }

            match task_kind {
                TaskKind::Regular | TaskKind::Compact => {
                    self.items.push(item);
                }
                TaskKind::Review => {
                    self.review_thread_history.push(item);
                }
            }
        }
    }

    pub(crate) fn replace(&mut self, items: Vec<ResponseItem>) {
        self.items = items;
    }

    pub(crate) fn initialize_review_history(
        &mut self,
        response_input: &ResponseInputItem,
        initial_context: Vec<ResponseItem>,
    ) {
        self.clear_review_thread();
        self.record_items(initial_context, TaskKind::Review);
        self.record_items(
            std::iter::once(ResponseItem::from(response_input.clone())),
            TaskKind::Review,
        );
    }

    pub(crate) fn add_pending_input(
        &mut self,
        pending_input: Vec<ResponseItem>,
        task_kind: TaskKind,
    ) {
        self.record_items(pending_input, task_kind);
    }

    pub(crate) fn handle_missing_tool_call_output(&mut self, task_kind: TaskKind) {
        // Select the appropriate thread's history vector.
        let thread_vec: &mut Vec<ResponseItem> = match task_kind {
            TaskKind::Regular | TaskKind::Compact => &mut self.items,
            TaskKind::Review => &mut self.review_thread_history,
        };

        // Determine which calls are already completed.
        let completed_call_ids = thread_vec
            .iter()
            .filter_map(|ri| match ri {
                ResponseItem::FunctionCallOutput { call_id, .. } => Some(call_id.clone()),
                ResponseItem::CustomToolCallOutput { call_id, .. } => Some(call_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        // Find tool calls that are missing outputs and insert synthetic outputs
        // immediately after the corresponding call so the call appears resolved
        // before any subsequent user input is processed.
        // We re-scan the vector for each missing call id so insertion indices stay valid.
        let pending_call_ids = thread_vec
            .iter()
            .filter_map(|ri| match ri {
                ResponseItem::FunctionCall { call_id, .. } => Some(call_id.clone()),
                ResponseItem::LocalShellCall {
                    call_id: Some(call_id),
                    ..
                } => Some(call_id.clone()),
                ResponseItem::CustomToolCall { call_id, .. } => Some(call_id.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        for call_id in pending_call_ids {
            if completed_call_ids.iter().any(|c| c == &call_id) {
                continue;
            }

            // Find the last index of the corresponding call in the current vector.
            if let Some(idx) = thread_vec.iter().rposition(|ri| match ri {
                ResponseItem::FunctionCall { call_id: id, .. } => id == &call_id,
                ResponseItem::LocalShellCall {
                    call_id: Some(id), ..
                } => id == &call_id,
                ResponseItem::CustomToolCall { call_id: id, .. } => id == &call_id,
                _ => false,
            }) {
                // Optionally fail fast in CI/dev to surface original issues.
                if std::env::var("CODEX_FAIL_ON_SYNTHETIC_TOOL_OUTPUT")
                    .map_or(false, |v| v == "1" || v.eq_ignore_ascii_case("true"))
                {
                    panic!("Synthetic tool output inserted for unresolved call_id={call_id}");
                }

                // Log a warning to help developers discover where/when this happens.
                warn!(
                    %call_id,
                    thread = ?task_kind,
                    "Inserting synthetic tool output for unresolved tool call"
                );

                SYNTHETIC_TOOL_OUTPUTS.fetch_add(1, Ordering::Relaxed);
                thread_vec.insert(
                    idx + 1,
                    ResponseItem::CustomToolCallOutput {
                        call_id: call_id.clone(),
                        output: "aborted".to_string(),
                    },
                );
            }
        }
    }

    pub(crate) fn prompt(&self, task_kind: TaskKind) -> Vec<ResponseItem> {
        match task_kind {
            TaskKind::Regular | TaskKind::Compact => self.contents(),
            TaskKind::Review => self.review_thread_contents(),
        }
    }
}

/// Anything that is not a system message or "reasoning" message is considered
/// an API message.
fn is_api_message(message: &ResponseItem) -> bool {
    match message {
        ResponseItem::Message { role, .. } => role.as_str() != "system",
        ResponseItem::FunctionCallOutput { .. }
        | ResponseItem::FunctionCall { .. }
        | ResponseItem::CustomToolCall { .. }
        | ResponseItem::CustomToolCallOutput { .. }
        | ResponseItem::LocalShellCall { .. }
        | ResponseItem::Reasoning { .. }
        | ResponseItem::WebSearchCall { .. } => true,
        ResponseItem::Other => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_protocol::models::ContentItem;
    use pretty_assertions::assert_eq;

    fn assistant_msg(text: &str) -> ResponseItem {
        ResponseItem::Message {
            id: None,
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: text.to_string(),
            }],
        }
    }

    fn user_msg(text: &str) -> ResponseItem {
        ResponseItem::Message {
            id: None,
            role: "user".to_string(),
            content: vec![ContentItem::OutputText {
                text: text.to_string(),
            }],
        }
    }

    #[test]
    fn filters_non_api_messages() {
        let mut h = ConversationHistory::default();
        // System message is not an API message; Other is ignored.
        let system = ResponseItem::Message {
            id: None,
            role: "system".to_string(),
            content: vec![ContentItem::OutputText {
                text: "ignored".to_string(),
            }],
        };
        h.record_items([system, ResponseItem::Other], TaskKind::Regular);

        // User and assistant should be retained.
        let u = user_msg("hi");
        let a = assistant_msg("hello");
        h.record_items([u, a], TaskKind::Regular);

        let items = h.contents();
        assert_eq!(
            items,
            vec![
                ResponseItem::Message {
                    id: None,
                    role: "user".to_string(),
                    content: vec![ContentItem::OutputText {
                        text: "hi".to_string()
                    }]
                },
                ResponseItem::Message {
                    id: None,
                    role: "assistant".to_string(),
                    content: vec![ContentItem::OutputText {
                        text: "hello".to_string()
                    }]
                }
            ],
        );
    }

    #[test]
    fn inserts_synthetic_tool_output_next_to_call_before_user_input() {
        let mut h = ConversationHistory::default();

        // Record a pending tool call without an output.
        let call_id = "call-1".to_string();
        let tool_call = ResponseItem::FunctionCall {
            id: None,
            name: "shell".to_string(),
            arguments: "{\"command\":[\"echo\",\"hi\"]}".to_string(),
            call_id: call_id.clone(),
        };
        h.record_items([tool_call], TaskKind::Regular);

        // Ensure missing outputs are handled first.
        h.handle_missing_tool_call_output(TaskKind::Regular);

        // Then record a new user message.
        let user = user_msg("follow up");
        h.add_pending_input(vec![user.clone()], TaskKind::Regular);

        // Expect the synthetic output to be inserted immediately after the call
        // and before the user message.
        let items = h.contents();
        assert_eq!(items.len(), 3);
        match (&items[0], &items[1], &items[2]) {
            (
                ResponseItem::FunctionCall { call_id: id0, .. },
                ResponseItem::CustomToolCallOutput {
                    call_id: id1,
                    output,
                },
                ResponseItem::Message { role, .. },
            ) => {
                assert_eq!(id0, &call_id);
                assert_eq!(id1, &call_id);
                assert_eq!(output, "aborted");
                assert_eq!(role, "user");
            }
            _ => panic!("unexpected item ordering: {items:?}"),
        }
    }

    // Intentionally not testing the env-based panic path here: mutating
    // environment variables is unsafe in this edition and risks test
    // interference. The behavior is exercised indirectly by integration tests.
}

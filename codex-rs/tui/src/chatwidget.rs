use std::path::{Path, PathBuf};
use std::sync::Arc;

use codex_core::codex_wrapper::init_codex;
use codex_core::config::Config;
use codex_core::protocol::AgentMessageEvent;
use codex_core::protocol::AgentReasoningEvent;
use codex_core::protocol::ApplyPatchApprovalRequestEvent;
use codex_core::protocol::ErrorEvent;
use codex_core::protocol::Event;
use codex_core::protocol::EventMsg;
use codex_core::protocol::ExecApprovalRequestEvent;
use codex_core::protocol::ExecCommandBeginEvent;
use codex_core::protocol::ExecCommandEndEvent;
use codex_core::protocol::InputItem;
use codex_core::protocol::McpToolCallBeginEvent;
use codex_core::protocol::McpToolCallEndEvent;
use codex_core::protocol::Op;
use codex_core::protocol::PatchApplyBeginEvent;
use codex_core::protocol::TaskCompleteEvent;
use codex_core::protocol::TokenUsage;
use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::layout::Rect;
use ratatui::widgets::Widget;
use ratatui::widgets::WidgetRef;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;

use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::bottom_pane::BottomPane;
use crate::bottom_pane::BottomPaneParams;
use crate::bottom_pane::InputResult;
use crate::conversation_history_widget::ConversationHistoryWidget;
use crate::history_cell::PatchEventType;
use crate::user_approval_widget::ApprovalRequest;
use crate::security_review::{run_security_review, SecurityReviewFailure, SecurityReviewMode, SecurityReviewRequest, SecurityReviewResult};
use codex_file_search::FileMatch;
use path_clean::PathClean;
use shlex;

pub(crate) struct ChatWidget<'a> {
    app_event_tx: AppEventSender,
    codex_op_tx: UnboundedSender<Op>,
    conversation_history: ConversationHistoryWidget,
    bottom_pane: BottomPane<'a>,
    input_focus: InputFocus,
    config: Config,
    initial_user_message: Option<UserMessage>,
    token_usage: TokenUsage,
    security_review_handle: Option<JoinHandle<()>>,
    active_security_review_mode: Option<SecurityReviewMode>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputFocus {
    HistoryPane,
    BottomPane,
}

struct UserMessage {
    text: String,
    image_paths: Vec<PathBuf>,
}

impl From<String> for UserMessage {
    fn from(text: String) -> Self {
        Self {
            text,
            image_paths: Vec::new(),
        }
    }
}

fn create_initial_user_message(text: String, image_paths: Vec<PathBuf>) -> Option<UserMessage> {
    if text.is_empty() && image_paths.is_empty() {
        None
    } else {
        Some(UserMessage { text, image_paths })
    }
}

#[derive(Debug, Default)]
struct ParsedSecReviewCommand {
    mode: SecurityReviewMode,
    include_paths: Vec<String>,
    output_path: Option<String>,
    repo_path: Option<String>,
    model_name: Option<String>,
}

impl ChatWidget<'_> {
    pub(crate) fn new(
        config: Config,
        app_event_tx: AppEventSender,
        initial_prompt: Option<String>,
        initial_images: Vec<PathBuf>,
    ) -> Self {
        let (codex_op_tx, mut codex_op_rx) = unbounded_channel::<Op>();

        let app_event_tx_clone = app_event_tx.clone();
        // Create the Codex asynchronously so the UI loads as quickly as possible.
        let config_for_agent_loop = config.clone();
        tokio::spawn(async move {
            let (codex, session_event, _ctrl_c) = match init_codex(config_for_agent_loop).await {
                Ok(vals) => vals,
                Err(e) => {
                    // TODO: surface this error to the user.
                    tracing::error!("failed to initialize codex: {e}");
                    return;
                }
            };

            // Forward the captured `SessionInitialized` event that was consumed
            // inside `init_codex()` so it can be rendered in the UI.
            app_event_tx_clone.send(AppEvent::CodexEvent(session_event.clone()));
            let codex = Arc::new(codex);
            let codex_clone = codex.clone();
            tokio::spawn(async move {
                while let Some(op) = codex_op_rx.recv().await {
                    let id = codex_clone.submit(op).await;
                    if let Err(e) = id {
                        tracing::error!("failed to submit op: {e}");
                    }
                }
            });

            while let Ok(event) = codex.next_event().await {
                app_event_tx_clone.send(AppEvent::CodexEvent(event));
            }
        });

        Self {
            app_event_tx: app_event_tx.clone(),
            codex_op_tx,
            conversation_history: ConversationHistoryWidget::new(),
            bottom_pane: BottomPane::new(BottomPaneParams {
                app_event_tx,
                has_input_focus: true,
            }),
            input_focus: InputFocus::BottomPane,
            config,
            initial_user_message: create_initial_user_message(
                initial_prompt.unwrap_or_default(),
                initial_images,
            ),
            token_usage: TokenUsage::default(),
            security_review_handle: None,
            active_security_review_mode: None,
        }
    }

    pub(crate) fn handle_key_event(&mut self, key_event: KeyEvent) {
        self.bottom_pane.clear_ctrl_c_quit_hint();
        // Special-case <Tab>: normally toggles focus between history and bottom panes.
        // However, when the slash-command popup is visible we forward the key
        // to the bottom pane so it can handle auto-completion.
        if matches!(key_event.code, crossterm::event::KeyCode::Tab)
            && !self.bottom_pane.is_popup_visible()
        {
            self.input_focus = match self.input_focus {
                InputFocus::HistoryPane => InputFocus::BottomPane,
                InputFocus::BottomPane => InputFocus::HistoryPane,
            };
            self.conversation_history
                .set_input_focus(self.input_focus == InputFocus::HistoryPane);
            self.bottom_pane
                .set_input_focus(self.input_focus == InputFocus::BottomPane);
            self.request_redraw();
            return;
        }

        match self.input_focus {
            InputFocus::HistoryPane => {
                let needs_redraw = self.conversation_history.handle_key_event(key_event);
                if needs_redraw {
                    self.request_redraw();
                }
            }
            InputFocus::BottomPane => match self.bottom_pane.handle_key_event(key_event) {
                InputResult::Submitted(text) => {
                    self.submit_user_message(text.into());
                }
                InputResult::None => {}
            },
        }
    }

    pub(crate) fn handle_paste(&mut self, text: String) {
        if matches!(self.input_focus, InputFocus::BottomPane) {
            self.bottom_pane.handle_paste(text);
        }
    }

    fn submit_user_message(&mut self, user_message: UserMessage) {
        let UserMessage { text, image_paths } = user_message;

        if self.try_handle_slash_command(&text) {
            return;
        }

        let mut items: Vec<InputItem> = Vec::new();

        if !text.is_empty() {
            items.push(InputItem::Text { text: text.clone() });
        }

        for path in image_paths {
            items.push(InputItem::LocalImage { path });
        }

        if items.is_empty() {
            return;
        }

        self.codex_op_tx
            .send(Op::UserInput { items })
            .unwrap_or_else(|e| {
                tracing::error!("failed to send message: {e}");
            });

        // Persist the text to cross-session message history.
        if !text.is_empty() {
            self.codex_op_tx
                .send(Op::AddToHistory { text: text.clone() })
                .unwrap_or_else(|e| {
                    tracing::error!("failed to send AddHistory op: {e}");
                });
        }

        // Only show text portion in conversation history for now.
        if !text.is_empty() {
            self.conversation_history.add_user_message(text);
        }
        self.conversation_history.scroll_to_bottom();
    }

    fn try_handle_slash_command(&mut self, text: &str) -> bool {
        let trimmed = text.trim();
        if trimmed.starts_with("/secreview") {
            match parse_security_review_command(trimmed) {
                Ok(command) => {
                    if let Err(err) = self.launch_security_review(command) {
                        self.report_security_review_error(err);
                    }
                }
                Err(err) => self.report_security_review_error(err),
            }
            return true;
        }
        false
    }

    pub(crate) fn start_security_review_with_defaults(&mut self) {
        let command = ParsedSecReviewCommand::default();
        if let Err(err) = self.launch_security_review(command) {
            self.report_security_review_error(err);
        }
    }

    fn launch_security_review(&mut self, command: ParsedSecReviewCommand) -> Result<(), String> {
        let repo_candidate = if let Some(repo_override) = command.repo_path.as_ref() {
            let candidate = Path::new(repo_override);
            if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                self.config.cwd.join(candidate)
            }
        } else {
            self.config.cwd.clone()
        }
        .clean();

        let repo_path = match repo_candidate.canonicalize() {
            Ok(path) => path,
            Err(_) => repo_candidate.clone(),
        };

        if !repo_path.exists() {
            return Err(format!(
                "Repository path '{}' does not exist.",
                repo_path.display()
            ));
        }
        if !repo_path.is_dir() {
            return Err(format!(
                "Repository path '{}' is not a directory.",
                repo_path.display()
            ));
        }

        let mut resolved_paths: Vec<PathBuf> = Vec::new();
        let mut display_paths: Vec<String> = Vec::new();

        for include in &command.include_paths {
            let candidate = resolve_path(&repo_path, include);
            let canonical = match candidate.canonicalize() {
                Ok(path) => path,
                Err(_) => candidate.clone(),
            };

            if !canonical.exists() {
                return Err(format!("Path '{}' does not exist.", canonical.display()));
            }
            if !canonical.starts_with(&repo_path) {
                return Err(format!(
                    "Path '{}' is outside the repository root '{}'.",
                    canonical.display(),
                    repo_path.display()
                ));
            }

            let relative = canonical
                .strip_prefix(&repo_path)
                .unwrap_or(&canonical)
                .display()
                .to_string();
            display_paths.push(relative);
            resolved_paths.push(canonical);
        }

        let output_root = if let Some(output_override) = command.output_path.as_ref() {
            let candidate = Path::new(output_override);
            if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                repo_path.join(candidate)
            }
        } else {
            repo_path.join("appsec_review")
        }
        .clean();

        let model_name = command
            .model_name
            .clone()
            .unwrap_or_else(|| self.config.model.clone());

        if self.security_review_handle.is_some() {
            return Err("A security review is already running. Please wait for it to finish or abort it before starting another.".to_string());
        }

        let scope_description = if resolved_paths.is_empty() {
            "entire repository".to_string()
        } else {
            display_paths.join(", ")
        };

        let summary = format!(
            "🔐 Running AppSec security review (mode: {}).\nRepository: {}\nScope: {}\nOutput: {}\nModel: {}",
            command.mode.as_str(),
            repo_path.display(),
            scope_description,
            output_root.display(),
            model_name
        );
        self.conversation_history.add_background_event(summary);
        self.conversation_history.scroll_to_bottom();
        self.bottom_pane.set_task_running(true);
        self.request_redraw();

        let provider = self.config.model_provider.clone();
        let request = SecurityReviewRequest {
            repo_path: repo_path.clone(),
            include_paths: resolved_paths,
            output_root: output_root.clone(),
            mode: command.mode,
            model: model_name,
            provider,
            progress_sender: Some(self.app_event_tx.clone()),
        };

        let app_event_tx = self.app_event_tx.clone();
        let mode = command.mode;
        let handle = tokio::spawn(async move {
            let outcome = run_security_review(request).await;
            app_event_tx.send(AppEvent::SecurityReviewFinished { mode, outcome });
        });
        self.security_review_handle = Some(handle);
        self.active_security_review_mode = Some(mode);

        Ok(())
    }

    fn report_security_review_error(&mut self, message: String) {
        self.security_review_handle = None;
        self.active_security_review_mode = None;
        self.bottom_pane.set_task_running(false);
        self.conversation_history
            .add_background_event(format!("❌ {message}"));
        self.conversation_history.scroll_to_bottom();
        self.request_redraw();
    }

    pub(crate) fn handle_security_review_finished(
        &mut self,
        mode: SecurityReviewMode,
        outcome: Result<SecurityReviewResult, SecurityReviewFailure>,
    ) {
        self.security_review_handle = None;
        self.active_security_review_mode = None;
        self.bottom_pane.set_task_running(false);
        match outcome {
            Ok(result) => {
                let SecurityReviewResult {
                    bugs_markdown,
                    report_markdown,
                    bugs_path,
                    report_path,
                    logs,
                } = result;

                let mut summary = format!(
                    "✅ AppSec security review complete (mode: {}).\nBugs saved to {}.",
                    mode.as_str(),
                    bugs_path.display()
                );
                if let Some(report_path) = report_path.as_ref() {
                    summary.push_str(&format!(
                        "\nReport saved to {}.",
                        report_path.display()
                    ));
                }
                self.conversation_history.add_background_event(summary);

                if matches!(mode, SecurityReviewMode::Full) {
                    if let Some(markdown) = report_markdown.and_then(|m| {
                        if m.trim().is_empty() {
                            None
                        } else {
                            Some(m)
                        }
                    }) {
                        self.conversation_history.add_agent_message(
                            &self.config,
                            format!("# AppSec Security Review Report\n\n{markdown}"),
                        );
                    }
                }

                if !bugs_markdown.trim().is_empty() {
                    let heading = if matches!(mode, SecurityReviewMode::Full) {
                        "## Bugs Summary"
                    } else {
                        "# AppSec Bugs Summary"
                    };
                    self.conversation_history.add_agent_message(
                        &self.config,
                        format!("{heading}\n\n{bugs_markdown}"),
                    );
                }

                if let Some(log_text) = format_security_review_logs(&logs) {
                    self.conversation_history
                        .add_background_event(format!("Logs:\n{log_text}"));
                }
            }
            Err(error) => {
                let SecurityReviewFailure { message, logs } = error;
                let mut summary = format!("❌ AppSec security review failed: {message}");
                if let Some(log_text) = format_security_review_logs(&logs) {
                    summary.push_str(&format!("\n\nLogs:\n{log_text}"));
                }
                self.conversation_history.add_background_event(summary);
            }
        }

        self.conversation_history.scroll_to_bottom();
        self.request_redraw();
    }

    pub(crate) fn handle_codex_event(&mut self, event: Event) {
        let Event { id, msg } = event;
        match msg {
            EventMsg::SessionConfigured(event) => {
                // Record session information at the top of the conversation.
                self.conversation_history
                    .add_session_info(&self.config, event.clone());

                // Forward history metadata to the bottom pane so the chat
                // composer can navigate through past messages.
                self.bottom_pane
                    .set_history_metadata(event.history_log_id, event.history_entry_count);

                if let Some(user_message) = self.initial_user_message.take() {
                    // If the user provided an initial message, add it to the
                    // conversation history.
                    self.submit_user_message(user_message);
                }

                self.request_redraw();
            }
            EventMsg::AgentMessage(AgentMessageEvent { message }) => {
                self.conversation_history
                    .add_agent_message(&self.config, message);
                self.request_redraw();
            }
            EventMsg::AgentReasoning(AgentReasoningEvent { text }) => {
                if !self.config.hide_agent_reasoning {
                    self.conversation_history
                        .add_agent_reasoning(&self.config, text);
                    self.request_redraw();
                }
            }
            EventMsg::TaskStarted => {
                self.bottom_pane.clear_ctrl_c_quit_hint();
                self.bottom_pane.set_task_running(true);
                self.request_redraw();
            }
            EventMsg::TaskComplete(TaskCompleteEvent {
                last_agent_message: _,
            }) => {
                self.bottom_pane.set_task_running(false);
                self.request_redraw();
            }
            EventMsg::TokenCount(token_usage) => {
                self.token_usage = add_token_usage(&self.token_usage, &token_usage);
                self.bottom_pane
                    .set_token_usage(self.token_usage.clone(), self.config.model_context_window);
            }
            EventMsg::Error(ErrorEvent { message }) => {
                self.conversation_history.add_error(message);
                self.bottom_pane.set_task_running(false);
            }
            EventMsg::ExecApprovalRequest(ExecApprovalRequestEvent {
                command,
                cwd,
                reason,
            }) => {
                let request = ApprovalRequest::Exec {
                    id,
                    command,
                    cwd,
                    reason,
                };
                self.bottom_pane.push_approval_request(request);
            }
            EventMsg::ApplyPatchApprovalRequest(ApplyPatchApprovalRequestEvent {
                changes,
                reason,
                grant_root,
            }) => {
                // ------------------------------------------------------------------
                // Before we even prompt the user for approval we surface the patch
                // summary in the main conversation so that the dialog appears in a
                // sensible chronological order:
                //   (1) codex → proposes patch (HistoryCell::PendingPatch)
                //   (2) UI → asks for approval (BottomPane)
                // This mirrors how command execution is shown (command begins →
                // approval dialog) and avoids surprising the user with a modal
                // prompt before they have seen *what* is being requested.
                // ------------------------------------------------------------------

                self.conversation_history
                    .add_patch_event(PatchEventType::ApprovalRequest, changes);

                self.conversation_history.scroll_to_bottom();

                // Now surface the approval request in the BottomPane as before.
                let request = ApprovalRequest::ApplyPatch {
                    id,
                    reason,
                    grant_root,
                };
                self.bottom_pane.push_approval_request(request);
                self.request_redraw();
            }
            EventMsg::ExecCommandBegin(ExecCommandBeginEvent {
                call_id,
                command,
                cwd: _,
            }) => {
                self.conversation_history
                    .add_active_exec_command(call_id, command);
                self.request_redraw();
            }
            EventMsg::PatchApplyBegin(PatchApplyBeginEvent {
                call_id: _,
                auto_approved,
                changes,
            }) => {
                // Even when a patch is auto‑approved we still display the
                // summary so the user can follow along.
                self.conversation_history
                    .add_patch_event(PatchEventType::ApplyBegin { auto_approved }, changes);
                if !auto_approved {
                    self.conversation_history.scroll_to_bottom();
                }
                self.request_redraw();
            }
            EventMsg::ExecCommandEnd(ExecCommandEndEvent {
                call_id,
                exit_code,
                stdout,
                stderr,
            }) => {
                self.conversation_history
                    .record_completed_exec_command(call_id, stdout, stderr, exit_code);
                self.request_redraw();
            }
            EventMsg::McpToolCallBegin(McpToolCallBeginEvent {
                call_id,
                server,
                tool,
                arguments,
            }) => {
                self.conversation_history
                    .add_active_mcp_tool_call(call_id, server, tool, arguments);
                self.request_redraw();
            }
            EventMsg::McpToolCallEnd(mcp_tool_call_end_event) => {
                let success = mcp_tool_call_end_event.is_success();
                let McpToolCallEndEvent { call_id, result } = mcp_tool_call_end_event;
                self.conversation_history
                    .record_completed_mcp_tool_call(call_id, success, result);
                self.request_redraw();
            }
            EventMsg::GetHistoryEntryResponse(event) => {
                let codex_core::protocol::GetHistoryEntryResponseEvent {
                    offset,
                    log_id,
                    entry,
                } = event;

                // Inform bottom pane / composer.
                self.bottom_pane
                    .on_history_entry_response(log_id, offset, entry.map(|e| e.text));
            }
            event => {
                self.conversation_history
                    .add_background_event(format!("{event:?}"));
                self.request_redraw();
            }
        }
    }

    /// Update the live log preview while a task is running.
    pub(crate) fn update_latest_log(&mut self, line: String) {
        // Forward only if we are currently showing the status indicator.
        self.bottom_pane.update_status_text(line);
    }

    fn request_redraw(&mut self) {
        self.app_event_tx.send(AppEvent::Redraw);
    }

    pub(crate) fn add_diff_output(&mut self, diff_output: String) {
        self.conversation_history.add_diff_output(diff_output);
        self.request_redraw();
    }

    pub(crate) fn handle_scroll_delta(&mut self, scroll_delta: i32) {
        // If the user is trying to scroll exactly one line, we let them, but
        // otherwise we assume they are trying to scroll in larger increments.
        let magnified_scroll_delta = if scroll_delta == 1 {
            1
        } else {
            // Play with this: perhaps it should be non-linear?
            scroll_delta * 2
        };
        self.conversation_history.scroll(magnified_scroll_delta);
        self.request_redraw();
    }

    /// Forward file-search results to the bottom pane.
    pub(crate) fn apply_file_search_result(&mut self, query: String, matches: Vec<FileMatch>) {
        self.bottom_pane.on_file_search_result(query, matches);
    }

    /// Handle Ctrl-C key press.
    /// Returns true if the key press was handled, false if it was not.
    /// If the key press was not handled, the caller should handle it (likely by exiting the process).
    pub(crate) fn on_ctrl_c(&mut self) -> bool {
        if let Some(handle) = self.security_review_handle.take() {
            handle.abort();
            let mode = self
                .active_security_review_mode
                .take()
                .unwrap_or_else(SecurityReviewMode::default);
            let failure = SecurityReviewFailure {
                message: "AppSec security review aborted by user.".to_string(),
                logs: vec!["AppSec security review aborted by user.".to_string()],
            };
            self.handle_security_review_finished(mode, Err(failure));
            return true;
        }

        if self.bottom_pane.is_task_running() {
            self.bottom_pane.clear_ctrl_c_quit_hint();
            self.submit_op(Op::Interrupt);
            false
        } else if self.bottom_pane.ctrl_c_quit_hint_visible() {
            true
        } else {
            self.bottom_pane.show_ctrl_c_quit_hint();
            false
        }
    }

    /// Forward an `Op` directly to codex.
    pub(crate) fn submit_op(&self, op: Op) {
        if let Err(e) = self.codex_op_tx.send(op) {
            tracing::error!("failed to submit op: {e}");
        }
    }
}

impl WidgetRef for &ChatWidget<'_> {
    fn render_ref(&self, area: Rect, buf: &mut Buffer) {
        let bottom_height = self.bottom_pane.calculate_required_height(&area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(bottom_height)])
            .split(area);

        self.conversation_history.render(chunks[0], buf);
        (&self.bottom_pane).render(chunks[1], buf);
    }
}

fn add_token_usage(current_usage: &TokenUsage, new_usage: &TokenUsage) -> TokenUsage {
    let cached_input_tokens = match (
        current_usage.cached_input_tokens,
        new_usage.cached_input_tokens,
    ) {
        (Some(current), Some(new)) => Some(current + new),
        (Some(current), None) => Some(current),
        (None, Some(new)) => Some(new),
        (None, None) => None,
    };
    let reasoning_output_tokens = match (
        current_usage.reasoning_output_tokens,
        new_usage.reasoning_output_tokens,
    ) {
        (Some(current), Some(new)) => Some(current + new),
        (Some(current), None) => Some(current),
        (None, Some(new)) => Some(new),
        (None, None) => None,
    };
    TokenUsage {
        input_tokens: current_usage.input_tokens + new_usage.input_tokens,
        cached_input_tokens,
        output_tokens: current_usage.output_tokens + new_usage.output_tokens,
        reasoning_output_tokens,
        total_tokens: current_usage.total_tokens + new_usage.total_tokens,
    }
}

fn parse_security_review_command(input: &str) -> Result<ParsedSecReviewCommand, String> {
    let tokens = shlex::split(input).ok_or_else(|| "Unable to parse command arguments.".to_string())?;
    if tokens.is_empty() {
        return Err("Empty command.".to_string());
    }

    if tokens[0] != "/secreview" {
        return Err("Unrecognized command.".to_string());
    }

    let mut command = ParsedSecReviewCommand::default();
    let mut idx = 1;
    while idx < tokens.len() {
        let token = &tokens[idx];

        if token == "--" {
            for extra in tokens.iter().skip(idx + 1) {
                if !extra.is_empty() {
                    command.include_paths.push(extra.to_string());
                }
            }
            break;
        } else if matches!(
            token.as_str(),
            "bugs" | "--bugs" | "--mode=bugs"
        ) {
            command.mode = SecurityReviewMode::Bugs;
        } else if matches!(
            token.as_str(),
            "full" | "--full" | "--mode=full"
        ) {
            command.mode = SecurityReviewMode::Full;
        } else if token == "--mode" {
            idx += 1;
            if idx >= tokens.len() {
                return Err("Expected value after --mode.".to_string());
            }
            command.mode = parse_mode(&tokens[idx])?;
        } else if let Some(value) = token.strip_prefix("--mode=") {
            command.mode = parse_mode(value)?;
        } else if token == "--path" || token == "-p" {
            idx += 1;
            if idx >= tokens.len() {
                return Err(format!("Expected value after {token}."));
            }
            command.include_paths.push(tokens[idx].clone());
        } else if let Some(value) = token.strip_prefix("--path=") {
            command.include_paths.push(value.to_string());
        } else if let Some(value) = token.strip_prefix("-p=") {
            command.include_paths.push(value.to_string());
        } else if matches!(
            token.as_str(),
            "--output" | "-o" | "--output-location"
        ) {
            idx += 1;
            if idx >= tokens.len() {
                return Err(format!("Expected value after {token}."));
            }
            command.output_path = Some(tokens[idx].clone());
        } else if let Some(value) = token.strip_prefix("--output=") {
            command.output_path = Some(value.to_string());
        } else if let Some(value) = token.strip_prefix("-o=") {
            command.output_path = Some(value.to_string());
        } else if matches!(
            token.as_str(),
            "--repo" | "--repo-location" | "--repository"
        ) {
            idx += 1;
            if idx >= tokens.len() {
                return Err(format!("Expected value after {token}."));
            }
            command.repo_path = Some(tokens[idx].clone());
        } else if let Some(value) = token.strip_prefix("--repo=") {
            command.repo_path = Some(value.to_string());
        } else if let Some(value) = token.strip_prefix("--repo-location=") {
            command.repo_path = Some(value.to_string());
        } else if token == "--model" || token == "--model-name" {
            idx += 1;
            if idx >= tokens.len() {
                return Err(format!("Expected value after {token}."));
            }
            command.model_name = Some(tokens[idx].clone());
        } else if let Some(value) = token.strip_prefix("--model=") {
            command.model_name = Some(value.to_string());
        } else if let Some(value) = token.strip_prefix("--model-name=") {
            command.model_name = Some(value.to_string());
        } else if !token.is_empty() {
            command.include_paths.push(token.clone());
        }

        idx += 1;
    }

    Ok(command)
}

fn parse_mode(value: &str) -> Result<SecurityReviewMode, String> {
    match value.to_ascii_lowercase().as_str() {
        "full" => Ok(SecurityReviewMode::Full),
        "bugs" | "bugs-only" | "bugsonly" => Ok(SecurityReviewMode::Bugs),
        other => Err(format!("Unknown mode '{other}'. Use 'full' or 'bugs'.")),
    }
}

fn resolve_path(base: &Path, candidate: &str) -> PathBuf {
    let path = Path::new(candidate);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
    .clean()
}

fn format_security_review_logs(logs: &[String]) -> Option<String> {
    if logs.is_empty() {
        return None;
    }

    let joined = logs.join("\n");
    if joined.trim().is_empty() {
        return None;
    }

    let lines: Vec<&str> = joined.lines().collect();
    const MAX_LINES: usize = 40;
    if lines.len() <= MAX_LINES {
        Some(joined)
    } else {
        let tail = lines[lines.len().saturating_sub(MAX_LINES)..].join("\n");
        Some(format!("… (showing last {MAX_LINES} lines)\n{tail}"))
    }
}

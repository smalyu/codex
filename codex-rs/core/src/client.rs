use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use crate::auth::CodexAuth;
use crate::chat_completions::AggregateStreamExt;
use crate::client_common::Prompt;
use crate::client_common::ResponseEvent;
use crate::client_common::ResponsesApiRequest;
use crate::client_common::create_reasoning_param_for_request;
use crate::client_common::create_text_param_for_request;
use crate::config::Config;
use crate::default_client::create_client;
use crate::error::CodexErr;
use crate::error::Result;
use crate::error::RetryLimitReachedError;
use crate::error::UnexpectedResponseError;
use crate::error::UsageLimitReachedError;
use crate::flags::CODEX_RS_SSE_FIXTURE;
use crate::model_provider_info::ModelProviderInfo;
use crate::model_provider_info::WireApi;
use crate::protocol::RateLimitSnapshot;
use crate::protocol::RateLimitWindow;
use crate::protocol::TokenUsage;
use crate::token_data::PlanType;
use bytes::Bytes;
use codex_app_server_protocol::AuthMode;
use codex_otel::otel_event_manager::OtelEventManager;
use codex_protocol::ConversationId;
use codex_protocol::config_types::ReasoningEffort as ReasoningEffortConfig;
use codex_protocol::config_types::ReasoningSummary as ReasoningSummaryConfig;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ReasoningItemContent;
use codex_protocol::models::ResponseItem;
use eventsource_stream::Eventsource;
use futures::Stream;
use futures::StreamExt;
use futures::TryStreamExt;
use regex_lite::Regex;
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tracing::debug;
use tracing::trace;
use tracing::warn;

use crate::AuthManager;
use crate::openai_tools::create_tools_json_for_chat_completions_api;
use crate::openai_tools::create_tools_json_for_responses_api;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum StreamMode {
    #[default]
    Aggregated,
    Streaming,
}

#[derive(Clone, Debug, Default)]
pub struct CallOpts {
    pub stream_mode: Option<StreamMode>,
    pub conversation_id: Option<ConversationId>,
    pub provider_hint: Option<WireDialect>,
    pub effort: Option<ReasoningEffortConfig>,
    pub summary: Option<ReasoningSummaryConfig>,
    pub output_schema: Option<Value>,
    pub show_raw_reasoning: Option<bool>,
}

#[derive(Clone, Debug)]
struct ResolvedCall {
    stream_mode: StreamMode,
    conversation_id: ConversationId,
    provider_hint: Option<WireDialect>,
    effort: Option<ReasoningEffortConfig>,
    summary: ReasoningSummaryConfig,
    output_schema: Option<Value>,
    show_raw_reasoning: bool,
}

#[derive(Clone, Debug)]
pub struct Client {
    cfg: Arc<Config>,
    provider: Arc<ModelProviderInfo>,
    auth: Option<Arc<AuthManager>>,
    http: reqwest::Client,
    otel: OtelEventManager,
    defaults: CallOpts,
}

#[derive(Default)]
pub struct ClientBuilder {
    config: Option<Arc<Config>>,
    provider: Option<ModelProviderInfo>,
    auth: Option<Arc<AuthManager>>,
    otel: Option<OtelEventManager>,
    http: Option<reqwest::Client>,
    defaults: CallOpts,
}

pub struct TurnStream {
    inner: Pin<Box<dyn Stream<Item = Result<ResponseEvent>> + Send + 'static>>,
    dialect: WireDialect,
}

pub struct TurnResult {
    pub events: Vec<ResponseEvent>,
    pub error: Option<CodexErr>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WireDialect {
    Responses,
    Chat,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        auth_manager: Option<Arc<AuthManager>>,
        otel_event_manager: OtelEventManager,
        provider: ModelProviderInfo,
        effort: Option<ReasoningEffortConfig>,
        summary: ReasoningSummaryConfig,
        conversation_id: ConversationId,
    ) -> Self {
        ClientBuilder::default()
            .config(config)
            .provider(provider)
            .auth_manager(auth_manager)
            .otel(otel_event_manager)
            .conversation_id(conversation_id)
            .reasoning_effort(effort)
            .reasoning_summary(summary)
            .build()
    }

    pub async fn stream(&self, prompt: &Prompt, opts: impl Into<CallOpts>) -> Result<TurnStream> {
        let call = self.resolve_call(opts.into())?;
        let dialect = self.resolve_dialect(call.provider_hint);

        if matches!(dialect, WireDialect::Responses)
            && let Some(path) = &*CODEX_RS_SSE_FIXTURE
        {
            return self.stream_from_fixture(path, &call).await;
        }

        let stream = match dialect {
            WireDialect::Responses => self.stream_responses(prompt, &call).await?,
            WireDialect::Chat => self.stream_chat(prompt, &call).await?,
        };

        Ok(stream)
    }

    pub async fn complete(&self, prompt: &Prompt, opts: impl Into<CallOpts>) -> Result<TurnResult> {
        let mut stream = self.stream(prompt, opts).await?;
        let mut events = Vec::new();
        let mut first_err: Option<CodexErr> = None;

        while let Some(item) = stream.next().await {
            match item {
                Ok(event) => events.push(event),
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                }
            }
        }

        Ok(TurnResult {
            events,
            error: first_err,
        })
    }

    fn resolve_dialect(&self, hint: Option<WireDialect>) -> WireDialect {
        if let Some(h) = hint {
            return h;
        }
        match self.provider.wire_api {
            WireApi::Responses => WireDialect::Responses,
            WireApi::Chat => WireDialect::Chat,
        }
    }

    fn resolve_call(&self, opts: CallOpts) -> Result<ResolvedCall> {
        let stream_mode = opts
            .stream_mode
            .or(self.defaults.stream_mode)
            .unwrap_or(StreamMode::Aggregated);

        let conversation_id = opts
            .conversation_id
            .or(self.defaults.conversation_id)
            .ok_or_else(|| CodexErr::Fatal("conversation_id must be provided".to_string()))?;

        let summary = opts.summary.or(self.defaults.summary).unwrap_or_default();

        Ok(ResolvedCall {
            stream_mode,
            conversation_id,
            provider_hint: opts.provider_hint.or(self.defaults.provider_hint),
            effort: opts.effort.or(self.defaults.effort),
            summary,
            output_schema: opts.output_schema.or(self.defaults.output_schema.clone()),
            show_raw_reasoning: opts
                .show_raw_reasoning
                .or(self.defaults.show_raw_reasoning)
                .unwrap_or(false),
        })
    }

    pub fn get_provider(&self) -> ModelProviderInfo {
        (*self.provider).clone()
    }

    pub fn get_otel_event_manager(&self) -> OtelEventManager {
        self.otel.clone()
    }

    pub fn get_model(&self) -> String {
        self.cfg.model.clone()
    }

    pub fn get_model_family(&self) -> crate::model_family::ModelFamily {
        self.cfg.model_family.clone()
    }

    pub fn get_model_context_window(&self) -> Option<u64> {
        self.cfg.model_context_window.or_else(|| {
            crate::openai_model_info::get_model_info(&self.cfg.model_family)
                .map(|info| info.context_window)
        })
    }

    pub fn get_auto_compact_token_limit(&self) -> Option<i64> {
        self.cfg.model_auto_compact_token_limit.or_else(|| {
            crate::openai_model_info::get_model_info(&self.cfg.model_family)
                .and_then(|info| info.auto_compact_token_limit)
        })
    }

    pub fn get_reasoning_effort(&self) -> Option<ReasoningEffortConfig> {
        self.defaults.effort
    }

    pub fn get_reasoning_summary(&self) -> ReasoningSummaryConfig {
        self.defaults
            .summary
            .unwrap_or(self.cfg.model_reasoning_summary)
    }

    pub fn get_auth_manager(&self) -> Option<Arc<AuthManager>> {
        self.auth.clone()
    }

    async fn stream_responses(&self, prompt: &Prompt, call: &ResolvedCall) -> Result<TurnStream> {
        let auth_manager = self.auth.clone();

        let full_instructions = prompt.get_full_instructions(&self.cfg.model_family);
        let tools_json = create_tools_json_for_responses_api(&prompt.tools)?;
        let reasoning =
            create_reasoning_param_for_request(&self.cfg.model_family, call.effort, call.summary);

        let include = if reasoning.is_some() {
            vec!["reasoning.encrypted_content".to_string()]
        } else {
            Vec::new()
        };

        let input_with_instructions = prompt.get_formatted_input();
        let output_schema = call
            .output_schema
            .clone()
            .or_else(|| prompt.output_schema.clone());

        let verbosity = match &self.cfg.model_family.family {
            family if family == "gpt-5" => self.cfg.model_verbosity,
            _ => {
                if self.cfg.model_verbosity.is_some() {
                    warn!(
                        "model_verbosity is set but ignored for non-gpt-5 model family: {}",
                        self.cfg.model_family.family
                    );
                }
                None
            }
        };

        let text = create_text_param_for_request(verbosity, &output_schema);
        let azure_workaround = self.provider.is_azure_responses_endpoint();

        let payload = ResponsesApiRequest {
            model: &self.cfg.model,
            instructions: &full_instructions,
            input: &input_with_instructions,
            tools: &tools_json,
            tool_choice: "auto",
            parallel_tool_calls: prompt.parallel_tool_calls,
            reasoning,
            store: azure_workaround,
            stream: true,
            include,
            prompt_cache_key: Some(call.conversation_id.to_string()),
            text,
        };

        let mut payload_json = serde_json::to_value(&payload)?;
        if azure_workaround {
            attach_item_ids(&mut payload_json, &input_with_instructions);
        }

        let max_attempts = self.provider.request_max_retries();
        for attempt in 0..=max_attempts {
            match self
                .attempt_stream_responses(attempt, &payload_json, call, auth_manager.as_ref())
                .await
            {
                Ok(resp) => {
                    let headers = resp.headers().clone();
                    let stream = resp.bytes_stream().map_err(CodexErr::Reqwest);
                    return Ok(self.build_turn_stream(
                        WireDialect::Responses,
                        stream,
                        Some(headers),
                        call,
                    ));
                }
                Err(StreamAttemptError::Fatal(err)) => return Err(err),
                Err(err) => {
                    if attempt == max_attempts {
                        return Err(err.into_error());
                    }
                    let delay = err.delay(attempt);
                    sleep(delay).await;
                }
            }
        }

        unreachable!("stream_responses attempts should return within loop");
    }

    async fn stream_chat(&self, prompt: &Prompt, call: &ResolvedCall) -> Result<TurnStream> {
        if prompt.output_schema.is_some() || call.output_schema.is_some() {
            return Err(CodexErr::UnsupportedOperation(
                "output_schema is not supported for Chat Completions API".to_string(),
            ));
        }

        let mut messages = Vec::<serde_json::Value>::new();
        let full_instructions = prompt.get_full_instructions(&self.cfg.model_family);
        messages.push(json!({"role": "system", "content": full_instructions}));

        let input = prompt.get_formatted_input();

        let mut reasoning_by_anchor_index: HashMap<usize, String> = HashMap::new();

        let mut last_emitted_role: Option<&str> = None;
        for item in &input {
            match item {
                ResponseItem::Message { role, .. } => last_emitted_role = Some(role.as_str()),
                ResponseItem::FunctionCall { .. } | ResponseItem::LocalShellCall { .. } => {
                    last_emitted_role = Some("assistant")
                }
                ResponseItem::FunctionCallOutput { .. } => last_emitted_role = Some("tool"),
                ResponseItem::Reasoning { .. } | ResponseItem::Other => {}
                ResponseItem::CustomToolCall { .. } => {}
                ResponseItem::CustomToolCallOutput { .. } => {}
                ResponseItem::WebSearchCall { .. } => {}
            }
        }

        let mut last_user_index: Option<usize> = None;
        for (idx, item) in input.iter().enumerate() {
            if let ResponseItem::Message { role, .. } = item
                && role == "user"
            {
                last_user_index = Some(idx);
            }
        }

        if !matches!(last_emitted_role, Some("user")) {
            for (idx, item) in input.iter().enumerate() {
                if let Some(u_idx) = last_user_index
                    && idx <= u_idx
                {
                    continue;
                }

                if let ResponseItem::Reasoning {
                    content: Some(items),
                    ..
                } = item
                {
                    let mut text = String::new();
                    for c in items {
                        match c {
                            ReasoningItemContent::ReasoningText { text: t }
                            | ReasoningItemContent::Text { text: t } => text.push_str(t),
                        }
                    }
                    if text.trim().is_empty() {
                        continue;
                    }

                    let mut attached = false;
                    if idx > 0
                        && let ResponseItem::Message { role, .. } = &input[idx - 1]
                        && role == "assistant"
                    {
                        reasoning_by_anchor_index
                            .entry(idx - 1)
                            .and_modify(|v| v.push_str(&text))
                            .or_insert(text.clone());
                        attached = true;
                    }

                    if !attached && idx + 1 < input.len() {
                        match &input[idx + 1] {
                            ResponseItem::FunctionCall { .. }
                            | ResponseItem::LocalShellCall { .. } => {
                                reasoning_by_anchor_index
                                    .entry(idx + 1)
                                    .and_modify(|v| v.push_str(&text))
                                    .or_insert(text.clone());
                            }
                            ResponseItem::Message { role, .. } if role == "assistant" => {
                                reasoning_by_anchor_index
                                    .entry(idx + 1)
                                    .and_modify(|v| v.push_str(&text))
                                    .or_insert(text.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let mut last_assistant_text: Option<String> = None;
        for (idx, item) in input.iter().enumerate() {
            match item {
                ResponseItem::Message { role, content, .. } => {
                    let mut text = String::new();
                    for c in content {
                        match c {
                            ContentItem::InputText { text: t }
                            | ContentItem::OutputText { text: t } => text.push_str(t),
                            _ => {}
                        }
                    }
                    if role == "assistant" {
                        if let Some(prev) = &last_assistant_text
                            && prev == &text
                        {
                            continue;
                        }
                        last_assistant_text = Some(text.clone());
                    }

                    let mut msg = json!({"role": role, "content": text});
                    if role == "assistant"
                        && let Some(reasoning) = reasoning_by_anchor_index.get(&idx)
                        && let Some(obj) = msg.as_object_mut()
                    {
                        obj.insert("reasoning".to_string(), json!(reasoning));
                    }
                    messages.push(msg);
                }
                ResponseItem::FunctionCall {
                    name,
                    arguments,
                    call_id,
                    ..
                } => {
                    let mut msg = json!({
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": arguments,
                            }
                        }]
                    });
                    if let Some(reasoning) = reasoning_by_anchor_index.get(&idx)
                        && let Some(obj) = msg.as_object_mut()
                    {
                        obj.insert("reasoning".to_string(), json!(reasoning));
                    }
                    messages.push(msg);
                }
                ResponseItem::LocalShellCall {
                    id,
                    call_id: _,
                    status,
                    action,
                } => {
                    let mut msg = json!({
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": id.clone().unwrap_or_default(),
                            "type": "local_shell_call",
                            "status": status,
                            "action": action,
                        }]
                    });
                    if let Some(reasoning) = reasoning_by_anchor_index.get(&idx)
                        && let Some(obj) = msg.as_object_mut()
                    {
                        obj.insert("reasoning".to_string(), json!(reasoning));
                    }
                    messages.push(msg);
                }
                ResponseItem::FunctionCallOutput { call_id, output } => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": output.content,
                    }));
                }
                ResponseItem::CustomToolCall {
                    id,
                    call_id: _,
                    name,
                    input: tool_input,
                    status: _,
                } => {
                    messages.push(json!({
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": id,
                            "type": "custom",
                            "custom": {
                                "name": name,
                                "input": tool_input,
                            }
                        }]
                    }));
                }
                ResponseItem::CustomToolCallOutput { call_id, output } => {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": output,
                    }));
                }
                ResponseItem::Reasoning { .. }
                | ResponseItem::WebSearchCall { .. }
                | ResponseItem::Other => {
                    continue;
                }
            }
        }

        let tools_json = create_tools_json_for_chat_completions_api(&prompt.tools)?;
        let payload = json!({
            "model": self.cfg.model_family.slug,
            "messages": messages,
            "stream": true,
            "tools": tools_json,
        });

        let mut attempt = 0;
        let max_retries = self.provider.request_max_retries();
        loop {
            attempt += 1;

            let req_builder = self
                .provider
                .create_request_builder(&self.http, &None)
                .await?;
            let res = self
                .otel
                .log_request(attempt, || {
                    req_builder
                        .header(reqwest::header::ACCEPT, "text/event-stream")
                        .json(&payload)
                        .send()
                })
                .await;

            match res {
                Ok(resp) if resp.status().is_success() => {
                    let headers = resp.headers().clone();
                    let stream = resp.bytes_stream().map_err(CodexErr::Reqwest);
                    return Ok(self.build_turn_stream(
                        WireDialect::Chat,
                        stream,
                        Some(headers),
                        call,
                    ));
                }
                Ok(res) => {
                    let status = res.status();
                    if !(status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()) {
                        let body = res.text().await.unwrap_or_default();
                        return Err(CodexErr::UnexpectedStatus(UnexpectedResponseError {
                            status,
                            body,
                            request_id: None,
                        }));
                    }

                    if attempt > max_retries {
                        return Err(CodexErr::RetryLimit(RetryLimitReachedError {
                            status,
                            request_id: None,
                        }));
                    }

                    let retry_after_secs = res
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());

                    let delay = retry_after_secs
                        .map(|s| Duration::from_millis(s * 1_000))
                        .unwrap_or_else(|| crate::util::backoff(attempt));
                    sleep(delay).await;
                }
                Err(err) => {
                    if attempt > max_retries {
                        return Err(err.into());
                    }
                    let delay = crate::util::backoff(attempt);
                    sleep(delay).await;
                }
            }
        }
    }

    async fn stream_from_fixture(&self, path: &str, call: &ResolvedCall) -> Result<TurnStream> {
        let file = File::open(path).map_err(CodexErr::Io)?;
        let reader = BufReader::new(file);
        let mut body = String::new();

        for line in reader.lines() {
            body.push_str(&line.map_err(CodexErr::Io)?);
            body.push_str("\n\n");
        }

        let cursor = Cursor::new(body);
        let stream = ReaderStream::new(cursor).map_err(CodexErr::Io);
        Ok(self.build_turn_stream(WireDialect::Responses, stream, None, call))
    }

    fn apply_stream_mode(
        &self,
        stream: TurnStream,
        dialect: WireDialect,
        call: &ResolvedCall,
    ) -> TurnStream {
        if !matches!(dialect, WireDialect::Chat) {
            return stream;
        }

        match call.stream_mode {
            StreamMode::Aggregated if !call.show_raw_reasoning => {
                let aggregated = stream.aggregate();
                TurnStream::new(aggregated, dialect)
            }
            _ => stream,
        }
    }

    fn build_turn_stream<S>(
        &self,
        dialect: WireDialect,
        stream: S,
        headers: Option<HeaderMap>,
        call: &ResolvedCall,
    ) -> TurnStream
    where
        S: Stream<Item = Result<Bytes>> + Send + Unpin + 'static,
    {
        let (tx, rx) = mpsc::channel::<Result<ResponseEvent>>(1024);
        let otel = self.otel.clone();
        let provider = self.provider.clone();
        let call_clone = call.clone();
        tokio::spawn(async move {
            run_sse_loop(dialect, stream, headers, provider, otel, call_clone, tx).await;
        });

        let base = TurnStream::new(ReceiverStream::new(rx), dialect);
        self.apply_stream_mode(base, dialect, call)
    }

    async fn attempt_stream_responses(
        &self,
        attempt: u64,
        payload_json: &Value,
        call: &ResolvedCall,
        auth_manager: Option<&Arc<AuthManager>>,
    ) -> std::result::Result<reqwest::Response, StreamAttemptError> {
        let auth = auth_manager.and_then(|manager| manager.auth());

        let mut req_builder = self
            .provider
            .create_request_builder(&self.http, &auth)
            .await
            .map_err(StreamAttemptError::Fatal)?;

        req_builder = req_builder
            .header("OpenAI-Beta", "responses=experimental")
            .header("conversation_id", call.conversation_id.to_string())
            .header("session_id", call.conversation_id.to_string())
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .json(payload_json);

        if let Some(auth) = auth.as_ref()
            && auth.mode == AuthMode::ChatGPT
            && let Some(account_id) = auth.get_account_id()
        {
            req_builder = req_builder.header("chatgpt-account-id", account_id);
        }

        let res = self.otel.log_request(attempt, || req_builder.send()).await;

        let mut request_id = None;
        if let Ok(resp) = &res {
            request_id = resp
                .headers()
                .get("cf-ray")
                .map(|v| v.to_str().unwrap_or_default().to_string());
        }

        match res {
            Ok(resp) if resp.status().is_success() => Ok(resp),
            Ok(resp) => {
                let status = resp.status();

                let retry_after = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|s| Duration::from_millis(s * 1_000));

                if status == StatusCode::UNAUTHORIZED
                    && let Some(manager) = auth_manager
                    && manager.auth().is_some()
                {
                    let _ = manager.refresh_token().await;
                }

                if !(status == StatusCode::TOO_MANY_REQUESTS
                    || status == StatusCode::UNAUTHORIZED
                    || status.is_server_error())
                {
                    let body = resp.text().await.unwrap_or_default();
                    return Err(StreamAttemptError::Fatal(CodexErr::UnexpectedStatus(
                        UnexpectedResponseError {
                            status,
                            body,
                            request_id: None,
                        },
                    )));
                }

                if status == StatusCode::TOO_MANY_REQUESTS {
                    let rate_limit_snapshot = parse_rate_limit_snapshot(resp.headers());
                    let body = resp.json::<ErrorResponse>().await.ok();
                    if let Some(ErrorResponse { error }) = body {
                        if error.r#type.as_deref() == Some("usage_limit_reached") {
                            let plan_type = error
                                .plan_type
                                .or_else(|| auth.as_ref().and_then(CodexAuth::get_plan_type));
                            let resets_in_seconds = error.resets_in_seconds;
                            let codex_err = CodexErr::UsageLimitReached(UsageLimitReachedError {
                                plan_type,
                                resets_in_seconds,
                                rate_limits: rate_limit_snapshot,
                            });
                            return Err(StreamAttemptError::Fatal(codex_err));
                        } else if error.r#type.as_deref() == Some("usage_not_included") {
                            return Err(StreamAttemptError::Fatal(CodexErr::UsageNotIncluded));
                        }
                    }
                }

                Err(StreamAttemptError::RetryableHttpError {
                    status,
                    retry_after,
                    request_id,
                })
            }
            Err(err) => Err(StreamAttemptError::RetryableTransportError(err.into())),
        }
    }
}

impl ClientBuilder {
    pub fn config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn provider(mut self, provider: ModelProviderInfo) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn auth_manager(mut self, auth: Option<Arc<AuthManager>>) -> Self {
        self.auth = auth;
        self
    }

    pub fn otel(mut self, otel: OtelEventManager) -> Self {
        self.otel = Some(otel);
        self
    }

    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    pub fn defaults(mut self, defaults: CallOpts) -> Self {
        self.defaults = defaults;
        self
    }

    pub fn conversation_id(mut self, conversation_id: ConversationId) -> Self {
        self.defaults.conversation_id = Some(conversation_id);
        self
    }

    pub fn reasoning_effort(mut self, effort: Option<ReasoningEffortConfig>) -> Self {
        self.defaults.effort = effort;
        self
    }

    pub fn reasoning_summary(mut self, summary: ReasoningSummaryConfig) -> Self {
        self.defaults.summary = Some(summary);
        self
    }

    pub fn stream_mode(mut self, mode: StreamMode) -> Self {
        self.defaults.stream_mode = Some(mode);
        self
    }

    pub fn show_raw_reasoning(mut self, show: bool) -> Self {
        self.defaults.show_raw_reasoning = Some(show);
        self
    }

    pub fn build(self) -> Client {
        let cfg = match self.config {
            Some(cfg) => cfg,
            None => panic!("config must be provided before building Client"),
        };
        let provider = match self.provider {
            Some(provider) => provider,
            None => panic!("provider must be provided before building Client"),
        };
        let otel = match self.otel {
            Some(otel) => otel,
            None => panic!("otel event manager must be provided before building Client"),
        };

        let mut defaults = self.defaults;
        if defaults.summary.is_none() {
            defaults.summary = Some(cfg.model_reasoning_summary);
        }
        if defaults.show_raw_reasoning.is_none() {
            defaults.show_raw_reasoning = Some(cfg.show_raw_agent_reasoning);
        }
        if defaults.stream_mode.is_none() {
            defaults.stream_mode = Some(if cfg.show_raw_agent_reasoning {
                StreamMode::Streaming
            } else {
                StreamMode::Aggregated
            });
        }

        let http = self.http.unwrap_or_else(create_client);

        Client {
            cfg,
            provider: Arc::new(provider),
            auth: self.auth,
            http,
            otel,
            defaults,
        }
    }
}

impl Stream for TurnStream {
    type Item = Result<ResponseEvent>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl Unpin for TurnStream {}

impl TurnStream {
    fn new<S>(stream: S, dialect: WireDialect) -> Self
    where
        S: Stream<Item = Result<ResponseEvent>> + Send + 'static,
    {
        Self {
            inner: Box::pin(stream),
            dialect,
        }
    }

    pub fn dialect(&self) -> WireDialect {
        self.dialect
    }
}

impl From<()> for CallOpts {
    fn from(_: ()) -> Self {
        CallOpts::default()
    }
}

impl From<StreamMode> for CallOpts {
    fn from(mode: StreamMode) -> Self {
        CallOpts {
            stream_mode: Some(mode),
            ..CallOpts::default()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Error,
}

#[derive(Debug, Deserialize)]
struct Error {
    r#type: Option<String>,
    code: Option<String>,
    message: Option<String>,
    plan_type: Option<PlanType>,
    resets_in_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ResponseCompleted {
    id: String,
    usage: Option<ResponseCompletedUsage>,
}

#[derive(Debug, Deserialize)]
struct ResponseCompletedUsage {
    input_tokens: u64,
    input_tokens_details: Option<ResponseCompletedInputTokensDetails>,
    output_tokens: u64,
    output_tokens_details: Option<ResponseCompletedOutputTokensDetails>,
    total_tokens: u64,
}

impl From<ResponseCompletedUsage> for TokenUsage {
    fn from(val: ResponseCompletedUsage) -> Self {
        TokenUsage {
            input_tokens: val.input_tokens,
            cached_input_tokens: val
                .input_tokens_details
                .map(|d| d.cached_tokens)
                .unwrap_or(0),
            output_tokens: val.output_tokens,
            reasoning_output_tokens: val
                .output_tokens_details
                .map(|d| d.reasoning_tokens)
                .unwrap_or(0),
            total_tokens: val.total_tokens,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResponseCompletedInputTokensDetails {
    cached_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct ResponseCompletedOutputTokensDetails {
    reasoning_tokens: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SseEvent {
    #[serde(rename = "type")]
    kind: String,
    response: Option<Value>,
    item: Option<Value>,
    delta: Option<String>,
}

#[derive(Debug)]
enum StreamAttemptError {
    RetryableHttpError {
        status: StatusCode,
        retry_after: Option<Duration>,
        request_id: Option<String>,
    },
    RetryableTransportError(CodexErr),
    Fatal(CodexErr),
}

impl StreamAttemptError {
    fn delay(&self, attempt: u64) -> Duration {
        let backoff_attempt = attempt + 1;
        match self {
            Self::RetryableHttpError { retry_after, .. } => {
                retry_after.unwrap_or_else(|| crate::util::backoff(backoff_attempt))
            }
            Self::RetryableTransportError { .. } => crate::util::backoff(backoff_attempt),
            Self::Fatal(_) => Duration::from_secs(0),
        }
    }

    fn into_error(self) -> CodexErr {
        match self {
            Self::RetryableHttpError {
                status, request_id, ..
            } => {
                if status == StatusCode::INTERNAL_SERVER_ERROR {
                    CodexErr::InternalServerError
                } else {
                    CodexErr::RetryLimit(RetryLimitReachedError { status, request_id })
                }
            }
            Self::RetryableTransportError(error) => error,
            Self::Fatal(error) => error,
        }
    }
}

#[derive(Default)]
struct DecodeOutcome {
    events: Vec<ResponseEvent>,
    errors: Vec<CodexErr>,
    completed: bool,
}

struct FinalizeResult {
    completed_emitted: bool,
    error_emitted: bool,
}

enum DecoderState {
    Responses(ResponsesDecoderState),
    Chat(ChatDecoderState),
}

impl DecoderState {
    fn new(dialect: WireDialect) -> Self {
        match dialect {
            WireDialect::Responses => DecoderState::Responses(ResponsesDecoderState::default()),
            WireDialect::Chat => DecoderState::Chat(ChatDecoderState::default()),
        }
    }
}

#[derive(Default)]
struct ResponsesDecoderState {
    completed: Option<ResponseCompleted>,
    error: Option<CodexErr>,
}

#[derive(Default)]
struct ChatDecoderState {
    fn_call: FunctionCallState,
    assistant_text: String,
    reasoning_text: String,
}

#[derive(Default)]
struct FunctionCallState {
    name: Option<String>,
    arguments: String,
    call_id: Option<String>,
    active: bool,
}

async fn run_sse_loop<S>(
    dialect: WireDialect,
    stream: S,
    headers: Option<HeaderMap>,
    provider: Arc<ModelProviderInfo>,
    otel: OtelEventManager,
    _call: ResolvedCall,
    mut tx: mpsc::Sender<Result<ResponseEvent>>,
) where
    S: Stream<Item = Result<Bytes>> + Send + Unpin + 'static,
{
    let mut decoder = DecoderState::new(dialect);
    let mut event_stream = stream.eventsource();
    let idle_timeout = provider.stream_idle_timeout();
    let mut saw_completed = false;

    if let Some(headers) = headers.as_ref() {
        emit_ratelimit_snapshot(headers, &mut tx).await;
    }

    loop {
        let start = Instant::now();
        let next = timeout(idle_timeout, event_stream.next()).await;
        let duration = start.elapsed();
        otel.log_sse_event(&next, duration);

        let sse = match next {
            Ok(Some(Ok(ev))) => ev,
            Ok(Some(Err(err))) => {
                forward_err(CodexErr::Stream(err.to_string(), None), &mut tx).await;
                break;
            }
            Ok(None) => break,
            Err(_) => {
                forward_err(
                    CodexErr::Stream("idle timeout waiting for SSE".into(), None),
                    &mut tx,
                )
                .await;
                break;
            }
        };

        trace!("SSE event: {}", sse.data);
        let outcome = decode_sse_line(&mut decoder, &sse.data);

        for err in outcome.errors {
            forward_err(err, &mut tx).await;
            if tx.is_closed() {
                return;
            }
        }

        for event in outcome.events {
            saw_completed |= matches!(event, ResponseEvent::Completed { .. });
            if forward_event(event, &mut tx).await {
                return;
            }
        }

        if tx.is_closed() {
            return;
        }
    }

    let finalize = finalize_decoder(&mut decoder, &mut tx, &otel).await;
    saw_completed |= finalize.completed_emitted;

    if !saw_completed {
        if matches!(dialect, WireDialect::Responses) && !finalize.error_emitted {
            let err = CodexErr::Stream("stream closed before response.completed".into(), None);
            otel.see_event_completed_failed(&err);
            forward_err(err, &mut tx).await;
        }
        let _ = tx
            .send(Ok(ResponseEvent::Completed {
                response_id: String::new(),
                token_usage: None,
            }))
            .await;
    }
}

fn decode_sse_line(state: &mut DecoderState, line: &str) -> DecodeOutcome {
    match state {
        DecoderState::Responses(inner) => decode_responses_line(inner, line),
        DecoderState::Chat(inner) => decode_chat_line(inner, line),
    }
}

fn decode_responses_line(state: &mut ResponsesDecoderState, line: &str) -> DecodeOutcome {
    let mut outcome = DecodeOutcome::default();
    let event: SseEvent = match serde_json::from_str(line) {
        Ok(ev) => ev,
        Err(err) => {
            debug!("Failed to parse SSE event: {err}, data: {line}");
            return outcome;
        }
    };

    match event.kind.as_str() {
        "response.output_item.done" => {
            if let Some(item_val) = event.item {
                match serde_json::from_value::<ResponseItem>(item_val) {
                    Ok(item) => outcome.events.push(ResponseEvent::OutputItemDone(item)),
                    Err(err) => debug!("failed to parse ResponseItem from output_item.done: {err}"),
                }
            }
        }
        "response.output_text.delta" => {
            if let Some(delta) = event.delta {
                outcome.events.push(ResponseEvent::OutputTextDelta(delta));
            }
        }
        "response.reasoning_summary_text.delta" => {
            if let Some(delta) = event.delta {
                outcome
                    .events
                    .push(ResponseEvent::ReasoningSummaryDelta(delta));
            }
        }
        "response.reasoning_text.delta" => {
            if let Some(delta) = event.delta {
                outcome
                    .events
                    .push(ResponseEvent::ReasoningContentDelta(delta));
            }
        }
        "response.created" => {
            if event.response.is_some() {
                outcome.events.push(ResponseEvent::Created);
            }
        }
        "response.failed" => {
            if let Some(resp_val) = event.response {
                let mut error = Some(CodexErr::Stream(
                    "response.failed event received".to_string(),
                    None,
                ));

                if let Some(err_val) = resp_val.get("error") {
                    match serde_json::from_value::<Error>(err_val.clone()) {
                        Ok(parsed) => {
                            if is_context_window_error(&parsed) {
                                error = Some(CodexErr::ContextWindowExceeded);
                            } else {
                                let delay = try_parse_retry_after(&parsed);
                                let message = parsed.message.unwrap_or_default();
                                error = Some(CodexErr::Stream(message, delay));
                            }
                        }
                        Err(err) => {
                            let msg = format!("failed to parse ErrorResponse: {err}");
                            debug!("{msg}");
                            error = Some(CodexErr::Stream(msg, None));
                        }
                    }
                }

                state.error = error;
            }
        }
        "response.completed" => {
            if let Some(resp_val) = event.response {
                match serde_json::from_value::<ResponseCompleted>(resp_val) {
                    Ok(completed) => state.completed = Some(completed),
                    Err(err) => {
                        let msg = format!("failed to parse ResponseCompleted: {err}");
                        debug!("{msg}");
                        state.error = Some(CodexErr::Stream(msg, None));
                    }
                }
            }
        }
        "response.output_item.added" => {
            if let Some(item) = event.item.as_ref()
                && let Some(ty) = item.get("type").and_then(|v| v.as_str())
                && ty == "web_search_call"
            {
                let call_id = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                outcome
                    .events
                    .push(ResponseEvent::WebSearchCallBegin { call_id });
            }
        }
        "response.reasoning_summary_part.added" => {
            outcome
                .events
                .push(ResponseEvent::ReasoningSummaryPartAdded);
        }
        "response.reasoning_summary_text.done"
        | "response.content_part.done"
        | "response.function_call_arguments.delta"
        | "response.custom_tool_call_input.delta"
        | "response.custom_tool_call_input.done"
        | "response.in_progress"
        | "response.output_text.done" => {}
        _ => {}
    }

    outcome
}

fn decode_chat_line(state: &mut ChatDecoderState, line: &str) -> DecodeOutcome {
    let mut outcome = DecodeOutcome::default();
    if line.trim() == "[DONE]" {
        if !state.assistant_text.is_empty() {
            let item = ResponseItem::Message {
                role: "assistant".to_string(),
                content: vec![ContentItem::OutputText {
                    text: std::mem::take(&mut state.assistant_text),
                }],
                id: None,
            };
            outcome.events.push(ResponseEvent::OutputItemDone(item));
        }

        if !state.reasoning_text.is_empty() {
            let item = ResponseItem::Reasoning {
                id: String::new(),
                summary: Vec::new(),
                content: Some(vec![ReasoningItemContent::ReasoningText {
                    text: std::mem::take(&mut state.reasoning_text),
                }]),
                encrypted_content: None,
            };
            outcome.events.push(ResponseEvent::OutputItemDone(item));
        }

        outcome.events.push(ResponseEvent::Completed {
            response_id: String::new(),
            token_usage: None,
        });
        outcome.completed = true;
        state.fn_call = FunctionCallState::default();
        return outcome;
    }

    let chunk: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return outcome,
    };
    trace!("chat_completions received SSE chunk: {chunk:?}");

    let Some(choice) = chunk.get("choices").and_then(|c| c.get(0)) else {
        return outcome;
    };

    if let Some(content) = choice
        .get("delta")
        .and_then(|d| d.get("content"))
        .and_then(|c| c.as_str())
        && !content.is_empty()
    {
        state.assistant_text.push_str(content);
        outcome
            .events
            .push(ResponseEvent::OutputTextDelta(content.to_string()));
    }

    if let Some(reasoning_val) = choice.get("delta").and_then(|d| d.get("reasoning")) {
        let mut maybe_text = reasoning_val
            .as_str()
            .map(str::to_string)
            .filter(|s| !s.is_empty());

        if maybe_text.is_none() && reasoning_val.is_object() {
            if let Some(s) = reasoning_val
                .get("text")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
            {
                maybe_text = Some(s.to_string());
            } else if let Some(s) = reasoning_val
                .get("content")
                .and_then(|t| t.as_str())
                .filter(|s| !s.is_empty())
            {
                maybe_text = Some(s.to_string());
            }
        }

        if let Some(reasoning) = maybe_text {
            state.reasoning_text.push_str(&reasoning);
            outcome
                .events
                .push(ResponseEvent::ReasoningContentDelta(reasoning));
        }
    }

    if let Some(message_reasoning) = choice.get("message").and_then(|m| m.get("reasoning")) {
        if let Some(s) = message_reasoning.as_str() {
            if !s.is_empty() {
                state.reasoning_text.push_str(s);
                outcome
                    .events
                    .push(ResponseEvent::ReasoningContentDelta(s.to_string()));
            }
        } else if let Some(obj) = message_reasoning.as_object()
            && let Some(s) = obj
                .get("text")
                .and_then(|t| t.as_str())
                .or_else(|| obj.get("content").and_then(|t| t.as_str()))
                .filter(|s| !s.is_empty())
        {
            state.reasoning_text.push_str(s);
            outcome
                .events
                .push(ResponseEvent::ReasoningContentDelta(s.to_string()));
        }
    }

    if let Some(tool_calls) = choice
        .get("delta")
        .and_then(|d| d.get("tool_calls"))
        .and_then(|tc| tc.as_array())
        && let Some(tool_call) = tool_calls.first()
    {
        state.fn_call.active = true;

        if let Some(id) = tool_call.get("id").and_then(|v| v.as_str()) {
            state.fn_call.call_id.get_or_insert_with(|| id.to_string());
        }

        if let Some(function) = tool_call.get("function") {
            if let Some(name) = function.get("name").and_then(|n| n.as_str()) {
                state.fn_call.name.get_or_insert_with(|| name.to_string());
            }

            if let Some(args_fragment) = function.get("arguments").and_then(|a| a.as_str()) {
                state.fn_call.arguments.push_str(args_fragment);
            }
        }
    }

    if let Some(finish_reason) = choice.get("finish_reason").and_then(|v| v.as_str()) {
        match finish_reason {
            "tool_calls" if state.fn_call.active => {
                if !state.reasoning_text.is_empty() {
                    let item = ResponseItem::Reasoning {
                        id: String::new(),
                        summary: Vec::new(),
                        content: Some(vec![ReasoningItemContent::ReasoningText {
                            text: std::mem::take(&mut state.reasoning_text),
                        }]),
                        encrypted_content: None,
                    };
                    outcome.events.push(ResponseEvent::OutputItemDone(item));
                }

                let item = ResponseItem::FunctionCall {
                    id: None,
                    name: state.fn_call.name.clone().unwrap_or_default(),
                    arguments: state.fn_call.arguments.clone(),
                    call_id: state.fn_call.call_id.clone().unwrap_or_default(),
                };
                outcome.events.push(ResponseEvent::OutputItemDone(item));
            }
            "stop" => {
                if !state.reasoning_text.is_empty() {
                    let item = ResponseItem::Reasoning {
                        id: String::new(),
                        summary: Vec::new(),
                        content: Some(vec![ReasoningItemContent::ReasoningText {
                            text: std::mem::take(&mut state.reasoning_text),
                        }]),
                        encrypted_content: None,
                    };
                    outcome.events.push(ResponseEvent::OutputItemDone(item));
                }
                if !state.assistant_text.is_empty() {
                    let item = ResponseItem::Message {
                        role: "assistant".to_string(),
                        content: vec![ContentItem::OutputText {
                            text: std::mem::take(&mut state.assistant_text),
                        }],
                        id: None,
                    };
                    outcome.events.push(ResponseEvent::OutputItemDone(item));
                }
            }
            _ => {}
        }

        outcome.events.push(ResponseEvent::Completed {
            response_id: String::new(),
            token_usage: None,
        });
        outcome.completed = true;
        state.fn_call = FunctionCallState::default();
    }

    outcome
}

async fn emit_ratelimit_snapshot(
    headers: &HeaderMap,
    tx: &mut mpsc::Sender<Result<ResponseEvent>>,
) {
    if let Some(snapshot) = parse_rate_limit_snapshot(headers) {
        let _ = tx.send(Ok(ResponseEvent::RateLimits(snapshot))).await;
    }
}

async fn finalize_decoder(
    state: &mut DecoderState,
    tx: &mut mpsc::Sender<Result<ResponseEvent>>,
    otel: &OtelEventManager,
) -> FinalizeResult {
    match state {
        DecoderState::Responses(inner) => finalize_responses_state(inner, tx, otel).await,
        DecoderState::Chat(inner) => finalize_chat_state(inner, tx).await,
    }
}

async fn finalize_responses_state(
    state: &mut ResponsesDecoderState,
    tx: &mut mpsc::Sender<Result<ResponseEvent>>,
    otel: &OtelEventManager,
) -> FinalizeResult {
    if let Some(completed) = state.completed.take() {
        if let Some(usage) = &completed.usage {
            otel.sse_event_completed(
                usage.input_tokens,
                usage.output_tokens,
                usage.input_tokens_details.as_ref().map(|d| d.cached_tokens),
                usage
                    .output_tokens_details
                    .as_ref()
                    .map(|d| d.reasoning_tokens),
                usage.total_tokens,
            );
        }

        let event = ResponseEvent::Completed {
            response_id: completed.id,
            token_usage: completed.usage.map(Into::into),
        };
        let _ = tx.send(Ok(event)).await;

        return FinalizeResult {
            completed_emitted: true,
            error_emitted: false,
        };
    }

    if let Some(error) = state.error.take() {
        otel.see_event_completed_failed(&error);
        let _ = tx.send(Err(error)).await;
        return FinalizeResult {
            completed_emitted: false,
            error_emitted: true,
        };
    }

    FinalizeResult {
        completed_emitted: false,
        error_emitted: false,
    }
}

async fn finalize_chat_state(
    state: &mut ChatDecoderState,
    tx: &mut mpsc::Sender<Result<ResponseEvent>>,
) -> FinalizeResult {
    if !state.assistant_text.is_empty() {
        let item = ResponseItem::Message {
            role: "assistant".to_string(),
            content: vec![ContentItem::OutputText {
                text: std::mem::take(&mut state.assistant_text),
            }],
            id: None,
        };
        let _ = tx.send(Ok(ResponseEvent::OutputItemDone(item))).await;
    }

    if !state.reasoning_text.is_empty() {
        let item = ResponseItem::Reasoning {
            id: String::new(),
            summary: Vec::new(),
            content: Some(vec![ReasoningItemContent::ReasoningText {
                text: std::mem::take(&mut state.reasoning_text),
            }]),
            encrypted_content: None,
        };
        let _ = tx.send(Ok(ResponseEvent::OutputItemDone(item))).await;
    }

    FinalizeResult {
        completed_emitted: false,
        error_emitted: false,
    }
}

async fn forward_event(event: ResponseEvent, tx: &mut mpsc::Sender<Result<ResponseEvent>>) -> bool {
    tx.send(Ok(event)).await.is_err()
}

async fn forward_err(err: CodexErr, tx: &mut mpsc::Sender<Result<ResponseEvent>>) {
    let _ = tx.send(Err(err)).await;
}

fn attach_item_ids(payload_json: &mut Value, original_items: &[ResponseItem]) {
    let Some(input_value) = payload_json.get_mut("input") else {
        return;
    };
    let Value::Array(items) = input_value else {
        return;
    };

    for (value, item) in items.iter_mut().zip(original_items.iter()) {
        if let ResponseItem::Reasoning { id, .. }
        | ResponseItem::Message { id: Some(id), .. }
        | ResponseItem::WebSearchCall { id: Some(id), .. }
        | ResponseItem::FunctionCall { id: Some(id), .. }
        | ResponseItem::LocalShellCall { id: Some(id), .. }
        | ResponseItem::CustomToolCall { id: Some(id), .. } = item
        {
            if id.is_empty() {
                continue;
            }

            if let Some(obj) = value.as_object_mut() {
                obj.insert("id".to_string(), Value::String(id.clone()));
            }
        }
    }
}

fn parse_rate_limit_snapshot(headers: &HeaderMap) -> Option<RateLimitSnapshot> {
    let primary = parse_rate_limit_window(
        headers,
        "x-codex-primary-used-percent",
        "x-codex-primary-window-minutes",
        "x-codex-primary-reset-after-seconds",
    );

    let secondary = parse_rate_limit_window(
        headers,
        "x-codex-secondary-used-percent",
        "x-codex-secondary-window-minutes",
        "x-codex-secondary-reset-after-seconds",
    );

    Some(RateLimitSnapshot { primary, secondary })
}

fn parse_rate_limit_window(
    headers: &HeaderMap,
    used_percent_header: &str,
    window_minutes_header: &str,
    resets_header: &str,
) -> Option<RateLimitWindow> {
    let used_percent: Option<f64> = parse_header_f64(headers, used_percent_header);

    used_percent.and_then(|used_percent| {
        let window_minutes = parse_header_u64(headers, window_minutes_header);
        let resets_in_seconds = parse_header_u64(headers, resets_header);

        let has_data = used_percent != 0.0
            || window_minutes.is_some_and(|minutes| minutes != 0)
            || resets_in_seconds.is_some_and(|seconds| seconds != 0);

        has_data.then_some(RateLimitWindow {
            used_percent,
            window_minutes,
            resets_in_seconds,
        })
    })
}

fn parse_header_f64(headers: &HeaderMap, name: &str) -> Option<f64> {
    parse_header_str(headers, name)?
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
}

fn parse_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    parse_header_str(headers, name)?.parse::<u64>().ok()
}

fn parse_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn rate_limit_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();

    #[expect(clippy::unwrap_used)]
    RE.get_or_init(|| Regex::new(r"Please try again in (\d+(?:\.\d+)?)(s|ms)").unwrap())
}

fn try_parse_retry_after(err: &Error) -> Option<Duration> {
    if err.code != Some("rate_limit_exceeded".to_string()) {
        return None;
    }

    let re = rate_limit_regex();
    if let Some(message) = &err.message
        && let Some(captures) = re.captures(message)
    {
        let seconds = captures.get(1);
        let unit = captures.get(2);

        if let (Some(value), Some(unit)) = (seconds, unit) {
            let value = value.as_str().parse::<f64>().ok()?;
            let unit = unit.as_str();

            if unit == "s" {
                return Some(Duration::from_secs_f64(value));
            } else if unit == "ms" {
                return Some(Duration::from_millis(value as u64));
            }
        }
    }
    None
}

fn is_context_window_error(error: &Error) -> bool {
    error.code.as_deref() == Some("context_length_exceeded")
}

pub type ModelClient = Client;

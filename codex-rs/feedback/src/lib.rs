use std::collections::VecDeque;
use std::fs;
use std::io::{self};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use codex_protocol::ConversationId;
use sentry::protocol::ItemContainer;
use sentry::protocol::Log;
use sentry::protocol::SpanId;
use sentry::protocol::TraceContext;
use sentry::protocol::TraceId;
use sentry_tracing::log_from_event;
use tracing::Event;
use tracing::Subscriber;

use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

const DEFAULT_MAX_MESSAGES: usize = 300;
const SENTRY_DSN: &str =
    "https://ae32ed50620d7a7792c1ce5df38b3e3e@o33249.ingest.us.sentry.io/4510195390611458";
const UPLOAD_TIMEOUT_SECS: u64 = 10;

#[derive(Clone)]
pub struct CodexFeedback {
    inner: Arc<FeedbackInner>,
}

impl Default for CodexFeedback {
    fn default() -> Self {
        Self::new()
    }
}

impl CodexFeedback {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_MESSAGES)
    }

    pub(crate) fn with_capacity(max_messages: usize) -> Self {
        Self {
            inner: Arc::new(FeedbackInner::new(max_messages)),
        }
    }

    pub fn make_layer(&self) -> FeedbackLayer {
        FeedbackLayer {
            inner: self.inner.clone(),
        }
    }

    pub fn snapshot(&self, session_id: Option<ConversationId>) -> CodexLogSnapshot {
        let logs = {
            let guard = self.inner.messages.lock().expect("mutex poisoned");
            guard.clone()
        };
        CodexLogSnapshot {
            logs,
            thread_id: session_id
                .map(|id| id.to_string())
                .unwrap_or("no-active-thread-".to_string() + &ConversationId::new().to_string()),
        }
    }
}

struct FeedbackInner {
    messages: Mutex<VecDeque<Log>>,
}

impl FeedbackInner {
    fn new(max_messages: usize) -> Self {
        Self {
            messages: Mutex::new(VecDeque::with_capacity(max_messages)),
        }
    }

    fn add_message(&self, message: Log) {
        let mut guard = self.messages.lock().expect("mutex poisoned");
        guard.push_back(message);
    }
}

pub struct FeedbackLayer {
    inner: Arc<FeedbackInner>,
}

impl<S> Layer<S> for FeedbackLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event, ctx: Context<'_, S>) {
        let log = log_from_event(event, Some(&ctx));
        self.inner.add_message(log);
    }
}

pub struct CodexLogSnapshot {
    logs: VecDeque<Log>,
    pub thread_id: String,
}

impl CodexLogSnapshot {
    pub fn save_to_temp_file(&self) -> io::Result<PathBuf> {
        let dir = std::env::temp_dir();
        let filename = format!("codex-feedback-{}.log", self.thread_id);
        let path = dir.join(filename);
        let messages_text = self
            .logs
            .iter()
            .filter_map(|message| serde_json::to_string(&message).ok())
            .collect::<Vec<String>>()
            .join("\n");
        fs::write(&path, messages_text)?;
        Ok(path)
    }

    /// Upload feedback to Sentry with optional attachments.
    pub fn upload_feedback(
        &mut self,
        classification: &str,
        reason: Option<&str>,
        cli_version: &str,
        include_logs: bool,
        rollout_path: Option<&std::path::Path>,
    ) -> Result<()> {
        use std::collections::BTreeMap;
        use std::fs;
        use std::str::FromStr;
        use std::sync::Arc;

        use sentry::Client;
        use sentry::ClientOptions;
        use sentry::protocol::Attachment;
        use sentry::protocol::Envelope;
        use sentry::protocol::EnvelopeItem;
        use sentry::protocol::Event;
        use sentry::protocol::Level;
        use sentry::transports::DefaultTransportFactory;
        use sentry::types::Dsn;

        // Build Sentry client
        let client = Client::from_config(ClientOptions {
            dsn: Some(Dsn::from_str(SENTRY_DSN).map_err(|e| anyhow!("invalid DSN: {e}"))?),
            transport: Some(Arc::new(DefaultTransportFactory {})),
            ..Default::default()
        });

        let mut tags = BTreeMap::from([
            (String::from("thread_id"), self.thread_id.to_string()),
            (String::from("classification"), classification.to_string()),
            (String::from("cli_version"), cli_version.to_string()),
        ]);
        if let Some(r) = reason {
            tags.insert(String::from("reason"), r.to_string());
        }

        let level = match classification {
            "bug" | "bad_result" => Level::Error,
            _ => Level::Info,
        };

        let title = format!(
            "[{}]: Codex session {}",
            display_classification(classification),
            self.thread_id
        );

        let mut event = Event {
            level,
            message: Some(title.clone()),
            tags,
            ..Default::default()
        };

        if let Some(r) = reason {
            use sentry::protocol::Exception;
            use sentry::protocol::Values;

            event.exception = Values::from(vec![Exception {
                ty: title.clone(),
                value: Some(r.to_string()),
                ..Default::default()
            }]);
        }

        let trace_id = TraceId::default();
        let trace_context = TraceContext {
            span_id: SpanId::default(),
            trace_id,
            ..Default::default()
        };

        let mut envelope = Envelope::new();
        event.contexts.insert(
            "trace".to_string(),
            sentry::protocol::Context::Trace(Box::new(trace_context)),
        );

        for log in self.logs.iter_mut() {
            log.trace_id = Some(trace_id);
        }

        if let Some((path, data)) = rollout_path.and_then(|p| fs::read(p).ok().map(|d| (p, d))) {
            let fname = path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "rollout.jsonl".to_string());
            let content_type = "text/plain".to_string();
            envelope.add_item(EnvelopeItem::Attachment(Attachment {
                buffer: data,
                filename: fname,
                content_type: Some(content_type),
                ty: None,
            }));
        }

        client.send_envelope(envelope);

        if include_logs {
            let mut log_envelope = Envelope::new();
            log_envelope.add_item(EnvelopeItem::ItemContainer(ItemContainer::Logs(
                self.logs.iter().cloned().collect(),
            )));
            client.send_envelope(log_envelope);
        }

        client.flush(Some(Duration::from_secs(UPLOAD_TIMEOUT_SECS)));
        Ok(())
    }
}

fn display_classification(classification: &str) -> String {
    match classification {
        "bug" => "Bug".to_string(),
        "bad_result" => "Bad result".to_string(),
        "good_result" => "Good result".to_string(),
        _ => "Other".to_string(),
    }
}

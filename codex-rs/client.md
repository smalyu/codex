# Codex Client: Minimal, Unified, Boring

Keep the client simple: one public type, one builder, one streaming path. Hide wire-protocol differences and keep tests lightweight without introducing extra indirection.

## Small Public Surface

```rust
pub struct Client { /* config + provider + reqwest + otel */ }

#[derive(Copy, Clone)]
pub enum StreamMode { Aggregated, Streaming }

#[derive(Default, Clone)]
pub struct CallOpts {
    pub stream_mode: StreamMode,
    // Optional overrides; use only what you need.
    pub conversation_id: Option<ConversationId>,
    pub provider_hint: Option<WireDialect>,
    pub effort: Option<ReasoningEffort>,
    pub summary: Option<ReasoningSummary>,
    pub output_schema: Option<serde_json::Value>,
    pub show_raw_reasoning: Option<bool>,
}

impl Client {
    pub fn builder() -> ClientBuilder; // one way in
    pub async fn stream(&self, p: &Prompt, o: impl Into<CallOpts>) -> TurnStream; // one way out
    pub async fn complete(&self, p: &Prompt, o: impl Into<CallOpts>) -> TurnResult; // optional drain helper
}
```

- Callers always consume `ResponseEvent` regardless of wire dialect.
- `CallOpts` carries per-call knobs so a single `Client` instance can be reused safely.

## Single Module

All logic lives in `core/src/client.rs` (or a `mod client` folder). There are only two internal decisions: how to build the request and how to decode each SSE line.

```rust
enum WireDialect { Responses, Chat }

struct Client {
    cfg: Arc<Config>,
    provider: Arc<ModelProviderInfo>,
    auth: Option<Arc<AuthManager>>,
    http: reqwest::Client,
    otel: OtelEventManager,
    defaults: CallOpts,
}
```

No public traits and no executor indirection. Tests use in-memory streams to exercise the SSE loop deterministically.

## Two Small Helpers

```rust
fn build_request(&self, prompt: &Prompt, call: &ResolvedCall) -> reqwest::Request {
    match self.resolve_dialect(call.provider_hint) {
        WireDialect::Responses => self.build_responses_request(prompt, call),
        WireDialect::Chat => self.build_chat_request(prompt, call),
    }
}

fn decode_sse_line(
    dialect: WireDialect,
    line: &str,
    mut emit: impl FnMut(ResponseEvent),
) {
    match dialect {
        WireDialect::Responses => decode_responses_line(line, &mut emit),
        WireDialect::Chat => decode_chat_line(line, &mut emit),
    }
}
```

- Each branch is local and short; no cross-module plumbing.
- Azure-specific behavior (Responses: `store: true`, preserve item ids) lives only in `build_responses_request()`.
- Chat limitation (`output_schema` unsupported) is validated once in `build_chat_request()`.

## One Unified SSE Loop

```rust
async fn run_sse(
    &self,
    dialect: WireDialect,
    resp: reqwest::Response,
    call: &ResolvedCall,
) -> TurnStream {
    let (tx, rx) = mpsc::channel::<Result<ResponseEvent>>(1024);
    let idle = self.provider.stream_idle_timeout();
    let otel = self.otel.clone();

    tokio::spawn(async move {
        let mut es = resp.bytes_stream().map_err(CodexErr::Reqwest).eventsource();
        let mut buffer = LineDecoder::default();
        let mut saw_completed = false;

        emit_ratelimit_snapshot(&resp, &tx, &otel);

        loop {
            let event = match next_event_with_timeout(&mut es, idle).await {
                Some(ev) => ev,
                None => break,
            };

            match event {
                Err(err) => { forward_err(err, &tx, &otel); break; }
                Ok(message) if message.event == "message" => {
                    if let Err(err) = buffer.decode(&message.data, |line| {
                        decode_sse_line(dialect, line, |ev| {
                            saw_completed |= matches!(ev, ResponseEvent::Completed { .. });
                            forward_event(ev, &tx, &otel, call)
                        })
                    }) {
                        forward_err(err, &tx, &otel);
                        break;
                    }
                }
                _ => continue,
            }

            if tx.is_closed() { break; }
        }

        // Close semantics: preserve partials and surface protocol errors.
        if !saw_completed {
            if matches!(dialect, WireDialect::Responses) {
                forward_err("stream closed before response.completed", &tx, &otel);
            }
            let _ = forward_event(ResponseEvent::Completed { response_id: String::new(), token_usage: None }, &tx, &otel, call);
        }
    });

    TurnStream { rx, dialect }
}
```

- One loop for both dialects; only the tiny `decode_sse_line()` differs.
- Enforces idle timeouts, respects backpressure, and reports decode issues as `Err`.
- Responses requires a terminal `response.completed`. If missing, we emit an error and still emit `Completed` so `complete()` can return partials plus the error. Chat already terminates with `[DONE]` and we synthesize `Completed` if needed.

## Aggregation, Kept Simple

Use the existing `AggregateStreamExt` and let `Client` apply it per-call:

```rust
pub async fn stream(&self, p: &Prompt, opts: impl Into<CallOpts>) -> Result<TurnStream> {
    let call = ResolvedCall::new(&self.defaults, opts.into());
    let req = self.build_request(p, &call);
    let resp = self.otel.log_request(0, || self.http.execute(req)).await?;
    ensure_success_or_map_errors(&resp, self.provider.is_azure_responses_endpoint(), &self.auth)?;
    let dialect = self.resolve_dialect(call.provider_hint);
    let stream = self.run_sse(dialect, resp, &call).await;
    Ok(match call.stream_mode { StreamMode::Aggregated => stream.aggregate(), StreamMode::Streaming => stream })
}
```

`complete()` drains `stream()` and returns the final turn result while surfacing the first error that occurred (if any) alongside whatever was already collected.

## Errors (One Outward Type)

Expose a single outward `Error` (alias to `CodexErr`). Map non-2xx responses in one spot (`ensure_success_or_map_errors`), and keep rate-limit extraction/status handling here so the SSE loop remains minimal.

## Dialect Selection (Explicit by Default)

```rust
fn resolve_dialect(&self, hint: Option<WireDialect>) -> WireDialect {
    if let Some(h) = hint { return h; }
    match self.provider.wire_api { WireApi::Responses => WireDialect::Responses, WireApi::Chat => WireDialect::Chat }
}
```

- Prefer explicit configuration via `ModelProviderInfo.wire_api`.
- Optional: add `builder.enable_auto_probe()` that performs one optimistic Responses attempt, falls back to Chat on 404/405, and caches the result in a per-client `OnceLock` keyed by base URL (+ auth mode). Keep this off by default to avoid surprises.

## Observability (Two Places)

- Wrap the HTTP send path with `otel.log_request`.
- Inside the SSE loop, emit one telemetry event per decoded SSE message (and any reconnects if added later).

## Testing (No Extra Indirection)

- Keep tests using in-memory readers (e.g., `ReaderStream`) to feed the unified SSE loop.
- This avoids introducing a public or private executor trait solely for testing.

## Migration (Straightforward)

1. Move the existing Responses/Chat request builders into `build_responses_request` / `build_chat_request`.
2. Inline two line decoders from the current SSE processors into `decode_responses_line` / `decode_chat_line`.
3. Replace the two SSE loops with the unified loop; keep aggregation via `AggregateStreamExt`.
4. Update `ModelClient::stream` to delegate to the new `Client` (or keep it as the concrete type and collapse duplication), preserving the public API.
5. Remove dead helpers after tests pass.

## Why This Is Simpler

- One public type, one entry, one streaming loop.
- Per-call options instead of per-client mutability.
- Explicit dialect selection; auto-probe is optional and scoped.
- No executor trait or public test seams; tests stay fast with in-memory streams.
- Clear error semantics: preserve partials and surface protocol issues.

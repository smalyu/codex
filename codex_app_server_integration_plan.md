# Codex App-Server Integration Plan (Rust Learning Track)

## Goals

- Practice Rust fundamentals through a concrete, asynchronous systems project.
- Understand the Codex JSON-RPC contract (`codex-rs/protocol/src/mcp_protocol.rs` and `protocol/src/protocol.rs`).
- Build confidence with tooling (`tokio`, `serde`, `clap`, `tracing`, `ratatui`).

## Project Ideas

1. **Minimal MCP Client**
   - Spawn `codex-app-server` with `tokio::process::Command` and manage stdio streams.
   - Implement JSON-RPC handshake (`initialize`, `newConversation`).
   - Send `addConversationListener` to receive `codex/event/*` notifications.

2. **Protocol Bindings Crate**
   - Re-export the schema types from Codex or mirror them in a new crate.
   - Derive `serde` traits and optionally generate TypeScript definitions with `ts_rs`.
   - Provide helper builders for common requests.

3. **Event Reactor**
   - Write an async dispatcher that matches notification `method` values.
   - Map `params.msg.type` to enums and forward them to handlers.
   - Demonstrate logging of plan updates, approvals, and tool call progress.

4. **CLI Wrapper**
   - Build a `clap`-based CLI: `new`, `send`, `interrupt`, `status`.
   - Manage Request IDs, handle JSON-RPC errors, serialize inputs with `serde_json`.
   - Support piping stdin into user messages.

5. **Tracing & Diagnostics**
   - Instrument the client with `tracing` spans around requests and responses.
   - Emit structured logs for event handling and error paths.
   - Optionally integrate with `tracing-subscriber` for pretty output or JSON logs.

6. **TUI Conversation Viewer**
   - Use `ratatui` to render conversation history, plan updates, and approvals.
   - Represent `PlanUpdate` events as checklists and reasoning deltas as streaming text.
   - Explore async UI patterns using `tokio` + `crossterm`.

7. **Diff & Approval UX**
   - Parse `applyPatchApproval` payloads and render diffs with crates like `dissimilar` or `similar`.
   - Provide approve/deny keybindings and feed decisions back via JSON-RPC.

8. **Custom MCP Tool Prototype**
   - Implement a Rust tool service that Codex can call (mirroring the plan tool pattern).
   - Showcase serde-based argument parsing and structured responses.

## Learning Outcomes

- Async process management, buffered IO, and JSON serialization in Rust.
- Familiarity with Codex’s turn lifecycle, event taxonomy, and approval flows.
- Experience building CLI/TUI applications and instrumenting them for observability.

## Next Steps

- Set up a dedicated Rust workspace with integration tests that launch `codex-app-server` in-process.
- Prioritize Project 1 to establish the transport loop, then layer on additional ideas as separate modules or binaries.


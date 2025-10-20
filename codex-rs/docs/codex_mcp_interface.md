# Codex MCP Server Interface [experimental]

This document describes Codex’s experimental MCP server interface: a JSON‑RPC API that runs over the Model Context Protocol (MCP) transport to control a local Codex engine.

- Status: experimental and subject to change without notice
- Server binary: `codex mcp-server` (or `codex-mcp-server`)
- Transport: standard MCP over stdio (JSON‑RPC 2.0, line‑delimited)

## Overview

Codex now surfaces its functionality through standard MCP `tools/call` requests. A `tools/list` request returns the `codex` tool, which starts a session, and the `codex-reply` tool, which continues an existing session. The JSON schemas backing both tools are generated in `codex-rs/mcp-server/src/codex_tool_config.rs`. Codex continues to reuse the shared event types defined in `codex-rs/protocol/src/protocol.rs`. For clients that still speak the legacy JSON‑RPC API, its protocol definitions live in `codex-rs/app-server-protocol/src/protocol.rs`.

## Starting the server

Run Codex as an MCP server and connect an MCP client:

```bash
codex mcp-server | your_mcp_client
```

For a simple inspection UI, you can also try:

```bash
npx @modelcontextprotocol/inspector codex mcp-server
```

Use the separate `codex mcp` subcommand to manage configured MCP server launchers in `config.toml`.

## Codex tools

Send `tools/list` to discover the available tools:

- `codex`: starts a new Codex session. The request `arguments` accept the fields surfaced by `CodexToolCallParam`, including the required `prompt` plus optional `model`, `profile`, `cwd`, `approval-policy`, `sandbox`, `config`, `base-instructions`, and `include-plan-tool` overrides. When the tool call finishes, the server resolves the `tools/call` request with the model’s final message in the response `content`.
- `codex-reply`: continues an existing session. The request `arguments` must include `conversationId` and `prompt`, matching the `CodexToolCallReplyParam` schema. Use the `conversationId` returned in earlier events to correlate with the active session.

Both tools run asynchronously. While a tool call is in flight, Codex streams progress via MCP notifications so the client can render intermediate output or handle approvals.

## Event stream

While a conversation runs, the server sends JSON‑RPC notifications whose `method` is `codex/event`. The payload embeds the serialized `Event`/`EventMsg` structures from `codex-rs/protocol/src/protocol.rs`. Notifications include `_meta.requestId` so clients can associate each event with the originating `tools/call`.

## Approvals (server → client)

When Codex needs approval to apply a patch or run a command, it issues an MCP elicitation request (`ElicitRequest`). Patch prompts carry `PatchApprovalElicitRequestParams` and command prompts use `ExecApprovalElicitRequestParams`. Respond with JSON that includes a `decision` field whose value is one of the `ReviewDecision` strings: `approved`, `approved_for_session`, `denied`, or `abort`. These map directly to the enum defined in `codex-rs/protocol/src/protocol.rs` and determine whether Codex proceeds, auto‑approves similar actions for the current session, or halts work.

## Example workflow

Start a session with the `codex` tool:

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "codex", "arguments": { "prompt": "List the files in this repo.", "approval-policy": "on-request", "sandbox": "workspace-write" } } }
```

The server streams `codex/event` notifications as the session runs. When the task completes, the `tools/call` response resolves with the final assistant message in its `content`. To keep going, call `codex-reply` with the returned `conversationId`:

```json
{ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "codex-reply", "arguments": { "conversationId": "c7b0…", "prompt": "Great, please open README.md." } } }
```

Any approval prompts during either call arrive as elicitation requests. Reply with the desired `ReviewDecision` to allow, deny, or pause execution.

## Compatibility and stability

This interface is experimental. Tool schemas, fields, and event shapes may evolve. For the authoritative definitions, consult `codex-rs/mcp-server/src/codex_tool_config.rs`, the shared event types in `codex-rs/protocol/src/protocol.rs`, and the legacy JSON‑RPC spec in `codex-rs/app-server-protocol/src/protocol.rs`.

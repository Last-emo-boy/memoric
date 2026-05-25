# Streamable HTTP Adapter Design

This design documents Memoric's Streamable HTTP adapter boundary without moving
protocol state into the current STDIO or worker loops. The current build
includes an in-process adapter model in `src/mcp/http_adapter.rs`; it does not
start a network listener.

## Current Transport Boundary

Current modes:

- STDIO: newline-delimited JSON-RPC over stdin/stdout.
- Worker bridge: named-pipe proxy for privileged tool calls and task ownership.
- Legacy server path: direct in-process JSON-RPC handler used by tests.
- Streamable HTTP adapter model: in-process POST/GET/DELETE routing used by
  tests and future listeners.

The shared MCP surface is already concentrated in:

- `src/mcp/protocol.rs`: initialize result and tool result envelopes.
- `src/mcp/tools.rs`: tool registration and dispatch facade.
- `src/mcp/resources.rs`: resource list/read helpers.
- `src/mcp/tasks.rs`: process-local task registry, polling, cancellation, and notifications.
- `src/mcp/server.rs`: reusable request handling patterns and conformance fixtures.
- `src/mcp/http_adapter.rs`: HTTP request/response model, Origin validation,
  protocol/session header extraction, mirrored header validation, optional
  2025-11-25 session state, SSE replay buffers, and dispatch into shared MCP
  helpers.

The Streamable HTTP adapter calls the same shared helpers. It does not fork tool
schemas, task state, policy checks, resource definitions, or result wrappers.

## Official Transport Constraints

The MCP Streamable HTTP transport uses JSON-RPC over a single HTTP endpoint.
The 2025-11-25 generation supports POST plus GET/SSE for streamed
server-to-client messages. The current draft moves toward stateless HTTP and no
longer requires protocol-level sessions. Memoric therefore supports two adapter
modes: draft-style stateless POST/DELETE handling and 2025-11-25-compatible
stateful session/SSE replay for compatibility tests.

Compatibility targets:

- The client sends `MCP-Protocol-Version` on HTTP requests after initialize.
- Stateful 2025-11-25-compatible HTTP sessions may use `Mcp-Session-Id`
  returned from initialize.
- Broken SSE streams may resume with `Last-Event-ID`.
- Servers must validate `Origin` for HTTP requests to reduce DNS rebinding risk.
- Local HTTP servers should bind to localhost by default.
- Clients may keep multiple SSE streams open; servers must not broadcast the
  same JSON-RPC message across streams.

The latest MCP draft is also moving toward less protocol-level session state.
Memoric should therefore isolate session headers in an adapter layer and keep
the core request context transport-neutral.

References:

- https://modelcontextprotocol.io/specification/draft/basic/transports
- https://modelcontextprotocol.io/legacy/concepts/transports
- https://modelcontextprotocol.io/seps/2575-stateless-mcp
- https://modelcontextprotocol.io/seps/2243-http-standardization

## Adapter Shape

The future adapter should have three layers:

1. HTTP ingress
2. transport-neutral MCP request context
3. existing MCP dispatch helpers

Implemented core shape:

```rust
pub struct McpRequestContext {
    pub transport: McpTransportKind,
    pub request_id: Option<serde_json::Value>,
    pub protocol_version: Option<String>,
    pub session_id: Option<String>,
    pub stream_id: Option<String>,
    pub last_event_id: Option<String>,
    pub progress_token: Option<serde_json::Value>,
    pub task_id: Option<String>,
    pub app_origin: Option<String>,
    pub policy_origin: PolicyOrigin,
    pub audit_correlation_id: Option<String>,
    pub redaction: RedactionProfile,
}
```

The core shape now lives in `src/mcp/request_context.rs`. `src/mcp/http_adapter.rs`
populates this context from request headers and JSON-RPC metadata before calling
the existing MCP dispatch helpers.

## Request Routing

Implemented POST `/mcp` behavior:

- Parse exactly one JSON-RPC request, notification, or response.
- Validate `MCP-Protocol-Version` when present.
- Validate mirrored MCP headers such as `Mcp-Method` and `Mcp-Name` before
  dispatch.
- For requests, route through the same method handlers as STDIO.
- For notifications, return HTTP 202 with no JSON-RPC body.
- For tool calls that become background tasks, return the same task-augmented
  response shape as STDIO.
- In stateful 2025-11-25-compatible mode, initialize without a session header
  mints an adapter-local `Mcp-Session-Id`; later requests must present it.

Implemented GET `/mcp` behavior in stateful compatibility mode:

- Open an SSE stream for server-to-client messages.
- If `Last-Event-ID` is supplied, resume only the stream represented by that
  event cursor.
- Never replay events that belonged to another stream.
- Replay buffers are bounded and redacted JSON-RPC notification envelopes are
  stored per adapter session. Future listener code can connect task
  notifications to these buffers.

Implemented DELETE `/mcp` behavior:

- If session management is active, terminate the HTTP session and detach any
  SSE streams.
- Do not cancel tasks automatically unless a separate task cancellation request
  is sent.
- Retained tasks continue to follow TTL/result-retention cleanup rules.

## Session State

Session state is transport-owned, not tool-owned.

HTTP session state may contain:

- negotiated protocol version
- client identity summary
- authenticated principal or local-only marker
- active SSE stream IDs
- event replay buffer cursors
- visibility scope for tasks/resources
- audit/app origin metadata

It must not contain:

- raw tool result payloads beyond bounded replay events
- raw memory bytes
- credentials or consent tokens after validation
- privileged worker pipe handles exposed to clients

Task records remain in `src/mcp/tasks.rs` and now carry visibility metadata
captured from `McpRequestContext`. Local single-user transports keep the
backward-compatible full process-local task view, while remote/app contexts
scope `tasks/list` by matching session ID or app origin so unrelated session
tasks are not listed.

## Event Replay

Replay support is bounded:

- Assign monotonic event IDs per adapter session and stream.
- Store only JSON-RPC notification envelopes already suitable for client
  delivery.
- Keep a byte and count limit per session.
- Expire replay buffers independently from task result retention.
- If a requested `Last-Event-ID` is no longer available, return a clean resume
  failure and require fresh polling rather than guessing.

Task polling remains the required fallback. `tasks/get` and `tasks/result` must
continue to work even when SSE is unavailable or unsupported by the host.

## Worker Bridge Compatibility

The HTTP adapter keeps the same ownership rule as STDIO:

- Non-elevated frontend handles initialize, lists, resources, tasks, ping, and
  request validation locally when possible.
- Privileged tool calls may be forwarded to the elevated worker.
- If the worker owns a background task, task polling/result/cancel routes to
  the worker just as STDIO does.
- Worker notifications must be converted into stream-aware SSE events by the
  HTTP frontend, not written directly to HTTP responses from worker code.

This preserves the named-pipe worker as a local privilege boundary and avoids
making the worker an HTTP server.

## Security Requirements

The in-process adapter already validates localhost-friendly `Origin` values and
allows explicitly configured origins in tests. Before enabling an HTTP listener:

- Bind localhost by default.
- Validate `Origin`.
- Require explicit opt-in for non-local bind addresses.
- Add authentication before any remote bind is allowed.
- Enforce request body size limits.
- Reuse current policy gates and redaction profiles.
- Keep protected-target overrides explicit per request.
- Record audit origin and transport kind for every tool call.

Remote access must not downgrade the current local policy model.

## Implementation Status

Implemented:

- `StreamableHttpAdapter` in `src/mcp/http_adapter.rs`.
- Stateless draft mode and 2025-11-25-compatible stateful session mode.
- POST/GET/DELETE request routing without a network listener.
- `MCP-Protocol-Version`, optional `Mcp-Session-Id`, `Mcp-Stream-Id`,
  `Last-Event-ID`, `Mcp-Method`, `Mcp-Name`, and `Origin` validation.
- Stream-scoped SSE replay buffers with bounded retention.
- Shared core and adversarial conformance fixture coverage for the HTTP adapter.

Still intentionally not enabled:

- A listening HTTP server socket.
- Authentication and remote bind support.
- Worker notification fan-out into live SSE streams.

## Acceptance Boundary

The HTTP design/adapter boundary is complete when the architecture documents and
tests:

- which state belongs to transport, task registry, worker, and tool handlers
- how Streamable HTTP POST/GET/DELETE map to existing MCP helpers
- how session IDs, protocol version headers, and `Last-Event-ID` stay adapter
  local
- how worker forwarding and task polling remain compatible
- which security gates are mandatory before enabling HTTP

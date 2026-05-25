# Memoric Compatibility Matrix

Last reviewed: 2026-05-23

This matrix is the operator-facing compatibility view for Memoric. It records what the current build advertises, what is implemented, and which newer MCP or platform features are still planned.

## MCP Protocol

| Area | Status | Notes |
| --- | --- | --- |
| Advertised protocol version | Implemented | `initialize` advertises MCP `2025-11-25` through `src/mcp/protocol.rs`. |
| Initialize consistency | Implemented | STDIO, worker, and legacy server paths use the same package version and capability shape. |
| Static server manifest | Implemented | `docs/server-manifest.json` is generated from runtime `initialize`, `tools/list`, `resources/list`, and package metadata. Tests compare protocol version, capabilities, resources, docs links, and tool-catalog hash against runtime surfaces. |
| Streamable HTTP adapter | Implemented boundary | `src/mcp/http_adapter.rs` provides an in-process Streamable HTTP adapter for POST/GET/DELETE, `MCP-Protocol-Version`, optional 2025-11-25 `Mcp-Session-Id`, SSE replay scoped by stream ID and `Last-Event-ID`, mirrored-header validation, Origin checks, and request-context hydration. No HTTP listener is enabled in the current binary. |
| Transport-neutral request context | Implemented | `src/mcp/request_context.rs` parses request ID, protocol/session/stream metadata, progress token, task ID, app origin, policy origin, audit correlation ID, and redaction profile without coupling those fields to STDIO, worker, or future HTTP code. |
| JSON-RPC base errors | Implemented | Parse, invalid request, unknown method, invalid params, and internal handler errors use stable JSON-RPC codes. |
| Structured tool results | Implemented | Tool calls return both text `content` and `structuredContent` for clients that can consume machine-readable results. Tools with a related Apps resource also emit strict widget-only hydration in `_meta["io.memoric/widget-hydration"]`, keeping richer UI data out of the model-visible result. |
| Artifact resource links | Implemented | Existing file artifacts plus generated memory-read, scan-list, target dump, kernel dump, and orchestration plan/execute artifacts are exposed as expiring `memoric://artifact/sha256/<hash>` resources with SHA-256 verification, `resource_link` content blocks, and cleanup dry-run preview. |
| Result strategy metadata | Implemented | Successful tool envelopes expose `metadata.result_strategy` with inline, paginated, streamed-progress, or reference mode, cursor/resource-link counts, progress availability, and cancellation/timeout boundary hints. |
| Observability timeline | Implemented | `memoric://timeline` and `self(action='state', sub_action='timeline')` link MCP request, tool dispatch, task lifecycle/progress, audit, worker IPC, and artifact metadata by correlation ID while omitting raw results, progress tokens, raw memory, credentials, and full local paths. |
| Mutation and rollback state views | Implemented summary views | `self(action='state', sub_action='mutations'|'rollback')` reads audit `state_change` metadata and returns summary-only provenance, mutation, rollback, artifact, and integrity fields while omitting raw rollback bytes, raw memory, credentials, and full result payloads. |
| Operator diagnostics bundle | Implemented | `self(action='diagnostics')` exports an operator-safe JSON artifact with compatibility, policy hash/status, audit config, capability-diff watch list, catalog hashes, and recent task summaries without raw target data or full local paths. |
| Tool metadata annotations | Implemented | Tools expose MCP annotations, output schemas, action traits, display titles, icon hints, selection hints, and `execution.taskSupport="optional"`. Ergonomics lint keeps descriptions concise and model-safe without changing policy semantics. |
| `tools/list` pagination | Implemented | Calls without pagination params return the full list; calls with `limit`/`cursor` return bounded pages with opaque `nextCursor`. `initialize.capabilities.tools.listChanged` is currently `false`. |
| Tool result pagination | Implemented | `memory(action='scan_list', session_id=...)` and `orchestrate(action='plan'/'execute')` support bounded result pages with opaque `nextCursor` and snapshot validation. Scan-list pages support `limit`, `offset`, `sort`, and `summary_only`, with cursors bound to the selected sort mode. Large scan sessions, large memory reads, and oversized static orchestration plans use artifact links instead of oversized inline responses. |
| Prompts | Implemented | `prompts/list` and `prompts/get` are available in the legacy server path. |

## Tasks And Progress

| Area | Status | Notes |
| --- | --- | --- |
| Task-augmented `tools/call` | Implemented | `params.task` creates a background task for read-only actions and dry-run previews. Live state-changing calls enter `input_required` and wait for operator consent before the owning flow resumes. |
| Legacy `as_task` | Implemented | Kept for backward compatibility and mapped onto the same task registry. |
| `tasks/list` | Implemented | Supports bounded cursor pagination with opaque `nextCursor`; invalid cursors return JSON-RPC `-32602`. Local single-user requests see all process-local tasks; remote/app contexts are scoped by matching session ID or app origin. |
| `tasks/get` | Implemented | Returns the current task object, progress, created/updated timestamps, TTL, poll interval, expiry epoch, result-retention policy, retry metadata, summary, result, and error fields. |
| `tasks/result` | Implemented | Waits briefly for completion, returns the original wrapped tool result with related-task metadata for terminal tasks, and returns an input-required result immediately when a task is waiting for input. |
| `tasks/cancel` | Implemented | Rejects terminal tasks and marks active tasks `cancelled`; cancellation is cooperative at handler checkpoints. |
| `tasks/input_response` / `tasks/update` | Implemented | `tasks/input_response` binds a response to a pending input request, records the response, moves the task from `input_required` back to `working`, and resumes process-local consent continuations when present; `tasks/update` accepts `kind="input_response"` as a compatibility alias. |
| Task-augmented sampling readiness | Implemented | `initialize` explicitly marks `tasks.requests.sampling.createMessage.supported=false` and does not advertise a top-level sampling capability. Future sampling support must reuse the existing task registry, visibility scope, TTL, cancellation, and result-retention contract. |
| Task lifecycle guards | Implemented | Status transitions are centralized; terminal `completed`, `failed`, and `cancelled` tasks cannot be reopened or overwritten by late worker updates. |
| Task TTL and retention cleanup | Implemented | Non-terminal tasks whose TTL elapsed become failed `task_expired` records with progress tokens cleared; terminal task results are removed after `resultRetentionMs`. Retry count/max metadata is exposed, but automatic retry execution is not enabled. |
| `notifications/progress` | Implemented | Progress tokens are parsed, progress notifications are emitted for opted-in handlers, and high-frequency progress is rate-limited per task while completion can still send final progress. |
| `notifications/tasks/status` | Implemented | Status transitions emit the full task state. Polling remains the required fallback for clients that ignore notifications. |
| `input_required` / input response | Implemented | Task records carry `inputRequests`, `inputResponses`, and `requestState`; `tasks/result` exposes input-required metadata, and response submission is routed across legacy, STDIO, and worker paths. Policy-gated state-changing `params.task` calls now automatically pause as `input_required` and resume or fail from the bound input response. |
| Task persistence | Implemented metadata snapshots | Default mode is process-local. If `MEMORIC_TASKS_PATH` is configured, non-sensitive task metadata snapshots survive restart, including status/timestamps/summaries/progress counters, TTL/result-retention/retry policy metadata, artifact references, visibility, and integrity hashes. Raw results, progress tokens, raw bytes, shellcode, and credentials are not persisted; previously live tasks reload as failed `task_not_resumable` records because chain execution resume is separate work. |
| Orchestration chain checkpoints | Implemented metadata snapshots | If `MEMORIC_CHAIN_STATE_PATH` is configured, live orchestration execution persists metadata-only chain progress with `last_completed_step`, `next_step`, safe argument/result summaries, and rollback summaries. `orchestrate` supports status/resume-preview/cancel/cleanup by `chain_id`; actual resume requires replaying the original authorized execute request with matching plan fingerprint and skipped completed steps. |

## Resources

| Resource | Status | Notes |
| --- | --- | --- |
| `memoric://status` | Implemented | Basic server status and capability summary. |
| `memoric://capabilities` | Implemented | Capability matrix for platform, policy, audit, driver readiness, and related environment probes. |
| `memoric://policy` | Implemented | Current policy configuration, active policy profile identity, verification status, and enforcement context. |
| `memoric://tasks` | Implemented | Current task registry plus persistence configuration status when `MEMORIC_TASKS_PATH` is set. |
| `memoric://audit/recent` | Implemented | Recent audit entries when audit logging is configured. |
| `memoric://artifacts` | Implemented | Process-local retained artifact resource links, expiry metadata, SHA-256 values, classification labels, and retention bounds. |
| `memoric://timeline` | Implemented | Read-only observability events from MCP request, task, audit, worker IPC, and artifact metadata sources with correlation filters. |
| `memoric://processes` | Implemented | Bounded process list. |
| `memoric://scan-sessions` | Implemented | Current scan sessions. |
| `memoric://drivers` | Implemented | Driver discovery and readiness metadata. |
| `resources/list` pagination | Implemented | Calls without pagination params return the full static list; calls with `limit`/`cursor` return bounded pages with opaque `nextCursor`. `resources/templates/list` exposes UI resource templates and artifact templates with the same cursor discipline. |

## MCP Apps

| Area | Status | Notes |
| --- | --- | --- |
| UI resource scheme | Implemented | `resources/list` exposes `ui://memoric/dashboard`, `ui://memoric/scans`, and `ui://memoric/plans` with `text/html;profile=mcp-app`; `resources/templates/list` exposes parameterized forms for dashboard, scans, and plans. |
| Operation dashboard app | Implemented | `ui://memoric/dashboard` hydrates a read-only dashboard from tasks, policy, audit, capabilities, artifacts, timeline, state, and operation history. |
| Scan session explorer app | Implemented | `ui://memoric/scans` hydrates a read-only scan explorer with bounded scan-list arguments, sort and summary-only controls, strict redaction metadata, and artifact registry context. |
| Orchestration plan review app | Implemented | `ui://memoric/plans` hydrates templates, dry-run plan previews, workflow replay, policy, and capability blockers without executing live steps. |
| Widget-only tool result hydration | Implemented | Tools linked to `ui://memoric/dashboard`, `ui://memoric/scans`, or `ui://memoric/plans` return `_meta["io.memoric/widget-hydration"]` with `visibility="widget"`, `modelVisible=false`, strict classification-aware redaction, resource URI, summary, artifacts, and redacted data. Unlinked tools omit this metadata. |
| Widget CSP/domain metadata | Implemented | UI resources declare empty `connect_domains` and `resource_domains`, `domain="ui://memoric"`, `openai/widgetDomain`, `openai/widgetCSP`, `widgetOnlyHydration=true`, and `toolCalls="none"`; tests fail on unsafe template-domain drift. |
| UI-to-tool consent guard | Implemented | Request context extracts app/widget origin from JSON-RPC `_meta`, policy denies app-originated state-changing calls without a matching `consent_token` or task-bound input response grant, audit/timeline records `app_origin` plus `policy_origin`, and App Bridge boundary fixtures cover `ui/initialize`, host-context notifications, and unsupported-host fallback handling across legacy, STDIO, and worker paths. |
| Extension key governance | Implemented | Runtime tests validate `_meta` keys across tools, resources, resource templates, task metadata, and error results. Memoric custom keys use `io.memoric/*` with legacy `x-memoric-*` mirrors; reviewed compatibility keys include `openai/outputTemplate`, `openai/widgetAccessible`, `openai/widgetCSP`, `openai/widgetDomain`, and `mcp/www_authenticate`. |

MCP Apps are currently passive/read-only. The server exposes app resources and tool metadata links, but it still does not advertise a separate Apps capability in `initialize`; clients that do not support Apps can read the same resources as HTML/text hydration payloads.

## Windows Platform Matrix

| Area | Status | Notes |
| --- | --- | --- |
| Non-elevated STDIO mode | Implemented | Handles initialize, tools/list, resources, tasks, and ping locally. Tool calls can bridge to an elevated worker. |
| Elevated worker bridge | Implemented | Named-pipe worker handles privileged tool calls and forwards task notifications to STDIO. |
| Read-only process inspection | Implemented | Process enumeration, module listing, target fingerprinting, and defensive diagnostics are available where Windows APIs permit. |
| Target allowlist | Implemented | PID/name/path/signer allowlist enforcement exists for state-changing target operations, backed by best-effort process fingerprinting. |
| Protected process guardrails | Implemented | Protected and critical targets require explicit override or environment allowance for state-changing operations. |
| Capability detection | Partial | Elevation, policy, audit, driver readiness, test-signing, HVCI/VBS, and vulnerable driver blocklist signals are exposed. Static orchestration planning and live orchestration execution both consume these signals. Planner output now includes read-only `selection` metadata for kernel driver source, shellcode injection method, and selected stealth method families; broader per-technique live dispatch integration is still being expanded. |
| Driver discovery | Implemented | `kernel(action='driver_discover')` annotates BYOVD candidates with `likely_blocked`, `blocklist_evidence`, and top-level blocklist context. |
| Driver deployment readiness | Implemented | `kernel(action='status')`, doctor, and capability resources expose probe-only signing, HVCI/VBS, vulnerable driver blocklist, payload, device, and offset-registry readiness before driver load. |
| Kernel mutation preflight | Partial | Kernel mutation handlers run capability-aware preflight before live dispatch and attach the preflight record to successful live results. Persisted preflight approval records are still future work. |

## Non-Windows Behavior

| Area | Status | Notes |
| --- | --- | --- |
| Build and unit tests | Partial | Current CI is Windows-only, but the MCP dispatch boundary now has a simulated unsupported-platform gate that is covered by unit tests. Broad native non-Windows compilation remains future work because many implementation modules still import Windows APIs directly. |
| MCP schema/status operations | Implemented fallback | `initialize`, `tools/list`, resource listing/reading, guide calls, and `self` status/doctor/diagnostics/error-explanation calls remain available without entering Windows-backed live handlers. |
| Windows operations | Unsupported with clean gate | The tool-call facade rejects Windows-backed process, memory, injection, hook, stealth, privilege, driver, kernel, and live orchestration handlers with `unsupported_platform` before dispatch when the platform is unsupported. `self(action='test')` remains callable but reports a skipped unsupported-platform diagnostic instead of running Windows memory checks. |

## Test And CI Coverage

| Area | Status | Notes |
| --- | --- | --- |
| Format/check/test | Implemented | Default CI runs format, check, all-target tests, schema contract tests, generated catalog drift checks, and release build on Windows without setting privileged integration or driver-path environment variables. |
| Schema snapshot | Implemented | Registered tool schema summary is compared against committed generated docs, and the dedicated schema contract CI job runs `mcp::tool_contract_tests`. |
| JSON-RPC legacy handler tests | Implemented | Covers initialize, tools/list and resources/list pagination, invalid list cursors, ping, notifications, bad JSON, invalid version, unknown method, missing params, tasks/result missing taskId, and input-required task response flow. Shared core and adversarial conformance fixtures now exercise the legacy path. |
| Task registry tests | Implemented | Covers lifecycle, cancellation, background eligibility, progress/status notifications, task result metadata, progress token parsing, and cursor pagination. |
| Cross-transport conformance fixtures | Implemented | A shared fixture suite runs the same core and adversarial protocol cases against the legacy handler, direct STDIO in-process handling, worker-style in-process handling, and the in-process Streamable HTTP adapter. Real subprocess STDIO stream replay covers mixed line-delimited requests, large `tools/list` responses, notification silence, bad JSON, ping, unknown methods, and oversized unknown-method params. Worker named-pipe replay covers the same mixed-message framing boundary without requiring privileged integration. |
| Privileged Windows integration | Implemented | Privileged/admin/driver-dependent tests are isolated in `.github/workflows/privileged-integration.yml`, require manual `workflow_dispatch`, an environment gate, a self-hosted Windows runner with `privileged` label, an elevation check, and an explicit local driver artifact path. |

## Watchlist

- MCP Tasks are still treated as an evolving capability by the MCP specification; Memoric should keep polling fallback behavior even when notifications are available, and avoid relying on automatic retry semantics until the protocol standardizes them.
- MCP pagination requires clients to treat cursors as opaque. Memoric currently uses simple process-local cursor tokens for protocol lists and tool-internal scan/orchestration result pages, and may replace their internals later without changing the caller contract.
- Artifact resource links are process-local and retention-bound. Clients should read linked resources promptly, verify hashes when preserving results, and not assume artifact URIs survive server restart.
- Timeline correlation is best-effort for sources that predate `correlation_id`; callers should pass stable `request_id` values when they need precise end-to-end reconstruction.
- JSON-RPC request validation is centralized for object shape, version, method type, id type, notifications, cursor errors, and oversized-but-bounded params. Stream-level coverage now includes real STDIO subprocess replay, worker named-pipe framing, and in-process Streamable HTTP routing.
- MCP Streamable HTTP transport details are still evolving; Memoric keeps optional `Mcp-Session-Id`, `MCP-Protocol-Version`, SSE stream IDs, and `Last-Event-ID` handling isolated in `src/mcp/http_adapter.rs` rather than leaking them into tool handlers.
- MCP Apps are now exposed as passive read-only resources. Memoric should keep widget-originated tool calls guarded behind explicit consent and retain the App Bridge boundary fixtures that prevent unsupported host calls from drifting into real bridge behavior.
- Authorization challenges are emitted in both structured tool payloads and `_meta["mcp/www_authenticate"]`; clients should treat them as explanatory metadata and still obey local policy gates.
- Driver compatibility depends on Windows policy state, signing, HVCI/VBS, WDAC, and vulnerable driver blocklist behavior. `likely_blocked` is an advisory planning signal, not authorization or bypass logic.

## External References

- MCP Tasks utility: https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks
- MCP pagination utility: https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination
- MCP Streamable HTTP transport: https://modelcontextprotocol.io/specification/draft/basic/transports
- MCP Apps overview: https://modelcontextprotocol.io/docs/extensions/apps
- MCP Apps announcement: https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/

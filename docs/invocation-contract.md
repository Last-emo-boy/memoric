# Memoric Invocation Contract

This document defines the caller-facing MCP contract. Generated tool details live in `docs/tool-reference.md` and `docs/tool-catalog.json`.

`docs/server-manifest.json` is the static package/server manifest. It is generated from runtime `initialize`, `tools/list`, and `resources/list` plus package metadata, includes no local machine state, and records the tool catalog hash, advertised capabilities, protocol version, resource summary, and documentation links for offline compatibility checks.

## Protocol

- Transport: JSON-RPC 2.0 over stdin/stdout, proxy/worker named-pipe bridge, or the in-process Streamable HTTP adapter model used by tests and future listeners.
- Current advertised MCP protocol version: `2025-11-25`.
- Runtime source of truth: `tools/list`.
- Binary modes:
  - default: STDIO MCP server
  - `--proxy`: STDIO bridge that starts an elevated worker
  - `--worker`: elevated named-pipe worker
- Streamable HTTP listener status: not exposed by the binary. `src/mcp/http_adapter.rs` is the reusable adapter boundary for future listeners and covers POST/GET/DELETE routing, protocol/session headers, Origin checks, SSE replay, and request-context hydration.
- `tools/list`, `resources/list`, and `tasks/list` support bounded cursor pagination when callers pass `limit` or `cursor`. Calls without pagination params remain backward compatible and return the full current list. Large tool results also reuse the same opaque cursor discipline where documented below.

## Initialize

`initialize` returns:

- `protocolVersion`
- `capabilities.tools`
- `capabilities.resources`
- `capabilities.prompts`
- `capabilities.logging`
- `capabilities.tasks.list`
- `capabilities.tasks.cancel`
- `capabilities.tasks.requests.tools.call`
- `capabilities.experimental.structuredContent`
- `serverInfo.name`
- `serverInfo.version`

The version is always `env!("CARGO_PKG_VERSION")`.

## Tool Calls

Every consolidated tool uses an `action` field except `memoric`, which also supports guide/status style calls.

Common optional fields are added to every tool schema:

- `dry_run`: preview state-changing calls without executing the live handler.
- `as_task`: compatibility flag for background execution; new MCP clients may prefer `params.task`.
- `task_id`: task ID propagated to long-running handlers for cooperative cancellation.
- `timeout_ms`: per-call cooperative timeout in milliseconds.
- `artifact_retention_secs`: retention window for process-local artifact resource links emitted by the call. Tool-call preflight rejects values outside the registry bounds, and artifact registration still defensively caps retention at the server maximum.
- `purpose`: caller-provided authorized purpose for audit/provenance.
- `request_id`: caller request identifier.
- `consent_token`: optional explicit consent token for policy-gated operations.
- `allow_protected_target`: explicit override for protected or critical Windows targets.
- `redaction`: inline output redaction profile: `none`, `standard`, or `strict`.

Every tool definition also includes Memoric extension metadata:

- `x-memoric-actions`: per-action policy, risk, state-changing, and data-classification summary.
- `x-memoric-data-classification`: output field paths tagged as `public`, `local-sensitive`, `credential-like`, `raw-memory`, `path`, or `artifact-reference`.

## Tool Results

Tool results include both legacy text content and structured content:

```json
{
  "content": [{ "type": "text", "text": "{...json...}" }],
  "structuredContent": {
    "success": true,
    "code": "ok",
    "message": "ok",
    "summary": "self action='doctor' completed",
    "data": {},
    "context": {},
    "artifacts": [],
    "warnings": [],
    "evidence": []
  }
}
```

When a tool has a related MCP Apps resource, successful results also include
widget-only hydration under `_meta["io.memoric/widget-hydration"]`. The
model-visible `content` and `structuredContent` remain the concise, redacted
tool envelope; richer app hydration is scoped to the widget channel with
`visibility="widget"` and `modelVisible=false`. Memoric always applies strict
classification-aware redaction to that widget payload, so raw bytes, credential
material, request IDs, and local paths are represented as redaction markers
instead of inline secrets. Tools without a related `ui://memoric/...` resource
do not emit widget hydration metadata.

Error results use the same envelope with `success=false`, stable `code`, `message`, `hint`, and `context`.

Successful structured envelopes include `metadata.data_classification`, which summarizes the output classifications used by result redaction. Classification metadata is advisory for clients, but the server also uses the same rules when applying strict result redaction.

Stable tool error codes are classified by `src/error.rs` and reused by `tools/call`, background task finalization, and `self(action='explain_error')`:

- `missing_param`: required field is absent.
- `invalid_param`: field type, range, or enum value is invalid.
- `invalid_target`: PID, TID, handle, or address is no longer valid.
- `access_denied`: elevation, privilege, or protected target blocked the call.
- `policy_denied`: configured policy or consent state blocked the call.
- `driver_unavailable`: kernel-backed capability is unavailable or the driver device is not reachable.
- `partial_read`: requested memory span crosses unreadable or incompatible pages.
- `unsupported_platform`: action is not available on the current platform.
- `timeout`: cooperative runtime deadline expired.
- `cancelled`: cooperative task cancellation was observed.
- `ipc_closed`: worker or named-pipe channel closed unexpectedly.
- `process_terminating`: target process is exiting.
- `not_found`: requested process, module, function, or session was not found.
- `tool_error`: fallback for unclassified handler failures.

Every tool definition includes `execution.taskSupport="optional"`. Memoric still runs read-only actions and state-changing dry-run previews directly as background tasks. Live state-changing `params.task` calls enter `input_required` and wait for operator consent before the owning flow resumes; the older `as_task=true` compatibility path still rejects live state-changing execution unless `dry_run=true`.

`tools/list` supports optional cursor pagination. Pass `limit` to receive a bounded page and pass the opaque `nextCursor` from the prior response as `cursor` to continue:

```json
{
  "method": "tools/list",
  "params": { "limit": 25, "cursor": "<nextCursor>" }
}
```

When no `limit` or `cursor` is supplied, Memoric returns the full tool list for older MCP clients. `initialize.capabilities.tools.listChanged` is currently `false`; clients should refresh cached metadata by calling `tools/list` after reconnect or version changes. Invalid tool-list cursors return JSON-RPC `-32602`.

Tool-internal large result pagination follows the same caller rule: treat cursors as opaque, pass `nextCursor` back unchanged, and stop when `nextCursor` is absent. Invalid cursors return an `invalid_param` tool error for `tools/call` handlers, while protocol list methods use JSON-RPC `-32602`.

Scan session candidate pages:

```json
{
  "name": "memory",
  "arguments": {
    "action": "scan_list",
    "session_id": "scan_1",
    "limit": 50,
    "sort": "address_asc",
    "cursor": "<nextCursor>"
  }
}
```

`scan_list` also accepts `offset` for first-page compatibility, `sort` values `index_asc`, `index_desc`, `address_asc`, `address_desc`, `value_asc`, and `value_desc`, plus `summary_only=true` when callers only need session metadata, counts, and the snapshot summary without inline candidate rows. Scan cursors are bound to the session, `scan_count`, and selected sort mode; changing any of those between pages returns an invalid-cursor error instead of mixing result snapshots.

Orchestration plan or execute result pages:

```json
{
  "name": "orchestrate",
  "arguments": {
    "action": "plan",
    "template": "reconnaissance",
    "limit": 10,
    "cursor": "<nextCursor>"
  }
}
```

Existing file artifacts and generated large-output artifacts are exposed as process-local MCP resources. Successful tool results keep artifact metadata under `structuredContent.artifacts[]` and append MCP `resource_link` content blocks for clients that prefer `resources/read`. Artifact URIs use the form `memoric://artifact/sha256/<hash>`, are validated against the recorded SHA-256 before serving, and expire after `artifact_retention_secs` or the server default. These dynamic artifact URIs are intentionally not required to appear in `resources/list`. Memory read modes that can return raw bytes, including raw, stealth, scattered, and physical reads, keep small results inline but automatically export large byte buffers or explicit `output_path` requests as artifact resources. `scan_list(session_id=...)` exports full sorted candidate snapshots for explicit `output_path` requests or large sessions unless `summary_only=true` suppresses candidate material. Target credential/SAM/Kerberos dump helpers and kernel `driver_pe_dump`/`driver_process_dump` produce artifact references for dump files or large dump metadata instead of forcing bulky evidence inline. `orchestrate(action='plan')` can export the full static plan with `output_path` and auto-exports oversized plans while returning only paginated sections inline; `orchestrate(action='execute')` exports full execution results when `output_path` is supplied.

Every successful tool result also includes `structuredContent.metadata.result_strategy` so callers can choose a display and retrieval path without inspecting handler-specific fields. The strategy reports whether the current response is `inline`, `paginated`, `streamed-progress`, or `reference`, whether `nextCursor` is available, how many resource links were emitted, whether progress notifications are used, and whether cancellation/timeout checks occur at stream or page boundaries. Current streamed-progress handlers are `memory(action='scan_new')`, `memory(action='scan_next')`, `orchestrate(action='execute')`, and `kernel(action='driver_discover')`; they use MCP task/progress notifications as bounded stream hooks and keep raw evidence in final summaries or resource links.

Artifact registry and cleanup preview:

```json
{
  "method": "resources/read",
  "params": { "uri": "memoric://artifacts" }
}
```

```json
{
  "name": "self",
  "arguments": {
    "action": "state",
    "sub_action": "artifact_cleanup"
  }
}
```

## Operator Diagnostics Bundle

`self(action='diagnostics')` exports an operator-safe diagnostics bundle as a JSON artifact. The bundle captures the compatibility matrix summary, policy hash/status, audit configuration, current capability-diff watch list, catalog/server-manifest/compatibility hashes, and recent task summaries. It omits raw task result payloads, raw memory, credentials, progress tokens, and full local paths by default; local paths are reduced to basename-only redaction markers.

```json
{
  "name": "self",
  "arguments": {
    "action": "diagnostics",
    "recent_task_limit": 10,
    "artifact_retention_secs": 3600
  }
}
```

The tool result includes `artifact_path` so the normal artifact registry emits an expiring `resource_link` content block and `memoric://artifact/sha256/<hash>` resource. The bundle includes warnings when audit is not configured, audit readiness is poor, privileged/kernel/destructive policy is active, protected-target override is enabled, or a consent token is configured.

## Observability Timeline

`memoric://timeline` and `self(action='state', sub_action='timeline')` expose a read-only timeline for troubleshooting a single operation without manually stitching logs. Timeline entries link MCP request receipt, tool dispatch/result status, task lifecycle/progress snapshots, audit entries, worker IPC request/response metadata, and artifact registrations through `correlation_id`, `request_id`, `task_id`, or `artifact_uri`.

```json
{
  "method": "resources/read",
  "params": { "uri": "memoric://timeline" }
}
```

```json
{
  "name": "self",
  "arguments": {
    "action": "state",
    "sub_action": "timeline",
    "correlation_id": "req-123",
    "limit": 50
  }
}
```

Supported timeline filters are `correlation_id`, `request_id`, `task_id`, `artifact_uri`, `since`, `until`, and `limit`; `audit_path` can override `MEMORIC_AUDIT_PATH` for offline troubleshooting. Returned events include timestamp, kind, source, status, summary, safe artifact references, result integrity hashes, progress counts, and source coverage. They intentionally omit raw tool results, raw memory, credentials, progress tokens, and full local paths; path sources are reduced to basename/hash markers.
The response also reports source coverage for `audit`, `artifacts`, `tasks`, `notifications`, `worker_ipc`, and in-memory live events when present.

## Data Classification And Redaction

Memoric classifies output fields before emitting `tools/list` and before wrapping successful tool results. The classification values are:

- `public`: safe operational metadata such as status and integrity fields.
- `local-sensitive`: operator-local state, request provenance, plans, command lines, environment details, or other contextual data.
- `credential-like`: credentials, tokens, tickets, secrets, or extracted authentication material.
- `raw-memory`: inline process/kernel bytes, hex dumps, shellcode, payload bytes, or memory previews.
- `path`: local filesystem or process image paths.
- `artifact-reference`: paths to files produced by handlers and separately represented in artifact metadata.

`standard` redaction hides credential-like material and legacy sensitive keys. `strict` redaction additionally hides fields classified as `local-sensitive`, `raw-memory`, `path`, or `artifact-reference` from inline output while preserving the common envelope, summary, integrity metadata, and redaction markers.

## JSON-RPC Errors

Transport-level JSON-RPC failures use stable codes:

- `-32700`: parse error.
- `-32600`: invalid JSON-RPC request shape, such as an unsupported `jsonrpc` version or missing `method`.
- `-32601`: unknown method.
- `-32602`: invalid params, such as missing `tools/call.params` or missing `taskId`.
- `-32603`: internal handler error.

MCP `tools/call` handler failures remain tool result errors where possible, so clients can inspect `structuredContent` and `isError` instead of only the JSON-RPC envelope.

## Policy Denials

If the configured policy does not allow an operation, the tool returns an MCP tool error result instead of executing:

```json
{
  "success": false,
  "code": "policy_denied",
  "message": "policy_denied: memory(action='write') blocked..."
}
```

Use `self(action='doctor')` or `resources/read` with `memoric://policy` to inspect active policy.

Memoric can also load a JSON policy profile from `MEMORIC_POLICY_PROFILE_PATH`. The profile should contain `profile`, `version`, and `policy` fields, and it may be paired with `<profile-file>.sha256` and `<profile-file>.sig` sidecars for hash/signature verification. Profile identity, declared policy, hash status, signature status, downgrade status, and any verification errors are reported through `memoric://policy`, `self(action='doctor')`, and audit entries. Profiles fail closed on malformed input, mismatched hashes, missing signature keys, or downgrade attempts unless a local debug override is explicitly enabled.

`policy_denied` and `access_denied` tool errors now include an `authorization` object with challenge metadata for future remote or App clients. The object carries `scheme`, `realm`, `required_policy`, `configured_policy`, `consent_token_configured`, and a `www_authenticate` array with a machine-readable challenge string. MCP tool error results also mirror that array into `_meta["mcp/www_authenticate"]` for clients that follow the authorization challenge convention. This is advisory metadata for clients; it does not weaken local policy enforcement.

## Dry Run

For state-changing actions, `dry_run=true` returns a preview and skips the live handler. The preview includes:

- required policy
- risk
- target requirement
- planned handles
- required privileges
- expected side effects
- rollback availability
- provided fields

The preview uses action-specific templates for common and less-common mutation surfaces, including memory writes/protection/allocation, target thread and string mutation, injection and thread hijack workflows, hook detour/IAT/hardware-breakpoint operations, payload cleanup/obfuscation, EDR suspension, stealth controls, kernel driver operations, and orchestration execution. Rollback metadata remains descriptive unless the live handler captures the required original bytes, handles, thread contexts, process IDs, or driver state.

Live memory, string, thread, and hook mutations now return the same rollback descriptor shape when capture is possible. `memory(action='write')` captures original bytes before writing, `target(action='string_write')` captures the original null-terminated bytes and emits a memory-write restore action, `target(action='thread_suspend')` captures `previous_suspend_count` and emits a resume action, `target(action='thread_resume')` reports partial suspend-count restoration metadata, `memory(action='protect')` captures `old_protect` and emits an executable restore action, `memory(action='alloc')` emits an executable free action, and `memory(action='free')` explicitly reports `available=false` with `reason="irreversible_release"`. Hook live handlers now attach rollback/provenance metadata for IAT install/remove, inline restore, detour transaction restore actions, hook restore undo metadata, hardware breakpoint install/remove, and Windows hook handle capture. Successful live state-changing tool results are normalized with provenance metadata at the `tool_call` boundary, so injection, stealth, driver, kernel, privilege, hook, target, and memory mutation methods can be traced even when their leaf implementation does not add provenance itself. Rollback byte captures are classified as raw memory and are redacted from strict result profiles.

Read-only actions may still execute normally when `dry_run=true`.

## Operation History

When `MEMORIC_AUDIT_PATH` is configured, callers can query audit-backed operation history:

```json
{
  "action": "state",
  "sub_action": "history",
  "tool": "memory",
  "status": "success",
  "pid": 1234,
  "limit": 25
}
```

Supported filters are `tool`, `action`, `status`, `pid`, `request_id`, `chain_id`, `since`, and `until`. Pagination uses `offset` and `limit`; entries are returned newest first.

`self(action='state', sub_action='mutations')` and `self(action='state', sub_action='rollback')` read the same audit trail but return only entries that contain `state_change` metadata. The view keeps operator-facing provenance, mutation, rollback, artifact, and integrity summaries while omitting raw rollback bytes, raw memory, credentials, and full result payloads. This lets clients inspect live mutation history and rollback opportunities by `chain_id`, `request_id`, `pid`, or timestamp range without replaying sensitive result data into the model-visible response.

`self(action='state', sub_action='replay')` performs an audit-backed workflow replay dry-run. It reads `MEMORIC_AUDIT_PATH` or an explicit `audit_path`, applies the same filters, converts replayable audit entries into static orchestration steps, forces `dry_run=true` on each step, and evaluates them against current policy and capability signals. It returns `steps`, `effective_plan`, `blocked_steps`, `validation_errors`, `validation_warnings`, and `summary` without executing recorded operations.

## Capability Diff

`self(action='capability_diff')` compares current read-only capability signals against a saved baseline. Pass either `baseline` with a previously saved `memoric://capabilities`, `self(action='doctor')`, or `capability_diff.current` object, or pass `baseline_path` pointing to a JSON file containing one of those shapes.

The diff watches elevation, SeDebug, driver payload/device/readiness, HVCI, VBS, vulnerable driver blocklist, test-signing, policy, protected-target override, audit path/configuration, and platform support. It reports `changed`, `severity`, `changes[]`, `watched_paths`, and `current` without loading drivers, elevating privileges, or mutating state.

## Next Steps

`self(action='next_steps')` returns a read-only recovery plan for a failed result, raw error, stable error code, or current doctor output. Pass one of:

- `result`: a failed tool result envelope.
- `code`: a stable tool error code such as `policy_denied` or `driver_unavailable`.
- `error` or `message`: raw error text.
- `doctor`: output from `self(action='doctor')`.

The response includes `steps[]`, `docs[]`, `doctor_blockers[]`, and a `safety` object. Suggestions are limited to read-only diagnostics, dry-run previews, task polling, and documentation. For `policy_denied`, the server does not suggest bypass actions or live mutation.

## Defensive Diagnostics

`memory(action='diagnostics')` and `self(action='memory_diagnostics')` expose a read-only defensive profile for process memory layout, module summary, handle summary, suspicious region labels, and bounded entropy sampling. The diagnostics result does not return raw memory bytes.

For deterministic local scanner validation, run the opt-in example:

```powershell
cargo run --example benign_test_target -- --seconds 120
```

The example prints its PID plus marker and counter addresses for authorized self-launched testing.

## Orchestration Templates

`orchestrate(action='templates')` returns registered static plan seeds from `src/orchestration/templates.rs`. Templates are not executed directly. Use them with `orchestrate(action='plan', template='<id>')` to produce a validated static plan with `executes_live_actions=false`.

Plan results include:

- `plan`: every syntactically valid step with planner metadata.
- `effective_plan`: only steps currently allowed by policy and runtime capability signals.
- `blocked_steps`: steps skipped by the planner with `skip_reason`, capability blockers, and alternatives.
- `policy_planner`: configured policy and capability summary used for planning.

For large plans, pass `limit` and then continue with `pagination.nextCursor`. Paginated responses keep the page in the top-level `plan`, `effective_plan`, and `blocked_steps` arrays and include per-section metadata under `pagination.sections.*Page`. Supplying `output_path` writes the full unpaginated plan as a retention-bound artifact resource, and oversized static plans auto-export instead of expanding the entire plan inline.

The `lab_validation` template is safe by default:

```json
{
  "action": "plan",
  "template": "lab_validation"
}
```

Without a target it only plans current-process `self` diagnostics. To validate against a process target, launch `examples/benign_test_target.rs` yourself and pass the printed PID/address values explicitly:

```json
{
  "action": "plan",
  "template": "lab_validation",
  "benign_pid": 1234,
  "marker_address": "0x1000",
  "counter_address": "0x2000"
}
```

The optional counter step is always generated as `memory(action='write', dry_run=true)` for preview only.

## Assessment Evidence

`orchestrate(action='assess')` keeps the legacy summary fields and also returns machine-readable evidence:

- `evidence.security_products`: detected security products, each with `method`, `confidence`, `timestamp`, and `raw_evidence_summary`.
- `evidence.environment_properties`: platform, privilege, driver readiness, scan results, and telemetry indicators.
- `evidence.assessment_inputs`: derived assessment facts such as the rule-based `threat_level`.

Evidence entries are summaries only. They are intended for explanation, audit, and follow-up planning, not for bypassing live policy gates.

## Tasks

Memoric exposes a task registry that is process-local by default:

- `tasks/list`
- `tasks/get`
- `tasks/result`
- `tasks/cancel`
- `tasks/input_response`
- `tasks/update` for legacy input-response compatibility
- resource: `memoric://tasks`

If `MEMORIC_TASKS_PATH` is configured, Memoric writes a non-sensitive task metadata snapshot to that JSON file. The snapshot preserves task IDs, status, timestamps, summaries, progress counters, TTL/result-retention/retry policy metadata, artifact references, and result integrity hashes. It does not persist raw result payloads, raw memory bytes, shellcode, credentials, or progress tokens. After process restart, previously live `working` or `input_required` tasks are reported as failed metadata records with `task_not_resumable`; Memoric does not resume their execution threads.

Orchestration chain checkpoints are separate from task snapshots. If `MEMORIC_CHAIN_STATE_PATH` is configured, `orchestrate(action='execute', dry_run=false, allow_live_execution=true)` writes metadata-only chain progress after creation, step start, step completion/failure, and final status. The checkpoint stores chain ID, status, target PID, plan fingerprint, DAG summary, per-step status, safe argument summaries, rollback summaries, `last_completed_step`, and `next_step`; it does not persist shellcode, byte payloads, raw memory, credentials, or full live results. `orchestrate(action='status', chain_id=...)` reads a checkpoint, `orchestrate(action='resume', chain_id=...)` returns a non-executing resume preview, `orchestrate(action='cancel', chain_id=...)` marks the checkpoint cancelled, and `orchestrate(action='cleanup', chain_id=..., dry_run=false)` removes checkpoint metadata. Actual resumed execution still uses `orchestrate(action='execute')` with the original authorized arguments, matching `chain_id`, matching plan fingerprint, and `skip_completed_steps=true`; checkpoint metadata only decides which completed step IDs to skip.

Task-augmented `sampling/createMessage` is not implemented and is explicitly not advertised as a live capability. `initialize.capabilities.tasks.requests.sampling.createMessage.supported=false` documents the compatibility path: future sampling work must reuse the existing task registry, visibility scope, TTL, cancellation, result-retention, and correlation metadata rather than creating a separate lifecycle.

Preferred MCP task-augmented execution uses `params.task` on `tools/call`:

```json
{
  "method": "tools/call",
  "params": {
    "name": "self",
    "arguments": { "action": "version" },
    "task": {
      "ttl": 60000,
      "resultRetentionMs": 900000,
      "maxRetries": 0
    }
  }
}
```

The immediate response is a `CreateTaskResult`-style object with `task.taskId`, `status="working"`, `createdAt`, `lastUpdatedAt`, `ttl`, `pollInterval`, `expiresAtEpochSecs`, `resultRetentionMs`, `retryCount`, `maxRetries`, and `_meta["io.modelcontextprotocol/model-immediate-response"]`. `ttl` defaults to `300000` ms, `resultRetentionMs` defaults to `900000` ms, and `maxRetries` currently records policy intent for clients/operators without automatically re-executing failed tool calls. The final tool result is retrieved with:

```json
{
  "method": "tasks/result",
  "params": { "taskId": "<task-id>" }
}
```

`tasks/list` supports bounded cursor pagination. Pass `limit` to control page size and pass the opaque `nextCursor` from the prior response as `cursor` to fetch the next page:

```json
{
  "method": "tasks/list",
  "params": { "limit": 50, "cursor": "<nextCursor>" }
}
```

If more task records are available, the response includes `nextCursor`; when the current page is the final page, `nextCursor` is omitted. Invalid cursors return JSON-RPC `-32602` instead of silently restarting or returning a partial page.

Task records now include a `visibility` object with the creation transport, optional session ID, optional app origin, policy origin, and request ID. Local single-user STDIO/worker/legacy requests remain backward compatible and can see all process-local tasks. Remote or app-origin request contexts scope `tasks/list` to tasks from the same session ID or same app origin; legacy records without visibility metadata are not exposed to remote/app contexts.

`tasks/get` returns the current task object, and `tasks/cancel` moves a non-terminal task to `cancelled`. Task status updates are guarded by the lifecycle rules `working|input_required -> working|input_required|completed|failed|cancelled`; terminal `completed`, `failed`, and `cancelled` tasks are not reopened or overwritten by late worker updates. Background task failures use the same stable tool error taxonomy as synchronous tool calls; cancellation is detected through the shared `cancelled` classification instead of a task-local string branch. The legacy `as_task=true` path remains available and returns the older tool-result wrapper containing the task record immediately, but it does not opt into automatic live-mutation consent continuations.

When a task needs operator input, it enters `status="input_required"` and stores stable request metadata in `inputRequests` plus continuation metadata in `requestState`. For policy-gated state-changing `params.task` calls, Memoric creates a process-local continuation, records a redacted argument hash in `requestState`, and asks for a boolean approval. `tasks/result` returns an input-required result immediately instead of waiting for terminal completion:

```json
{
  "resultType": "input_required",
  "taskId": "<task-id>",
  "status": "input_required",
  "inputRequests": [
    {
      "request_id": "<input-request-id>",
      "prompt": "Provide approval",
      "mode": "form",
      "schema": { "type": "object" },
      "responded": false
    }
  ],
  "requestState": {
    "continuation": "<safe-continuation-metadata>"
  }
}
```

Clients submit the matching response through `tasks/input_response`:

```json
{
  "method": "tasks/input_response",
  "params": {
    "taskId": "<task-id>",
    "requestId": "<input-request-id>",
    "input": { "approved": true }
  }
}
```

The response must bind to an existing pending `requestId`; duplicate or mismatched responses are rejected. A successful response records `inputResponses`, updates `requestState` to `input_received`, emits a task status notification, and moves the task back to `working`. If the task owns a process-local policy-consent continuation, `approved=false` fails the task with `policy_denied`; `approved=true` creates a one-time task/request/argument-hash-bound consent grant and resumes the original tool call. Approval records operator intent but does not elevate `MEMORIC_POLICY`, so the resumed call can still fail if the configured policy level is too low. For older clients, `tasks/update` with `kind="input_response"` is accepted as the same operation.

Memoric also exposes passive MCP Apps surfaces through `ui://memoric/dashboard`, `ui://memoric/scans`, and `ui://memoric/plans`. These resources are hydration payloads for read-only dashboard, scan explorer, and plan review views. Their metadata sets `widgetOnlyHydration=true`, `toolCalls="none"`, `openai/widgetDomain="ui://memoric"`, `openai/widgetCSP` with empty domain lists, and vendor-scoped `io.memoric/ui` mirror metadata, so the default surface remains read-only. Tool descriptors that have a related UI also expose `_meta["openai/outputTemplate"]` alongside `_meta.ui.resourceUri`; matching successful tool results expose `_meta["io.memoric/widget-hydration"]` with strict widget-only hydration while keeping `content` and `structuredContent` model-visible. Every tool sets `_meta["openai/widgetAccessible"]=false` unless a future App Bridge flow explicitly opts in. Request context records `app_origin` and `policy_origin` from `_meta`, and tool calls from app/widget origins are audited with that origin and policy classification. App-origin state-changing calls require explicit consent through either a matching `consent_token` or the task-augmented `input_required` consent flow.

All custom `_meta` keys are governed in code: Memoric-owned metadata uses `io.memoric/*`, legacy generated docs may keep `x-memoric-*`, and standard compatibility keys are limited to reviewed MCP/OpenAI names such as `mcp/www_authenticate`, `openai/outputTemplate`, `openai/widgetAccessible`, `openai/widgetCSP`, and `openai/widgetDomain`.

Task cleanup is opportunistic and runs on task reads and result retrieval. A non-terminal task whose TTL elapsed is moved to `failed` with result code `task_expired`; its progress token is cleared and the failure result contains only safe task/policy metadata. A terminal task whose `resultRetentionMs` elapsed is removed from the in-process registry so stale result payloads do not accumulate. A `null` TTL or result-retention value is treated as unbounded for that specific policy.

Live state-changing calls are not backgrounded unless they are dry-run previews. Dry-run previews include planned handle classes, required privilege markers, expected side effects, and structured rollback metadata when a handler can describe reversible state, such as `available`, `strategy`, `captured_fields`, and a human-readable `detail`. Live memory writes/protection/allocation/free operations, target string writes, target thread suspend/resume operations, and hook mutation operations also return rollback descriptors and executable rollback actions where the handler captured enough state. Long-running handlers such as orchestration and scan sessions check `task_id` cancellation and `timeout_ms` at safe boundaries; cancellation is cooperative rather than thread termination.

### Task Progress

Handlers that opt into `RuntimeContext` update the task registry and, when a client supplies `_meta.progressToken`, emit MCP progress notifications. Push notifications are rate-limited per task so high-frequency scans do not flood STDIO or the worker pipe; `tasks/get` still exposes every stored progress update, and task completion forces the final progress notification when progress advanced.

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/progress",
  "params": {
    "progressToken": "<token>",
    "progress": 32,
    "total": 128,
    "message": "scan_new: scanned 32/128 regions, 14 matches",
    "_meta": {
      "io.modelcontextprotocol/related-task": {
        "taskId": "<task-id>"
      }
    }
  }
}
```

Task status transitions also emit `notifications/tasks/status` with the full task object as `params`. Clients that do not consume push notifications can poll `tasks/get` or `memoric://tasks`:

```json
{
  "task": {
    "taskId": "<task-id>",
    "status": "working",
    "statusMessage": "scan_new: scanned 32/128 regions, 14 matches",
    "progress": {
      "current": 32,
      "total": 128
    }
  }
}
```

Current opt-in handlers:

- `memory(action='scan_new')`: region scan phase, current/total regions, match count summary.
- `memory(action='scan_next')`: candidate filter phase, current/total candidates, remaining count summary, and safe delta metrics for added/removed/changed/unchanged/unreadable candidates.
- `orchestrate(action='execute')`: assessment and per-step execution progress.
- `kernel(action='driver_discover')`: loaded-driver enumeration and bounded disk-location scan progress.

Progress summaries are intentionally safe display strings. They report phase and counts, not raw memory bytes or large evidence payloads. Direct STDIO and elevated worker bridge paths serialize notification writes so they do not interleave with normal JSON-RPC responses.

## Driver Readiness

`kernel(action='status')` is a read-only, probe-only driver readiness view. It returns the same signing, WDAC/HVCI, vulnerable driver blocklist, payload, and device reachability signals used by `self(action='doctor')` and `memoric://capabilities`, plus static kernel offset registry support for the current or supplied `build_number`. It does not call driver load or auto-install paths; `driver_auto_installed` is always `false`.

Recommended operator flow:

- `kernel(action='status')`: inspect signing, HVCI, blocklist, payload, device, and offset support without mutation.
- `kernel(action='driver_discover')`: inspect BYOVD candidates and blocklist evidence when a driver path is needed.
- `kernel(action='driver_load', dry_run=true)`: preview service/install effects before any live load attempt.

## Driver Discovery

`kernel(action='driver_discover')` is read-only. It enumerates loaded driver names and bounded disk locations, then annotates each BYOVD candidate with compatibility signals:

```json
{
  "name": "RTCore64",
  "status": "on_disk",
  "likely_blocked": true,
  "blocklist_evidence": {
    "driver": "RTCore64",
    "confidence": "medium",
    "reasons": [
      { "code": "vulnerable_driver_blocklist_enabled" }
    ],
    "signals": {
      "hvci_enabled": false,
      "vulnerable_driver_blocklist_enabled": true,
      "test_signing_active": false
    }
  }
}
```

The top-level `blocklist_context` includes the same WDAC, HVCI, and signing readiness signals used by `self(action='doctor')`. These fields are advisory compatibility evidence; they do not load, unload, or bypass drivers.

## Resources

Shared resources:

- `memoric://status`
- `memoric://capabilities`
- `memoric://policy`
- `memoric://tasks`
- `memoric://audit/recent`
- `memoric://artifacts`
- `memoric://timeline`
- `memoric://processes`
- `memoric://scan-sessions`
- `memoric://drivers`

`resources/list` and `resources/read` are available through active STDIO, worker, and legacy MCP server paths.

`resources/list` supports the same optional cursor pagination contract as `tools/list`:

```json
{
  "method": "resources/list",
  "params": { "limit": 25, "cursor": "<nextCursor>" }
}
```

Calls without `limit` or `cursor` return the full static resource list. Invalid resource-list cursors return JSON-RPC `-32602`.

`memoric://artifacts` lists currently retained process-local artifact resource links. Individual `memoric://artifact/sha256/<hash>` resources can be read directly when a tool result provides the URI; reads fail if the link expired, the backing file disappeared, or the recorded hash no longer matches.

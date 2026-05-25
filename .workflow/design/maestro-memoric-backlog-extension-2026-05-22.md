# Memoric Maestro Backlog Extension - 2026-05-22

## Context

This extension adds new iteration candidates beyond `TASK-001..TASK-065`.

Recent external inputs:

- MCP `2025-11-25` progress utility: `progressToken`, `notifications/progress`, optional total/message, task lifetime behavior.
- MCP draft Tasks utility: `notifications/tasks/status`, task polling, task result retrieval, task lifecycle and `input_required`.
- MCP Apps announcement on 2026-01-26: tools can attach interactive UI resources rendered in sandboxed iframes, with auditable UI-to-host JSON-RPC and user consent for UI-initiated calls.

Design bias remains: make Memoric stronger through reliability, visibility, evidence quality, client compatibility, operator consent, and safe lab workflows. Do not add new destructive primitives just to expand capability count.

## Wave A - Progress, Tasks, and Push Notifications

### TASK-066: Implement `notifications/progress` transport push

Files: `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/tasks.rs`, `src/runtime.rs`

Work:
- Parse `_meta.progressToken` from incoming JSON-RPC requests.
- Bind active progress tokens to task IDs and synchronous request IDs.
- Emit `notifications/progress` with monotonic `progress`, optional `total`, and safe `message`.
- Rate-limit progress pushes to avoid flooding STDIO or worker pipe.

Acceptance:
- A task-augmented `tools/call` with `_meta.progressToken` receives progress notifications while `tasks/get` polling remains valid.
- Notifications stop after completed, failed, or cancelled status.

### TASK-067: Implement `notifications/tasks/status`

Files: `src/mcp/tasks.rs`, `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/server.rs`

Work:
- Add a status-change event hook in the task registry.
- Emit full task state on selected status transitions.
- Ensure `tasks/get`, `tasks/list`, and `tasks/cancel` do not add redundant related-task metadata.

Acceptance:
- Clients can observe `working -> completed|failed|cancelled` without an extra `tasks/get` round trip.
- Polling is still documented as the fallback path.

### TASK-068: Add `tasks/input_response` and `input_required` flow

Files: `src/mcp/tasks.rs`, `src/mcp/consent.rs`, `src/stdio_server.rs`, `src/worker.rs`

Work:
- Support task records that pause at `input_required`.
- Store input request descriptors and opaque request state.
- Resume tasks when the requestor provides valid `inputResponses`.

Acceptance:
- Privileged operations can pause for consent or missing operator input without failing the whole task.

### TASK-069: Persist task registry snapshots

Files: `src/mcp/tasks.rs`, `src/state.rs`

Work:
- Persist non-sensitive task records with TTL cleanup.
- Preserve status, timestamps, summaries, and result artifact references.
- Do not persist raw memory bytes or sensitive payload fields.

Acceptance:
- A restarted process can report recent completed/failed task metadata and explain that live tasks cannot be resumed unless chain state is resumable.

### TASK-070: Add cursor-based `tasks/list` pagination

Files: `src/mcp/tasks.rs`, `src/mcp/server.rs`

Work:
- Replace limit-only listing with stable cursor pagination.
- Keep backward-compatible `limit`.
- Add tests for invalid cursor and next cursor behavior.

Acceptance:
- Large task histories are listable without oversized JSON-RPC responses.

## Wave B - MCP Apps and Operator UI

### TASK-071: Add MCP App resource for operation dashboard

Files: `src/mcp/resources.rs`, `docs/architecture.md`, `ui/operation-dashboard/`

Work:
- Expose an app resource such as `ui://memoric/operations`.
- Render tasks, audit status, policy level, recent errors, and capability readiness.
- Keep the UI read-only initially.

Acceptance:
- MCP Apps-capable clients can open a dashboard without invoking state-changing tools.

### TASK-072: Add MCP App resource for scan session explorer

Files: `src/mcp/resources.rs`, `src/memory/session.rs`, `ui/scan-explorer/`

Work:
- Provide bounded, paginated scan session data to an interactive explorer.
- Support sorting/filtering client-side.
- Redact raw bytes unless redaction profile allows them.

Acceptance:
- Large scan results can be explored without dumping the full result set into chat text.

### TASK-073: Add MCP App resource for orchestration plan review

Files: `src/orchestration/engine.rs`, `src/mcp/resources.rs`, `ui/plan-review/`

Work:
- Visualize `plan`, `effective_plan`, `blocked_steps`, policy decisions, capability blockers, and alternatives.
- Require explicit user approval before any UI-initiated tool call that could mutate state.

Acceptance:
- Operators can inspect a plan graphically before execution, with blocked steps and reasons visible.

### TASK-074: Add UI-to-tool consent guard

Files: `src/policy.rs`, `src/mcp/consent.rs`, UI resources

Work:
- Add a consent gate specifically for MCP App initiated calls.
- Record app resource URI, tool/action, arguments summary, and user decision in audit.

Acceptance:
- A UI cannot trigger privileged or state-changing tools without an auditable consent record.

## Wave C - Security and Governance

### TASK-075: Harden STDIO command execution boundaries

Files: `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/server.rs`

Work:
- Add transport-level fuzz tests for malformed JSON, overlong messages, unexpected notifications, and mixed request streams.
- Ensure no user-controlled field is ever passed to a shell command.

Acceptance:
- Protocol handling failures stay JSON-RPC errors or ignored notifications; no panic and no command execution path.

### TASK-076: Add tool description injection scanner

Files: `src/mcp/tools.rs`, `src/mcp/action_registry.rs`, tests

Work:
- Validate tool descriptions, guide text, and generated docs for unsafe instruction patterns.
- Fail tests when a tool description contains model-directed override language.

Acceptance:
- Tool poisoning regressions are caught before publishing tool metadata.

### TASK-077: Add per-tool data classification

Files: `src/mcp/action_registry.rs`, `src/redaction.rs`, docs

Work:
- Tag output fields as public, local-sensitive, credential-like, raw-memory, path, or artifact-reference.
- Apply redaction by classification instead of only key/name heuristics.

Acceptance:
- Strict redaction can be proven by schema-driven tests.

### TASK-078: Add signed policy profile files

Files: `src/policy.rs`, docs

Work:
- Load policy profiles from disk with optional signature/hash verification.
- Report profile identity in `self(action='doctor')`.

Acceptance:
- Lab sessions can prove which policy file allowed a privileged action.

## Wave D - Typed Core and Maintainability

### TASK-079: Split `tools.rs` by domain handlers

Files: `src/mcp/tools.rs`, `src/mcp/handlers/*.rs`

Work:
- Extract memory, kernel, orchestration, self, target, and privilege handlers.
- Keep `register_tools()` and `call_tool()` stable.

Acceptance:
- `src/mcp/tools.rs` becomes a facade; behavior and schema snapshots stay unchanged.

### TASK-080: Generate dispatch from action registry

Files: `src/mcp/action_registry.rs`, `src/mcp/tools.rs`

Work:
- Replace manual string dispatch coverage checks with generated dispatch metadata.
- Keep explicit handlers for implementation, but remove duplicated action lists.

Acceptance:
- Adding an action in the registry requires adding a handler or compilation/tests fail.

### TASK-081: Add schema-driven argument parser generation

Files: `src/args.rs`, `src/mcp/action_registry.rs`

Work:
- Move common bounds, enum values, aliases, and required fields into typed descriptors.
- Generate parser hints and validation tests from descriptors.

Acceptance:
- Parameter behavior is consistent across schemas, docs, and runtime validation.

## Wave E - Evidence, Artifacts, and Memory Workflow

### TASK-082: Add scan result pagination and artifact export

Files: `src/memory/session.rs`, `src/artifact.rs`, `src/mcp/tools.rs`

Work:
- Add `limit`, `offset`, `sort`, `summary_only`, and artifact export for large scan results.
- Hash exported result sets.

Acceptance:
- Large scan sessions never return oversized MCP responses by default.

### TASK-083: Add scan diff summaries

Files: `src/memory/session.rs`

Work:
- Track added, removed, changed, unchanged, and unreadable counts between scan rounds.
- Add safe summaries for task progress and final result.

Acceptance:
- `scan_next` explains what changed without exposing raw memory bytes.

### TASK-084: Add memory region cache with freshness controls

Files: `src/memory/session.rs`, `src/memory/reader.rs`

Work:
- Cache query results per PID with age and coverage metadata.
- Invalidate on process exit or explicit caller request.

Acceptance:
- Scan output reports cache age and whether the cache was reused.

## Wave F - Conformance and Compatibility

### TASK-085: Add MCP conformance fixture suite

Files: `tests/`, `src/mcp/server.rs`, `src/stdio_server.rs`

Work:
- Build request/response fixtures for initialize, tools/list, resources, tasks, errors, cancellation, and progress metadata.
- Run fixtures against STDIO, worker, and legacy handler paths.

Acceptance:
- Protocol regressions are caught before integration with new MCP clients.

### TASK-086: Add generated docs drift gate for task and app metadata

Files: `scripts/generate_tool_catalog.py`, docs, CI

Work:
- Include `execution.taskSupport`, output schema, app resource metadata, redaction classification, and policy metadata in generated docs.

Acceptance:
- CI fails when runtime metadata and committed docs diverge.

### TASK-087: Add compatibility matrix document

Files: `docs/compatibility.md`

Work:
- Document supported MCP protocol versions, task/progress/app feature status, Windows build assumptions, and non-Windows fallback behavior.

Acceptance:
- Operators can see which features are stable, experimental, partial, or unavailable.

## Wave G - Developer and Operator Experience

### TASK-088: Add `self(action='capability_diff')`

Files: `src/capability.rs`, `src/mcp/tools.rs`

Work:
- Compare current capability matrix against a saved baseline.
- Highlight changes in elevation, driver readiness, HVCI/VBS, policy, and audit path.

Acceptance:
- Operators can explain why a workflow worked yesterday but is blocked today.

### TASK-089: Add `self(action='next_steps')`

Files: `src/mcp/tools.rs`, `src/error.rs`, `src/capability.rs`

Work:
- Given a failed result or current doctor output, suggest safe diagnostic calls and relevant docs.
- Do not suggest bypass actions when policy denies an operation.

Acceptance:
- Common failure recovery becomes a single read-only tool call.

### TASK-090: Add workflow replay dry-run

Files: `src/state.rs`, `src/orchestration/engine.rs`

Work:
- Replay an audit chain in dry-run mode against current policy and capabilities.
- Report which steps would now be allowed, blocked, or changed.

Acceptance:
- Prior operations are explainable and reproducible without mutating state.

## Wave H - 2026 MCP Scalability and Discovery

### TASK-091: Add `tools/list` pagination and list-changed coverage

Files: `src/mcp/server.rs`, `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/tools.rs`

Work:
- Add bounded cursor pagination to `tools/list` while preserving backward-compatible full-list behavior.
- Add deterministic tool ordering and tests for optional `notifications/tools/list_changed`.
- Document when clients should refresh cached tool metadata.

Acceptance:
- Large future tool catalogs can be listed incrementally without breaking existing clients.

### TASK-092: Add static MCP server metadata manifest

Files: `docs/`, `scripts/generate_tool_catalog.py`, `src/mcp/protocol.rs`

Work:
- Generate a static server metadata manifest with server identity, supported protocol version, capabilities, resources, and docs links.
- Include catalog provenance and generation marker.
- Keep the manifest free of local machine state.

Acceptance:
- Clients and operators can inspect Memoric capabilities without starting a live privileged session.

### TASK-093: Prepare remote/streamable HTTP session abstractions

Files: `src/mcp/`, `src/stdio_server.rs`, `src/worker.rs`, `docs/architecture.md`

Work:
- Separate protocol session state from STDIO-specific loop state.
- Define transport-neutral request context for request ID, progress token, cancellation, and audit origin.
- Document which state remains local-only.

Acceptance:
- Future streamable HTTP or remote gateway support does not require rewriting handler contracts.

### TASK-094: Add task retry, expiry, and result-retention policy

Files: `src/mcp/tasks.rs`, `src/runtime.rs`, `docs/invocation-contract.md`

Work:
- Add per-task `expires_at`, `result_ttl_ms`, retry count, and terminal retention metadata.
- Cleanup old task records while preserving safe audit/artifact references.
- Keep raw result payloads out of persisted task metadata.

Acceptance:
- Long-running task state is bounded, resumability is explicit, and stale results do not accumulate indefinitely.

### TASK-095: Add `tasks/input_response` for resumable consent

Files: `src/mcp/tasks.rs`, `src/policy.rs`, `src/mcp/server.rs`, `docs/invocation-contract.md`

Work:
- Add `input_required` task status with a stable input request ID.
- Add `tasks/input_response` to resume gated operations after consent or denial.
- Bind input responses to request ID, policy level, purpose, and audit origin.

Acceptance:
- Policy-gated flows no longer rely only on one-shot `consent_token` fields.

## Wave I - MCP Apps and Operator UI Metadata

### TASK-096: Add MCP Apps UI resource templates

Files: `src/mcp/resources.rs`, `src/mcp/action_registry.rs`, `docs/tool-reference.md`

Work:
- Add UI resource template metadata for operation dashboard, scan explorer, and orchestration review views.
- Link read-only tools to UI resources through app/tool descriptor metadata.
- Keep UI resources passive by default.

Acceptance:
- Apps-capable clients can discover appropriate UI surfaces from tool metadata.

### TASK-097: Add app visibility and UI-origin consent guard

Files: `src/policy.rs`, `src/audit.rs`, `src/mcp/tools.rs`

Work:
- Track whether a tool call originated from a model, direct caller, or UI widget.
- Add policy checks for UI-initiated calls.
- Record app origin in audit entries without trusting client-provided free-form text.

Acceptance:
- UI-triggered state-changing calls require explicit consent and are distinguishable in audit logs.

### TASK-098: Split model-visible and widget-only result payloads

Files: `src/mcp/protocol.rs`, `src/mcp/tool_result.rs`, `src/redaction.rs`

Work:
- Keep `structuredContent` and text summaries safe for model visibility.
- Add a widget-only metadata channel for UI hydration where supported.
- Apply classification-aware redaction separately to each visibility channel.

Acceptance:
- UI views can hydrate efficiently without leaking raw memory, paths, or credential-like data into model-visible content.

### TASK-099: Add widget CSP/domain metadata and validation

Files: `src/mcp/resources.rs`, `docs/safety-model.md`, `src/mcp/tools.rs`

Work:
- Define CSP/domain metadata for each app resource.
- Validate that resource templates do not request unexpected external domains.
- Document the sandbox and network assumptions.

Acceptance:
- UI resources have explicit sandbox metadata and tests fail on unsafe domain drift.

### TASK-100: Add resource pagination and template drift tests

Files: `src/mcp/resources.rs`, `src/mcp/server.rs`, `src/mcp/tools.rs`

Work:
- Add cursor pagination for `resources/list`.
- Add resource template metadata for parameterized views such as scan sessions or task details.
- Extend generated catalog snapshot tests to include templates.

Acceptance:
- Resource growth and UI template metadata are covered by deterministic drift gates.

## Wave J - Result Streaming, Artifacts, and Enterprise Readiness

### TASK-101: Add resource-link result artifacts for large outputs

Files: `src/artifact.rs`, `src/mcp/tool_result.rs`, `src/memory/session.rs`

Work:
- Return artifact/resource links for large scan, read, dump, and orchestration-log outputs.
- Include hash, size, classification, and retention metadata.
- Avoid oversized inline MCP responses by default.

Acceptance:
- Large operations remain usable in MCP clients without leaking raw bytes inline.

### TASK-102: Add tool title and icon metadata

Files: `src/mcp/action_registry.rs`, `scripts/generate_tool_catalog.py`, `docs/tool-reference.md`

Work:
- Add short titles and icon hints to tool descriptors.
- Validate uniqueness and clarity in generated docs.
- Keep icons non-authoritative and independent from security decisions.

Acceptance:
- MCP clients can render clearer tool pickers without reading long descriptions.

### TASK-103: Add scoped authorization metadata and error docs

Files: `src/policy.rs`, `src/error.rs`, `docs/invocation-contract.md`

Work:
- Document policy scopes that map to observe, research, lab-write, kernel, and destructive operations.
- Add authorization challenge metadata for remote-capable clients.
- Ensure policy-denied errors never suggest bypassing policy.

Acceptance:
- Authorization failures are machine-readable and operator-actionable.

### TASK-104: Add enterprise readiness export

Files: `src/capability.rs`, `src/policy.rs`, `src/audit.rs`, `docs/compatibility.md`

Work:
- Export current policy profile, audit configuration, tool catalog hash, driver readiness, and platform assumptions.
- Include warnings for non-persistent audit paths or unsafe policy settings.
- Keep local secrets and raw target data out of the export.

Acceptance:
- Operators can attach a safe readiness bundle to review or change-control records.

### TASK-105: Add MCP Apps bridge fixture tests

Files: `tests/`, `src/mcp/server.rs`, `src/stdio_server.rs`

Work:
- Add fixtures for UI resource discovery, widget tool calls, UI-origin audit metadata, and denied state-changing UI calls.
- Run the same fixtures against legacy handler, STDIO, and worker bridge paths.

Acceptance:
- Apps integration regressions are caught before UI work depends on them.

### TASK-106: Add tool description quality lint

Files: `src/mcp/tools.rs`, `scripts/generate_tool_catalog.py`

Work:
- Lint tool and action descriptions for length, overlap, prompt-injection phrases, and missing selection hints.
- Report findings in tests and generated docs.
- Allow explicit exceptions only in a small reviewed list.

Acceptance:
- Tool metadata stays readable and safe as the action catalog grows.

### TASK-107: Add signed policy profile loading

Files: `src/policy.rs`, `src/capability.rs`, `docs/safety-model.md`

Work:
- Load policy profiles from a file with hash/signature reporting.
- Expose active profile hash in status, doctor, and audit entries.
- Fail closed on malformed or downgraded profiles unless explicitly overridden in local dev.

Acceptance:
- Policy posture is portable, reviewable, and tamper-evident.

### TASK-108: Add package/registry metadata checks

Files: `docs/`, `scripts/generate_tool_catalog.py`, `src/mcp/protocol.rs`

Work:
- Generate server package metadata: name, version, license, protocol support, docs, catalog hash, and resource list.
- Validate consistency with initialize metadata and generated catalog.
- Document publication assumptions separately from local lab usage.

Acceptance:
- Server identity and compatibility metadata do not drift across docs, runtime, and distribution artifacts.

### TASK-109: Design streamed and reference-based results

Files: `src/mcp/protocol.rs`, `src/memory/session.rs`, `docs/architecture.md`

Work:
- Define when operations return inline summaries, paginated data, streamed progress, or resource-link artifacts.
- Add bounded streaming hooks for long scans and orchestration logs.
- Keep cancellation and timeout checks at stream boundaries.

Acceptance:
- Heavy workflows have a clear result strategy before more large-output features are added.

### TASK-110: Add tracing correlation across boundaries

Files: `src/audit.rs`, `src/mcp/tasks.rs`, `src/worker.rs`, `src/mcp/tool_result.rs`

Work:
- Propagate correlation IDs through MCP request, task registry, worker IPC, audit entry, and artifact metadata.
- Add a read-only lookup path from result envelope to related audit/task records.
- Redact local paths and target details according to classification policy.

Acceptance:
- Operators can trace a result back to task, worker, audit, and artifact records without manual log stitching.

## Wave K - Latest MCP Tasks Extension Alignment

### TASK-111: Add task lifecycle transition guards

Files: `src/mcp/tasks.rs`, `docs/invocation-contract.md`

Work:
- Centralize task status transitions behind helper functions instead of directly mutating `TaskRecord.status`.
- Reject attempts to reopen `completed`, `failed`, or `cancelled` tasks.
- Distinguish protocol-level task failure from tool-level error results in task metadata.

Acceptance:
- Tests prove terminal tasks cannot move back to `working` or `input_required`, and task status transitions match the documented lifecycle.

### TASK-112: Add task-augmented elicitation/input update flow

Files: `src/mcp/tasks.rs`, `src/policy.rs`, `src/mcp/server.rs`, `src/stdio_server.rs`, `src/worker.rs`

Work:
- Extend task records with stable `inputRequests` metadata for consent or operator confirmation.
- Add a `tasks/update` or compatibility `tasks/input_response` handler to resume `input_required` tasks.
- Bind responses to request ID, policy level, purpose, and audit origin.

Acceptance:
- Policy-gated operations can pause as `input_required` and resume or fail deterministically from a later input response.

### TASK-113: Add task-augmented sampling readiness gates

Files: `src/mcp/protocol.rs`, `src/mcp/tasks.rs`, `docs/architecture.md`

Work:
- Document how future `sampling/createMessage` or client-side requests would attach to task lifecycle records.
- Add capability guards so sampling-style task support is never advertised before handlers exist.
- Reuse task polling, cancellation, TTL, and correlation metadata rather than creating a parallel state machine.

Acceptance:
- Future sampling support has a clear compatibility path without changing the current tool task contract.

### TASK-114: Add task visibility scoping

Files: `src/mcp/tasks.rs`, `src/mcp/protocol.rs`, `src/audit.rs`

Work:
- Record request/session/app origin on each task.
- Filter `tasks/list` by visible scope once remote or app transports are active.
- Keep local single-user STDIO behavior backward compatible.

Acceptance:
- Task enumeration cannot leak unrelated session or app tasks when multi-session transports are introduced.

## Wave L - MCP Apps Concrete UI Surfaces

### TASK-115: Add read-only operation dashboard UI resource

Files: `src/mcp/resources.rs`, `src/mcp/tools.rs`, `docs/compatibility.md`

Work:
- Add `ui://memoric/dashboard` as a passive MCP Apps resource.
- Hydrate it from tasks, policy, audit summary, capability readiness, and recent error summaries.
- Keep model-visible tool results concise; place richer UI data in widget-only metadata where supported.

Acceptance:
- Apps-capable hosts can render a read-only operational dashboard without granting UI-originated mutation rights.

### TASK-116: Add scan session explorer UI resource

Files: `src/mcp/resources.rs`, `src/memory/session.rs`, `src/artifact.rs`

Work:
- Add `ui://memoric/scans` with paginated scan session and candidate data.
- Use strict redaction and artifact links for raw memory or large evidence.
- Provide empty/error states for unsupported platform or missing scan data.

Acceptance:
- Operators can inspect scan progress and summaries through UI resources without inline raw byte leakage.

### TASK-117: Add orchestration plan review UI resource

Files: `src/mcp/resources.rs`, `src/orchestration/engine.rs`, `src/mcp/tools.rs`

Work:
- Add `ui://memoric/plans` for effective plan, blocked steps, policy decisions, and capability blockers.
- Surface dry-run previews and rollback availability as read-only review data.
- Avoid triggering execution from the UI resource itself.

Acceptance:
- Apps-capable hosts can show plan review data before any live operation is approved.

### TASK-118: Add App Bridge boundary validation

Files: `tests/`, `src/mcp/server.rs`, `src/mcp/resources.rs`, `src/audit.rs`

Work:
- Add fixtures for `ui/initialize`, host context updates, widget-originated `tools/call`, and unsupported-host fallback.
- Ensure widget-originated calls carry app origin into policy and audit.
- Reject state-changing widget calls unless explicit UI consent policy allows them.

Acceptance:
- UI bridge regressions fail in tests before dashboard resources depend on them.

## Wave M - Extension Governance, Transport, and Conformance

### TASK-119: Add custom extension identifier governance

Files: `src/mcp/protocol.rs`, `src/mcp/tool_result.rs`, `scripts/generate_tool_catalog.py`

Work:
- Inventory all custom `_meta` keys and extension identifiers.
- Enforce reviewed vendor prefixes for Memoric-specific keys.
- Prevent accidental use of reserved MCP prefixes for non-standard metadata.

Acceptance:
- Catalog tests fail on malformed or unreviewed extension identifiers.

### TASK-120: Add authorization challenge metadata

Files: `src/policy.rs`, `src/error.rs`, `docs/invocation-contract.md`

Work:
- Add machine-readable challenge metadata to `policy_denied` and `access_denied` results.
- Map local policy levels to future remote authorization scopes.
- Keep denial messages free of bypass instructions.

Acceptance:
- Remote-capable clients can explain authorization failures without weakening local policy gates.

### TASK-121: Add static server manifest drift tests

Files: `docs/`, `scripts/generate_tool_catalog.py`, `src/mcp/protocol.rs`

Work:
- Generate a static manifest with server identity, protocol revision, capabilities, resource list, tool catalog hash, docs links, and build provenance.
- Compare manifest content against `initialize`, `tools/list`, and `resources/list`.
- Keep local machine state out of the manifest.

Acceptance:
- Operators can inspect package/server compatibility without starting a privileged runtime.

### TASK-122: Design streamable HTTP session adapter

Files: `src/mcp/`, `src/stdio_server.rs`, `src/worker.rs`, `docs/architecture.md`

Work:
- Define session IDs, resumable event streams, cancellation boundaries, and request routing for a future HTTP transport.
- Document which state remains local-only versus transport-neutral.
- Preserve current STDIO and worker behavior.

Acceptance:
- Adding streamable HTTP later does not require rewriting handler contracts.

### TASK-123: Add transport-neutral request context

Files: `src/mcp/protocol.rs`, `src/audit.rs`, `src/mcp/tasks.rs`, `src/worker.rs`

Work:
- Introduce a shared request context carrying request ID, session ID, progress token, task ID, policy origin, app origin, audit correlation ID, and redaction profile.
- Replace scattered ad hoc extraction where safe.
- Keep legacy request parsing backward compatible.

Acceptance:
- Tool calls, tasks, audit, and worker IPC receive the same request metadata through one typed path.

### TASK-124: Add cross-transport conformance fixture runner

Files: `tests/`, `src/mcp/server.rs`, `src/stdio_server.rs`, `src/worker.rs`

Work:
- Build a fixture runner that replays the same JSON-RPC cases through the legacy handler, direct STDIO, elevated worker bridge, and future transport adapters.
- Cover initialize, pagination, tasks, resources, tool errors, notifications, and malformed requests.
- Isolate privileged worker tests behind explicit local opt-in.

Acceptance:
- Protocol behavior stays consistent across all supported transports.

### TASK-125: Add adversarial JSON-RPC fixture corpus

Files: `tests/`, `src/mcp/server.rs`, `docs/compatibility.md`

Work:
- Add malformed and adversarial cases for invalid ids, batch-like shapes, oversized params, invalid cursors, notification/request confusion, and bad JSON.
- Verify stable JSON-RPC error codes and no panics.
- Reuse fixtures across direct handler and transport tests.

Acceptance:
- Edge-case request handling is deterministic and documented.

## Wave N - Data Volume, Retention, and Observability

### TASK-126: Add bounded result pagination

Files: `src/memory/session.rs`, `src/orchestration/engine.rs`, `src/mcp/tools.rs`

Work:
- Add opaque cursor pagination for scan session candidates and orchestration logs.
- Use stable snapshot semantics so repeated pages do not reorder unexpectedly.
- Document page-size limits and invalid cursor behavior.

Acceptance:
- Large scan and orchestration outputs can be browsed without oversized MCP responses.

### TASK-127: Add artifact retention policy

Files: `src/artifact.rs`, `src/mcp/tool_result.rs`, `docs/safety-model.md`

Work:
- Track per-artifact expiry, hash, size, classification, and cleanup status.
- Add dry-run cleanup previews before deleting retained artifacts.
- Keep raw memory and credential-like artifacts out of inline model-visible output.

Acceptance:
- Artifact growth is bounded and cleanup decisions are explainable.

### TASK-128: Add operator-safe diagnostics bundle

Files: `src/capability.rs`, `src/policy.rs`, `src/audit.rs`, `docs/compatibility.md`

Work:
- Export compatibility matrix, policy hash, audit config, capability diff, catalog hash, and recent task summaries.
- Redact paths, raw target data, credentials, and raw memory by default.
- Include warnings for non-persistent audit paths or unsafe policy settings.

Acceptance:
- Operators can attach a safe diagnostic bundle to review or change-control records.

### TASK-129: Add tool ergonomics review gate

Files: `src/mcp/action_registry.rs`, `scripts/generate_tool_catalog.py`, `docs/tool-reference.md`

Work:
- Review action overlap, terse titles, selection hints, icon hints, and model-safe descriptions.
- Fail catalog tests for ambiguous or overly long action descriptions.
- Keep security semantics independent from display metadata.

Acceptance:
- Tool pickers remain readable and safe as the action catalog grows.

### TASK-130: Add observability timeline data model

Files: `src/audit.rs`, `src/mcp/tasks.rs`, `src/worker.rs`, `src/artifact.rs`

Work:
- Link MCP request, task lifecycle, progress notifications, audit entries, worker IPC events, and artifacts by correlation ID.
- Expose a read-only timeline data shape for future UI and troubleshooting.
- Apply classification-aware redaction before returning timeline entries.

Acceptance:
- A single operation can be explained end to end without manual log stitching or raw data exposure.

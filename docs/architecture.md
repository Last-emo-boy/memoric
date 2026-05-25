# Memoric Architecture

Memoric is a Rust MCP server that exposes a consolidated action-based tool surface over Windows process, memory, privilege, driver, and orchestration primitives.

## Runtime Modes

`src/main.rs` dispatches:

- default STDIO mode: `src/stdio_server.rs`
- proxy mode: `src/proxy.rs`
- worker mode: `src/worker.rs`

STDIO mode handles `initialize`, `tools/list`, resources, tasks, and ping locally. Tool calls execute directly when elevated or are forwarded to an elevated worker through named-pipe IPC. When the elevated worker owns a background task, task polling/result/cancel requests are forwarded to that worker.

Streamable HTTP is not exposed as a network listener in the current binary. `src/mcp/http_adapter.rs` implements an in-process adapter boundary for POST/GET/DELETE, protocol/session headers, SSE replay buffers, Origin checks, and transport metadata conversion, while `docs/streamable-http-adapter.md` defines the listener/security requirements that must be satisfied before enabling an actual socket.

## MCP Modules

- `src/mcp/tools.rs`: compatibility facade for public tool schema/list helpers.
- `src/mcp/tool_contract_tests.rs`: schema, catalog, manifest, metadata, guide, dispatch, payload envelope, redaction, and dry-run contract tests for the public MCP tool surface.
- `src/mcp/tool_schema.rs`: runtime `tools/list` schema definitions before registry enhancement.
- `src/mcp/*_tool.rs`: focused consolidated domain handlers for target, memory, inject, payload, hook, stealth, detect, privilege, kernel, self, and orchestration workflows.
- `src/mcp/tool_call.rs`: cross-cutting tool-call facade for legacy alias resolution, common argument normalization, runtime checks, policy, dry-run previews, dispatch, state tracing, audit, and observability.
- `src/mcp/tool_dispatch.rs`: standard consolidated-tool dispatch table and registry sync checks.
- `src/mcp/legacy_tools.rs`: legacy top-level tool alias conversion into consolidated action calls.
- `src/mcp/action_registry.rs`: action metadata, policy level, risk, annotations, common schema fields.
- `src/mcp/protocol.rs`: shared initialize, JSON-RPC request validation, error response, and tool result wrappers.
- `src/mcp/request_context.rs`: transport-neutral request metadata for request IDs, session IDs, progress tokens, task IDs, policy/app origin, audit correlation, and redaction profile.
- `src/mcp/http_adapter.rs`: in-process Streamable HTTP adapter model that validates HTTP transport headers, maps POST/GET/DELETE to the shared MCP helpers, manages optional 2025-11-25 session/SSE replay state, and runs the shared conformance fixtures without enabling a listener.
- `src/mcp/resources.rs`: shared MCP resource providers.
- `src/mcp/tasks.rs`: process-local task registry.
- `src/mcp/conformance.rs`: shared JSON-RPC fixture runner used by tests to compare transport-neutral behavior across legacy, STDIO, worker, and future adapters.
- `src/mcp/server.rs`: legacy/alternate MCP server path.
- `src/observability.rs`: read-only timeline assembly across MCP requests, task lifecycle, audit, worker IPC, and artifacts.

## Support Modules

- `src/args.rs`: shared parsing for MCP arguments such as PID/TID, addresses, sizes, byte payloads, protection flags, limits, and timeouts.
- `src/capability.rs`: read-only runtime readiness matrix for platform, elevation, SeDebug, policy, audit, target reachability, driver payload, driver device, test-signing, HVCI, VBS, and vulnerable driver blocklist signals.
- `src/policy.rs`: policy-level gate for tool calls, target allowlist enforcement, protected target override checks, and consent token validation.
- `src/audit.rs`: optional JSONL audit trail with sensitive argument redaction.
- `src/artifact.rs`: SHA-256 integrity metadata plus process-local artifact resource links for existing files reported by handlers.
- `src/redaction.rs`: `none`, `standard`, and `strict` redaction profiles plus schema-driven data classification rules for MCP output and audit arguments.
- `src/runtime.rs`: cooperative `timeout_ms` and task cancellation checks for long-running handlers.
- `src/info/process.rs`: process enumeration plus best-effort target fingerprinting for policy, including image name, executable path, parent PID, session ID, Authenticode signer identity, and Windows process protection level.
- `src/memory/diagnostics.rs`: read-only defensive memory diagnostics for layout, module, handle, suspicious-region, and bounded entropy summaries without returning raw bytes.
- `src/orchestration/templates.rs`: registered safe-by-default orchestration plan seeds for lab validation, memory diagnostics, driver readiness, reconnaissance, cleanup, and privilege review.

## Tool Call Flow

1. MCP client sends `tools/call`.
2. STDIO/worker parses tool name and arguments.
3. If `params.task` or legacy `as_task=true` is present, the call is queued only when the action is read-only or `dry_run=true`.
4. `src/mcp/tool_call.rs` resolves legacy aliases.
5. Common aliases are normalized.
6. `src/runtime.rs` checks `timeout_ms` and task cancellation request shape before dispatch.
7. Registry preflight validates per-action required parameters and registered choice parameters such as `memory(action='read').mode` and `memory(action='scan').scan_mode`.
8. Policy evaluates action metadata from the registry.
9. State-changing target calls are checked against `MEMORIC_TARGET_ALLOWLIST` when configured.
10. Protected or critical Windows targets require `allow_protected_target=true` or `MEMORIC_ALLOW_PROTECTED_TARGETS=1`.
11. `dry_run=true` state-changing calls return a preview with planned handle classes, required privilege markers, side effects, and rollback metadata, including action-specific coverage for payload cleanup, EDR suspension, hook detours/hardware breakpoints, thread hijack workflows, and target thread/string mutation.
12. Live handler dispatches through `src/mcp/tool_dispatch.rs` to the relevant consolidated handler.
13. Live memory writes/protection/allocation/free operations, target string writes, target thread suspend/resume operations, and hook mutations attach rollback descriptors and executable rollback actions when the handler captures original bytes, old page protection, allocated region addresses, thread suspend counts, IAT pointers, detour original bytes, hardware breakpoint debug-register state, or Windows hook handles; irreversible frees, partial resume restoration, and partial debug-register or Windows hook restoration report that explicitly.
14. Successful live state-changing tool results are normalized at the `tool_call` boundary with provenance metadata, so injection, stealth, driver, kernel, privilege, hook, target, and memory mutation methods remain traceable even when the leaf handler does not own its own provenance helper.
15. Result envelopes attach SHA-256 integrity metadata and artifact hashes for existing output files.
16. Existing file artifacts are registered as expiring `memoric://artifact/sha256/<hash>` resources and exposed through `structuredContent.artifacts[]`.
17. Redaction profile is applied to inline text/structured output, including strict redaction of rollback original-byte captures.
18. Audit records the policy/result status when configured.
19. Observability records safe timeline metadata for request, task, audit, worker IPC, and artifact boundaries.
20. Protocol wrapper returns text content, `structuredContent`, and `resource_link` content blocks when artifacts are available.

`params.task` creates a `working` task and returns a CreateTaskResult-style object; `tasks/result` later returns the original tool result with related-task metadata. The legacy `as_task=true` flag creates the same background task but returns the compatibility tool-result wrapper immediately. Handlers that opt into cooperative runtime checks can observe `tasks/cancel` and `timeout_ms` at safe boundaries.

Sampling-style task requests are deliberately gated off. `initialize` advertises task-augmented `tools/call` but marks `tasks.requests.sampling.createMessage.supported=false` and does not expose a top-level sampling capability. If future client-side `sampling/createMessage` support is added, it must attach to the same task registry, visibility scoping, TTL, cancellation, result-retention, and correlation metadata instead of creating a parallel state machine.

## Streamable HTTP Adapter

The Streamable HTTP boundary keeps transport state out of tool handlers:

- HTTP POST/GET/DELETE routing lives in `src/mcp/http_adapter.rs`, not in domain handlers.
- `MCP-Protocol-Version`, optional 2025-11-25 `Mcp-Session-Id`, SSE stream IDs, and `Last-Event-ID` replay cursors stay adapter-local.
- The adapter populates `McpRequestContext` with request ID, session ID, stream ID, progress token, task ID, policy origin, app origin, audit correlation ID, and redaction profile before dispatch.
- Task records remain in `src/mcp/tasks.rs`; `tasks/get` and `tasks/result` remain the fallback when SSE is unavailable or replay buffers expire.
- The elevated worker remains a named-pipe privilege boundary; worker notifications are expected to be converted into stream-aware events by the HTTP frontend, not by the worker itself.
- HTTP must bind localhost by default, validate `Origin`, enforce request size limits, and require explicit authentication before any remote bind is allowed.

HTTP listener implementation is intentionally deferred. Core and adversarial fixtures now cover legacy, direct STDIO, worker-style handling, in-process Streamable HTTP routing, real STDIO subprocess streams, and worker named-pipe replay. A future listener should reuse `StreamableHttpAdapter` rather than duplicating JSON-RPC dispatch.

## Registry And Schemas

The current tool schemas are still seeded in `src/mcp/tool_schema.rs`, then enhanced by `action_registry` with:

- `outputSchema`
- MCP annotations
- `execution.taskSupport="optional"`
- `x-memoric-actions`
- `x-memoric-data-classification`
- per-action `required_parameters` and `conditional_required_parameters` metadata used by runtime preflight, conditional JSON Schema enhancement, generated docs, static orchestration validation, and schema drift tests
- per-action `parameter_aliases` metadata used by runtime argument normalization
- per-action `choice_parameters` metadata used by schema enum enhancement, generated docs, runtime preflight validation, and handler error text
- per-action `parameter_bounds` metadata used by schema bound enhancement, generated docs, runtime preflight validation, and schema drift tests
- per-action `parser_hints` metadata derived from required parameters, aliases, choices, bounds, and parameter names; runtime preflight uses high-confidence hints such as PID/TID, address, unsigned integer, byte payload, wildcard byte pattern, and protection parsers before policy and live dispatch
- common fields: `dry_run`, `as_task`, `task_id`, `timeout_ms`, `artifact_retention_secs`, `purpose`, `request_id`, `consent_token`, `allow_protected_target`, `redaction`
- common numeric bounds for `timeout_ms` and `artifact_retention_secs`, enforced by the same registry-driven preflight path as action-specific bounds

`action_registry` owns `ToolDescriptor`, common input field descriptors, common input bounds, parameter alias descriptors, expanded memory choice parameter descriptors for read modes, typed primitive/endian values, scan modes, scan sub-parameters, and scan session value types, plus registry-backed stealth/kernel choice descriptors for syscall method, Sysmon/BCD/CI modes, Defender/MpCmdRun/firewall options, registry protection, notification callbacks, object hook actions, and many direct driver sub-mode fields such as DPC, port hide, global hook, auto-inject, PTE/MSR, PPL, callback nuke, minifilter detach, kernel APC, and WFP actions. It also owns an expanded set of per-action required parameter descriptors for actions with unconditional handler requirements, method-dependent conditional required descriptors such as `inject(action='shellcode')` payload requirements, including target inspection helpers, memory typed/session helpers, self introspection helpers, hook hardware-breakpoint/detour/restore helpers, stealth defensive/evasion helpers, legacy kernel callback helpers, object/registry callback helpers, minifilter/module helpers, driver-map entry points, and payload lifecycle helpers, plus initial per-action parameter bounds for high-risk stealth parameters such as `mutate_code.size`, `mutate_code.intensity`, and `sentinel_start.interval_ms`. Runtime argument normalization reads alias descriptors before policy and dispatch, runtime preflight checks registered required/conditional-required/choice/common-bounds/action-bounds descriptors plus derived parser hints, static orchestration validation consumes the same missing-parameter descriptors, and `tools/list` exposes the same aliases, required parameters, conditional required parameters, choice metadata, parameter bounds, and parser hints in `x-memoric-actions`; schema enhancement emits action-specific required/conditional-required/choice/bounds conditions while tool-level enum enhancement unions same-named choice parameters so shared fields stay valid until full action-conditional schemas exist. Future work should complete required-parameter coverage and move broader per-action bounds, remaining enum values, richer conditional action-specific schemas, and full schema generation into the registry.

`x-memoric-data-classification` tags output paths as `public`, `local-sensitive`, `credential-like`, `raw-memory`, `path`, or `artifact-reference`. The same registry rules are used by strict result redaction, so `tools/list`, generated docs, and runtime envelopes share one classification source.

Artifacts are process-local references rather than durable storage. `memoric://artifacts` lists retained artifact links, and `resources/read(uri='memoric://artifact/sha256/<hash>')` verifies the backing file hash before serving text or base64 content. Expired or changed artifacts fail closed. `self(action='state', sub_action='artifact_cleanup')` exposes a cleanup dry-run preview; reads and registry listing also remove expired entries opportunistically.

`memoric://timeline` and `self(action='state', sub_action='timeline')` assemble an operator-safe event stream from the process-local ring buffer, JSONL audit trail, task registry, worker IPC metadata, and artifact registry. Timeline events use `correlation_id`, `request_id`, `task_id`, and artifact URI links so one operation can be explained end to end without returning raw result payloads, progress tokens, raw memory, credentials, or full local paths.

Tool success envelopes include `metadata.result_strategy` as the shared large-result decision record. It identifies inline summaries, paginated pages, task/progress notification streams, and artifact/resource-link references, plus cursor/resource counts and the cancellation or timeout boundaries where callers can safely resume, poll, or stop. This keeps handler-specific result shapes behind a common MCP-facing contract.

## State

`src/state.rs` tracks:

- session ID
- target PID
- detected EDR products
- loaded driver
- applied evasion
- active injections
- stealth score
- kernel callback status

`src/mcp/tasks.rs` tracks task records for MCP polling, `tasks/result`, background read-only/dry-run calls, and cooperative cancellation requests. By default the registry is process-local. When `MEMORIC_TASKS_PATH` is configured, it writes a non-sensitive metadata snapshot containing status, summaries, progress counters, artifact references, and result integrity hashes; raw result payloads and progress tokens are not persisted, and live tasks are not resumed after restart.

`src/orchestration/engine.rs` has a separate metadata-only chain checkpoint store behind `MEMORIC_CHAIN_STATE_PATH`. Live `orchestrate(action='execute')` checkpoints chain creation, per-step running/completed/failed states, final status, `last_completed_step`, and `next_step` without writing shellcode, raw bytes, credentials, or full live results. Operators can inspect, preview resume, cancel, and cleanup persisted checkpoints by chain ID. Resumed execution is an explicit replay of the original authorized execute request with matching plan fingerprint and `skip_completed_steps=true`.

`self(action='state', sub_action='history')` reads the configured JSONL audit trail and returns paginated operation history with filters for tool, action, result status, PID, request ID, chain ID, and timestamp range.

`self(action='state', sub_action='mutations')` and `self(action='state', sub_action='rollback')` filter that history to audit entries with `state_change` metadata and return summary-only provenance, mutation, rollback, artifact, and integrity fields. Raw rollback bytes, raw memory, credentials, and full result payloads stay out of the state view.

`self(action='state', sub_action='replay')` reads the same audit trail, converts matching entries into static orchestration plan steps with `dry_run=true`, and reports what the current policy and capability planner would allow or block without executing recorded operations.

Scan session candidate lists are paginated through `memory(action='scan_list', session_id=...)` with bounded `limit`/`offset` or opaque `nextCursor` continuation. Candidates can be sorted by original index, address, or value in ascending or descending order, and `summary_only=true` returns only metadata/counts/snapshot information without inline candidate rows. Cursors bind to the scan session, `scan_count`, and sort mode, so clients get a clear invalid-cursor error instead of silently mixing pages from different scan snapshots. Raw, stealth, scattered, and physical memory read modes share the same large-output policy: small buffers can remain inline, while large buffers or explicit `output_path` requests are exported as retention-bound artifact resources. Target credential/SAM/Kerberos dump helpers, kernel PE dumps, and large kernel process-dump region lists also route through artifact references. Orchestration plan and execute result sections support bounded cursors; full static plans can be written to artifact resources with `output_path`, and oversized plan responses auto-export while keeping paginated sections inline.

## Test Targets

`examples/benign_test_target.rs` is an opt-in local process with stable marker bytes and a changing `u64` counter. It is intended for deterministic scanner and diagnostics validation against a process the operator explicitly launched.

## Driver Layer

`src/driver.rs` is the user-mode wrapper for `memoric.sys`. The driver payload path is `driver/memoric.sys`; it is read at runtime when needed instead of embedded at compile time.

`src/kernel.rs` handles generic driver/BYOVD helpers and higher-level kernel workflows.

Driver readiness is surfaced through `src/capability.rs`, `self(action='doctor')`, `kernel(action='status')`, and `memoric://capabilities`. These checks are probe-only; they do not load a driver or change privileges. `kernel(action='status')` packages signing, HVCI, vulnerable driver blocklist, device reachability, payload presence, and static offset registry support into a kernel-scoped status response before any live driver operation. `self(action='capability_diff')` compares the same readiness matrix against a saved baseline so operators can explain changed elevation, policy, audit, signing, HVCI/VBS, blocklist, or driver-readiness outcomes across runs. `self(action='next_steps')` consumes failed results, error text, stable error codes, or doctor output and returns only read-only diagnostics, dry-run previews, task polling, and documentation links.

`kernel(action='driver_discover')` consumes the same readiness signals and annotates discovered BYOVD candidates with `likely_blocked` plus `blocklist_evidence` for HVCI, vulnerable driver blocklist, and test-signing state. The annotation is advisory and read-only.

## Orchestration

`src/orchestration/engine.rs` supports environment assessment, explicitly opted-in execution, and static plan validation. `orchestrate(action='plan')` never executes live steps; it validates either caller-provided `steps` or a registered `template` from `src/orchestration/templates.rs`.

`orchestrate(action='templates')` is generated from the template registry instead of inline JSON in `tools.rs`. The `lab_validation` profile defaults to current-process `self` checks and only includes target-process diagnostics or marker reads when the caller passes an explicit benign test target PID/address.

The static planner consumes `src/capability.rs` and `src/policy.rs` signals. Plan output contains the full `plan`, an `effective_plan` filtered to steps allowed by current policy/capabilities, `blocked_steps` with skip reasons, and alternatives such as dry-run previews or read-only diagnostics. Live `orchestrate(action='execute', dry_run=false, allow_live_execution=true)` reuses the same planner decision before each step dispatch; optional blocked steps are skipped, while required blocked steps halt the chain and trigger dependency-aware rollback for already executed steps.

Assessment output is evidence-driven. `orchestrate(action='assess')` keeps compatibility fields such as `detected_products` and `detection_methods`, and adds `evidence.security_products`, `evidence.environment_properties`, and `evidence.assessment_inputs` entries with method, confidence, timestamp, and raw evidence summaries.

Large orchestration plan and execution result arrays support bounded pagination when callers pass `limit`, `offset`, or `cursor`. Cursor fingerprints bind to the result snapshot, so stale continuation tokens fail explicitly when the underlying plan, effective plan, blocked steps, results, or failures change.

## Diagnostics Bundle

`src/capability.rs` builds the operator-safe diagnostics bundle behind `self(action='diagnostics')`. It reuses capability/policy/task/catalog state, strips full local paths to basename/hash-only markers, omits task result payloads, writes a JSON file artifact, and relies on `src/artifact.rs` plus MCP `resource_link` content blocks for retention-bound retrieval.

## Generated Documentation

`scripts/generate_tool_catalog.py` starts the runtime binary, calls `initialize` and `tools/list`, then writes:

- `docs/tool-catalog.json`
- `docs/tool-reference.md`
- `docs/server-manifest.json`

CI verifies these generated docs are committed.

Tool ergonomics metadata is generated from `src/mcp/action_registry.rs` as `x-memoric-display` plus mirrored `annotations.memoric` fields. It includes display title, icon hint, and selection hint for tool pickers. The metadata is linted for concise, model-safe descriptions and is kept separate from policy traits such as `required_policy`, `read_only`, and `destructive`.

## Compatibility

`docs/compatibility.md` tracks the caller-facing compatibility matrix for MCP protocol features, tasks/progress, resources, planned MCP Apps support, Windows capability assumptions, non-Windows fallback behavior, and test coverage. Update it when advertised protocol capabilities or platform support change.

# Memoric Maestro Iteration Backlog - 2026-05-21

## Context

Goal: continue iterating Memoric into a stronger, more professional MCP-based Windows research and authorized red-team control plane.

Design bias: improve power through reliability, compatibility, observability, operator safety, evidence quality, testability, and workflow intelligence. Avoid making the product stronger only by adding more destructive primitives.

Current repository anchors:

- Active entry: `src/main.rs`, `src/stdio_server.rs`
- Tool surface: `src/mcp/tools.rs`
- Session state: `src/state.rs`
- Orchestration: `src/orchestration/engine.rs`
- Driver wrapper: `src/driver.rs`
- Kernel/BYOVD bridge: `src/kernel.rs`

External design inputs checked:

- MCP latest specification `2025-11-25`: Tasks utility, tool metadata, structured tool results, authorization and elicitation updates.
- MCP security guidance: user consent, tool/result visibility, tool poisoning and confused-deputy risk mitigation.
- Microsoft driver block rules and Windows driver signing requirements for operational compatibility checks.

## Product Direction

Memoric should evolve from "large action catalog" to "auditable MCP operation platform":

1. Every powerful action has preflight checks, capability gating, dry-run preview, and structured result contracts.
2. Long operations become resumable MCP tasks with progress reporting.
3. Tool outputs become machine-readable first, human-readable second.
4. Driver and kernel features become environment-aware with compatibility warnings.
5. Orchestration becomes policy-aware and evidence-driven instead of just chaining actions.
6. Tests focus on parameter normalization, JSON-RPC behavior, state mutation, and safe local-only primitives.

## Wave 1 - MCP Protocol Modernization

### TASK-001: Upgrade MCP initialize metadata

Files: `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/server.rs`

Work:
- Align `protocolVersion` handling with latest supported MCP version negotiation.
- Return consistent `serverInfo.version` from `env!("CARGO_PKG_VERSION")`.
- Add declared capabilities for tools, resources, prompts, logging/progress where implemented.

Acceptance:
- `initialize` response is identical across STDIO, worker, and legacy server path where retained.
- Version no longer diverges between `0.1.0`, `0.3.0`, and Cargo package version.

### TASK-002: Add tool output schemas

Files: `src/mcp/tools.rs`

Work:
- Add `outputSchema` for the 12 consolidated tools.
- Define shared result envelopes: `success`, `code`, `message`, `context`, `artifacts`, `warnings`, `evidence`.
- Keep backward-compatible text content wrapping.

Acceptance:
- Each public tool has both `inputSchema` and `outputSchema`.
- Common error payload validates against the shared schema.

### TASK-003: Return structuredContent for tool results

Files: `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/server.rs`

Work:
- Wrap successful tool calls with MCP `structuredContent` plus text summary.
- Preserve text-only behavior for older clients.
- Add a compatibility toggle if needed.

Acceptance:
- MCP clients can read JSON result without parsing `content[0].text`.
- Existing text behavior remains available.

### TASK-004: Add tool annotations/readOnly hints

Files: `src/mcp/tools.rs`

Work:
- Tag actions as read-only, state-changing, privileged, destructive, kernel-level, or requires-target.
- Surface annotations in tool metadata.

Acceptance:
- `target(ps_list)`, `detect(*)`, `self(info)` are marked read-only.
- Injection, stealth mutation, driver load, write, kill/delete style actions are marked state-changing or destructive.

### TASK-005: Add MCP Tasks support for long-running operations

Files: `src/stdio_server.rs`, `src/mcp/tasks.rs` new, `src/state.rs`

Work:
- Implement a lightweight task registry for long-running scans, orchestration chains, driver discovery, and large memory reads.
- Add task IDs, progress states, cancellation, and result retrieval.

Acceptance:
- `orchestrate(action='execute', dry_run=false)` can run as a task.
- Caller can poll status and retrieve final result.

### TASK-006: Add progress notifications

Files: `src/stdio_server.rs`, `src/worker.rs`, `src/orchestration/engine.rs`

Work:
- Emit progress for scan sessions, orchestration steps, and driver discovery.
- Include total steps, current step, phase, and safe summary.

Acceptance:
- Long workflows no longer appear hung to MCP clients.

### TASK-007: Introduce elicitation/consent flow

Files: `src/mcp/consent.rs` new, `src/stdio_server.rs`, `src/mcp/tools.rs`

Work:
- Add consent checkpoint metadata for privileged or destructive actions.
- Support explicit consent tokens in tool arguments.
- In non-interactive clients, return a structured consent-required error.

Acceptance:
- State-changing privileged actions can be blocked unless consent token is present.
- Dry-run calls do not require consent token.

### TASK-008: Normalize JSON-RPC error handling

Files: `src/stdio_server.rs`, `src/worker.rs`, `src/mcp/server.rs`, `src/mcp/tools.rs`

Work:
- Standardize parse, method, parameter, internal, and tool errors.
- Keep MCP `tools/call` errors as tool result errors where appropriate.

Acceptance:
- No silent parse failures in STDIO path.
- Notifications still produce no response.

## Wave 2 - Safety, Policy, and Authorization

### TASK-009: Add policy engine

Files: `src/policy.rs` new, `src/mcp/tools.rs`

Work:
- Define policy levels: `observe`, `research`, `lab-write`, `privileged`, `kernel`, `destructive`.
- Gate actions based on environment variables or config file.

Acceptance:
- Default policy allows read-only/self-test only unless configured.
- Policy denial returns structured error with required capability.

### TASK-010: Add per-action risk registry

Files: `src/mcp/action_registry.rs` new, `src/mcp/tools.rs`

Work:
- Move action metadata out of giant string constants into typed registry entries.
- Include risk, read/write behavior, privilege needs, target needs, output shape, and aliases.

Acceptance:
- `is_known_tool_action` uses registry.
- Guide output and schema generation are derived from same registry.

### TASK-011: Add allowlist target policy

Files: `src/policy.rs`, `src/info/process.rs`, `src/mcp/tools.rs`

Work:
- Support PID/name allowlist for state-changing operations.
- Add process identity fingerprint: pid, exe path, parent, session, signer if available.

Acceptance:
- Writes/injection/stealth changes fail if target is outside allowlist.

### TASK-012: Add protected process guardrails

Files: `src/policy.rs`, `src/info/process.rs`, `src/kernel.rs`

Work:
- Detect critical Windows processes and protected process light status.
- Require explicit override for high-risk targets.

Acceptance:
- Read-only operations can report protection state.
- State-changing operations require override and policy capability.

### TASK-013: Add dry-run planner to every state-changing action

Files: `src/mcp/tools.rs`, action modules

Work:
- Introduce common `dry_run` semantics.
- Return planned handles, required privileges, likely side effects, rollback availability.

Acceptance:
- At least memory write/protect, driver load/unload, injection, stealth patching, and privilege actions support dry-run preview.

### TASK-014: Add rollback metadata

Files: `src/state.rs`, `src/opsec_cleanup.rs`, action modules

Work:
- Record rollback handles/data for reversible actions where feasible.
- Distinguish reversible, partially reversible, and irreversible actions.

Acceptance:
- `self(action='state')` shows rollback opportunities.
- Cleanup can target a specific chain/task ID.

### TASK-015: Add audit log

Files: `src/audit.rs` new, `src/mcp/tools.rs`, `src/state.rs`

Work:
- Append JSONL audit entries for every tool call: timestamp, tool, action, arguments redacted, policy decision, result status.
- Add secret redaction for shellcode, keys, tokens, paths if configured.

Acceptance:
- Audit log path is configurable.
- No raw shellcode appears by default.

### TASK-016: Add command provenance

Files: `src/state.rs`, `src/mcp/tools.rs`

Work:
- Attach `request_id`, `task_id`, `chain_id`, and caller-provided `purpose` to state changes.

Acceptance:
- Every recorded evasion/injection/driver operation can be traced to a tool call.

## Wave 3 - Reliability and Typed Core

### TASK-017: Split `src/mcp/tools.rs`

Files: `src/mcp/tools.rs`, `src/mcp/tool_registry.rs`, `src/mcp/handlers/*.rs`

Work:
- Move schemas, dispatch, error formatting, guide, and domain handlers into separate modules.
- Preserve public `register_tools()` and `call_tool()`.

Acceptance:
- No behavior change.
- `tools.rs` becomes a small facade.

### TASK-018: Replace string action constants with typed enums

Files: `src/mcp/action_registry.rs`, `src/mcp/handlers/*.rs`

Work:
- Generate enums or typed action descriptors for each domain.
- Keep alias normalization.

Acceptance:
- Unknown actions are detected through typed registry.
- Guide and schemas are generated from typed descriptors.

### TASK-019: Centralize parameter parsing

Files: `src/args.rs` new, `src/util.rs`, `src/mcp/tools.rs`

Work:
- Add typed parsers for pid, tid, address, size, bytes, hex string, protection flags, module names.
- Remove repeated manual parsing.

Acceptance:
- Hex string and integer parsing behavior is consistent across all tools.

### TASK-020: Add bounded input validation

Files: `src/args.rs`, action modules

Work:
- Enforce max sizes, max result counts, path length, chunk size, timeout, and allowed enum values.
- Add validation errors before opening handles.

Acceptance:
- Large reads/scans cannot accidentally allocate unbounded memory.

### TASK-021: Add error code taxonomy

Files: `src/error.rs`, `src/mcp/tools.rs`

Work:
- Define stable tool error codes: `missing_param`, `invalid_target`, `access_denied`, `policy_denied`, `driver_unavailable`, `partial_read`, `unsupported_platform`, `timeout`.

Acceptance:
- Tool errors use stable machine-readable codes.

### TASK-022: Add capability detection layer

Files: `src/capability.rs` new, `src/orchestration/engine.rs`, `src/mcp/tools.rs`

Work:
- Detect OS build, architecture, elevation, SeDebug status, driver availability, test signing, WDAC/blocklist state, virtualization indicators.

Acceptance:
- `memoric(status=true)` returns capabilities matrix.
- Orchestration uses capabilities instead of guessing.

### TASK-023: Add platform fallback strategy

Files: `src/capability.rs`, `src/mcp/tools.rs`

Work:
- If unsupported platform or non-Windows environment, allow schema/list/status/self-test but block Windows operations cleanly.

Acceptance:
- `cargo test` on non-Windows can compile with cfg-gated stubs, or unsupported paths fail gracefully.

### TASK-024: Add timeout/cancellation primitives

Files: `src/runtime.rs` new, scan/orchestration modules

Work:
- Support per-action timeout.
- Wire cancellation into MCP task registry.

Acceptance:
- Long scan/orchestration can be cancelled.

## Wave 4 - Driver and Kernel Compatibility

### TASK-025: Driver blocklist awareness

Files: `src/kernel.rs`, `src/capability.rs`

Work:
- Detect vulnerable driver blocklist / WDAC policy state where possible.
- Warn when a BYOVD path is likely blocked.

Acceptance:
- `kernel(action='driver_discover')` includes `likely_blocked` and evidence fields.

### TASK-026: Driver signing readiness checks

Files: `src/driver.rs`, `driver/README.md`

Work:
- Add a check command that reports signing/test-signing/readiness status.
- Document supported build/signing flow.

Acceptance:
- `self(info)` or `kernel(status)` shows driver deploy readiness.

### TASK-027: IOCTL contract verification

Files: `src/driver.rs`, `driver/memoric.h`, tests/build script

Work:
- Add compile-time or test-time checks for Rust struct sizes and IOCTL constants matching the C header.

Acceptance:
- Mismatch fails tests before runtime.

### TASK-028: Driver capability handshake

Files: `src/driver.rs`, `driver/memoric.c`, `driver/memoric.h`

Work:
- Add driver version/capabilities IOCTL.
- User mode refuses unsupported driver versions unless override is set.

Acceptance:
- Driver wrapper reports version and feature bitmap.

### TASK-029: Safe driver loading lifecycle

Files: `src/driver.rs`, `src/kernel.rs`

Work:
- Track service creation, start, stop, deletion, handle open, and cleanup separately.
- Add idempotent unload/delete behavior.

Acceptance:
- Failed load attempts return exact stage and cleanup status.

### TASK-030: Kernel operation preflight

Files: `src/kernel.rs`, `src/driver.rs`

Work:
- Require preflight before kernel mutation: driver open, version, capability, OS build, offset availability, policy capability.

Acceptance:
- Kernel mutation reports why it is unsafe/unsupported before attempting.

### TASK-031: Offset profile registry

Files: `src/kernel_offsets.rs` new, `src/driver.rs`, `src/kernel.rs`

Work:
- Centralize EPROCESS/MMVAD/etc. offsets by OS build.
- Add unknown-build behavior.

Acceptance:
- Hard-coded offsets are minimized and reported with confidence.

## Wave 5 - Orchestration Intelligence

### TASK-032: Convert orchestration to graph execution

Files: `src/orchestration/engine.rs`

Work:
- Replace linear chain with DAG of steps, dependencies, required/optional flags, rollback hooks, preconditions.

Acceptance:
- Dry-run plan shows DAG, dependencies, and skip reasons.

### TASK-033: Add orchestration policy planner

Files: `src/orchestration/engine.rs`, `src/policy.rs`

Work:
- Planner selects only actions allowed by current policy and capabilities.
- Return alternatives when a step is blocked.

Acceptance:
- A restricted policy produces a valid read-only assessment plan.

### TASK-034: Add evidence-driven assessment

Files: `src/orchestration/engine.rs`, `src/evasion/edr.rs`, `src/capability.rs`

Work:
- Each detected security product or environment property includes method, confidence, timestamp, and raw evidence summary.

Acceptance:
- Assessment output is explainable and machine-readable.

### TASK-035: Add chain templates registry

Files: `src/orchestration/templates.rs` new

Work:
- Move templates out of JSON literals in `tools.rs`.
- Add categories: reconnaissance, memory diagnostics, driver readiness, authorized lab validation, cleanup.

Acceptance:
- `orchestrate(action='templates')` is generated from registry.

### TASK-036: Add resumable chain state

Files: `src/state.rs`, `src/orchestration/engine.rs`, `src/mcp/tasks.rs`

Work:
- Persist chain execution progress.
- Resume, cancel, or cleanup by chain ID.

Acceptance:
- Interrupted chain can report last completed step.

### TASK-037: Add dependency-aware rollback

Files: `src/orchestration/engine.rs`, `src/opsec_cleanup.rs`

Work:
- Execute rollback in reverse dependency order.
- Skip irreversible steps and report them.

Acceptance:
- Failed required step triggers rollback where available.

## Wave 6 - Memory and Scanner Strengthening

### TASK-038: Memory region cache

Files: `src/memory/session.rs`, `src/memory/scanner.rs`, `src/memory/reader.rs`

Work:
- Cache region queries per PID with freshness controls.
- Use cache in scans to avoid repeated expensive queries.

Acceptance:
- Scan output reports region cache age and coverage.

### TASK-039: Scan result pagination

Files: `src/memory/session.rs`, `src/mcp/tools.rs`

Work:
- Add `limit`, `offset`, `sort`, and `summary_only` for large result sets.

Acceptance:
- Large scan sessions do not produce oversized MCP responses.

### TASK-040: Add scan diff summaries

Files: `src/memory/session.rs`

Work:
- Track added/removed/changed candidate counts between scan rounds.

Acceptance:
- `scan_next` returns concise delta metrics.

### TASK-041: Add typed read/write helpers

Files: `src/memory/struct_rw.rs`, `src/mcp/tools.rs`

Work:
- Support safe typed reads/writes for primitive numeric types with endian and alignment metadata.

Acceptance:
- Caller can read/write `u8/u16/u32/u64/i32/f32/f64` without manual byte arrays.

### TASK-042: Add memory artifact export

Files: `src/memory/reader.rs`, `src/audit.rs`

Work:
- Allow large reads/dumps to be saved to artifact files instead of inline MCP payloads.
- Return hash, path, byte count, and redaction status.

Acceptance:
- Responses stay small while preserving evidence.

### TASK-043: Add local-only memory test harness

Files: `src/memory/reader.rs`, `src/memory/writer.rs`, tests

Work:
- Expand current self-test into deterministic tests for read/write/protect/alloc/free/scan on current process only.

Acceptance:
- No external target process needed for CI smoke tests.

## Wave 7 - Observability and Operator UX

### TASK-044: Add `self(action='doctor')`

Files: `src/mcp/tools.rs`, `src/capability.rs`

Work:
- Return environment health: admin, debug privilege, MCP mode, worker connectivity, driver readiness, policy level, audit path.

Acceptance:
- First-call troubleshooting is one tool call.

### TASK-045: Add `self(action='explain_error')`

Files: `src/mcp/tools.rs`, `src/error.rs`

Work:
- Given an error payload, return likely causes and safe next diagnostic calls.

Acceptance:
- Common Windows errors map to actionable diagnostics.

### TASK-046: Add operation history filters

Files: `src/state.rs`, `src/mcp/tools.rs`

Work:
- Query state history by tool, action, PID, chain ID, time range, status.

Acceptance:
- `self(action='state')` supports filters and pagination.

### TASK-047: Add resource providers for capabilities and audit

Files: `src/mcp/server.rs`, `src/stdio_server.rs`, resource handlers

Work:
- Expose `memoric://capabilities`, `memoric://policy`, `memoric://audit/recent`, `memoric://tasks`.

Acceptance:
- MCP clients can inspect state without invoking tools.

### TASK-048: Add concise human summaries

Files: `src/mcp/tools.rs`

Work:
- Each tool result includes `summary` suitable for UI display.
- Keep full details in structured fields/artifacts.

Acceptance:
- No MCP response requires reading huge JSON to understand outcome.

## Wave 8 - Testing and CI

### TASK-049: Add JSON-RPC protocol tests

Files: tests or `src/stdio_server.rs` test helpers

Work:
- Test initialize, tools/list, ping, notifications, bad JSON, unknown method, missing params.

Acceptance:
- Protocol regressions are caught without Windows privileged features.

### TASK-050: Add schema snapshot tests

Files: tests, `src/mcp/tools.rs`

Work:
- Snapshot registered tool schemas and action lists.
- Require intentional update when surface changes.

Acceptance:
- Accidental schema drift is visible.

### TASK-051: Add action registry tests

Files: tests, `src/mcp/action_registry.rs`

Work:
- Validate every schema action has a dispatch handler and guide entry.
- Validate every legacy alias maps to a known action.

Acceptance:
- No tool lists an action that cannot dispatch.

### TASK-052: Add policy tests

Files: tests, `src/policy.rs`

Work:
- Test allowed/denied matrix for read-only, state-changing, privileged, kernel, destructive actions.

Acceptance:
- Default policy blocks risky operations.

### TASK-053: Add orchestration dry-run tests

Files: `src/orchestration/engine.rs`

Work:
- Test plan generation under low/medium/high capability profiles.
- Ensure dry-run never executes live actions.

Acceptance:
- Dry-run path is deterministic and side-effect free.

### TASK-054: Add driver wrapper compile checks

Files: `src/driver.rs`, tests

Work:
- Assert struct sizes, constants, and response parsing.
- Use mocks for DeviceIoControl where practical.

Acceptance:
- User-mode/driver contract drift is caught.

### TASK-055: Add CI matrix

Files: `.github/workflows/*.yml`

Work:
- Run format, clippy, unit tests, schema tests.
- Separate privileged Windows integration tests from default CI.

Acceptance:
- Default CI never requires admin or a driver.

## Wave 9 - Documentation and Generated Catalog

### TASK-056: Regenerate tool catalog from registry

Files: `scripts/generate_tool_catalog.py`, `src/mcp/action_registry.rs`, docs

Work:
- Make docs generated from typed registry, not duplicated strings.

Acceptance:
- Runtime schema and docs cannot disagree.

### TASK-057: Add invocation contract v2

Files: `docs/invocation-contract.md`

Work:
- Document structuredContent, outputSchema, consent token, policy denial, task polling, artifact outputs.

Acceptance:
- MCP caller can integrate without reading source.

### TASK-058: Add safety model document

Files: `docs/safety-model.md`

Work:
- Explain policy levels, consent, audit, target allowlist, dry-run, rollback, and protected-process guards.

Acceptance:
- Operational boundaries are explicit.

### TASK-059: Add troubleshooting guide

Files: `docs/troubleshooting.md`

Work:
- Cover UAC, worker pipe, access denied, partial copy, driver unavailable, schema/client mismatch.

Acceptance:
- Common support questions have documented answers.

### TASK-060: Add developer architecture map

Files: `docs/architecture.md`

Work:
- Document mode dispatch, MCP request flow, worker IPC, action registry, policy checks, state mutation, driver lifecycle.

Acceptance:
- New contributor can find the right module quickly.

## Wave 10 - Refined Feature Additions

### TASK-061: Add defensive memory diagnostics profile

Files: `src/orchestration/templates.rs`, `src/mcp/tools.rs`

Work:
- Provide a read-only workflow to inspect process memory layout, modules, handles, suspicious regions, and entropy.

Acceptance:
- Useful in blue-team/lab analysis without mutation.

### TASK-062: Add lab validation profile

Files: `src/orchestration/templates.rs`

Work:
- Provide a controlled self-target workflow that validates memory/injection primitives only against the current process or a spawned benign test process.

Acceptance:
- Users can verify installation without touching unrelated processes.

### TASK-063: Add benign test target helper

Files: `examples/`, `src/self_test_target.rs` optional

Work:
- Add a small opt-in test process with known memory markers and lifecycle controls.

Acceptance:
- Scanners can be tested deterministically.

### TASK-064: Add artifact hashing

Files: `src/artifact.rs` new, memory/driver dump modules

Work:
- Hash exported artifacts with SHA-256 or available crypto implementation.

Acceptance:
- Dumps and logs include integrity metadata.

### TASK-065: Add result redaction profiles

Files: `src/redaction.rs` new, `src/mcp/tools.rs`

Work:
- Support `none`, `standard`, `strict` redaction modes for paths, tokens, shellcode, raw bytes, credentials.

Acceptance:
- Strict mode never returns raw sensitive bytes inline.

## Suggested Execution Order

1. TASK-017, TASK-010, TASK-018, TASK-019: create typed registry foundation.
2. TASK-001 to TASK-008: modernize MCP compatibility.
3. TASK-009 to TASK-016: add policy, audit, consent, and provenance.
4. TASK-049 to TASK-055: lock behavior with tests.
5. TASK-032 to TASK-037: make orchestration genuinely robust.
6. TASK-025 to TASK-031: harden driver compatibility.
7. TASK-056 to TASK-060: generate docs from source of truth.

## Immediate "Next 10" Candidate Tasks

These are the best first tasks because they strengthen the whole codebase without adding risky new primitives:

1. Split `src/mcp/tools.rs` into registry/dispatch/handlers.
2. Build typed action registry with risk metadata.
3. Generate schemas and guide output from registry.
4. Add structuredContent responses.
5. Add stable outputSchema and result envelope.
6. Add default policy engine.
7. Add audit JSONL with redaction.
8. Add protocol tests for STDIO JSON-RPC.
9. Add schema/action coverage tests.
10. Add `self(action='doctor')` capability diagnostics.


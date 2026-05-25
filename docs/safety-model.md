# Memoric Safety Model

Memoric is intended for authorized lab and security research environments. The safety model is designed to make powerful operations explicit, auditable, and policy-gated.

## Policy Levels

Policy is controlled by `MEMORIC_POLICY`.

| Level | Purpose |
|---|---|
| `observe` | Default. Allows read-only operations and dry-run previews. |
| `research` | Allows read-oriented process, memory, and detection work. |
| `lab-write` | Allows controlled write/mutation operations in authorized lab targets. |
| `privileged` | Allows privilege-sensitive operations. |
| `kernel` | Allows kernel/driver operations. |
| `destructive` | Allows explicitly destructive operations. |

Unknown or unset policy falls back to `observe`.

## Policy Profiles

Policy can also be loaded from a JSON profile file by setting `MEMORIC_POLICY_PROFILE_PATH`.
The profile file should contain at least:

- `profile`: a stable identity string
- `version`: a monotonic integer version
- `policy`: the configured policy level string

Optional verification sidecars are supported:

- `<profile-file>.sha256` for a SHA-256 hash check
- `<profile-file>.sig` for an HMAC-SHA256 check when `MEMORIC_POLICY_PROFILE_SIGNATURE_KEY` is set

Malformed profiles, hash mismatches, signature mismatches, and downgrade attempts fail closed by default. In local debug builds only, `MEMORIC_POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE=1` can override that fail-closed behavior for development workflows.

The active profile identity and verification status are exposed through `resources/read(uri='memoric://policy')`, `self(action='doctor')`, and audit entries.

## Action Classification

The action registry assigns metadata to every consolidated tool action:

- read-only
- state-changing
- privileged
- kernel
- destructive
- requires target
- risk
- required policy

This metadata is emitted in `tools/list` as annotations and `x-memoric-actions`.

## Default Behavior

By default:

- Read-only operations are allowed.
- State-changing operations are denied unless policy allows them.
- State-changing `dry_run=true` calls return a preview and skip the live handler.
- Denials are returned as structured tool errors.

## Consent Token

If `MEMORIC_CONSENT_TOKEN` is configured, callers can provide `consent_token`. Consent is not a replacement for policy; it only provides an additional explicit operator acknowledgement.

## Target Allowlist

`MEMORIC_TARGET_ALLOWLIST` can restrict state-changing operations to known lab targets. Entries are comma, semicolon, or newline separated and support:

- `pid:<id>`
- `name:<process.exe>`
- `path:<full\path\to\process.exe>`

When the allowlist is configured, writes, injection, hook, stealth, privilege, kernel, and other state-changing target operations are denied if their target cannot be matched. Read-only calls are still allowed so operators can discover and verify targets before mutation.

## Protected Target Guard

State-changing calls against critical Windows targets or protected process levels require an explicit override in addition to the normal policy level. The guard uses a best-effort process fingerprint with PID, image name, executable path, parent PID, session ID, Authenticode signer identity, and Windows process protection level.

Use `allow_protected_target=true` on an individual tool call, or set `MEMORIC_ALLOW_PROTECTED_TARGETS=1` for an authorized lab session. Dry-run calls remain allowed without this override.

## Audit

If `MEMORIC_AUDIT_PATH` is configured, every tool call is appended as JSONL with:

- timestamp
- tool/action
- redacted arguments
- request ID and purpose
- policy decision
- result status
- error, if any
- result integrity metadata
- artifact hash metadata when result paths point to existing files

## Result Redaction

Result redaction is controlled by the per-call `redaction` argument or `MEMORIC_REDACTION`.

| Profile | Behavior |
|---|---|
| `none` | Return values unchanged. Use only in controlled local debugging. |
| `standard` | Redact payloads, shellcode, keys, tokens, passwords, secrets, and consent tokens. |
| `strict` | Also redact raw byte arrays, hex blobs, credential-like fields, and paths from inline output. |

Strict mode keeps structured success/error envelopes and integrity metadata, but suppresses raw sensitive bytes inline.

The tool registry also emits `x-memoric-data-classification` in `tools/list`. Output paths can be tagged as `public`, `local-sensitive`, `credential-like`, `raw-memory`, `path`, or `artifact-reference`. Strict redaction uses these rules first, then falls back to legacy key/name heuristics for older result shapes.

## Artifact Integrity

Successful tool result envelopes include SHA-256 integrity metadata for the JSON result. If a handler reports an existing file path through fields such as `dump_file`, `output_path`, or successful `path` entries, the envelope and audit log include artifact metadata with file size and SHA-256.

## Defensive Diagnostics

`memory(action='diagnostics')` and `self(action='memory_diagnostics')` are read-only diagnostics paths. They summarize process memory layout, modules, handles, suspicious region labels, and bounded entropy samples without returning raw bytes or changing target state.

For deterministic local validation, `examples/benign_test_target.rs` is opt-in and only targets a process the operator explicitly launches. It prints stable marker and counter addresses for scanner validation.

## Lab Validation Template

`orchestrate(action='plan', template='lab_validation')` is static planning only and reports `executes_live_actions=false`. With no target arguments, it contains only current-process `self` checks. Target-process diagnostics and marker reads are generated only when the caller provides an explicit `benign_pid` and address values from `examples/benign_test_target.rs`.

The optional counter mutation check is always a `memory(action='write', dry_run=true)` preview step, so the lab validation template never mutates the target by default.

## Policy-Aware Planning

`orchestrate(action='plan')` uses the action registry, active `MEMORIC_POLICY`, and runtime capability matrix to build an `effective_plan`. Steps blocked by policy, unsupported platform, missing elevation, or driver readiness stay in `blocked_steps` with machine-readable reasons and safer alternatives. This is advisory planning only; it does not bypass the live policy gate used by `tools/call`.

## Driver Payload

`driver/memoric.sys` is loaded at runtime if available. It is no longer embedded at compile time, so missing driver artifacts do not break ordinary build/test flows. `self(action='doctor')` reports whether the payload exists and whether the device is reachable.

`kernel(action='driver_discover')` is a read-only compatibility check. It annotates discovered BYOVD candidates with `likely_blocked` and `blocklist_evidence` based on HVCI, vulnerable driver blocklist, and test-signing readiness signals. These fields are warnings for planning and troubleshooting; they are not consent, authorization, or a bypass path.

## Operator Checks

Recommended first calls:

1. `self(action='doctor')`
2. `memoric(status=true)`
3. `resources/read(uri='memoric://policy')`
4. `resources/read(uri='memoric://capabilities')`

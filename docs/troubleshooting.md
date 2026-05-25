# Memoric Troubleshooting

Use `self(action='doctor')` first. It reports policy, elevation, driver payload state, driver device reachability, and general readiness.

## Policy Denied

Symptoms:

- Tool result contains `policy_denied`.
- State-changing action does not execute.

Checks:

- `self(action='next_steps', result=<failed-result>)`
- `resources/read` with `memoric://policy`
- `self(action='doctor')`

Fix:

- Use `dry_run=true` for preview.
- Resolve the policy mismatch only after confirming the operation is authorized and the `next_steps` output points to the relevant read-only diagnostics.

## Access Denied

Symptoms:

- Windows API error includes access denied.
- Process open, memory read/write, or token operations fail.

Checks:

- `privilege(action='check', dry_run=true)`
- `self(action='doctor')`
- Confirm target PID and protection state.

Fix:

- Run with the required privileges.
- Avoid protected/system processes unless explicitly authorized and policy-gated.

## Worker Pipe Closed

Symptoms:

- Error mentions pipe, broken pipe, IPC closed, or worker unavailable.

Checks:

- Confirm the UAC prompt was accepted.
- Retry the call; STDIO mode drops broken worker state and respawns on the next call.

Fix:

- Start the MCP client as Administrator for privileged sessions.
- Use default STDIO mode for read-only work.

## Driver Unavailable

Symptoms:

- `memoric.sys device is not reachable`.
- Kernel-backed actions fail.

Checks:

- `kernel(action='status')` for probe-only signing, HVCI, blocklist, payload, device, and offset readiness.
- `self(action='doctor')`
- `resources/read(uri='memoric://capabilities')`
- `kernel(action='driver_discover')` and inspect `likely_blocked` plus `blocklist_evidence`.
- Confirm `driver/memoric.sys` exists.

Fix:

- Build the driver separately.
- Load a supported explicit driver path where appropriate.
- Check Windows driver signing/test-signing requirements, HVCI/Memory Integrity state, and vulnerable driver blocklist signals.

## Worked Yesterday, Blocked Today

Symptoms:

- A workflow that previously passed is now blocked by policy, driver readiness, signing, or platform checks.
- `self(action='doctor')` shows different elevation, audit, HVCI/VBS, blocklist, or driver state than expected.

Checks:

- Save the prior `memoric://capabilities` or `self(action='doctor')` output as a baseline.
- Run `self(action='capability_diff', baseline_path='path\\to\\baseline.json')`.
- If the prior workflow was audited, run `self(action='state', sub_action='replay', chain_id='<chain>')` to see which recorded steps current policy and capabilities would now allow or block.

Fix:

- Use the reported `changes[]` paths to identify the changed setting.
- Prefer read-only diagnostics and dry-run previews until the environment difference is understood.

## Partial Read

Symptoms:

- Error mentions partial copy or unreadable memory.

Checks:

- Query memory regions before reading.
- Reduce read size.
- Align reads to committed readable regions.

Fix:

- Use `memory(action='query', pid=...)` first.
- Read smaller spans.

## Tool Catalog Out Of Date

Symptoms:

- CI `Tool Catalog` job fails.

Fix:

- Run `python scripts/generate_tool_catalog.py`.
- Commit `docs/tool-catalog.json` and `docs/tool-reference.md`.

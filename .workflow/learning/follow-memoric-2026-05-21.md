# Memoric Reading Notes - 2026-05-21

## Purpose

Memoric is a Windows-focused Rust MCP server that exposes low-level process, memory, privilege, evasion, injection, kernel-driver, and orchestration capabilities through a compact JSON-RPC/MCP tool surface.

The product shape is not a normal CLI toolkit. It is an AI-callable control plane: callers use a small set of consolidated tools with `action` parameters, and the server translates those structured requests into Windows APIs, named-pipe worker calls, BYOVD/custom-driver operations, and session-state updates.

## Main Flow

- `src/main.rs:41` dispatches one binary into three modes: default STDIO MCP server, `--proxy`, or elevated `--worker`.
- `src/stdio_server.rs:15` is the active STDIO MCP path used by `main.rs`.
- `src/stdio_server.rs:91` handles tool calls directly when already elevated.
- `src/stdio_server.rs:96` lazily starts an elevated worker on the first tool call when not elevated.
- `src/stdio_server.rs:220` creates the named-pipe bridge to the worker.
- `src/stdio_server.rs:284` launches the worker with `ShellExecuteExW` and `runas`.

## MCP Surface

- `src/mcp/tools.rs:714` registers the caller-facing tools.
- `src/mcp/tools.rs:1444` normalizes modern and legacy tool names, dispatches the tool, then records session state on success.
- `src/mcp/tools.rs:1523` handles target/process/thread/module/environment introspection.
- `src/mcp/tools.rs:1611` handles memory read/write/scan/query/allocation/protection operations.
- `src/mcp/tools.rs:1742` handles injection and payload execution operations.
- `src/mcp/tools.rs:2422` handles stealth/evasion operations.
- `src/mcp/tools.rs:5647` handles kernel and driver-backed operations.
- `src/mcp/tools.rs:5917` handles orchestration.
- `src/mcp/tools.rs:6018` implements the self-describing `memoric` guide tool.

## State Model

- `src/state.rs:16` defines a global session state.
- `src/state.rs:195` records the active target PID.
- `src/state.rs:201` records detected EDR/security products.
- `src/state.rs:211` records loaded driver capability state.
- `src/state.rs:222` records applied evasion steps.
- `src/state.rs:233` records injection attempts.
- `src/state.rs:262` computes a rough stealth posture score from recorded state.

## Architecture Pattern

The core pattern is "consolidated MCP facade over many Windows primitives":

1. The MCP server accepts JSON-RPC over stdin/stdout.
2. The tool layer normalizes action aliases and validates required parameters.
3. Domain handlers route to module-level primitives.
4. Privileged operations either run in-process when elevated or are forwarded to an elevated worker.
5. Kernel-level operations route through `memoric.sys` wrappers or BYOVD-style generic driver paths.
6. Session state gives the AI caller continuity across multi-step workflows.

## Current Maturity Signals

- The repository has real Windows API implementations for basic process memory operations, injection primitives, service/driver operations, and MCP dispatch.
- Some advanced driver and orchestration paths appear intentionally ambitious and uneven: several code paths are complete wrappers around IOCTLs, while some kernel mapping comments describe intended behavior more strongly than the implementation can currently prove.
- There are unit tests in focused modules such as memory self-read and orchestration static-plan validation, but coverage is not broad enough for the size and risk of the surface.
- `src/mcp/server.rs` looks like an older or alternate MCP server implementation; `src/stdio_server.rs` is the actual active path from `main.rs`.

## Assumptions

- This project is meant for authorized lab/red-team environments, not general administration.
- The intended user is an AI assistant or MCP-compatible client, not a human manually invoking dozens of low-level commands.
- The repo is currently in a rapid prototyping/consolidation phase: the public surface is organized, but implementation depth and test coverage vary by domain.

## Things That Would Break If Changed

- Changing action names without preserving aliases would break existing AI/MCP prompts and legacy callers.
- Changing `src/stdio_server.rs` response wrapping would affect MCP client compatibility.
- Changing driver IOCTL structs or constants must stay synchronized with `driver/memoric.h` and `driver/memoric.c`.
- Removing state recording would make orchestration and `self(action='state')` less useful for multi-step workflows.
- Making worker spawning eager instead of lazy would change the UAC/user-experience model.

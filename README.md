# Memoric

<p align="center">
  <strong>A red-team memory weapon MCP Server for Windows</strong><br>
  <sub>102 source files &middot; ~62K lines of Rust &middot; 12 consolidated MCP tools</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.80%2B-orange?logo=rust" alt="Rust 1.80+">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue?logo=windows" alt="Windows 10/11">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/driver-WDM%20x64-red" alt="WDM x64 Driver">
</p>

---

## Overview

Memoric exposes a unified 12-tool MCP surface that gives AI assistants (Claude Desktop, etc.) deep control over Windows processes, memory, kernel primitives, and defense evasion — all through the Model Context Protocol.

Think of it as an instrument panel for live Windows offensive operations, where every dial and switch is accessible through structured tool calls rather than raw shell commands.

### Architecture

```
                ┌─────────────┐
                │  MCP Client │  (Claude Desktop / API)
                └──────┬──────┘
                       │ JSON-RPC over stdin/stdout
              ┌────────┴────────┐
              │   STDIO Mode    │  default, direct MCP
              │   (no elevation) │
              └────────┬────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    ┌────┴────┐  ┌────┴────┐  ┌────┴────┐
    │  Target  │  │  Memory │  │  ...10  │  12-tool surface
    │          │  │         │  │  tools  │
    └──────────┘  └─────────┘  └─────────┘
         │             │             │
         └─────────────┼─────────────┘
                       │
              ┌────────┴────────┐
              │   Proxy Mode    │  --proxy flag
              │  (Named Pipe)   │  STDIO bridge + UAC elevation
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │   Worker Mode   │  --worker flag
              │  (elevated)     │  privileged operations
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              │  Kernel Driver  │  WDM custom driver (memoric.sys)
              │  (BYOVD fallback)│  or third-party BYOVD
              └─────────────────┘
```

**Three operational modes:**

| Mode | Flag | Privilege | Role |
|------|------|-----------|------|
| STDIO | *(default)* | Normal | Direct MCP over stdin/stdout |
| Proxy | `--proxy` | Normal (bridge) | STDIO bridge → spawns elevated Worker via UAC |
| Worker | `--worker` | Elevated | Executes privileged operations via Named Pipe IPC |

---

## 12-Tool Surface

Every tool follows a consistent `action`-driven call pattern. Start with `memoric` for guided discovery.

| # | Tool | Domain | Selected Capabilities |
|---|------|--------|-----------------------|
| 1 | `memoric` | Guide | Session discovery, domain help, workflow suggestions |
| 2 | `target` | Target | Process list/find/info, thread suspend/resume/context, module enumeration, handle inspection, PEB, heap, callstack, credential/SAM/Kerberos dump |
| 3 | `memory` | Memory | Read/write/scan/query/alloc/free/protect, Cheat Engine-style scan sessions, stealth reads via BYOVD, scattered reads with jitter, physical memory access |
| 4 | `inject` | Inject | 17+ shellcode injection methods, DLL injection (classic/manual-map/phantom/reflective), process hollowing (ghost/doppelganger/herpaderp), Pool Party 1-8, thread hijacking |
| 5 | `payload` | Payload | PE parsing (imports/exports/sections/IAT), obfuscation (XOR/RC4/AES-256-CTR/polymorphic/UUID/IPv4/MAC), serialization, lifecycle control |
| 6 | `hook` | Hook | IAT patching, inline detours, hardware breakpoints (DR0-DR3), trampoline, Windows hook APIs |
| 7 | `stealth` | Stealth | ETW/AMSI/CFG patching, syscalls (direct/indirect/INT2E), ntdll unhooking, sleep obfuscation (Ekko/Foliage/Gargoyle/Death), callstack/PPID spoofing, module hiding, memory encryption, code mutation, Sysmon blinding, timestomp, test signing bypass (10+ techniques), WDAC disable, Defender disable/exclusion, firewall rules, sentinel persistence |
| 8 | `detect` | Detect | EDR product/hook detection, ETW session enumeration, VEH chain, VM/sandbox/hypervisor detection, forensic tool detection, syscall resolution, stealth scoring, bypass recommendations |
| 9 | `privilege` | Privilege | UAC bypass (fodhelper/eventvwr/computerdefaults/sdclt/disk_cleanup), token steal/impersonate/scan, SeDebugPrivilege, Potato family, service abuse, symlink |
| 10 | `kernel` | Kernel | BYOVD driver management, kernel R/W, physical memory, PTE/VAD manipulation, callback enumeration/removal, PPL/DSE bypass, DKOM hiding, test signing concealment, global hooks, auto-injection, infinity hook, WFP removal, minifilter ops, MSR/IDT/CR access, credential dump, token swap, process protection |
| 11 | `self` | Self | Server identity, driver status, operation history, cleanup, self-destruct |
| 12 | `orchestrate` | Orchestration | Multi-stage workflows, environment assessment, health monitoring, session management |

---

## Quick Start

Recommended first calls from any MCP client:

```
1. memoric(status=true)                              → session probe
2. memoric(domain='memory')                          → discover memory domain
3. self(action='info')                               → server identity & driver status
4. detect(action='stealth_score')                    → assess current stealth posture
5. target(action='ps_find', name='target.exe')       → find a process
6. memory(action='query', pid=1234, limit=50)        → inspect memory regions
7. memory(action='scan_new', pid=1234, value_type='u32', value=100)
8. memory(action='scan_next', session_id='scan_1', filter='changed')
```

---

## Building

### Prerequisites

- Windows 10/11 (x64)
- [Rust 1.80+](https://rustup.rs/) with `x86_64-pc-windows-msvc` target
- Administrator privileges (for most operations)

### Compile

```bash
cargo build --release
```

The optimized binary lands at `target/release/memoric.exe`.

### Kernel Driver (Optional)

A custom WDM driver (`driver/memoric.c`) provides deeper kernel primitives. See [`driver/DRIVER_MANUAL.md`](driver/DRIVER_MANUAL.md) for build and deployment instructions. Requires:

- Visual Studio 2022 + WDK
- Test signing enabled (`bcdedit /set testsigning on`)
- Secure Boot disabled

---

## Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "memoric": {
      "command": "path\\to\\memoric.exe",
      "args": [],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

For elevated operations, use Proxy mode:

```json
{
  "mcpServers": {
    "memoric": {
      "command": "path\\to\\memoric.exe",
      "args": ["--proxy"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/invocation-contract.md`](docs/invocation-contract.md) | Canonical calling contract |
| [`docs/invocation-examples.md`](docs/invocation-examples.md) | Recommended invocation shapes |
| [`docs/tool-reference.md`](docs/tool-reference.md) | Human-readable tool reference |
| [`docs/tool-catalog.json`](docs/tool-catalog.json) | Machine-readable tool catalog |
| [`driver/DRIVER_MANUAL.md`](driver/DRIVER_MANUAL.md) | Kernel driver build & deployment |

Regenerate derived tool docs:

```bash
python scripts/generate_tool_catalog.py
```

### Source of Truth

For caller-facing behavior, consult in this order:

1. `src/mcp/tools.rs` — runtime implementation
2. `docs/tool-catalog.json` — generated catalog
3. `docs/tool-reference.md` — generated reference
4. `docs/invocation-contract.md` — calling contract
5. `docs/invocation-examples.md` — example invocations

---

## Project Structure

```
src/
├── bruteforce/     Anti-forensics, kernel R/W, page table ops, physical memory, self-protection, sniffing
├── crypto/         AES-256 implementation
├── evasion/        AMSI, anti-VM, CFG, Defender, EDR, ETW, firewall, hypervisor, PPID, ret-spoof,
│                   Sentinel, sleep obfuscation, stealth scoring, syscalls, Sysmon, timestomp, unhook, WDAC
├── info/           Environment, handles, Kerberos, memory, modules, processes, SAM
├── inject/         Code injection methods
├── ipc/            Named Pipe IPC protocol
├── kernel/         Driver-backed kernel operations
├── mcp/            MCP protocol handler & tool dispatch
├── memory/         Memory operations & scanning
├── privilege/      Token operations & elevation
├── orchestration/  Multi-stage workflows
├── proxy.rs        Proxy mode (STDIO bridge + UAC)
├── worker.rs       Worker mode (elevated process)
└── main.rs         Entry point (mode dispatch)
```

---

## Warning

> This tool is **highly invasive**. It operates at the kernel level, manipulates live processes, disables security mechanisms, and can destabilize the target system. Use **only** in authorized environments with explicit written consent. Unauthorized use may violate computer fraud laws, including the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent statutes in your jurisdiction.

---

## Disclaimer

This software is provided for **educational purposes and authorized security testing only**. The authors assume no liability for misuse, damage, or legal consequences arising from the use of this tool. You are solely responsible for compliance with all applicable laws and regulations.

---

## License

MIT

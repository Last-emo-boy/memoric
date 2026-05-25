# Memoric Kernel Driver

Custom WDM kernel driver providing direct kernel-level primitives for memoric, replacing the BYOVD (Bring Your Own Vulnerable Driver) approach with a purpose-built driver.

## Prerequisites

- Windows 10 1809+ (x64)
- **Secure Boot disabled** in BIOS/UEFI
- **Test signing enabled**: `bcdedit /set testsigning on` (reboot required)
- **HVCI/VBS disabled** (for CR0.WP force-write)
- Visual Studio 2019/2022 with **C++ Desktop Development** workload
- [Windows Driver Kit (WDK) 10](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

## IOCTLs

| IOCTL | Code | Description |
|-------|------|-------------|
| `PHYS_READ` | `0x80002000` | Read physical memory (MmCopyMemory) |
| `PHYS_WRITE` | `0x80002004` | Write physical memory (MmMapIoSpace) |
| `VIRT_READ` | `0x80002008` | Read virtual memory (kernel or cross-process) |
| `VIRT_WRITE` | `0x8000200C` | Write virtual memory (kernel or cross-process) |
| `GET_CR3` | `0x80002010` | Get process CR3/DirectoryTableBase |
| `GET_EPROCESS` | `0x80002014` | Get EPROCESS info + dynamic offsets |
| `TOKEN_STEAL` | `0x80002018` | Copy token between processes |
| `DKOM_HIDE` | `0x8000201C` | Unlink from ActiveProcessLinks |
| `PPL_REMOVE` | `0x80002020` | Zero PS_PROTECTION field |
| `WRITE_KERNEL` | `0x80002024` | Force-write kernel memory (CR0.WP bypass) |
| `VA_TO_PA` | `0x80002028` | Translate VA→PA (MmGetPhysicalAddress) |
| `CAPABILITIES` | `0x80002104` | Query ABI version, driver version, feature bitmap, and driver limits |

## Build

### Option 1: Command Line (Recommended)

Open **x64 Native Tools Command Prompt for VS 2022** and run:

```bat
cd driver
build.bat
```

### Option 2: Visual Studio + WDK

1. Open VS, create new project → **Empty WDM Driver**
2. Copy `memoric.c` and `memoric.h` into the project
3. Set platform to **x64**, configuration to **Release**
4. Build → Build Solution

### Option 3: Manual Compilation

```bat
cl.exe /kernel /W4 /O2 /GS- /Gz /D_AMD64_ /D_WIN64 /D_KERNEL_MODE ^
    /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.xxxxx.0\km" ^
    /I"C:\Program Files (x86)\Windows Kits\10\Include\10.0.xxxxx.0\shared" ^
    /c memoric.c /Fo memoric.obj

link.exe /DRIVER:WDM /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /MACHINE:X64 ^
    /OUT:memoric.sys memoric.obj ^
    /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.xxxxx.0\km\x64" ^
    ntoskrnl.lib hal.lib wdm.lib BufferOverflowFastFailK.lib
```

Replace `10.0.xxxxx.0` with your WDK version.

## Loading

```bat
:: As Administrator:
load.bat              # Load driver
load.bat unload       # Unload driver
load.bat status       # Check status
load.bat reload       # Unload + reload

:: Or manually:
sc create memoric type=kernel binPath="C:\Windows\System32\drivers\memoric.sys"
sc start memoric
sc stop memoric
sc delete memoric
```

## Usage from Rust

The `src/driver.rs` module provides a type-safe Rust client:

```rust
use crate::driver::MemoricDriver;

// Open device
let drv = MemoricDriver::open()?;

// Physical memory R/W
let data = drv.read_physical(0x1000, 4096)?;
drv.write_physical(0x1000, &[0x90; 4])?;

// Cross-process virtual memory
let mem = drv.read_virtual(1234, 0x7FF600000000, 256)?;

// Token steal (SYSTEM → target)
drv.token_steal(4, target_pid)?;

// DKOM hide
drv.dkom_hide(target_pid)?;

// VA to PA translation
let pa = drv.va_to_pa(pid, 0x7FF600001000)?;
```

## Dynamic EPROCESS Offsets

The driver dynamically discovers critical EPROCESS offsets at load time:

- **UniqueProcessId**: Scans current EPROCESS for own PID
- **ActiveProcessLinks**: Located immediately after UniqueProcessId
- **Token**: Located via `PsReferencePrimaryToken` + EX_FAST_REF scan
- **ImageFileName**: Located via `PsGetProcessImageFileName`
- **Protection, VadRoot**: Discovered dynamically; offset-dependent operations fail closed if resolution is incomplete.

Supported Windows builds: 17763 (1809), 18362/18363 (1903/1909), 19041-19045 (2004-22H2), 22000+ (Win11), 26100+ (24H2).

Before loading, use `kernel(action='status')` from the MCP server to inspect signing, HVCI/Memory Integrity, vulnerable driver blocklist, payload/device reachability, and static callback offset support. The status action is probe-only and does not auto-load or install the driver.

## Debugging

Use [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) (enable Capture → Capture Kernel) to see `[memoric]` debug messages:

```
[memoric] DriverEntry - loading memoric kernel driver
[memoric] Dynamic: UniqueProcessId=0x440, ActiveProcessLinks=0x448
[memoric] Dynamic: Token=0x4B8
[memoric] Dynamic: ImageFileName=0x5A8 (System)
[memoric] EPROCESS offsets resolved for build 22631
[memoric] Driver loaded successfully. Device: \Device\Memoric
```

## Architecture

```
User Mode (memoric.exe)          Kernel Mode (memoric.sys)
┌──────────────────────┐         ┌─────────────────────────┐
│  src/driver.rs       │         │  DriverEntry            │
│  MemoricDriver       │         │  ├─ ResolveOffsets()    │
│  ├─ open()           │  IOCTL  │  ├─ IoCreateDevice      │
│  ├─ read_physical()  │────────>│  └─ DispatchControl     │
│  ├─ write_physical() │         │     ├─ HandlePhysRead   │
│  ├─ read_virtual()   │         │     ├─ HandlePhysWrite  │
│  ├─ token_steal()    │         │     ├─ HandleVirtRead   │
│  ├─ dkom_hide()      │         │     ├─ HandleVirtWrite  │
│  └─ ...              │<────────│     ├─ HandleTokenSteal │
│                      │ Results │     ├─ HandleDkomHide   │
└──────────────────────┘         │     └─ ...              │
                                 └─────────────────────────┘
```

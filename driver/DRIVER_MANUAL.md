# Memoric Kernel Driver — 技术手册

> **memoric.sys** — 一个从零构建的 Windows x64 WDM 内核驱动，提供 56 个 IOCTL 接口，覆盖内存操作、进程操控、安全机制绕过、EDR 对抗、内核隐身和武器化原语等全栈内核能力。

```
代码规模：  memoric.c  ~12,600 行  |  memoric.h  ~1,500 行
编译产物：  memoric_new.sys  ~118 KB (test-signed)
IOCTL 数量：56 个（14 个开发阶段累积）
目标平台：  Windows 10 1809+ / 11 (x64)，支持到 Build 26220
```

---

## 目录

1. [架构总览](#1-架构总览)
2. [构建与部署](#2-构建与部署)
3. [安全模型](#3-安全模型)
4. [EPROCESS 偏移动态发现](#4-eprocess-偏移动态发现)
5. [IOCTL 完整参考](#5-ioctl-完整参考)
   - [Phase 1–2: 内存原语](#phase-12-内存原语)
   - [Phase 3–4: 进程操控](#phase-34-进程操控)
   - [Phase 5–6: 回调与通知](#phase-56-回调与通知)
   - [Phase 7–8: 监控与信息](#phase-78-监控与信息)
   - [Phase 9: 全局钩子与自动注入](#phase-9-全局钩子与自动注入)
   - [Phase 10–11: CI 绕过与 PTE 操控](#phase-1011-ci-绕过与-pte-操控)
   - [Phase 12: 武器化内核原语](#phase-12-武器化内核原语)
   - [Phase 13: 高级武器化](#phase-13-高级武器化)
   - [Phase 14: EDR 歼灭与内核隐身](#phase-14-edr-歼灭与内核隐身)
6. [内部机制详解](#6-内部机制详解)
7. [Rust 用户态客户端](#7-rust-用户态客户端)
8. [质量迭代历史](#8-质量迭代历史)
9. [已知限制](#9-已知限制)

---

## 1. 架构总览

```
┌─────────────────────────────────────────────────────┐
│                     User Mode                       │
│  ┌──────────────────────────────────┐               │
│  │  memoric.exe (Rust)              │               │
│  │  src/driver.rs — 类型安全 IOCTL  │               │
│  │  src/mcp/     — MCP Server       │               │
│  └──────────┬───────────────────────┘               │
│             │ DeviceIoControl(\\.\Memoric)           │
├─────────────┼───────────────────────────────────────┤
│             ▼          Kernel Mode                   │
│  ┌──────────────────────────────────────────────┐   │
│  │  memoric.sys (WDM Driver)                    │   │
│  │                                              │   │
│  │  DriverEntry()                               │   │
│  │    ├─ ResolveEprocessOffsets()  ← 动态探测    │   │
│  │    ├─ IoCreateDevice(\Device\Memoric)        │   │
│  │    ├─ IoCreateSymbolicLink(\DosDevices\...)  │   │
│  │    ├─ DACL: SYSTEM + Administrators only     │   │
│  │    └─ IRP_MJ_DEVICE_CONTROL → 56 IOCTLs     │   │
│  │                                              │   │
│  │  IOCTL Dispatcher (METHOD_BUFFERED)          │   │
│  │    ├─ Read-only 组 (IRQL PASSIVE_LEVEL)      │   │
│  │    └─ Read-write 组 (需要修改权限)            │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  ntoskrnl.exe  │  CI.dll  │  NETIO.SYS      │   │
│  │  FLTMGR.SYS   │  win32kbase.sys             │   │
│  │  (运行时动态解析导出函数)                      │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### 设计原则

| 原则 | 实现 |
|------|------|
| **零硬编码偏移** | 所有 EPROCESS/ETHREAD 字段通过 API 探测 + 多进程交叉验证动态发现 |
| **METHOD_BUFFERED** | 全部 56 个 IOCTL 使用缓冲 I/O，内核自动复制用户缓冲区 |
| **优雅降级** | 偏移发现失败时记录日志并返回 `STATUS_NOT_SUPPORTED`，不崩溃 |
| **运行时函数解析** | FltMgr / NETIO / CI / win32k 函数通过 `MmGetSystemRoutineAddress` 或导出表扫描获取 |
| **SEH 全覆盖** | 所有内核内存访问包裹在 `__try/__except` 中 |
| **DACL 访问控制** | 设备对象仅允许 SYSTEM (S-1-5-18) 和 Administrators (S-1-5-32-544) 打开 |

---

## 2. 构建与部署

### 前置要求

| 组件 | 要求 |
|------|------|
| 操作系统 | Windows 10 1809+ (x64) |
| 编译器 | Visual Studio 2022 BuildTools + C++ Desktop 工作负载 |
| WDK | Windows Driver Kit 10.0.26100.0+ |
| Secure Boot | **必须关闭** |
| Test Signing | `bcdedit /set testsigning on` (需重启) |
| HVCI/VBS | 建议关闭（CR0.WP 旁路需要） |

### 编译

```bat
cd driver
.\build.bat
```

`build.bat` 自动完成：
1. 查找 Visual Studio 环境 (`vcvarsall.bat x64`)
2. 设置 WDK Include/Lib 路径
3. `cl.exe /kernel /O2 /GS-` 编译 → `memoric.obj`
4. `link.exe /DRIVER:WDM /SUBSYSTEM:NATIVE /ENTRY:DriverEntry` 链接 → `memoric_new.sys`
5. `signtool sign /a /s PrivateCertStore /n MemoricTestCert` 测试签名

### 加载

```bat
:: 首次安装
sc create memoric type=kernel binPath="C:\Windows\System32\drivers\memoric.sys"
sc start memoric

:: 快速加载
.\load.bat              # 安装 + 启动
.\load.bat unload       # 停止 + 删除
.\load.bat reload       # 卸载 → 复制新文件 → 重新加载
.\load.bat status       # 查看驱动状态
```

### 验证

```
:: DebugView (Sysinternals) 中应看到：
[memoric] DriverEntry - loading memoric kernel driver
[memoric] ResolveEprocessOffsets: Build 26220
[memoric] Offsets resolved: UniqueProcessId=0x...
[memoric] Device DACL set: SYSTEM + Administrators only
[memoric] Driver loaded successfully. Device: \Device\Memoric
```

---

## 3. 安全模型

### 设备访问控制

驱动在 `DriverEntry` 中构建 DACL，仅授权两个 SID：

```
ACE[0]: GENERIC_ALL → S-1-5-18          (NT AUTHORITY\SYSTEM)
ACE[1]: GENERIC_ALL → S-1-5-32-544      (BUILTIN\Administrators)
```

非管理员进程调用 `CreateFile("\\\\.\\Memoric")` 会收到 `ACCESS_DENIED`。

### IOCTL 权限分组

驱动内部将 IOCTL 分为两组：

| 组别 | 描述 | 示例 |
|------|------|------|
| 只读 (Read) | 不修改系统状态，仅返回信息 | `PHYS_READ`, `ENUM_PROCESS`, `DRIVER_STATS` |
| 读写 (Write) | 修改内核数据结构、进程状态等 | `TOKEN_STEAL`, `DKOM_HIDE`, `CALLBACK_REMOVE` |

### 输入校验

每个 IOCTL handler 验证：
- `inputBufferLength >= sizeof(请求结构体)`
- `outputBufferLength >= sizeof(响应结构体)`
- 所有指针在 `__try` 块内解引用
- 缓冲区大小上限：`MEMORIC_MAX_IO_SIZE = 4 MB`

---

## 4. EPROCESS 偏移动态发现

驱动启动时 `ResolveEprocessOffsets()` 自动探测以下字段的偏移量，**不依赖任何硬编码偏移表**：

### 发现方法

| 字段 | 方法 |
|------|------|
| `UniqueProcessId` | 以当前进程 PID 为锚点扫描 EPROCESS，找到匹配的 ULONG_PTR |
| `ActiveProcessLinks` | 在 UniqueProcessId 附近搜索有效的 LIST_ENTRY 双向链表指针 |
| `Token` | 搜索 EX_FAST_REF 格式的值（高位为内核指针，低 4 位为引用计数） |
| `ImageFileName` | 调用 `PsGetProcessImageFileName()` 获取名称，在 EPROCESS 中搜索匹配 |
| `InheritedFromUniqueProcessId` | 调用 `ZwQueryInformationProcess` 获取父 PID，搜索匹配 |
| `ObjectTable` | 调用 `ObReferenceObjectByHandle` 推算当前进程句柄表地址 |
| `Protection` | 使用 `PS_PROTECTION` 知名值在 EPROCESS 后半段(+0x600..+0x900)搜索 |
| `DebugPort` | QWORD 值扫描，通常在 Token 附近 |
| `VadRoot` | 搜索 RTL_AVL_TREE 格式的有效指针 |
| `Flags2` | 三进程交叉验证：在多个进程的相同偏移处找到非零 ULONG，且第三个进程验证一致 |

### 探测失败处理

```
如果某字段未发现 → g_Offsets.XXX = 0
依赖该字段的 IOCTL → 返回 STATUS_NOT_SUPPORTED
驱动继续运行，不影响其他功能
```

---

## 5. IOCTL 完整参考

### Phase 1–2: 内存原语

最底层的内存读写能力，所有高级功能的基础。

| IOCTL | 代码 | 描述 | 方法 |
|-------|------|------|------|
| `PHYS_READ` | `0x80002000` | 读取物理内存 | `MmCopyMemory(MM_COPY_MEMORY_PHYSICAL)` |
| `PHYS_WRITE` | `0x80002004` | 写入物理内存 | `MmMapIoSpace` → 映射为非缓存虚拟地址 → 写入 → `MmUnmapIoSpace` |
| `VIRT_READ` | `0x80002008` | 读取虚拟内存（内核或跨进程） | PID=0/4 → 直接内核读；其他 → `KeStackAttachProcess` 切换上下文 |
| `VIRT_WRITE` | `0x8000200C` | 写入虚拟内存（跨进程） | 同上，Attach 后写入 |
| `GET_CR3` | `0x80002010` | 获取进程 CR3/DirectoryTableBase | 从 EPROCESS.DirectoryTableBase 读取 |
| `VA_TO_PA` | `0x80002028` | 虚拟地址→物理地址转换 | `MmGetPhysicalAddress` |
| `WRITE_KERNEL` | `0x80002024` | 强制写入内核只读内存 | 临时清除 CR0.WP 位 → 写入 → 恢复 |

### Phase 3–4: 进程操控

直接操作内核进程/线程数据结构。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `GET_EPROCESS` | `0x80002014` | 获取 EPROCESS 地址 + 动态偏移表 + Token/CR3 值 |
| `TOKEN_STEAL` | `0x80002018` | 将源进程 Token 复制到目标进程 (典型: System PID 4 → 目标) |
| `DKOM_HIDE` | `0x8000201C` | 从 ActiveProcessLinks 双向链表中摘除进程 (DKOM 隐藏) |
| `PPL_REMOVE` | `0x80002020` | 清零 EPROCESS.Protection 字段 (移除 PPL 保护) |
| `ENUM_PROCESS` | `0x8000202C` | 内核级进程枚举：遍历 ActiveProcessLinks，返回完整进程列表 |
| `MODULE_HIDE` | `0x80002030` | 从 PsLoadedModuleList 中摘除内核模块 |
| `THREAD_HIDE` | `0x80002034` | 从线程链表中摘除线程 |

### Phase 5–6: 回调与通知

操控 Windows 内核回调机制——EDR/AV 的防御基石。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `CALLBACK_ENUM` | `0x80002038` | 枚举内核回调数组 (Process/Thread/Image/Registry/Object 五种) |
| `CALLBACK_REMOVE` | `0x8000203C` | 移除指定回调条目 (Process/Thread/Image: 清零数组槽位；Registry: `CmUnRegisterCallback`；Object: `ObUnRegisterCallbacks`) |
| `NOTIFY_ROUTINE` | `0x80002050` | 注册/注销/查询自有通知回调 (进程/线程/镜像加载事件记录) |
| `OBJECT_HOOK` | `0x80002068` | 注册 `ObRegisterCallbacks` 保护指定进程 (剥离外部进程对目标的访问权限) |

**回调发现机制：**
- Process/Thread/Image: 扫描 `PsSetCreateProcessNotifyRoutine` 等函数的内部代码模式，定位回调数组首地址
- Registry: 注册临时探测回调，扫描 `CM_CALLBACK_CONTEXT_BLOCK` 结构 (+0x10..+0x40) 定位 `CmpCallBackList` 链表头
- Object: 自注册 `ObRegisterCallbacks` 后遍历 `ObTypeInitializer` 回调链表，校准 Handle 偏移

### Phase 7–8: 监控与信息

系统内省与信息收集。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `PE_DUMP` | `0x80002054` | 从内核上下文 dump 进程 PE 镜像 (绕过 PPL/反读取保护) |
| `SET_DEBUG_PORT` | `0x80002058` | 操控 EPROCESS.DebugPort (反调试：清零/设 NoDebugInherit/全清) |
| `DPC_TIMER` | `0x8000205C` | 注册内核 DPC 定时器 (8 个槽位，延迟执行 hide/escalate/log) |
| `PORT_HIDE` | `0x80002060` | 隐藏 TCP/UDP 端口 (NSI hook，最多 32 个端口) |
| `TOKEN_DUP` | `0x80002064` | Token 复制/替换/恢复原始 Token |
| `DRIVER_STATS` | `0x8000206C` | 驱动健康统计 (总 IOCTL 数、成功/失败/异常计数、各子系统状态) |
| `MEMORY_POOL` | `0x80002070` | 按 PoolTag 查询内核池分配 |
| `MINIFILTER_ENUM` | `0x80002074` | 枚举所有文件系统 minifilter 驱动 (通过 `FltEnumerateFilters`) |
| `PROCESS_DUMP` | `0x80002078` | dump 进程虚拟内存区域描述符 (VAD 树遍历) |
| `HYPERVISOR_DETECT` | `0x8000207C` | 内核级虚拟化检测 (CPUID/RDTSC/MSR/IDT 组合判断) |
| `HANDLE_STRIP` | `0x80002048` | 遍历系统句柄表，剥离外部进程对目标的句柄访问权限 |
| `REG_PROTECT` | `0x8000204C` | 注册表保护 (CmRegisterCallbackEx 拦截删除/修改/创建操作) |
| `APC_INJECT` | `0x80002044` | 用户态 APC 注入 (ZwQuerySystemInformation 查找线程 + KeInsertQueueApc) |
| `PATCH_KERNEL` | `0x80002040` | 内核函数补丁 (ETW-Ti / DSE / PatchGuard) |

### Phase 9: 全局钩子与自动注入

系统级拦截机制。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `TESTSIGN_HIDE` | `0x80002080` | 隐藏测试签名水印 (补丁 `KUSER_SHARED_DATA` + ci.dll `g_CiOptions`) |
| `GLOBAL_HOOK` | `0x80002084` | 内核函数钩子 (Inline/IAT/Infinity 三种模式，16 个槽位) |
| `AUTO_INJECT` | `0x80002088` | 进程创建时自动注入 (ETW/AMSI/自定义 shellcode，可按进程名过滤) |
| `INFINITY_HOOK` | `0x8000208C` | Infinity Hook: 通过 `HalPrivateDispatchTable.GetCpuClock` 拦截系统调用 |
| `GET_MODULE_BASE` | `0x80002090` | 查询内核模块基址和大小 |

**Infinity Hook 实现细节：**
1. 扫描 ntoskrnl 导出表找到 `HalPrivateDispatchTable`
2. 动态发现 `KTHREAD.SystemCallNumber` 偏移（交叉验证：对比 System 进程线程的同一偏移值）
3. 替换 `GetCpuClock` 指针为自定义 handler
4. Handler 内读取 `KTHREAD.SystemCallNumber` 判断当前系统调用号
5. 命中目标 syscall 时执行替换逻辑

### Phase 10–11: CI 绕过与 PTE 操控

绕过代码完整性验证和页表级内存保护。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `CI_CALLBACK_PATCH` | `0x80002094` | 替换 ntoskrnl `SeCiCallbacks` 中的 `CiValidateImageHeader` 指针为 `ZwFlushInstructionCache` (始终返回成功) |
| `CI_FUNC_PATCH` | `0x80002098` | 补丁 CI.dll 中 `CiValidateImageHeader` 的函数序言为 `xor eax, eax; ret` → 所有驱动签名检查通过 |
| `PTE_RW` | `0x8000209C` | PTE 级别内存操控：读取/修改/设可写/恢复任意虚拟地址的页表条目 |

**PTE 操控：**
- 通过扫描 ntoskrnl `.text` 段中 `MiGetPteAddress` 的代码模式获取 PTE Base 地址
- 支持在 Hyper-V 环境下工作（不依赖 CR0.WP）

### Phase 12: 武器化内核原语

面向攻击的高对抗原语。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `MSR_RW` | `0x800020A0` | 任意 MSR 读写 (`__readmsr` / `__writemsr`)：LSTAR, IA32_DEBUGCTL 等 |
| `DRIVER_CLOAK` | `0x800020A4` | 驱动隐身: 从 PsLoadedModuleList 摘除 + 清除 MmUnloadedDrivers 记录 |
| `FORCE_KILL` | `0x800020A8` | 强杀进程 (三种模式: `ZwTerminateProcess` / DKOM 摘除 / 逐线程终止) |
| `FORCE_DELETE` | `0x800020AC` | 强制删除文件/目录 (IRP 级操作，绕过用户态文件锁) |
| `SYSTEM_THREAD` | `0x800020B0` | 创建 Ring-0 系统线程 (任意内核代码执行) |
| `KERNEL_EXEC` | `0x800020B4` | 分配非分页池 → 复制 shellcode → 直接执行 (Ring-0 代码执行原语) |
| `PPL_BYPASS` | `0x800020B8` | PPL 绕过: 设置/剥离/查询 `PS_PROTECTION` (Signer 类型可指定) |
| `CR_RW` | `0x800020BC` | 控制寄存器读写 (CR0/CR3/CR4) |
| `IDT_RW` | `0x800020C0` | IDT 条目读写 (覆盖中断服务例程) |
| `UNLOADED_DRV_CLEAR` | `0x800020C4` | 清除 MmUnloadedDrivers 痕迹 (全清/按名称清/查询) |
| `TOKEN_SWAP` | `0x800020C8` | Token 交换 (保留原 Token 以便恢复) |
| `PROCESS_PROTECT` | `0x800020CC` | 设置进程 PPL 保护 (可指定 Signer 类型/级别) |

### Phase 13: 高级武器化

纵深持久化与证据清理。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `KEYLOGGER` | `0x800020D0` | 内核键盘记录器 (通过 `gafAsyncKeyState` 轮询，无 API hook) |
| `REG_HIDE` | `0x800020D4` | 注册表隐藏 (CmRegisterCallbackEx 拦截 `RegEnumKey`/`RegEnumValue`) |
| `FILE_LOCK` | `0x800020D8` | 文件锁 (防删除/防写入/防读取，可指定豁免 PID) |
| `ETW_BLIND` | `0x800020DC` | ETW 致盲: 通过 `EtwpGuidHashTable` 找到 Provider → 清零 EnableInfo |
| `EPROCESS_SPOOF` | `0x800020E0` | 进程伪装: 修改 ImageFileName / CommandLine / ParentPID |
| `EVENT_LOG_CLEAR` | `0x800020E4` | 事件日志清理: 终止 EventLog 服务线程 + 删除 .evtx 文件 |
| `CRED_DUMP` | `0x800020E8` | 内核级内存读取 (绕过 PPL 读取 LSASS 等受保护进程) |
| `DRIVER_IMPERSONATE` | `0x800020EC` | 驱动伪装: 用合法 MS 签名驱动文件覆盖自身磁盘文件 |

**ETW 致盲机制：**
1. 通过 `EtwRegister` 导出函数的代码分析定位 `EtwpGuidHashTable`
2. 自注册临时 Provider → 遍历 64 个 hash bucket 找到自身 → 校准 GUID 偏移
3. 通过 GUID hash 定位目标 Provider 的 `ETW_GUID_ENTRY`
4. 清零 `EnableInfo` 字段 → Provider 不再被触发
5. `KILL_ALL` 模式: 补丁 `EtwWrite` 函数序言为 `xor eax,eax; ret` → 全局 ETW 静默

### Phase 14: EDR 歼灭与内核隐身

系统性拆解 EDR/AV 的所有内核驻留机制。

| IOCTL | 代码 | 描述 |
|-------|------|------|
| `CALLBACK_NUKE` | `0x800020F0` | 回调核弹: 枚举/移除/全清 Process/Thread/Image/Object/Registry 回调 |
| `MINIFILTER_DETACH` | `0x800020F4` | Minifilter 摘除 (ENUM/DETACH/NUKE 三种模式) |
| `KERNEL_APC_INJECT` | `0x800020FC` | 内核 APC 注入: `KeInitializeApc` + `KeInsertQueueApc` (KernelMode APC) |
| `WFP_REMOVE` | `0x80002100` | WFP 网络过滤摘除 (ENUM/REMOVE/NUKE 三种模式) |

#### Minifilter 摘除

```
ENUM  → FltEnumerateFilters → 返回所有 minifilter 名称/高度/实例数
DETACH → FltEnumerateInstances + FltDetachVolume → 官方 API 逐卷次摘除
NUKE  → 先尝试 DETACH 路径摘除所有实例
       → 若仍有实例残留 → 降级到 FltUnregisterFilter
       → 内置 EDR filter 名单: WdFilter, csagent, SentinelMonitor...
```

#### WFP 摘除

```
ENUM  → FwpmCalloutEnum0 → 列出所有 WFP callout
REMOVE → 分两步：
  1. FwpmCalloutDeleteById0 — 管理面先删 (阻止新 flow 关联)
  2. FwpsCalloutUnregisterById0 — 内核注销
     └─ 若 STATUS_DEVICE_BUSY:
        a) 枚举所有 WFP filter，删除引用此 callout 的 filter
        b) 指数退避重试 (最多 12 次，~2s)
NUKE  → 枚举所有 callout，跳过 Windows/Microsoft/WFP/TCP-IP，
       对其余全部执行上述两步移除
```

#### Callback Nuke

```
ENUM      → 枚举指定类型的所有回调（返回函数地址、模块名）
REMOVE    → 移除指定索引 (Process/Thread/Image: 清零函数指针；
            Registry: CmUnRegisterCallback；Object: ObUnRegisterCallbacks)
NUKE_ALL  → 全清非 OS 回调（跳过 ntoskrnl/CI/FLTMGR 拥有的回调）
RESTORE   → 恢复之前移除的回调
```

---

## 6. 内部机制详解

### 6.1 动态函数解析

驱动不静态链接任何 FltMgr / NETIO / win32k 函数，而是运行时解析：

```c
// 方式 1: MmGetSystemRoutineAddress (标准方式)
UNICODE_STRING name = RTL_CONSTANT_STRING(L"FltEnumerateFilters");
pFltEnum = MmGetSystemRoutineAddress(&name);

// 方式 2: 导出表扫描 (适用于未导出到 SSDT 的函数)
pUnregById = EtwFindExportByName(netioBase, "FwpsCalloutUnregisterById0");
```

### 6.2 内核写入方式

三层写入策略，按环境自动选择：

| 层级 | 方式 | 适用场景 |
|------|------|----------|
| 1 | PTE 操控 | Hyper-V/VBS 环境，修改页表条目设置可写位 |
| 2 | CR0.WP 清除 | 无虚拟化栈的裸机，临时清除写保护位 |
| 3 | 物理内存映射 | 最后手段，`MmMapIoSpace` 直接操作物理页 |

### 6.3 线程选择算法

APC 注入需要找到合适的目标线程，驱动使用多级策略：

```
层级 1: ZwQuerySystemInformation(SystemProcessInformation)
       → 遍历所有线程，评分系统：
         WaitReason==UserRequest ± 线程 ID 启发式
       → 选择得分最高的线程

层级 2: ThreadListHead 遍历 (ZwQuery 失败时)
       → 遍历 EPROCESS.ThreadListHead 链表
       → PsIsThreadTerminating 过滤已终止线程
       → ObReferenceObject 安全引用最佳线程

层级 3: KernelApcInject 评分增强
       → 评分后验证 PsIsThreadTerminating
       → 若终止 → 回退到次优线程
```

### 6.4 Registry Callback 发现

```
1. CmRegisterCallbackEx 注册临时探测回调 (返回 cookie)
2. 扫描探测回调上下文结构 (+0x10..+0x40):
   a. 查找匹配探测回调函数指针的 QWORD → 确定函数偏移
   b. 查找匹配 cookie 的 LARGE_INTEGER → 确定 cookie 偏移
3. 从上下文结构 Flink/Blink 定位 CmpCallBackList 链表头
4. CmUnRegisterCallback 注销探测回调
5. 后续枚举/移除操作直接遍历链表
```

### 6.5 Object Callback 校准

```
1. ObRegisterCallbacks 注册临时回调保护 PID=0
2. 遍历 PsProcessType→CallbackList 找到自己的条目
3. 提取 OB_CALLBACK_REGISTRATION 句柄
4. 启发式搜索：在条目结构中查找句柄值 → 确定 Handle 偏移
5. 校准失败 → 清空 4 个缓存偏移 → 重新校准 → 再次尝试
6. ObUnRegisterCallbacks 清理探测回调
```

### 6.6 ETW GuidHashTable 校准

```
1. 扫描 ntoskrnl .text 段中 EtwRegister 附近的 LEA 指令 → 定位 EtwpGuidHashTable
2. EtwRegister 注册临时 Provider (已知 GUID)
3. 遍历 64 个 hash bucket (LIST_ENTRY 链)
4. 在每个 chain entry 的多个偏移处搜索匹配的 GUID 字节
5. 命中 → 该偏移即 GuidOffset → 缓存至 g_EtwGuidEntryGuidOffset
6. EtwUnregister 清理临时 Provider
```

---

## 7. Rust 用户态客户端

驱动通过 `src/driver.rs` 中的 `MemoricDriver` 结构体暴露给 Rust 用户态：

```rust
use crate::driver::MemoricDriver;

// 打开设备
let drv = MemoricDriver::open()?;

// 物理内存读写
let data = drv.read_physical(0x1000, 4096)?;
drv.write_physical(0x1000, &[0x90; 4])?;

// 跨进程虚拟内存
let mem = drv.read_virtual(target_pid, 0x7FF600000000, 256)?;

// Token 窃取 (SYSTEM → 目标)
drv.token_steal(4, target_pid)?;

// DKOM 进程隐藏
drv.dkom_hide(target_pid)?;

// PPL 移除
drv.ppl_remove(target_pid)?;

// 回调枚举
let callbacks = drv.callback_enum(MEMORIC_CALLBACK_PROCESS, 64)?;

// EDR 歼灭
drv.callback_nuke(MEMORIC_CB_TYPE_PROCESS, MEMORIC_CBNUKE_NUKE_ALL)?;
drv.minifilter_detach("WdFilter")?;
drv.wfp_nuke()?;
drv.etw_blind(&defender_ti_guid)?;
```

所有请求/响应结构体通过 `#[repr(C)]` 与 C 头文件字节级对齐。

---

## 8. 质量迭代历史

| 轮次 | 焦点 | 修复数 | 代表性改进 |
|------|------|--------|-----------|
| Round 1 | 基础边界检查、SEH 覆盖 | ~15 | 全 handler 添加输入长度校验 |
| Round 2 | IOCTL 语义正确性 | ~12 | 修复 Token/DKOM/PPL 的竞态条件 |
| Round 3 | 回调机制健壮性 | ~10 | Registry callback cookie 校验增强 |
| Round 4 | 内存安全与资源泄漏 | ~8 | ObDereferenceObject 配对审计 |
| Round 5 | 官方 API 对齐 | 7 | Minifilter 使用 FltDetachVolume 替代结构体扫描 |
| Round 6 | 消除简化/未完全实现 | 10 | EPROCESS 零硬编码偏移表 / ETW 移除 .data 后备扫描 / WFP filter 清理 / Minifilter NUKE detach-first |

### Round 6 关键改进

1. **EPROCESS 偏移表完全移除** — 删除整个 Build Number 硬编码回退表 (~100 行)，所有字段通过 API 探测 + 多进程交叉验证发现
2. **Registry 校准范围扩展** — 探测偏移从 +0x10..+0x30 扩展到 +0x10..+0x40
3. **Object Callback 重校准** — 首次失败时自动清空缓存偏移并重新校准
4. **APC 线程选择** — ThreadListHead 回退路径：从"取第一个线程"改为完整链表遍历 + PsIsThreadTerminating 过滤
5. **KernelApcInject** — 选中线程后增加 PsIsThreadTerminating 验证 + 次优线程回退
6. **InfinityHook KTHREAD 偏移** — 与 System 进程线程交叉验证候选偏移
7. **EtwBlind** — 移除 .data 段后备扫描，校准失败即干净失败
8. **Minifilter NUKE** — detach-first 策略：先 FltDetachVolume 全卷次摘除，仅残留实例才降级到 FltUnregisterFilter
9. **WFP DEVICE_BUSY** — 首次遇到 BUSY 时主动枚举并删除引用目标 callout 的 WFP filter
10. **新增 5 个 WFP API** — FwpmFilterCreateEnumHandle0 / FwpmFilterEnum0 / FwpmFilterDestroyEnumHandle0 / FwpmFilterDeleteById0 / FwpmCalloutGetById0

---

## 9. 已知限制

| 类别 | 限制 | 原因 |
|------|------|------|
| **PatchGuard** | 实验性禁用 | PatchGuard 检测模式随 Windows 更新变化 |
| **HVCI 环境** | CR0.WP 旁路不可用 | Hyper-V 虚拟化拦截 CR0 写入；使用 PTE 操控替代 |
| **Secure Boot** | 必须关闭 | 测试签名驱动无法在 Secure Boot 下加载 |
| **EPROCESS 不透明** | 偏移探测可能在新 Build 上失败 | 微软不保证 EPROCESS 布局稳定性；驱动已实现优雅降级 |
| **FltUnregisterFilter** | NUKE 最后手段 | MS 文档声明仅应由拥有者调用；是合约违反但非执行限制 |
| **WFP flow 清理** | 外部 callout 的 flow 无法直接清除 | 缺少 flowId/layerId；通过 filter 清理 + 退避重试缓解 |
| **InfinityHook** | 依赖 KTHREAD 内部布局 | SystemCallNumber 偏移通过启发式扫描发现 |
| **Keylogger** | 需要 win32kbase.sys 可访问 | Session 0 驱动可能无法直接读取 win32k 内存映射 |

---

## 文件结构

```
driver/
├── memoric.c           # 驱动主体 (~12,600 行)
├── memoric.h           # 共享定义：IOCTL 码 + 请求/响应结构体 (~1,500 行)
├── build.bat           # 自动构建脚本
├── load.bat            # 驱动加载/卸载/重载脚本
├── memoric.ps1         # PowerShell 辅助脚本
├── memoric_new.sys     # 最新编译的签名驱动 (~118 KB)
├── memoric.sys         # 当前加载的驱动副本
└── DRIVER_MANUAL.md    # 本文档
```

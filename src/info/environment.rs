//! Process environment and command line extraction via PEB walk

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Read environment variables from a process via PEB->ProcessParameters->Environment
pub fn get_environment(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;

    tracing::info!("[INFO] get_environment pid={}", pid);

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Get PEB address via NtQueryInformationProcess
        let peb_addr = get_peb_address(*handle)?;

        // Read ProcessParameters pointer (offset 0x20 in PEB on x64)
        let mut params_ptr = [0u8; 8];
        read_remote(*handle, peb_addr + 0x20, &mut params_ptr)?;
        let params_addr = u64::from_ne_bytes(params_ptr);

        // Read Environment pointer and EnvironmentSize from RTL_USER_PROCESS_PARAMETERS
        // Environment is at offset 0x80, EnvironmentSize at offset 0x3F0
        let mut env_ptr_buf = [0u8; 8];
        read_remote(*handle, params_addr + 0x80, &mut env_ptr_buf)?;
        let env_addr = u64::from_ne_bytes(env_ptr_buf);

        let mut env_size_buf = [0u8; 8];
        read_remote(*handle, params_addr + 0x3F0, &mut env_size_buf)?;
        let env_size = u64::from_ne_bytes(env_size_buf) as usize;

        // Clamp to reasonable size
        let read_size = env_size.min(1024 * 1024); // max 1MB

        if env_addr == 0 || read_size == 0 {
            return Ok(serde_json::json!({
                "success": true,
                "pid": pid,
                "variables": [],
                "count": 0,
                "message": "Environment block not found or empty"
            }));
        }

        let mut env_buf = vec![0u8; read_size];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *handle,
            env_addr as *const _,
            env_buf.as_mut_ptr() as *mut _,
            read_size,
            Some(&mut bytes_read as *mut _),
        )
        .map_err(|e| {
            MemoricError::MemoryAccess(format!("Failed to read environment block: {}", e))
        })?;
        env_buf.truncate(bytes_read);

        // Parse double-null-terminated UTF-16LE string list
        let wide: Vec<u16> = env_buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut variables = Vec::new();
        let mut start = 0;

        for i in 0..wide.len() {
            if wide[i] == 0 {
                if start == i {
                    break;
                } // double null = end
                let entry = String::from_utf16_lossy(&wide[start..i]);
                if let Some(eq_pos) = entry.find('=') {
                    if eq_pos > 0 {
                        variables.push(serde_json::json!({
                            "key": &entry[..eq_pos],
                            "value": &entry[eq_pos+1..]
                        }));
                    }
                }
                start = i + 1;
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "variables": variables,
            "count": variables.len()
        }))
    }
}

/// Read command line of a process via PEB->ProcessParameters->CommandLine
pub fn get_command_line(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;

    tracing::info!("[INFO] get_command_line pid={}", pid);

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let peb_addr = get_peb_address(*handle)?;

        // ProcessParameters at PEB+0x20
        let mut params_ptr = [0u8; 8];
        read_remote(*handle, peb_addr + 0x20, &mut params_ptr)?;
        let params_addr = u64::from_ne_bytes(params_ptr);

        // CommandLine UNICODE_STRING at RTL_USER_PROCESS_PARAMETERS+0x70
        // UNICODE_STRING: Length (u16), MaximumLength (u16), padding, Buffer (ptr)
        let mut len_buf = [0u8; 2];
        read_remote(*handle, params_addr + 0x70, &mut len_buf)?;
        let cmd_len = u16::from_ne_bytes(len_buf) as usize;

        let mut buf_ptr = [0u8; 8];
        read_remote(*handle, params_addr + 0x78, &mut buf_ptr)?;
        let cmd_buf_addr = u64::from_ne_bytes(buf_ptr);

        if cmd_buf_addr == 0 || cmd_len == 0 {
            return Ok(serde_json::json!({
                "success": true,
                "pid": pid,
                "command_line": ""
            }));
        }

        let mut cmd_buf = vec![0u8; cmd_len];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *handle,
            cmd_buf_addr as *const _,
            cmd_buf.as_mut_ptr() as *mut _,
            cmd_len,
            Some(&mut bytes_read as *mut _),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("Failed to read command line: {}", e)))?;

        let wide: Vec<u16> = cmd_buf[..bytes_read]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let command_line = String::from_utf16_lossy(&wide)
            .trim_end_matches('\0')
            .to_string();

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "command_line": command_line
        }))
    }
}

// Helper: get PEB address via NtQueryInformationProcess
unsafe fn get_peb_address(handle: windows::Win32::Foundation::HANDLE) -> Result<u64, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
        .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle(ntdll): {}", e)))?;

    let func = GetProcAddress(
        ntdll,
        windows::core::PCSTR(b"NtQueryInformationProcess\0".as_ptr()),
    )
    .ok_or_else(|| MemoricError::WindowsApi("NtQueryInformationProcess not found".to_string()))?;

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i64,
        peb_base_address: u64,
        affinity_mask: u64,
        base_priority: i32,
        _pad: u32,
        unique_process_id: u64,
        inherited_from_unique_process_id: u64,
    }

    let mut pbi = ProcessBasicInformation {
        exit_status: 0,
        peb_base_address: 0,
        affinity_mask: 0,
        base_priority: 0,
        _pad: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let mut ret_len = 0u32;

    type NtQueryFn = unsafe extern "system" fn(
        windows::Win32::Foundation::HANDLE,
        u32,
        *mut std::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    let nt_query: NtQueryFn = std::mem::transmute(func);
    let status = nt_query(
        handle,
        0, // ProcessBasicInformation
        &mut pbi as *mut _ as *mut _,
        std::mem::size_of::<ProcessBasicInformation>() as u32,
        &mut ret_len,
    );

    if status != 0 {
        return Err(MemoricError::WindowsApi(format!(
            "NtQueryInformationProcess failed: 0x{:X}",
            status
        )));
    }

    Ok(pbi.peb_base_address)
}

// Helper: read remote process memory at a specific address
unsafe fn read_remote(
    handle: windows::Win32::Foundation::HANDLE,
    addr: u64,
    buf: &mut [u8],
) -> Result<(), MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let mut bytes_read = 0usize;
    ReadProcessMemory(
        handle,
        addr as *const _,
        buf.as_mut_ptr() as *mut _,
        buf.len(),
        Some(&mut bytes_read as *mut _),
    )
    .map_err(|e| MemoricError::MemoryAccess(format!("ReadProcessMemory at 0x{:X}: {}", addr, e)))
}

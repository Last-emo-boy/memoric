//! MCP-facing readiness and diagnostic response helpers.

use serde_json::{json, Value};

pub(crate) fn runtime_readiness_json(args: &Value) -> Value {
    crate::capability::runtime_readiness_json(args)
}

pub(crate) fn kernel_status(args: &Value) -> Result<Value, String> {
    let runtime = runtime_readiness_json(args);
    let readiness = runtime["driver"].clone();
    let build_number = args
        .get("build_number")
        .and_then(|value| value.as_u64())
        .or_else(|| {
            runtime["platform"]["windows"]["current_build"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
        })
        .map(|value| value as u32);
    let callback_profile = build_number
        .map(|build| {
            crate::kernel_offsets::resolve_callback_offset(
                build,
                crate::kernel_offsets::CallbackOffsetKind::Process,
            )
            .to_json()
        })
        .unwrap_or_else(|| {
            json!({
                "known_build": false,
                "confidence": "unknown",
                "source": "build_number_unavailable",
                "supported_builds": crate::kernel_offsets::supported_builds_summary(),
            })
        });
    let device_reachable = readiness["device"]["reachable"].as_bool().unwrap_or(false);
    let payload_exists = readiness["payload"]["exists"].as_bool().unwrap_or(false);
    let driver_load_possible = readiness["readiness"]["driver_load_possible"]
        .as_bool()
        .unwrap_or(false);
    let next_steps = if device_reachable {
        vec![
            json!("Use kernel(action='driver_stats') for live driver ABI and IOCTL counters."),
            json!("Use kernel(action='driver_enum_process') for read-only kernel process enumeration."),
        ]
    } else if driver_load_possible {
        vec![
            json!("Use kernel(action='driver_load', dry_run=true) to preview service creation."),
            json!("Use kernel(action='driver_discover') to inspect BYOVD candidates and blocklist evidence."),
        ]
    } else {
        vec![
            json!("Run self(action='doctor') or resources/read(uri='memoric://capabilities') for the full readiness matrix."),
            json!("Resolve payload, elevation, test-signing, HVCI, or vulnerable-driver blocklist blockers before live driver load."),
        ]
    };

    Ok(json!({
        "success": true,
        "action": "status",
        "read_only": true,
        "probe_only": true,
        "side_effects": [],
        "driver_source": "memoric",
        "driver_auto_installed": false,
        "fallback_used": false,
        "device": readiness["device"].clone(),
        "payload": readiness["payload"].clone(),
        "signing": readiness["signing"].clone(),
        "wdac": readiness["wdac"].clone(),
        "readiness": readiness["readiness"].clone(),
        "loaded": device_reachable,
        "payload_exists": payload_exists,
        "driver_load_possible": driver_load_possible,
        "message": readiness["message"].clone(),
        "offset_profile": {
            "build_number": build_number,
            "callback_offsets": callback_profile,
            "supported_profiles": crate::kernel_offsets::supported_profiles_json(),
            "supported_builds": crate::kernel_offsets::supported_builds_summary(),
            "eprocess": {
                "strategy": "driver_dynamic_discovery",
                "resolved": null,
                "note": "EPROCESS runtime offsets are reported after the driver is loaded through driver_stats or EPROCESS-returning actions."
            }
        },
        "docs": [
            "docs/troubleshooting.md#driver-unavailable",
            "docs/compatibility.md#windows-platform-matrix",
            "driver/README.md#dynamic-eprocess-offsets"
        ],
        "next_steps": next_steps
    }))
}

pub(crate) fn self_doctor_json(args: &Value) -> Value {
    crate::capability::doctor_json(args)
}

pub(crate) fn explain_error_next_steps(code: &str) -> Vec<Value> {
    match code {
        "missing_param" => vec![json!({
            "tool": "memoric",
            "arguments": { "domain": "all" },
            "reason": "Review available actions and required fields"
        })],
        "invalid_param" => vec![json!({
            "tool": "memoric",
            "arguments": { "domain": "all" },
            "reason": "Review accepted parameter names, types, and enum values"
        })],
        "access_denied" => vec![
            json!({
                "tool": "self",
                "arguments": { "action": "doctor" },
                "reason": "Check elevation, policy, and driver readiness"
            }),
            json!({
                "tool": "privilege",
                "arguments": { "action": "check", "dry_run": true },
                "reason": "Inspect current privilege posture without mutation"
            }),
        ],
        "policy_denied" => vec![json!({
            "tool": "self",
            "arguments": { "action": "doctor" },
            "reason": "Inspect active MEMORIC_POLICY and consent configuration"
        })],
        "driver_unavailable" => vec![json!({
            "tool": "self",
            "arguments": { "action": "doctor" },
            "reason": "Check driver readiness, signing state, and kernel capability blockers"
        })],
        "unsupported_platform" => vec![json!({
            "tool": "self",
            "arguments": { "action": "doctor" },
            "reason": "Confirm runtime platform and available read-only fallback capabilities"
        })],
        "timeout" => vec![json!({
            "tool": "self",
            "arguments": { "action": "doctor" },
            "reason": "Check runtime readiness, then retry with narrower scope or larger timeout_ms"
        })],
        "cancelled" => vec![json!({
            "method": "tasks/get",
            "params": { "taskId": "<task-id>" },
            "reason": "Confirm final task state before starting a replacement task"
        })],
        "partial_read" | "partial_copy" => vec![json!({
            "tool": "memory",
            "arguments": { "action": "query", "pid": "<pid>", "dry_run": true },
            "reason": "Query readable committed regions before retrying a smaller read"
        })],
        "invalid_target" | "not_found" | "process_terminating" => vec![json!({
            "tool": "target",
            "arguments": { "action": "ps_list" },
            "reason": "Refresh process and target readiness before retrying"
        })],
        "ipc_closed" => vec![json!({
            "tool": "self",
            "arguments": { "action": "doctor" },
            "reason": "Check worker/pipe and privilege readiness"
        })],
        _ => vec![json!({
            "tool": "self",
            "arguments": { "action": "doctor" },
            "reason": "Collect baseline diagnostics"
        })],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_status_is_probe_only_and_read_only() {
        let status = kernel_status(&json!({"build_number": 26100})).expect("kernel status");

        assert_eq!(status["success"], json!(true));
        assert_eq!(status["action"], json!("status"));
        assert_eq!(status["read_only"], json!(true));
        assert_eq!(status["probe_only"], json!(true));
        assert_eq!(status["driver_auto_installed"], json!(false));
        assert!(status["offset_profile"]["supported_profiles"].is_array());
    }

    #[test]
    fn explain_error_next_steps_uses_read_only_diagnostics() {
        let access = explain_error_next_steps("access_denied");
        assert_eq!(access.len(), 2);
        assert_eq!(access[0]["tool"], json!("self"));
        assert_eq!(access[0]["arguments"]["action"], json!("doctor"));
        assert_eq!(access[1]["arguments"]["dry_run"], json!(true));

        let fallback = explain_error_next_steps("unknown");
        assert_eq!(fallback[0]["tool"], json!("self"));
        assert_eq!(fallback[0]["arguments"]["action"], json!("doctor"));
    }
}

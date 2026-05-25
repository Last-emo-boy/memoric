//! Post-dispatch state trace recording for successful MCP tool calls.

use serde_json::Value;

pub fn record_trace(tool: &str, args: &Value) {
    let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let pid = args.get("pid").and_then(|v| v.as_u64());

    match tool {
        "stealth" => {
            let status = "applied";
            match action {
                "patch_etw" => {
                    crate::state::record_evasion("patch_etw", "ETW", status);
                }
                "patch_amsi" => {
                    crate::state::record_evasion("patch_amsi", "AMSI", status);
                }
                "unhook_ntdll" => {
                    crate::state::record_evasion("unhook_ntdll", "ntdll.dll", status);
                }
                "hide_module" => {
                    crate::state::record_evasion("hide_module", "PEB", status);
                }
                "sleep_ekko" | "sleep_foliage" | "sleep_gargoyle" | "sleep_death" => {
                    crate::state::record_evasion(action, "sleep", status);
                }
                _ => {}
            }
        }
        "inject" => {
            if let Some(p) = pid {
                let sc_size = args
                    .get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                if sc_size > 0 {
                    crate::state::record_injection(p as u32, action, sc_size);
                }
            }
        }
        "detect" if action == "edr_products" => {
            // State recording is done inside handle_detect when result JSON is available.
        }
        "kernel" => {
            if action == "driver_load" {
                if let Some(driver) = args.get("driver").and_then(|v| v.as_str()) {
                    let path = args
                        .get("driver_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    crate::state::record_driver(driver, path, &["kernel_rw"]);
                }
            }
        }
        _ => {}
    }
}

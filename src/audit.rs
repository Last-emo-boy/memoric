//! JSONL audit logging for MCP tool calls.

use serde_json::{json, Value};
use std::io::Write;

pub fn record_tool_call(
    tool: &str,
    args: &Value,
    policy: &Value,
    result_status: &str,
    error: Option<&str>,
    result: Option<&Value>,
) {
    let Some(path) = crate::policy::audit_path() else {
        return;
    };

    let request_context = crate::mcp::request_context::current_request_context();
    let redaction_profile = crate::redaction::profile_from_args(args);
    let artifacts = result
        .map(|result| {
            let mut artifacts = crate::artifact::collect_artifact_references(result);
            artifacts.extend(crate::artifact::collect_artifacts(result));
            artifacts.sort_by(|left, right| {
                left["uri"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["uri"].as_str().unwrap_or_default())
            });
            artifacts.dedup_by(|left, right| left["uri"] == right["uri"]);
            artifacts
        })
        .unwrap_or_default();
    let integrity = result
        .map(crate::artifact::json_integrity)
        .unwrap_or(Value::Null);
    let state_change = result
        .map(|result| state_change_summary(result, redaction_profile))
        .unwrap_or(Value::Null);

    let entry = json!({
        "ts": crate::state::chrono_now_public(),
        "tool": tool,
        "action": args.get("action").and_then(|v| v.as_str()).unwrap_or(""),
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
        "app_origin": request_context
            .as_ref()
            .and_then(|context| context.app_origin.clone())
            .map(Value::String)
            .unwrap_or(Value::Null),
        "policy_origin": request_context
            .as_ref()
            .map(|context| json!(context.policy_origin.as_str()))
            .unwrap_or(Value::Null),
        "args": crate::redaction::redact_value(args, redaction_profile),
        "redaction": crate::redaction::metadata(redaction_profile),
        "policy": policy,
        "policy_profile": crate::policy::policy_profile_audit_json(),
        "result_status": result_status,
        "error": error,
        "artifacts": artifacts,
        "integrity": integrity,
        "state_change": state_change,
    });
    crate::observability::record_audit_entry(&entry);

    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut file) => {
            let _ = writeln!(file, "{}", entry);
        }
        Err(err) => {
            tracing::warn!("failed to write audit log {}: {}", path, err);
        }
    }
}

fn state_change_summary(result: &Value, profile: crate::redaction::RedactionProfile) -> Value {
    let provenance = result.get("provenance").cloned().unwrap_or(Value::Null);
    let mutation = result.get("mutation").cloned().unwrap_or(Value::Null);
    let rollback = result
        .get("rollback")
        .map(|rollback| rollback_summary(rollback, profile))
        .unwrap_or(Value::Null);

    if provenance.is_null() && mutation.is_null() && rollback.is_null() {
        return Value::Null;
    }

    json!({
        "provenance": crate::redaction::redact_value(&provenance, profile),
        "mutation": crate::redaction::redact_value(&mutation, profile),
        "rollback": rollback,
    })
}

fn rollback_summary(rollback: &Value, profile: crate::redaction::RedactionProfile) -> Value {
    if rollback.is_null() {
        return Value::Null;
    }

    let mut summary = serde_json::Map::new();
    for key in [
        "available",
        "strategy",
        "kind",
        "reason",
        "detail",
        "captured_fields",
        "original_state",
    ] {
        if let Some(value) = rollback.get(key) {
            summary.insert(key.to_string(), value.clone());
        }
    }

    if let Some(action) = rollback.get("action").and_then(|value| value.as_object()) {
        summary.insert(
            "action".to_string(),
            json!({
                "tool": action.get("tool").cloned().unwrap_or(Value::Null),
                "action": action.get("action").cloned().unwrap_or(Value::Null),
                "args_present": action.get("args").is_some(),
            }),
        );
    }
    if let Some(actions) = rollback.get("actions").and_then(|value| value.as_array()) {
        summary.insert("action_count".to_string(), json!(actions.len()));
    }

    if summary.is_empty() {
        return json!({
            "available": rollback.get("available").cloned().unwrap_or(Value::Null),
            "summary_only": true,
        });
    }

    crate::redaction::redact_value(&Value::Object(summary), profile)
}

#[cfg(test)]
mod tests {
    use super::record_tool_call;
    use serde_json::json;
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FIXTURE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn redacts_sensitive_fields() {
        let value = crate::redaction::redact_value(
            &json!({
                "action": "shellcode",
                "shellcode": [1, 2, 3],
                "nested": { "token": "abc", "pid": 1 }
            }),
            crate::redaction::RedactionProfile::Standard,
        );
        assert_eq!(value["shellcode"], "<redacted>");
        assert_eq!(value["nested"]["token"], "<redacted>");
        assert_eq!(value["nested"]["pid"], 1);
    }

    #[test]
    fn records_app_origin_and_policy_origin_in_audit_entry() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let audit_path = std::env::temp_dir().join(format!(
            "memoric-audit-{}-{}-{}.jsonl",
            std::process::id(),
            fixture_id,
            crate::state::chrono_now_public().replace([':', '-'], "")
        ));
        let _audit_guard =
            crate::policy::set_test_audit_path(Some(audit_path.display().to_string()));

        let request = json!({
            "jsonrpc": "2.0",
            "id": "audit-app-origin",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": {
                    "action": "version",
                    "request_id": "audit-app-origin"
                },
                "_meta": {
                    "io.memoric/app-origin": "ui://memoric/dashboard"
                }
            }
        });
        let context = crate::mcp::request_context::McpRequestContext::from_request(
            &request,
            crate::mcp::request_context::McpTransportKind::Http,
        );
        let _context_guard = crate::mcp::request_context::set_current_request_context(context);

        record_tool_call(
            "self",
            &json!({
                "action": "version",
                "request_id": "audit-app-origin"
            }),
            &json!({
                "allowed": true,
                "configured_policy": "observe",
                "required_policy": "observe",
                "reason": "allowed"
            }),
            "success",
            None,
            Some(&json!({"message": "ok"})),
        );

        let content = std::fs::read_to_string(&audit_path).expect("audit file");
        let entry_line = content
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("audit entry line");
        let entry: Value = serde_json::from_str(entry_line).expect("audit json");
        assert_eq!(entry["app_origin"], "ui://memoric/dashboard");
        assert_eq!(entry["policy_origin"], "app");

        let _ = std::fs::remove_file(audit_path);
    }

    #[test]
    fn records_policy_profile_identity_in_audit_entry() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let audit_path = std::env::temp_dir().join(format!(
            "memoric-audit-policy-profile-{}-{}.jsonl",
            std::process::id(),
            fixture_id
        ));
        let profile_path = std::env::temp_dir().join(format!(
            "memoric-audit-policy-profile-{}-{}.json",
            std::process::id(),
            fixture_id
        ));
        let profile = json!({
            "profile": "audit-lab-policy",
            "version": 1,
            "policy": "observe"
        });
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        std::fs::write(&profile_path, &profile_bytes).unwrap();
        std::fs::write(
            format!("{}.sha256", profile_path.display()),
            crate::artifact::sha256_bytes(&profile_bytes),
        )
        .unwrap();
        let _audit_guard =
            crate::policy::set_test_audit_path(Some(audit_path.display().to_string()));
        std::env::set_var(
            "MEMORIC_POLICY_PROFILE_PATH",
            profile_path.display().to_string(),
        );

        record_tool_call(
            "self",
            &json!({
                "action": "version",
                "request_id": "audit-policy-profile"
            }),
            &crate::policy::policy_profile_audit_json(),
            "success",
            None,
            Some(&json!({"message": "ok"})),
        );

        let content = std::fs::read_to_string(&audit_path).expect("audit file");
        let entry_line = content
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("audit entry line");
        let entry: Value = serde_json::from_str(entry_line).expect("audit json");
        assert_eq!(entry["policy_profile"]["profile"], "audit-lab-policy");
        assert_eq!(entry["policy_profile"]["status"], "loaded");
        assert_eq!(entry["policy_profile"]["hash"]["verified"], true);

        let _ = std::fs::remove_file(audit_path);
        let _ = std::fs::remove_file(profile_path.clone());
        let _ = std::fs::remove_file(format!("{}.sha256", profile_path.display()));
        std::env::remove_var("MEMORIC_POLICY_PROFILE_PATH");
    }

    #[test]
    fn records_state_change_summary_without_raw_rollback_bytes() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let audit_path = std::env::temp_dir().join(format!(
            "memoric-audit-state-change-{}-{}.jsonl",
            std::process::id(),
            fixture_id
        ));
        let _audit_guard =
            crate::policy::set_test_audit_path(Some(audit_path.display().to_string()));

        record_tool_call(
            "memory",
            &json!({
                "action": "write",
                "request_id": "audit-state-change",
                "redaction": "strict"
            }),
            &json!({"allowed": true}),
            "success",
            None,
            Some(&json!({
                "success": true,
                "provenance": {
                    "request_id": "audit-state-change",
                    "task_id": "task-audit",
                    "chain_id": "chain-audit"
                },
                "mutation": {
                    "kind": "memory_write",
                    "target_pid": 1234,
                    "address": "0x1000"
                },
                "rollback": {
                    "available": true,
                    "strategy": "restore_original_bytes",
                    "captured_fields": ["original_bytes"],
                    "original_bytes": [1, 2, 3],
                    "action": {
                        "tool": "memory",
                        "action": "write",
                        "args": {
                            "bytes": [1, 2, 3]
                        }
                    }
                }
            })),
        );

        let content = std::fs::read_to_string(&audit_path).expect("audit file");
        let entry: Value = serde_json::from_str(
            content
                .lines()
                .find(|line| !line.trim().is_empty())
                .expect("audit entry"),
        )
        .expect("audit json");
        assert_eq!(entry["state_change"]["provenance"]["task_id"], "task-audit");
        assert_eq!(entry["state_change"]["mutation"]["kind"], "memory_write");
        assert_eq!(
            entry["state_change"]["rollback"]["strategy"],
            "restore_original_bytes"
        );
        assert!(entry["state_change"]["rollback"]
            .get("original_bytes")
            .is_none());
        assert_eq!(
            entry["state_change"]["rollback"]["action"]["args_present"],
            true
        );

        let _ = std::fs::remove_file(audit_path);
    }
}

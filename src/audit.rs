//! JSONL audit logging for MCP tool calls.
//!
//! Audit entries are built synchronously (observability + redaction) but
//! the file write is dispatched to a background thread so the response path
//! is never blocked on disk I/O.

use serde_json::{json, Value};
use std::io::Write;
use std::sync::mpsc::{self, SyncSender};
use std::sync::OnceLock;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    static TEST_AUDIT_PATH: RefCell<Option<String>> = const { RefCell::new(None) };
}

static AUDIT_SENDER: OnceLock<SyncSender<String>> = OnceLock::new();

fn audit_sender() -> Option<&'static SyncSender<String>> {
    let path = audit_path()?;
    let sender = AUDIT_SENDER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<String>(1024);
        std::thread::Builder::new()
            .name("memoric-audit".into())
            .spawn(move || {
                for line in rx {
                    let dir = std::path::Path::new(&path).parent();
                    if let Some(parent) = dir {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        Ok(mut file) => {
                            let _ = writeln!(file, "{}", line);
                        }
                        Err(err) => {
                            tracing::warn!("audit bg write failed {}: {}", path, err);
                        }
                    }
                }
            })
            .ok();
        tx
    });
    Some(sender)
}

pub fn audit_path() -> Option<String> {
    #[cfg(test)]
    {
        if let Some(path) = TEST_AUDIT_PATH.with(|slot| slot.borrow().clone()) {
            return Some(path);
        }
    }
    std::env::var("MEMORIC_AUDIT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
pub(crate) fn set_test_audit_path(path: Option<String>) -> TestAuditPathGuard {
    let previous = TEST_AUDIT_PATH.with(|slot| slot.replace(path));
    TestAuditPathGuard { previous }
}

#[cfg(test)]
pub(crate) struct TestAuditPathGuard {
    previous: Option<String>,
}

#[cfg(test)]
impl Drop for TestAuditPathGuard {
    fn drop(&mut self) {
        TEST_AUDIT_PATH.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

pub fn record_tool_call(
    tool: &str,
    args: &Value,
    policy: &Value,
    result_status: &str,
    error: Option<&str>,
    result: Option<&Value>,
) {
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
        "policy_profile": json!({}),
        "result_status": result_status,
        "error": error,
        "artifacts": artifacts,
        "integrity": integrity,
        "state_change": state_change,
    });
    crate::observability::record_audit_entry(&entry);

    let line = entry.to_string();
    #[cfg(test)]
    if let Some(path) = TEST_AUDIT_PATH.with(|slot| slot.borrow().clone()) {
        write_audit_line(&path, &line);
        return;
    }

    // Dispatch file write to background thread — never block the response.
    if let Some(sender) = audit_sender() {
        if sender.send(line).is_err() {
            tracing::debug!("audit channel full, entry dropped");
        }
    }
}

fn write_audit_line(path: &str, line: &str) {
    let dir = std::path::Path::new(path).parent();
    if let Some(parent) = dir {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut file) => {
            let _ = writeln!(file, "{}", line);
        }
        Err(err) => {
            tracing::warn!("audit write failed {}: {}", path, err);
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
    use super::{record_tool_call, set_test_audit_path};
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
            set_test_audit_path(Some(audit_path.display().to_string()));

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
        let _audit_guard =
            set_test_audit_path(Some(audit_path.display().to_string()));

        record_tool_call(
            "self",
            &json!({
                "action": "version",
                "request_id": "audit-policy-profile"
            }),
            &json!({}),
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
        assert_eq!(entry["policy_profile"], json!({}));

        let _ = std::fs::remove_file(audit_path);
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
            set_test_audit_path(Some(audit_path.display().to_string()));

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

use serde_json::{json, Value};

use crate::mcp::tool_args::{normalize_common_args, parse_address_arg, parse_u64_arg};

const MAX_SUMMARY_CHARS: usize = 180;

pub fn tool_error_payload(tool: &str, args: &Value, message: &str) -> Value {
    let normalized_args = normalize_common_args(tool, args);
    let args = &normalized_args;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let classification = crate::error::classify_tool_error(message);
    let authorization = authorization_challenge(tool, args, &classification);
    let mut context = serde_json::Map::new();

    context.insert("tool".to_string(), json!(tool));
    if !action.is_empty() {
        context.insert("action".to_string(), json!(action));
    }
    for key in [
        "pid",
        "tid",
        "session_id",
        "module",
        "module_name",
        "function",
    ] {
        if let Some(value) = args.get(key) {
            context.insert(key.to_string(), value.clone());
        }
    }
    if let Some(address) = parse_address_arg(args.get("address")) {
        context.insert("address".to_string(), json!(format!("0x{:016X}", address)));
    }
    if let Some(size) = parse_u64_arg(args.get("size")) {
        context.insert("size".to_string(), json!(size));
    }

    let profile = crate::redaction::profile_from_args(args);
    let payload = json!({
        "success": false,
        "code": classification.code,
        "error": message,
        "message": message,
        "hint": classification.hint,
        "summary": concise_text(&format!("{} failed: {}", tool, message)),
        "context": context,
        "authorization": authorization,
        "artifacts": [],
        "integrity": crate::artifact::json_integrity(&json!({
            "success": false,
            "code": classification.code,
            "message": message
        })),
        "warnings": [classification.hint],
        "evidence": [],
        "redaction": crate::redaction::metadata(profile)
    });

    crate::redaction::redact_value(&payload, profile)
}

fn authorization_challenge(
    tool: &str,
    args: &Value,
    classification: &crate::error::ToolErrorClassification,
) -> Value {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if !matches!(classification.code, "policy_denied" | "access_denied") {
        return Value::Null;
    }

    let traits = crate::mcp::action_registry::classify_action(tool, action);
    let configured_policy = crate::policy::configured_level();
    let consent_token_configured = std::env::var("MEMORIC_CONSENT_TOKEN")
        .ok()
        .is_some_and(|token| !token.trim().is_empty());
    let scheme = if classification.code == "policy_denied" {
        "memoric-policy"
    } else {
        "memoric-access"
    };
    let challenge = format!(
        "Memoric realm=\"memoric\", error=\"{}\", scope=\"{}\", required_policy=\"{}\"",
        classification.code,
        traits.required_policy.as_str(),
        configured_policy.as_str()
    );

    json!({
        "required": true,
        "status": "challenge",
        "scheme": scheme,
        "realm": "memoric",
        "code": classification.code,
        "tool": tool,
        "action": action,
        "required_policy": traits.required_policy.as_str(),
        "configured_policy": configured_policy.as_str(),
        "state_changing": traits.state_changing,
        "consent_token_configured": consent_token_configured,
        "www_authenticate": [challenge],
    })
}

pub fn tool_error_text(tool: &str, args: &Value, message: &str) -> String {
    serde_json::to_string(&tool_error_payload(tool, args, message)).unwrap_or_else(|_| {
        format!(
            "{{\"success\":false,\"code\":\"tool_error\",\"error\":\"{}\"}}",
            message.replace('"', "'")
        )
    })
}

pub fn tool_success_payload(tool: &str, args: &Value, result: &Value) -> Value {
    let normalized_args = normalize_common_args(tool, args);
    let action = normalized_args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let traits = crate::mcp::action_registry::classify_action(tool, action);
    let mut context = serde_json::Map::new();

    context.insert("tool".to_string(), json!(tool));
    if !action.is_empty() {
        context.insert("action".to_string(), json!(action));
    }
    if let Some(request_id) = normalized_args.get("request_id") {
        context.insert("request_id".to_string(), request_id.clone());
    }
    if let Some(purpose) = normalized_args.get("purpose") {
        context.insert("purpose".to_string(), purpose.clone());
    }

    let profile = crate::redaction::profile_from_args(args);
    let mut artifacts = crate::artifact::collect_artifact_references(result);
    artifacts.extend(crate::artifact::collect_artifacts_with_retention(
        result,
        crate::artifact::retention_secs_from_args(args),
    ));
    artifacts.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["uri"].as_str().unwrap_or_default())
    });
    artifacts.dedup_by(|left, right| left["uri"] == right["uri"]);
    let classification_rules = crate::mcp::action_registry::tool_output_classification_rules(tool);
    let payload = json!({
        "success": true,
        "code": "ok",
        "message": result.get("message").and_then(|v| v.as_str()).unwrap_or("ok"),
        "summary": summarize_tool_result(tool, action, result),
        "data": result,
        "context": context,
        "artifacts": artifacts,
        "integrity": crate::artifact::json_integrity(result),
        "warnings": [],
        "evidence": [],
        "metadata": {
            "read_only": traits.read_only,
            "state_changing": traits.state_changing,
            "risk": traits.risk.as_str(),
            "required_policy": traits.required_policy.as_str(),
            "result_strategy": result_strategy(tool, action, args, result, &artifacts),
            "redaction": crate::redaction::metadata(profile),
            "data_classification": crate::mcp::action_registry::tool_classification_summary(tool),
        }
    });

    crate::redaction::redact_value_with_classifications(&payload, profile, &classification_rules)
}

fn result_strategy(
    tool: &str,
    action: &str,
    args: &Value,
    result: &Value,
    artifacts: &[Value],
) -> Value {
    let has_pagination = result.get("nextCursor").is_some()
        || result.get("pagination").is_some()
        || result.pointer("/snapshot/cursorKind").is_some()
        || result.pointer("/pagination/nextCursor").is_some();
    let has_artifacts = !artifacts.is_empty();
    let uses_streamed_progress = action_uses_streamed_progress(tool, action);
    let inline_mode = if has_artifacts {
        "summary_with_resource_links"
    } else if has_pagination {
        "paginated_inline_page"
    } else {
        "inline"
    };
    let mut boundaries = vec!["result_envelope"];
    if has_pagination {
        boundaries.push("page_cursor");
    }
    if has_artifacts {
        boundaries.push("artifact_resource");
    }
    if uses_streamed_progress {
        boundaries.push("progress_notification");
    }
    let cursor = result
        .get("nextCursor")
        .or_else(|| result.pointer("/pagination/nextCursor"))
        .cloned()
        .unwrap_or(Value::Null);
    let progress_token_present = args.get("task_id").is_some()
        || args
            .get("_meta")
            .and_then(|meta| meta.get("progressToken"))
            .is_some();

    json!({
        "inline": inline_mode,
        "paginated": has_pagination,
        "nextCursor": cursor,
        "resource_links": has_artifacts,
        "artifact_count": artifacts.len(),
        "streamed_progress": uses_streamed_progress,
        "progress_token_present": progress_token_present,
        "stream_boundaries": boundaries,
        "cancellation_boundary": uses_streamed_progress || has_pagination,
        "timeout_boundary": uses_streamed_progress || matches!((tool, action), ("memory", "scan") | ("memory", "scan_new") | ("memory", "scan_next") | ("orchestrate", "execute")),
        "strategy": if has_artifacts {
            "reference"
        } else if uses_streamed_progress {
            "streamed-progress"
        } else if has_pagination {
            "paginated"
        } else {
            "inline"
        }
    })
}

fn action_uses_streamed_progress(tool: &str, action: &str) -> bool {
    matches!(
        (tool, action),
        ("memory", "scan_new")
            | ("memory", "scan_next")
            | ("orchestrate", "execute")
            | ("kernel", "driver_discover")
    )
}

fn summarize_tool_result(tool: &str, action: &str, result: &Value) -> String {
    if let Some(summary) = string_field(result, "summary") {
        return concise_text(summary);
    }
    if let Some(summary) = summarize_by_tool(tool, action, result) {
        return concise_text(&summary);
    }
    if let Some(message) = result.get("message").and_then(|v| v.as_str()) {
        return concise_text(message);
    }
    if let Some(success) = result.get("success").and_then(|v| v.as_bool()) {
        return concise_text(&format!(
            "{}{} completed ({})",
            tool,
            if action.is_empty() {
                String::new()
            } else {
                format!(" action='{}'", action)
            },
            if success {
                "success"
            } else {
                "reported failure"
            }
        ));
    }
    concise_text(&format!(
        "{}{} completed",
        tool,
        if action.is_empty() {
            String::new()
        } else {
            format!(" action='{}'", action)
        }
    ))
}

fn summarize_by_tool(tool: &str, action: &str, result: &Value) -> Option<String> {
    match tool {
        "memory" => summarize_memory(action, result),
        "target" => summarize_target(action, result),
        "kernel" => summarize_kernel(action, result),
        "self" => summarize_self(action, result),
        "orchestrate" => summarize_orchestrate(action, result),
        _ => summarize_collection(tool, action, result),
    }
}

fn summarize_memory(action: &str, result: &Value) -> Option<String> {
    match action {
        "read" | "typed_read" => {
            let bytes = u64_field(result, "bytes_read")?;
            let address = string_field(result, "address")
                .map(|address| format!(" from {}", address))
                .unwrap_or_default();
            let partial = bool_field(result, "partial")
                .filter(|partial| *partial)
                .map(|_| " (partial)")
                .unwrap_or_default();
            Some(format!(
                "memory {}: {} bytes{}{}",
                action, bytes, address, partial
            ))
        }
        "write" | "typed_write" | "write_string" => {
            let bytes = u64_field(result, "bytes_written")
                .or_else(|| u64_field(result, "bytes"))
                .or_else(|| u64_field(result, "size"));
            let address = string_field(result, "address")
                .map(|address| format!(" to {}", address))
                .unwrap_or_default();
            bytes
                .map(|bytes| format!("memory {}: {} bytes{}", action, bytes, address))
                .or_else(|| summarize_collection("memory", action, result))
        }
        "scan_new" => {
            let session = string_field(result, "session_id").unwrap_or("unknown session");
            let matches = u64_field(result, "result_count")
                .or_else(|| u64_field(result, "count"))
                .or_else(|| u64_field(result, "total_count"))
                .unwrap_or_default();
            Some(format!(
                "scan_new: session {} with {} matches",
                session, matches
            ))
        }
        "scan_next" => {
            let session = string_field(result, "session_id").unwrap_or("unknown session");
            let after = result
                .get("delta")
                .and_then(|delta| u64_field(delta, "after"))
                .or_else(|| u64_field(result, "count"))
                .or_else(|| u64_field(result, "total_count"));
            after.map(|after| {
                format!(
                    "scan_next: session {} narrowed to {} candidates",
                    session, after
                )
            })
        }
        "scan_list" => {
            let session = string_field(result, "session_id").unwrap_or("unknown session");
            let count = u64_field(result, "count")?;
            let total = u64_field(result, "total_count").unwrap_or(count);
            Some(format!(
                "scan_list: {}/{} candidates for session {}",
                count, total, session
            ))
        }
        "alloc" => {
            let address = string_field(result, "address").unwrap_or("unknown address");
            let size = u64_field(result, "size").unwrap_or_default();
            Some(format!("memory alloc: {} bytes at {}", size, address))
        }
        "free" => {
            let address = string_field(result, "address").unwrap_or("requested address");
            Some(format!("memory free: released {}", address))
        }
        "protect" => {
            let address = string_field(result, "address").unwrap_or("requested address");
            let protect = string_field(result, "new_protect")
                .or_else(|| string_field(result, "protect"))
                .unwrap_or("requested protection");
            Some(format!("memory protect: {} set to {}", address, protect))
        }
        "diagnostics" => result
            .get("summary")
            .and_then(|summary| u64_field(summary, "total_regions"))
            .map(|regions| format!("memory diagnostics: {} regions summarized", regions)),
        _ => summarize_collection("memory", action, result),
    }
}

fn summarize_target(action: &str, result: &Value) -> Option<String> {
    if let Some(count) = u64_field(result, "count").or_else(|| array_len(result, "processes")) {
        let label = match action {
            "ps_list" | "ps_find" => "processes",
            "modules" => "modules",
            "threads" | "threads_list" => "threads",
            _ => "items",
        };
        return Some(format!("target {}: {} {}", action, count, label));
    }
    if let Some(pid) = u64_field(result, "pid") {
        return Some(format!("target {}: PID {} summarized", action, pid));
    }
    summarize_collection("target", action, result)
}

fn summarize_kernel(action: &str, result: &Value) -> Option<String> {
    if action == "status" {
        let possible = result
            .pointer("/readiness/driver_load_possible")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let readiness = if possible {
            "driver load appears possible"
        } else {
            "driver load blocked or not ready"
        };
        return Some(format!("kernel status: {}", readiness));
    }
    if action == "driver_discover" {
        let found = array_len(result, "drivers")
            .or_else(|| array_len(result, "found_drivers"))
            .or_else(|| u64_field(result, "count"))
            .unwrap_or_default();
        return Some(format!("driver_discover: {} candidates found", found));
    }
    summarize_collection("kernel", action, result)
}

fn summarize_self(action: &str, result: &Value) -> Option<String> {
    match action {
        "diagnostics" => {
            let artifact = result
                .pointer("/artifact/uri")
                .and_then(|value| value.as_str())
                .is_some();
            Some(if artifact {
                "self diagnostics: operator bundle exported as artifact".to_string()
            } else {
                "self diagnostics: operator bundle generated".to_string()
            })
        }
        "next_steps" => array_len(result, "steps")
            .map(|steps| format!("next_steps: {} recommended steps", steps)),
        "capability_diff" => array_len(result, "changes")
            .map(|changes| format!("capability_diff: {} watched changes", changes)),
        "state" => summarize_collection("self", action, result),
        _ => None,
    }
}

fn summarize_orchestrate(action: &str, result: &Value) -> Option<String> {
    match action {
        "templates" => array_len(result, "templates")
            .map(|templates| format!("orchestrate templates: {} templates available", templates)),
        "plan" | "execute" => {
            let steps = array_len(result, "plan")
                .or_else(|| array_len(result, "effective_plan"))
                .or_else(|| array_len(result, "steps"))
                .unwrap_or_default();
            let blocked = array_len(result, "blocked_steps").unwrap_or_default();
            Some(format!(
                "orchestrate {}: {} steps, {} blocked",
                action, steps, blocked
            ))
        }
        "assess" => array_len(result, "detected_products")
            .map(|products| format!("orchestrate assess: {} detected products", products)),
        _ => summarize_collection("orchestrate", action, result),
    }
}

fn summarize_collection(tool: &str, action: &str, result: &Value) -> Option<String> {
    for (key, label) in [
        ("processes", "processes"),
        ("modules", "modules"),
        ("threads", "threads"),
        ("handles", "handles"),
        ("regions", "regions"),
        ("addresses", "addresses"),
        ("results", "results"),
        ("matches", "matches"),
        ("candidates", "candidates"),
        ("entries", "entries"),
        ("artifacts", "artifacts"),
        ("steps", "steps"),
        ("plan", "plan steps"),
        ("effective_plan", "effective steps"),
        ("templates", "templates"),
    ] {
        if let Some(count) = array_len(result, key).or_else(|| {
            if key == "results" || key == "entries" || key == "candidates" {
                u64_field(result, "count")
            } else {
                None
            }
        }) {
            let total = u64_field(result, "total_count").unwrap_or(count);
            return Some(if total != count {
                format!(
                    "{}{}: {}/{} {}",
                    tool,
                    action_suffix(action),
                    count,
                    total,
                    label
                )
            } else {
                format!("{}{}: {} {}", tool, action_suffix(action), count, label)
            });
        }
    }

    u64_field(result, "count").map(|count| {
        let total = u64_field(result, "total_count").unwrap_or(count);
        if total != count {
            format!(
                "{}{}: {}/{} items",
                tool,
                action_suffix(action),
                count,
                total
            )
        } else {
            format!("{}{}: {} items", tool, action_suffix(action), count)
        }
    })
}

fn action_suffix(action: &str) -> String {
    if action.is_empty() {
        String::new()
    } else {
        format!(" action='{}'", action)
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(|value| value.as_bool())
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|n| u64::try_from(n).ok()))
            .or_else(|| {
                value
                    .as_str()
                    .and_then(|text| text.trim().parse::<u64>().ok())
            })
    })
}

fn array_len(value: &Value, key: &str) -> Option<u64> {
    value
        .get(key)
        .and_then(|value| value.as_array())
        .map(|values| values.len() as u64)
}

fn concise_text(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_SUMMARY_CHARS {
        return collapsed;
    }

    let mut truncated = collapsed
        .chars()
        .take(MAX_SUMMARY_CHARS.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_error_payload_includes_policy_authorization_challenge() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        std::env::set_var("MEMORIC_POLICY", "observe");
        std::env::set_var("MEMORIC_CONSENT_TOKEN", "expected-token");

        let payload = tool_error_payload(
            "memory",
            &json!({"action": "write", "consent_token": "expected-token"}),
            "policy_denied: memory(action='write') blocked by policy",
        );

        assert_eq!(payload["code"], "policy_denied");
        assert_eq!(payload["authorization"]["required"], true);
        assert_eq!(payload["authorization"]["status"], "challenge");
        assert_eq!(payload["authorization"]["scheme"], "memoric-policy");
        assert_eq!(payload["authorization"]["realm"], "memoric");
        assert_eq!(payload["authorization"]["required_policy"], "lab-write");
        assert_eq!(payload["authorization"]["configured_policy"], "observe");
        assert_eq!(payload["authorization"]["consent_token_configured"], true);
        assert!(payload["authorization"]["www_authenticate"][0]
            .as_str()
            .unwrap_or_default()
            .contains("error=\"policy_denied\""));

        std::env::remove_var("MEMORIC_POLICY");
        std::env::remove_var("MEMORIC_CONSENT_TOKEN");
    }

    #[test]
    fn tool_error_payload_includes_access_denied_challenge_metadata() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();

        let payload = tool_error_payload(
            "target",
            &json!({"action": "ps_info", "pid": 4}),
            "access is denied",
        );

        assert_eq!(payload["code"], "access_denied");
        assert_eq!(payload["authorization"]["required"], true);
        assert_eq!(payload["authorization"]["scheme"], "memoric-access");
        assert!(payload["authorization"]["www_authenticate"][0]
            .as_str()
            .unwrap_or_default()
            .contains("error=\"access_denied\""));
    }

    #[test]
    fn success_payload_uses_memory_scan_specific_summary() {
        let payload = tool_success_payload(
            "memory",
            &json!({"action": "scan_list"}),
            &json!({
                "session_id": "scan-1",
                "count": 25,
                "total_count": 400,
                "candidates": []
            }),
        );

        assert_eq!(
            payload["summary"],
            "scan_list: 25/400 candidates for session scan-1"
        );
    }

    #[test]
    fn success_payload_summarizes_collections_without_reading_data() {
        let payload = tool_success_payload(
            "target",
            &json!({"action": "ps_list"}),
            &json!({
                "count": 2,
                "processes": [
                    {"pid": 1, "name": "one.exe"},
                    {"pid": 2, "name": "two.exe"}
                ]
            }),
        );

        assert_eq!(payload["summary"], "target ps_list: 2 processes");
    }

    #[test]
    fn success_payload_strict_redacts_memory_rollback_original_bytes() {
        let payload = tool_success_payload(
            "memory",
            &json!({"action": "write", "redaction": "strict"}),
            &json!({
                "success": true,
                "bytes_written": 4,
                "rollback": {
                    "available": true,
                    "strategy": "restore_original_bytes",
                    "original_bytes": [1, 2, 3, 4],
                    "action": {
                        "tool": "memory",
                        "action": "write",
                        "args": {
                            "bytes": [1, 2, 3, 4]
                        }
                    }
                }
            }),
        );

        assert_eq!(
            payload["data"]["rollback"]["original_bytes"]["redacted"],
            true
        );
        assert_eq!(
            payload["data"]["rollback"]["action"]["args"]["bytes"]["redacted"],
            true
        );
    }

    #[test]
    fn success_payload_strict_redacts_target_string_rollback_original_bytes() {
        let payload = tool_success_payload(
            "target",
            &json!({"action": "string_write", "redaction": "strict"}),
            &json!({
                "success": true,
                "bytes_written": 4,
                "rollback": {
                    "available": true,
                    "strategy": "restore_original_string_bytes",
                    "original_bytes": [111, 108, 100, 0],
                    "action": {
                        "tool": "memory",
                        "action": "write",
                        "args": {
                            "bytes": [111, 108, 100, 0]
                        }
                    }
                }
            }),
        );

        assert_eq!(
            payload["data"]["rollback"]["original_bytes"]["redacted"],
            true
        );
        assert_eq!(
            payload["data"]["rollback"]["action"]["args"]["bytes"]["redacted"],
            true
        );
    }

    #[test]
    fn success_payload_strict_redacts_hook_rollback_original_bytes() {
        let payload = tool_success_payload(
            "hook",
            &json!({"action": "detour", "redaction": "strict"}),
            &json!({
                "success": true,
                "rollback": {
                    "available": true,
                    "strategy": "restore_detour_original_bytes",
                    "original_bytes": [1, 2, 3, 4],
                    "action": {
                        "tool": "hook",
                        "action": "restore",
                        "args": {
                            "original_bytes": [1, 2, 3, 4]
                        }
                    },
                    "actions": [
                        {
                            "tool": "hook",
                            "action": "restore",
                            "args": {
                                "original_bytes": [5, 6, 7, 8]
                            }
                        }
                    ],
                    "hooks": [
                        {
                            "rollback": {
                                "original_bytes": [9, 10],
                                "action": {
                                    "tool": "hook",
                                    "action": "restore",
                                    "args": {
                                        "original_bytes": [9, 10]
                                    }
                                }
                            }
                        }
                    ]
                }
            }),
        );

        assert_eq!(
            payload["data"]["rollback"]["original_bytes"]["redacted"],
            true
        );
        assert_eq!(
            payload["data"]["rollback"]["action"]["args"]["original_bytes"]["redacted"],
            true
        );
        assert_eq!(
            payload["data"]["rollback"]["actions"][0]["args"]["original_bytes"]["redacted"],
            true
        );
        assert_eq!(
            payload["data"]["rollback"]["hooks"][0]["rollback"]["original_bytes"]["redacted"],
            true
        );
        assert_eq!(
            payload["data"]["rollback"]["hooks"][0]["rollback"]["action"]["args"]["original_bytes"]
                ["redacted"],
            true
        );
    }

    #[test]
    fn success_payload_preserves_thread_rollback_and_provenance_metadata() {
        let payload = tool_success_payload(
            "target",
            &json!({
                "action": "thread_suspend",
                "request_id": "req-thread",
                "task_id": "task-thread",
                "purpose": "capture thread rollback"
            }),
            &json!({
                "success": true,
                "tid": 1234,
                "previous_suspend_count": 0,
                "rollback": {
                    "available": true,
                    "strategy": "resume_thread",
                    "captured_fields": ["tid", "previous_suspend_count"],
                    "action": {
                        "tool": "target",
                        "action": "thread_resume",
                        "args": {
                            "tid": 1234
                        }
                    }
                },
                "provenance": {
                    "request_id": "req-thread",
                    "task_id": "task-thread",
                    "purpose": "capture thread rollback"
                }
            }),
        );

        assert_eq!(payload["context"]["request_id"], "req-thread");
        assert_eq!(payload["context"]["purpose"], "capture thread rollback");
        assert_eq!(payload["data"]["rollback"]["strategy"], "resume_thread");
        assert_eq!(
            payload["data"]["rollback"]["action"]["action"],
            "thread_resume"
        );
        assert_eq!(payload["data"]["provenance"]["task_id"], "task-thread");
    }

    #[test]
    fn success_payload_prefers_explicit_summary_and_truncates_long_text() {
        let long_summary = format!("{} {}", "summary", "x".repeat(512));
        let payload = tool_success_payload(
            "self",
            &json!({"action": "state"}),
            &json!({"summary": long_summary}),
        );

        let summary = payload["summary"].as_str().expect("summary");
        assert!(summary.starts_with("summary "));
        assert!(summary.ends_with("..."));
        assert!(summary.chars().count() <= MAX_SUMMARY_CHARS);
    }

    #[test]
    fn success_payload_summarizes_kernel_and_orchestration_results() {
        let kernel = tool_success_payload(
            "kernel",
            &json!({"action": "status"}),
            &json!({
                "readiness": {
                    "driver_load_possible": false
                }
            }),
        );
        assert_eq!(
            kernel["summary"],
            "kernel status: driver load blocked or not ready"
        );

        let plan = tool_success_payload(
            "orchestrate",
            &json!({"action": "plan"}),
            &json!({
                "plan": [{ "id": "a" }, { "id": "b" }],
                "blocked_steps": [{ "id": "b" }]
            }),
        );
        assert_eq!(plan["summary"], "orchestrate plan: 2 steps, 1 blocked");
    }

    #[test]
    fn success_payload_exposes_result_strategy_for_references_pagination_and_streams() {
        let artifact_path = std::env::temp_dir().join(format!(
            "memoric-result-strategy-{}.txt",
            std::process::id()
        ));
        std::fs::write(&artifact_path, "strategy").unwrap();

        let referenced = tool_success_payload(
            "memory",
            &json!({"action": "read"}),
            &json!({
                "message": "read exported",
                "artifact_path": artifact_path.display().to_string()
            }),
        );
        let reference_strategy = &referenced["metadata"]["result_strategy"];
        assert_eq!(reference_strategy["strategy"], "reference");
        assert_eq!(reference_strategy["resource_links"], true);
        assert_eq!(reference_strategy["artifact_count"], 1);
        let artifact_uri = referenced["artifacts"][0]["uri"].as_str().unwrap();

        let paginated = tool_success_payload(
            "memory",
            &json!({"action": "scan_list"}),
            &json!({
                "session_id": "scan-1",
                "total": 3,
                "count": 1,
                "nextCursor": "scan-result-cursor:scan-1:1:index_asc:1",
                "candidates": []
            }),
        );
        let paginated_strategy = &paginated["metadata"]["result_strategy"];
        assert_eq!(paginated_strategy["strategy"], "paginated");
        assert_eq!(paginated_strategy["paginated"], true);
        assert_eq!(
            paginated_strategy["nextCursor"],
            "scan-result-cursor:scan-1:1:index_asc:1"
        );

        let streamed = tool_success_payload(
            "memory",
            &json!({
                "action": "scan_new",
                "task_id": "task-1",
                "_meta": {"progressToken": "progress-1"}
            }),
            &json!({
                "session_id": "scan-1",
                "results": 3,
                "message": "scan complete"
            }),
        );
        let stream_strategy = &streamed["metadata"]["result_strategy"];
        assert_eq!(stream_strategy["strategy"], "streamed-progress");
        assert_eq!(stream_strategy["streamed_progress"], true);
        assert_eq!(stream_strategy["progress_token_present"], true);
        assert_eq!(stream_strategy["cancellation_boundary"], true);
        assert_eq!(stream_strategy["timeout_boundary"], true);

        let _ = crate::artifact::forget(artifact_uri);
        let _ = std::fs::remove_file(artifact_path);
    }
}

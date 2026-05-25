//! Shared MCP JSON-RPC conformance fixtures.
//!
//! These fixtures intentionally target transport-neutral protocol behavior so
//! legacy, STDIO, worker, and future HTTP adapters can reuse the same cases.

use serde_json::{json, Value};

#[derive(Clone, Copy)]
pub(crate) enum ExpectedShape {
    Empty,
    ResultPath(&'static [&'static str]),
    ResultNull,
    ErrorCode(i64),
    ErrorMessageContains(i64, &'static str),
}

pub(crate) struct ConformanceCase {
    pub(crate) name: &'static str,
    pub(crate) request: String,
    pub(crate) expected: ExpectedShape,
}

pub(crate) fn core_cases() -> Vec<ConformanceCase> {
    let input_task_id = crate::mcp::tasks::create("self", "elicitation", "waiting for operator")
        .expect("fixture input task");
    crate::mcp::tasks::mark_input_required(
        &input_task_id,
        "fixture-input-request",
        "Approve dry-run continuation",
        "form",
        json!({
            "type": "object",
            "properties": {
                "approved": { "type": "boolean" }
            },
            "required": ["approved"]
        }),
        Some(json!({
            "continuation": "fixture"
        })),
    )
    .expect("fixture task should enter input_required");
    let update_task_id = crate::mcp::tasks::create("self", "elicitation", "waiting for update")
        .expect("fixture update task");
    crate::mcp::tasks::mark_input_required(
        &update_task_id,
        "fixture-update-request",
        "Approve update continuation",
        "form",
        json!({
            "type": "object",
            "properties": {
                "approved": { "type": "boolean" }
            },
            "required": ["approved"]
        }),
        Some(json!({
            "continuation": "fixture-update"
        })),
    )
    .expect("fixture update task should enter input_required");
    let cancel_task_id =
        crate::mcp::tasks::create("self", "cancel-fixture", "waiting for cancellation")
            .expect("fixture cancel task");

    vec![
        ConformanceCase {
            name: "bad_json",
            request: "{not-json".to_string(),
            expected: ExpectedShape::ErrorCode(-32700),
        },
        ConformanceCase {
            name: "initialize",
            request: json!({
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {}
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["protocolVersion"]),
        },
        ConformanceCase {
            name: "tools_list",
            request: json!({
                "jsonrpc": "2.0",
                "id": "tools",
                "method": "tools/list"
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["tools"]),
        },
        ConformanceCase {
            name: "resources_list",
            request: json!({
                "jsonrpc": "2.0",
                "id": "resources",
                "method": "resources/list"
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["resources"]),
        },
        ConformanceCase {
            name: "resources_templates_list",
            request: json!({
                "jsonrpc": "2.0",
                "id": "resource-templates",
                "method": "resources/templates/list"
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["resourceTemplates"]),
        },
        ConformanceCase {
            name: "app_bridge_ui_initialize_unsupported",
            request: json!({
                "jsonrpc": "2.0",
                "id": "ui-init",
                "method": "ui/initialize",
                "params": {
                    "host": {
                        "name": "fixture-host",
                        "supportsAppBridge": true
                    }
                }
            })
            .to_string(),
            expected: ExpectedShape::ErrorMessageContains(-32601, "App Bridge host-side only"),
        },
        ConformanceCase {
            name: "app_bridge_update_model_context_unsupported",
            request: json!({
                "jsonrpc": "2.0",
                "id": "ui-update-context",
                "method": "ui/update-model-context",
                "params": {
                    "context": {
                        "resource": "ui://memoric/dashboard",
                        "selection": { "taskId": "task-fixture" }
                    }
                }
            })
            .to_string(),
            expected: ExpectedShape::ErrorMessageContains(-32601, "App Bridge host-side only"),
        },
        ConformanceCase {
            name: "tasks_list",
            request: json!({
                "jsonrpc": "2.0",
                "id": "tasks",
                "method": "tasks/list",
                "params": { "limit": 1 }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["success"]),
        },
        ConformanceCase {
            name: "task_augmented_tools_call",
            request: json!({
                "jsonrpc": "2.0",
                "id": "task-call",
                "method": "tools/call",
                "params": {
                    "name": "self",
                    "arguments": { "action": "version" },
                    "task": { "ttl": 1000 },
                    "_meta": { "progressToken": "fixture-progress" }
                }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["task", "taskId"]),
        },
        ConformanceCase {
            name: "task_augmented_consent_required",
            request: json!({
                "jsonrpc": "2.0",
                "id": "task-consent",
                "method": "tools/call",
                "params": {
                    "name": "memory",
                    "arguments": {
                        "action": "write",
                        "pid": std::process::id(),
                        "address": "0x1000",
                        "bytes": [1, 2, 3, 4],
                        "bypass_protect": false
                    },
                    "task": { "ttl": 1000 },
                    "_meta": { "progressToken": "fixture-consent-progress" }
                }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["task", "inputRequests"]),
        },
        ConformanceCase {
            name: "tasks_result_input_required",
            request: json!({
                "jsonrpc": "2.0",
                "id": "task-input-required",
                "method": "tasks/result",
                "params": {
                    "taskId": input_task_id,
                    "wait_ms": 0
                }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["inputRequests"]),
        },
        ConformanceCase {
            name: "tasks_input_response",
            request: json!({
                "jsonrpc": "2.0",
                "id": "task-input-response",
                "method": "tasks/input_response",
                "params": {
                    "taskId": input_task_id,
                    "requestId": "fixture-input-request",
                    "input": { "approved": true }
                }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["task", "inputResponses"]),
        },
        ConformanceCase {
            name: "tasks_update_input_response_compat",
            request: json!({
                "jsonrpc": "2.0",
                "id": "task-update-input-response",
                "method": "tasks/update",
                "params": {
                    "kind": "input_response",
                    "taskId": update_task_id,
                    "requestId": "fixture-update-request",
                    "input": { "approved": true }
                }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["task", "inputResponses"]),
        },
        ConformanceCase {
            name: "tasks_cancel",
            request: json!({
                "jsonrpc": "2.0",
                "id": "task-cancel",
                "method": "tasks/cancel",
                "params": {
                    "taskId": cancel_task_id
                }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["status"]),
        },
        ConformanceCase {
            name: "invalid_params",
            request: json!({
                "jsonrpc": "2.0",
                "id": "invalid",
                "method": "tasks/result",
                "params": {}
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32602),
        },
        ConformanceCase {
            name: "unknown_method",
            request: json!({
                "jsonrpc": "2.0",
                "id": "unknown",
                "method": "not/a_method"
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32601),
        },
        ConformanceCase {
            name: "ping",
            request: json!({
                "jsonrpc": "2.0",
                "id": "ping",
                "method": "ping"
            })
            .to_string(),
            expected: ExpectedShape::ResultNull,
        },
        ConformanceCase {
            name: "notification",
            request: json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            })
            .to_string(),
            expected: ExpectedShape::Empty,
        },
        ConformanceCase {
            name: "app_bridge_host_context_notification",
            request: json!({
                "jsonrpc": "2.0",
                "method": "ui/notifications/host-context-changed",
                "params": {
                    "host": {
                        "name": "fixture-host",
                        "displayMode": "inline"
                    },
                    "resource": "ui://memoric/dashboard"
                }
            })
            .to_string(),
            expected: ExpectedShape::Empty,
        },
    ]
}

pub(crate) fn adversarial_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "batch_like_array",
            request: json!([
                {
                    "jsonrpc": "2.0",
                    "id": "batch-ping",
                    "method": "ping"
                }
            ])
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "non_object_json",
            request: json!("not an object").to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "invalid_object_id",
            request: json!({
                "jsonrpc": "2.0",
                "id": { "nested": true },
                "method": "ping"
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "invalid_array_id",
            request: json!({
                "jsonrpc": "2.0",
                "id": ["bad"],
                "method": "ping"
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "invalid_boolean_id",
            request: json!({
                "jsonrpc": "2.0",
                "id": true,
                "method": "ping"
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "invalid_numeric_jsonrpc",
            request: json!({
                "jsonrpc": 2.0,
                "id": "bad-version-type",
                "method": "ping"
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "non_string_method",
            request: json!({
                "jsonrpc": "2.0",
                "id": "bad-method-type",
                "method": 42
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32600),
        },
        ConformanceCase {
            name: "notification_with_id_confusion",
            request: json!({
                "jsonrpc": "2.0",
                "id": "should-still-be-silent",
                "method": "notifications/initialized"
            })
            .to_string(),
            expected: ExpectedShape::Empty,
        },
        ConformanceCase {
            name: "tools_list_invalid_cursor",
            request: json!({
                "jsonrpc": "2.0",
                "id": "tools-bad-cursor",
                "method": "tools/list",
                "params": { "cursor": "bad-cursor" }
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32602),
        },
        ConformanceCase {
            name: "resources_list_invalid_cursor_type",
            request: json!({
                "jsonrpc": "2.0",
                "id": "resources-bad-cursor-type",
                "method": "resources/list",
                "params": { "cursor": 5 }
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32602),
        },
        ConformanceCase {
            name: "resources_templates_list_invalid_cursor",
            request: json!({
                "jsonrpc": "2.0",
                "id": "templates-bad-cursor",
                "method": "resources/templates/list",
                "params": { "cursor": "bad-cursor" }
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32602),
        },
        ConformanceCase {
            name: "tasks_list_negative_limit",
            request: json!({
                "jsonrpc": "2.0",
                "id": "tasks-negative-limit",
                "method": "tasks/list",
                "params": { "limit": -1 }
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32602),
        },
        ConformanceCase {
            name: "tools_list_oversized_limit_clamped",
            request: json!({
                "jsonrpc": "2.0",
                "id": "tools-large-limit",
                "method": "tools/list",
                "params": { "limit": 1_000_000_000_000_u64 }
            })
            .to_string(),
            expected: ExpectedShape::ResultPath(&["tools"]),
        },
        ConformanceCase {
            name: "oversized_params_unknown_method",
            request: json!({
                "jsonrpc": "2.0",
                "id": "oversized-unknown",
                "method": "unknown/oversized",
                "params": {
                    "blob": "x".repeat(8192)
                }
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32601),
        },
        ConformanceCase {
            name: "shell_like_params_unknown_method",
            request: json!({
                "jsonrpc": "2.0",
                "id": "shell-like-unknown",
                "method": "unknown/shell",
                "params": {
                    "command": "cmd.exe /c echo should-not-run",
                    "shell": "powershell -NoProfile -Command should-not-run"
                }
            })
            .to_string(),
            expected: ExpectedShape::ErrorCode(-32601),
        },
    ]
}

pub(crate) fn run_conformance<F>(transport: &str, mut handle: F)
where
    F: FnMut(&ConformanceCase) -> String,
{
    for case in core_cases() {
        let text = handle(&case);
        let label = format!("{}::{}", transport, case.name);
        assert_response_shape(&label, &text, case.expected);
    }
}

pub(crate) fn run_adversarial_conformance<F>(transport: &str, mut handle: F)
where
    F: FnMut(&ConformanceCase) -> String,
{
    for case in adversarial_cases() {
        let text = handle(&case);
        let label = format!("{}::{}", transport, case.name);
        assert_response_shape(&label, &text, case.expected);
    }
}

fn assert_response_shape(label: &str, text: &str, expected: ExpectedShape) {
    match expected {
        ExpectedShape::Empty => {
            assert!(text.is_empty(), "{} should produce no response", label);
        }
        ExpectedShape::ResultPath(path) => {
            let value: Value = serde_json::from_str(text)
                .unwrap_or_else(|err| panic!("{} invalid JSON: {}", label, err));
            assert_eq!(value["jsonrpc"], "2.0", "{}", label);
            assert_json_path_present(&value["result"], path, label);
        }
        ExpectedShape::ResultNull => {
            let value: Value = serde_json::from_str(text)
                .unwrap_or_else(|err| panic!("{} invalid JSON: {}", label, err));
            assert_eq!(value["jsonrpc"], "2.0", "{}", label);
            assert_eq!(value["result"], Value::Null, "{}", label);
        }
        ExpectedShape::ErrorCode(code) => {
            let value: Value = serde_json::from_str(text)
                .unwrap_or_else(|err| panic!("{} invalid JSON: {}", label, err));
            assert_eq!(value["jsonrpc"], "2.0", "{}", label);
            assert_eq!(value["error"]["code"], code, "{}", label);
        }
        ExpectedShape::ErrorMessageContains(code, needle) => {
            let value: Value = serde_json::from_str(text)
                .unwrap_or_else(|err| panic!("{} invalid JSON: {}", label, err));
            assert_eq!(value["jsonrpc"], "2.0", "{}", label);
            assert_eq!(value["error"]["code"], code, "{}", label);
            let message = value["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains(needle),
                "{} error message should contain {:?}, got {:?}",
                label,
                needle,
                message
            );
        }
    }
}

fn assert_json_path_present(value: &Value, path: &[&str], label: &str) {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .unwrap_or_else(|| panic!("{} missing result path {:?}", label, path));
    }
    assert!(
        !current.is_null(),
        "{} result path {:?} should not be null",
        label,
        path
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn transport_boundary_sources_do_not_spawn_shell_commands() {
        let sources = [
            ("mcp/protocol.rs", include_str!("protocol.rs")),
            ("mcp/server.rs", include_str!("server.rs")),
            ("stdio_server.rs", include_str!("../stdio_server.rs")),
            ("worker.rs", include_str!("../worker.rs")),
            ("ipc/client.rs", include_str!("../ipc/client.rs")),
            ("ipc/server.rs", include_str!("../ipc/server.rs")),
        ];
        let forbidden = [
            "std::process::Command",
            "Command::new",
            "cmd.exe",
            "cmd /c",
            "cmd /C",
            "powershell",
            "pwsh",
        ];

        for (path, source) in sources {
            for needle in forbidden {
                assert!(
                    !source.contains(needle),
                    "transport boundary source {path} must not spawn or reference shell commands via {needle:?}"
                );
            }
        }
    }
}

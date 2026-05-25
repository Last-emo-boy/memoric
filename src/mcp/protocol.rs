//! Shared MCP protocol helpers for STDIO, worker, and legacy server paths.

use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Debug)]
pub struct JsonRpcRequestParts<'a> {
    pub method: &'a str,
    pub id: Option<Value>,
    pub expects_response: bool,
}

pub fn validate_json_rpc_request(value: &Value) -> Result<JsonRpcRequestParts<'_>, Value> {
    if !value.is_object() {
        return Err(json_rpc_error_value(
            -32600,
            "Invalid request: expected JSON object",
            None,
        ));
    }

    let id = match normalize_json_rpc_id(value) {
        Ok(id) => id,
        Err(message) => return Err(json_rpc_error_value(-32600, message, None)),
    };

    if value.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(json_rpc_error_value(-32600, "Invalid JSON-RPC version", id));
    }

    let method = match value.get("method") {
        Some(Value::String(method)) => method.as_str(),
        Some(_) => {
            return Err(json_rpc_error_value(
                -32600,
                "Invalid method: expected string",
                id,
            ));
        }
        None => return Err(json_rpc_error_value(-32600, "Missing method", id)),
    };

    let expects_response = id.is_some() && !is_notification_method(method);

    Ok(JsonRpcRequestParts {
        method,
        id,
        expects_response,
    })
}

pub fn json_rpc_error_value(code: i64, message: &str, id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message,
        },
        "id": id.unwrap_or(Value::Null),
    })
}

pub fn json_rpc_error_string(code: i64, message: &str, id: Option<Value>) -> String {
    json_rpc_error_value(code, message, id).to_string()
}

pub fn is_notification_method(method: &str) -> bool {
    method.starts_with("notifications/") || method.starts_with("ui/notifications/")
}

pub fn is_app_bridge_host_only_method(method: &str) -> bool {
    matches!(
        method,
        "ui/initialize"
            | "ui/update-model-context"
            | "ui/message"
            | "ui/open-link"
            | "ui/download-file"
            | "ui/request-display-mode"
            | "ui/resource-teardown"
    )
}

pub fn app_bridge_unsupported_error_value(method: &str, id: Option<Value>) -> Value {
    json_rpc_error_value(
        -32601,
        &format!(
            "MCP Apps method {} is App Bridge host-side only; this MCP server exposes ui://memoric resources as passive read-only resources and does not implement an App Bridge host",
            method
        ),
        id,
    )
}

pub fn app_bridge_unsupported_error_string(method: &str, id: Option<Value>) -> String {
    app_bridge_unsupported_error_value(method, id).to_string()
}

fn normalize_json_rpc_id(value: &Value) -> Result<Option<Value>, &'static str> {
    match value.get("id") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(_)) | Some(Value::Number(_)) => Ok(value.get("id").cloned()),
        Some(_) => Err("Invalid id: expected string, number, or null"),
    }
}

pub fn initialize_result(server_name: &str) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false },
            "resources": {
                "templates": {}
            },
            "prompts": {},
            "logging": {},
            "tasks": {
                "list": {},
                "cancel": {},
                "inputResponse": {},
                "update": {},
                "requests": {
                    "tools": {
                        "call": {}
                    },
                    "sampling": {
                        "createMessage": {
                            "supported": false,
                            "taskLifecycle": "reuse-existing-task-registry-when-implemented"
                        }
                    }
                }
            },
            "experimental": {
                "structuredContent": true,
                "tasks": true,
                "progress": true
            }
        },
        "serverInfo": {
            "name": server_name,
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

pub fn tool_success_content(tool: &str, args: &Value, result: &Value) -> Value {
    let retention_secs = crate::artifact::retention_secs_from_args(args);
    let mut artifact_links = crate::artifact::collect_artifact_references(result);
    artifact_links.extend(crate::artifact::collect_artifacts_with_retention(
        result,
        retention_secs,
    ));
    let correlation_id = crate::observability::correlation_id_from_args(args);
    if let Some(correlation_id) = correlation_id.as_deref() {
        for artifact in &artifact_links {
            if let Some(uri) = artifact["uri"].as_str() {
                crate::observability::link_artifact(uri, correlation_id);
            }
        }
    }
    artifact_links.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["uri"].as_str().unwrap_or_default())
    });
    artifact_links.dedup_by(|left, right| left["uri"] == right["uri"]);
    let payload = crate::mcp::tools::tool_success_payload(tool, args, result);
    let widget_meta =
        crate::mcp::meta::widget_result_hydration_meta(tool, args, &payload, &artifact_links);
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
    let mut content = vec![json!({ "type": "text", "text": text })];
    content.extend(resource_link_content_blocks(&artifact_links));
    let mut result = json!({
        "content": content,
        "structuredContent": payload,
    });
    if !widget_meta.is_null() {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("_meta".to_string(), widget_meta);
        }
    }
    result
}

fn resource_link_content_blocks(artifacts: &[Value]) -> Vec<Value> {
    artifacts
        .iter()
        .filter_map(|artifact| {
            let uri = artifact["uri"].as_str()?;
            Some(json!({
                "type": "resource_link",
                "uri": uri,
                "name": artifact["name"].as_str().unwrap_or("Artifact"),
                "title": artifact["name"].as_str().unwrap_or("Artifact"),
                "description": format!(
                    "Artifact {} (sha256 {})",
                    artifact["name"].as_str().unwrap_or("file"),
                    artifact["sha256"].as_str().unwrap_or("unknown")
                ),
                "mimeType": artifact["mimeType"].as_str().unwrap_or("application/octet-stream"),
                "size": artifact["size_bytes"].as_u64(),
                "annotations": {
                    "audience": ["user"],
                    "priority": 0.7,
                    "lastModified": artifact["last_modified"].as_str().unwrap_or_default()
                }
            }))
        })
        .collect::<Vec<_>>()
}

pub fn tool_error_content(tool: &str, args: &Value, message: &str) -> Value {
    let payload = crate::mcp::tools::tool_error_payload(tool, args, message);
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| {
        format!(
            "{{\"success\":false,\"code\":\"tool_error\",\"error\":\"{}\"}}",
            message.replace('"', "'")
        )
    });
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": payload,
        "isError": true
    });
    let auth_meta = crate::mcp::meta::authorization_meta(
        &result["structuredContent"]["authorization"]["www_authenticate"],
    );
    if !auth_meta.is_null() {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("_meta".to_string(), auth_meta);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_uses_package_version_and_current_protocol() {
        let value = initialize_result("memoric-test");
        assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(value["serverInfo"]["name"], "memoric-test");
        assert_eq!(value["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(value["capabilities"]["tools"].is_object());
        assert!(value["capabilities"]["tasks"]["list"].is_object());
        assert!(value["capabilities"]["tasks"]["cancel"].is_object());
        assert!(value["capabilities"]["tasks"]["inputResponse"].is_object());
        assert!(value["capabilities"]["tasks"]["update"].is_object());
        assert!(value["capabilities"]["tasks"]["requests"]["tools"]["call"].is_object());
        assert_eq!(
            value["capabilities"]["tasks"]["requests"]["sampling"]["createMessage"]["supported"],
            false
        );
        assert!(value["capabilities"].get("sampling").is_none());
        assert_eq!(value["capabilities"]["experimental"]["tasks"], true);
        assert_eq!(value["capabilities"]["experimental"]["progress"], true);
    }

    #[test]
    fn tool_success_content_includes_structured_content() {
        let result = tool_success_content(
            "self",
            &json!({"action": "info", "request_id": "req-1"}),
            &json!({"message": "ok", "pid": 1234}),
        );

        assert_eq!(result["structuredContent"]["success"], true);
        assert_eq!(result["structuredContent"]["code"], "ok");
        assert_eq!(result["structuredContent"]["context"]["tool"], "self");
        assert_eq!(result["structuredContent"]["context"]["action"], "info");
        assert!(result["content"][0]["text"].as_str().is_some());
    }

    #[test]
    fn tool_success_content_splits_widget_only_hydration_meta() {
        let result = tool_success_content(
            "memory",
            &json!({"action": "read", "redaction": "none", "request_id": "req-widget"}),
            &json!({
                "message": "read ok",
                "address": "0x1000",
                "bytes_read": 4,
                "bytes": [1, 2, 3, 4],
                "hex": "01020304"
            }),
        );

        let hydration = &result["_meta"][crate::mcp::meta::MEMORIC_WIDGET_HYDRATION];
        assert_eq!(hydration["visibility"], "widget");
        assert_eq!(hydration["modelVisible"], false);
        assert_eq!(hydration["resourceUri"], "ui://memoric/scans");
        assert_eq!(hydration["tool"], "memory");
        assert_eq!(hydration["action"], "read");
        assert_eq!(hydration["redaction"]["profile"], "strict");
        assert_eq!(hydration["data"]["bytes"]["classification"], "raw-memory");
        assert_eq!(hydration["data"]["hex"]["classification"], "raw-memory");
        assert_eq!(
            hydration["context"]["request_id"]["classification"],
            "local-sensitive"
        );
        assert!(result["structuredContent"]
            .get(crate::mcp::meta::MEMORIC_WIDGET_HYDRATION)
            .is_none());
        assert!(crate::mcp::meta::validate_extension_keys(&json!({
            "_meta": result["_meta"].clone()
        }))
        .is_empty());
    }

    #[test]
    fn tool_success_content_omits_widget_meta_for_unlinked_tools() {
        let result = tool_success_content(
            "target",
            &json!({"action": "ps_list"}),
            &json!({"message": "ok", "processes": []}),
        );

        assert!(result.get("_meta").is_none());
    }

    #[test]
    fn tool_success_content_includes_artifact_resource_links() {
        let path = std::env::temp_dir().join(format!(
            "memoric-protocol-artifact-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "linked").unwrap();
        let result = tool_success_content(
            "self",
            &json!({"action": "info"}),
            &json!({"artifact_path": path.display().to_string()}),
        );

        assert!(result["content"].as_array().unwrap().iter().any(|block| {
            block["type"] == "resource_link"
                && block["uri"]
                    .as_str()
                    .is_some_and(crate::artifact::is_artifact_uri)
        }));
        let uri = result["structuredContent"]["artifacts"][0]["uri"]
            .as_str()
            .unwrap();
        let _ = crate::artifact::forget(&uri);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tool_success_content_preserves_resource_links_under_strict_redaction() {
        let path = std::env::temp_dir().join(format!(
            "memoric-protocol-artifact-strict-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "linked strict").unwrap();
        let artifact = crate::artifact::register_file_artifact(&path, 60).expect("artifact");
        let uri = artifact["uri"].as_str().unwrap().to_string();
        let result = tool_success_content(
            "self",
            &json!({"action": "info", "redaction": "strict"}),
            &json!({"artifact_path": path.display().to_string()}),
        );

        assert!(result["content"].as_array().unwrap().iter().any(|block| {
            block["type"] == "resource_link"
                && block["uri"]
                    .as_str()
                    .is_some_and(crate::artifact::is_artifact_uri)
        }));
        let _ = crate::artifact::forget(&uri);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tool_error_content_includes_structured_content() {
        let result = tool_error_content("memory", &json!({"action": "read"}), "Missing pid");
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["success"], false);
        assert_eq!(result["structuredContent"]["code"], "missing_param");
    }

    #[test]
    fn tool_error_content_exposes_mcp_www_authenticate_meta_for_policy_errors() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        std::env::set_var("MEMORIC_POLICY", "observe");

        let result = tool_error_content(
            "memory",
            &json!({"action": "write"}),
            "policy_denied: memory(action='write') blocked by policy",
        );

        assert_eq!(result["isError"], true);
        assert!(result["_meta"]["mcp/www_authenticate"][0]
            .as_str()
            .unwrap_or_default()
            .contains("error=\"policy_denied\""));

        std::env::remove_var("MEMORIC_POLICY");
    }

    #[test]
    fn json_rpc_validation_rejects_batch_like_values() {
        let error = validate_json_rpc_request(&json!([])).expect_err("batch-like request rejected");
        assert_eq!(error["error"]["code"], -32600);
        assert_eq!(error["id"], Value::Null);
    }

    #[test]
    fn json_rpc_validation_rejects_invalid_ids() {
        let error = validate_json_rpc_request(&json!({
            "jsonrpc": "2.0",
            "id": { "nested": true },
            "method": "ping"
        }))
        .expect_err("object id rejected");

        assert_eq!(error["error"]["code"], -32600);
        assert_eq!(error["id"], Value::Null);
    }

    #[test]
    fn json_rpc_validation_treats_notifications_as_silent() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": "confused-client",
            "method": "notifications/initialized"
        });
        let parts = validate_json_rpc_request(&value).expect("notification shape");

        assert_eq!(parts.method, "notifications/initialized");
        assert_eq!(parts.id, Some(json!("confused-client")));
        assert!(!parts.expects_response);
    }

    #[test]
    fn json_rpc_validation_treats_app_bridge_host_context_notifications_as_silent() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": "host-context-notification",
            "method": "ui/notifications/host-context-changed",
            "params": {
                "resource": "ui://memoric/dashboard"
            }
        });
        let parts = validate_json_rpc_request(&value).expect("app bridge notification shape");

        assert_eq!(parts.method, "ui/notifications/host-context-changed");
        assert_eq!(parts.id, Some(json!("host-context-notification")));
        assert!(!parts.expects_response);
    }

    #[test]
    fn app_bridge_host_only_error_is_explicit() {
        let value = app_bridge_unsupported_error_value("ui/initialize", Some(json!("ui-init")));

        assert_eq!(value["error"]["code"], -32601);
        let message = value["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("App Bridge host-side only"));
        assert!(message.contains("passive read-only resources"));
    }
}

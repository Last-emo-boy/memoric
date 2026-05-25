use serde_json::{json, Map, Value};

pub const MEMORIC_VENDOR_PREFIX: &str = "io.memoric/";
pub const MEMORIC_LEGACY_PREFIX: &str = "x-memoric-";
pub const OPENAI_OUTPUT_TEMPLATE: &str = "openai/outputTemplate";
pub const OPENAI_WIDGET_ACCESSIBLE: &str = "openai/widgetAccessible";
pub const OPENAI_WIDGET_CSP: &str = "openai/widgetCSP";
pub const OPENAI_WIDGET_DOMAIN: &str = "openai/widgetDomain";
pub const MCP_WWW_AUTHENTICATE: &str = "mcp/www_authenticate";
pub const MCP_RELATED_TASK: &str = "io.modelcontextprotocol/related-task";
pub const MCP_MODEL_IMMEDIATE_RESPONSE: &str = "io.modelcontextprotocol/model-immediate-response";
pub const MEMORIC_WIDGET_HYDRATION: &str = "io.memoric/widget-hydration";

const MEMORIC_UI_VENDOR: &str = "io.memoric/ui";
const MEMORIC_INPUT_RESPONSE_METHOD: &str = "io.memoric/input-response-method";
const MEMORIC_INPUT_RESPONSE_COMPAT_METHOD: &str = "io.memoric/input-response-compat-method";

pub fn app_resource_meta(kind: &str, html_capable: bool) -> Value {
    let resource_uri = format!("ui://memoric/{}", kind);
    let widget_csp = widget_csp();

    json!({
        "ui": {
            "kind": kind,
            "resourceUri": resource_uri,
            "visibility": "user",
            "htmlCapable": html_capable,
            "widgetOnlyHydration": true,
            "toolCalls": "none",
            "csp": widget_csp,
            "domain": "ui://memoric",
            "prefersBorder": true
        },
        OPENAI_WIDGET_CSP: widget_csp,
        OPENAI_WIDGET_DOMAIN: "ui://memoric",
        MEMORIC_UI_VENDOR: {
            "kind": kind,
            "readOnly": true,
            "resourceUri": resource_uri,
            "visibility": ["model", "app"],
            "htmlCapable": html_capable,
            "widgetOnlyHydration": true,
            "toolCalls": "none"
        },
        "x-memoric-ui": {
            "kind": kind,
            "readOnly": true,
            "resourceUri": resource_uri,
            "visibility": ["model", "app"],
            "htmlCapable": html_capable,
            "widgetOnlyHydration": true,
            "toolCalls": "none"
        }
    })
}

pub fn tool_meta(resource_uri: Option<&str>) -> Value {
    match resource_uri {
        Some(uri) => json!({
            "ui": {
                "resourceUri": uri,
                "visibility": "user",
                "readOnly": true
            },
            OPENAI_OUTPUT_TEMPLATE: uri,
            OPENAI_WIDGET_ACCESSIBLE: false,
            MEMORIC_UI_VENDOR: {
                "resourceUri": uri,
                "readOnly": true,
                "widgetOnlyHydration": true,
                "toolCalls": "none"
            },
            "x-memoric-ui": {
                "resourceUri": uri,
                "readOnly": true,
                "widgetOnlyHydration": true,
                "toolCalls": "none"
            }
        }),
        None => json!({
            OPENAI_WIDGET_ACCESSIBLE: false,
            MEMORIC_UI_VENDOR: {
                "resourceUri": Value::Null,
                "readOnly": true,
                "toolCalls": "none"
            },
            "x-memoric-ui": {
                "resourceUri": Value::Null,
                "readOnly": true,
                "toolCalls": "none"
            }
        }),
    }
}

pub fn authorization_meta(www_authenticate: &Value) -> Value {
    match www_authenticate.as_array() {
        Some(values) if !values.is_empty() => json!({
            MCP_WWW_AUTHENTICATE: values
        }),
        _ => Value::Null,
    }
}

pub fn widget_result_hydration_meta(
    tool: &str,
    args: &Value,
    payload: &Value,
    artifacts: &[Value],
) -> Value {
    let Some(resource_uri) = crate::mcp::action_registry::tool_ui_resource_uri(tool) else {
        return Value::Null;
    };

    let normalized_args = crate::mcp::tool_args::normalize_common_args(tool, args);
    let action = normalized_args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let profile = crate::redaction::RedactionProfile::Strict;
    let classification_rules = crate::mcp::action_registry::tool_output_classification_rules(tool);
    let redacted_payload = crate::redaction::redact_value_with_classifications(
        payload,
        profile,
        &classification_rules,
    );
    let data = redacted_payload.get("data").cloned().unwrap_or(Value::Null);
    let context = redacted_payload
        .get("context")
        .cloned()
        .unwrap_or(Value::Null);
    let artifacts = crate::redaction::redact_value_with_classifications(
        &Value::Array(artifacts.to_vec()),
        profile,
        &classification_rules,
    );

    json!({
        MEMORIC_WIDGET_HYDRATION: {
            "schemaVersion": 1,
            "visibility": "widget",
            "modelVisible": false,
            "resourceUri": resource_uri,
            "tool": tool,
            "action": action,
            "summary": payload.get("summary").cloned().unwrap_or(Value::Null),
            "code": payload.get("code").cloned().unwrap_or(Value::Null),
            "context": context,
            "artifacts": artifacts,
            "data": data,
            "redaction": crate::redaction::metadata(profile)
        }
    })
}

pub fn task_model_immediate_response(task_id: &str) -> Value {
    json!({
        MCP_MODEL_IMMEDIATE_RESPONSE: format!(
            "Task {} accepted; poll tasks/get or tasks/result for completion.",
            task_id
        )
    })
}

pub fn related_task_meta(task_id: &str) -> Value {
    json!({
        MCP_RELATED_TASK: {
            "taskId": task_id
        }
    })
}

pub fn input_required_meta(task_id: &str) -> Value {
    let mut meta = related_task_meta(task_id)
        .as_object()
        .cloned()
        .unwrap_or_default();
    meta.insert(
        MEMORIC_INPUT_RESPONSE_METHOD.to_string(),
        json!("tasks/input_response"),
    );
    meta.insert(
        MEMORIC_INPUT_RESPONSE_COMPAT_METHOD.to_string(),
        json!("tasks/update"),
    );
    Value::Object(meta)
}

pub fn widget_csp() -> Value {
    json!({
        "connect_domains": [],
        "resource_domains": []
    })
}

pub fn validate_extension_keys(value: &Value) -> Vec<String> {
    let mut findings = Vec::new();
    validate_value(value, "$", &mut findings);
    findings
}

fn validate_value(value: &Value, path: &str, findings: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if path.ends_with("._meta") {
                validate_meta_object(map, path, findings);
            }
            for (key, child) in map {
                validate_value(child, &format!("{}.{}", path, key), findings);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_value(child, &format!("{}[{}]", path, index), findings);
            }
        }
        _ => {}
    }
}

fn validate_meta_object(map: &Map<String, Value>, path: &str, findings: &mut Vec<String>) {
    for key in map.keys() {
        if is_allowed_meta_key(key) {
            continue;
        }
        findings.push(format!("{} uses ungoverned _meta key '{}'", path, key));
    }
}

fn is_allowed_meta_key(key: &str) -> bool {
    matches!(
        key,
        "ui" | OPENAI_OUTPUT_TEMPLATE
            | OPENAI_WIDGET_ACCESSIBLE
            | OPENAI_WIDGET_CSP
            | OPENAI_WIDGET_DOMAIN
            | MCP_WWW_AUTHENTICATE
            | MCP_RELATED_TASK
            | MCP_MODEL_IMMEDIATE_RESPONSE
    ) || key.starts_with(MEMORIC_VENDOR_PREFIX)
        || key.starts_with(MEMORIC_LEGACY_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_key_governance_rejects_unscoped_meta_keys() {
        let findings = validate_extension_keys(&json!({
            "_meta": {
                "unsafe": true,
                "io.memoric/example": true,
                "openai/outputTemplate": "ui://memoric/dashboard"
            }
        }));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("unsafe"));
    }

    #[test]
    fn app_resource_meta_includes_apps_sdk_compatibility_keys() {
        let meta = app_resource_meta("dashboard", false);

        assert_eq!(meta["ui"]["resourceUri"], "ui://memoric/dashboard");
        assert_eq!(meta[OPENAI_WIDGET_DOMAIN], "ui://memoric");
        assert!(meta[OPENAI_WIDGET_CSP]["connect_domains"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(meta[MEMORIC_UI_VENDOR]["toolCalls"], "none");
    }
}

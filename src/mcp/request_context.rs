//! Transport-neutral MCP request metadata.
//!
//! This module keeps transport/session metadata out of tool handlers. Current
//! STDIO, worker, and legacy paths can populate it from JSON-RPC request fields;
//! a future HTTP adapter can add header-derived metadata before dispatch.

use serde_json::Value;
use std::cell::RefCell;

thread_local! {
    static CURRENT_REQUEST_CONTEXT: RefCell<Option<McpRequestContext>> = const {
        RefCell::new(None)
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportKind {
    Stdio,
    Worker,
    Legacy,
    Http,
    Unknown(String),
}

impl McpTransportKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Stdio => "stdio",
            Self::Worker => "worker",
            Self::Legacy => "legacy",
            Self::Http => "http",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOrigin {
    Local,
    App,
    Remote,
    Unknown,
}

impl PolicyOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::App => "app",
            Self::Remote => "remote",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpTransportMetadata {
    pub protocol_version: Option<String>,
    pub session_id: Option<String>,
    pub stream_id: Option<String>,
    pub last_event_id: Option<String>,
    pub app_origin: Option<String>,
    pub policy_origin: Option<PolicyOrigin>,
    pub audit_correlation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRequestContext {
    pub transport: McpTransportKind,
    pub request_id: Option<Value>,
    pub protocol_version: Option<String>,
    pub session_id: Option<String>,
    pub stream_id: Option<String>,
    pub last_event_id: Option<String>,
    pub progress_token: Option<Value>,
    pub task_id: Option<String>,
    pub app_origin: Option<String>,
    pub policy_origin: PolicyOrigin,
    pub audit_correlation_id: Option<String>,
    pub redaction: crate::redaction::RedactionProfile,
}

#[must_use]
pub struct McpRequestContextGuard {
    previous: Option<McpRequestContext>,
}

impl Drop for McpRequestContextGuard {
    fn drop(&mut self) {
        CURRENT_REQUEST_CONTEXT.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

impl McpRequestContext {
    pub fn from_request(request: &Value, transport: McpTransportKind) -> Self {
        Self::from_request_with_metadata(request, transport, McpTransportMetadata::default())
    }

    pub fn from_request_with_metadata(
        request: &Value,
        transport: McpTransportKind,
        metadata: McpTransportMetadata,
    ) -> Self {
        let params = request.get("params");
        let args = params
            .and_then(|params| params.get("arguments"))
            .filter(|value| value.is_object())
            .or_else(|| request.get("arguments").filter(|value| value.is_object()));
        let meta = params
            .and_then(|params| params.get("_meta"))
            .filter(|value| value.is_object())
            .or_else(|| request.get("_meta").filter(|value| value.is_object()));

        let app_origin = metadata.app_origin.or_else(|| app_origin_from_meta(meta));
        let policy_origin = metadata
            .policy_origin
            .or_else(|| policy_origin_from_meta(meta))
            .unwrap_or_else(|| infer_policy_origin(&transport, app_origin.as_deref()));

        let audit_correlation_id = metadata.audit_correlation_id.or_else(|| {
            string_field(args, "request_id")
                .or_else(|| string_field(params, "request_id"))
                .or_else(|| string_field(meta, "io.memoric/audit-correlation-id"))
                .or_else(|| string_field(meta, "correlationId"))
                .or_else(|| string_field(meta, "correlation_id"))
        });

        Self {
            transport,
            request_id: request.get("id").filter(|value| !value.is_null()).cloned(),
            protocol_version: metadata.protocol_version.or_else(|| {
                string_field(meta, "MCP-Protocol-Version")
                    .or_else(|| string_field(meta, "mcpProtocolVersion"))
                    .or_else(|| string_field(params, "protocolVersion"))
                    .or_else(|| string_field(request.get("params"), "protocolVersion"))
            }),
            session_id: metadata.session_id.or_else(|| {
                string_field(meta, "Mcp-Session-Id")
                    .or_else(|| string_field(meta, "mcpSessionId"))
                    .or_else(|| string_field(params, "session_id"))
                    .or_else(|| string_field(params, "sessionId"))
            }),
            stream_id: metadata.stream_id.or_else(|| {
                string_field(meta, "streamId").or_else(|| string_field(meta, "stream_id"))
            }),
            last_event_id: metadata.last_event_id.or_else(|| {
                string_field(meta, "Last-Event-ID")
                    .or_else(|| string_field(meta, "lastEventId"))
                    .or_else(|| string_field(meta, "last_event_id"))
            }),
            progress_token: progress_token_from_request(request),
            task_id: task_id_from_request(request),
            app_origin,
            policy_origin,
            audit_correlation_id,
            redaction: args
                .map(crate::redaction::profile_from_args)
                .unwrap_or_else(|| {
                    params
                        .map(crate::redaction::profile_from_args)
                        .unwrap_or(crate::redaction::RedactionProfile::Standard)
                }),
        }
    }
}

pub fn set_current_request_context(context: McpRequestContext) -> McpRequestContextGuard {
    let previous = CURRENT_REQUEST_CONTEXT.with(|slot| slot.replace(Some(context)));
    McpRequestContextGuard { previous }
}

pub fn current_request_context() -> Option<McpRequestContext> {
    CURRENT_REQUEST_CONTEXT.with(|slot| slot.borrow().clone())
}

pub fn with_current_request_context<R>(context: McpRequestContext, f: impl FnOnce() -> R) -> R {
    let _guard = set_current_request_context(context);
    f()
}

pub fn with_request_context_from_request<R>(
    request: &Value,
    transport: McpTransportKind,
    f: impl FnOnce() -> R,
) -> R {
    let context = McpRequestContext::from_request(request, transport);
    with_current_request_context(context, f)
}

pub fn progress_token_from_request(request: &Value) -> Option<Value> {
    request
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get("progressToken"))
        .filter(|value| value.is_string() || value.is_i64() || value.is_u64())
        .cloned()
}

fn task_id_from_request(request: &Value) -> Option<String> {
    let params = request.get("params");
    string_field(params, "taskId")
        .or_else(|| string_field(params, "task_id"))
        .or_else(|| string_field(params, "id"))
        .or_else(|| params.and_then(|params| string_field(params.get("arguments"), "task_id")))
}

fn app_origin_from_meta(meta: Option<&Value>) -> Option<String> {
    string_field(meta, "io.memoric/app-origin")
        .or_else(|| string_field(meta, "appOrigin"))
        .or_else(|| string_field(meta, "app_origin"))
        .or_else(|| string_field(meta, "openai/widgetDomain"))
}

fn policy_origin_from_meta(meta: Option<&Value>) -> Option<PolicyOrigin> {
    let value = string_field(meta, "io.memoric/policy-origin")
        .or_else(|| string_field(meta, "policyOrigin"))
        .or_else(|| string_field(meta, "policy_origin"))?;
    match value.trim().to_ascii_lowercase().as_str() {
        "local" | "stdio" | "worker" | "legacy" => Some(PolicyOrigin::Local),
        "app" | "ui" | "widget" => Some(PolicyOrigin::App),
        "remote" | "http" => Some(PolicyOrigin::Remote),
        _ => Some(PolicyOrigin::Unknown),
    }
}

fn infer_policy_origin(transport: &McpTransportKind, app_origin: Option<&str>) -> PolicyOrigin {
    if app_origin.is_some() {
        return PolicyOrigin::App;
    }
    match transport {
        McpTransportKind::Http => PolicyOrigin::Remote,
        McpTransportKind::Stdio | McpTransportKind::Worker | McpTransportKind::Legacy => {
            PolicyOrigin::Local
        }
        McpTransportKind::Unknown(_) => PolicyOrigin::Unknown,
    }
}

fn string_field(parent: Option<&Value>, key: &str) -> Option<String> {
    parent?
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_context_extracts_common_tool_call_metadata() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": {
                    "action": "doctor",
                    "request_id": "audit-1",
                    "task_id": "task-1",
                    "redaction": "strict"
                },
                "_meta": {
                    "progressToken": "progress-1",
                    "MCP-Protocol-Version": "2025-11-25",
                    "Mcp-Session-Id": "session-1",
                    "Last-Event-ID": "event-9",
                    "io.memoric/app-origin": "ui://memoric/dashboard"
                }
            }
        });

        let context = McpRequestContext::from_request(&request, McpTransportKind::Http);

        assert_eq!(context.transport.as_str(), "http");
        assert_eq!(context.request_id, Some(json!("req-1")));
        assert_eq!(context.protocol_version.as_deref(), Some("2025-11-25"));
        assert_eq!(context.session_id.as_deref(), Some("session-1"));
        assert_eq!(context.last_event_id.as_deref(), Some("event-9"));
        assert_eq!(context.progress_token, Some(json!("progress-1")));
        assert_eq!(context.task_id.as_deref(), Some("task-1"));
        assert_eq!(
            context.app_origin.as_deref(),
            Some("ui://memoric/dashboard")
        );
        assert_eq!(context.policy_origin, PolicyOrigin::App);
        assert_eq!(context.policy_origin.as_str(), "app");
        assert_eq!(context.audit_correlation_id.as_deref(), Some("audit-1"));
        assert_eq!(
            context.redaction,
            crate::redaction::RedactionProfile::Strict
        );
    }

    #[test]
    fn request_context_accepts_transport_header_metadata() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tasks/get",
            "params": { "taskId": "task-7" }
        });
        let metadata = McpTransportMetadata {
            protocol_version: Some("2025-11-25".to_string()),
            session_id: Some("session-header".to_string()),
            stream_id: Some("stream-header".to_string()),
            last_event_id: Some("event-header".to_string()),
            app_origin: None,
            policy_origin: Some(PolicyOrigin::Remote),
            audit_correlation_id: Some("corr-header".to_string()),
        };

        let context = McpRequestContext::from_request_with_metadata(
            &request,
            McpTransportKind::Http,
            metadata,
        );

        assert_eq!(context.request_id, Some(json!(7)));
        assert_eq!(context.protocol_version.as_deref(), Some("2025-11-25"));
        assert_eq!(context.session_id.as_deref(), Some("session-header"));
        assert_eq!(context.stream_id.as_deref(), Some("stream-header"));
        assert_eq!(context.last_event_id.as_deref(), Some("event-header"));
        assert_eq!(context.task_id.as_deref(), Some("task-7"));
        assert_eq!(context.policy_origin, PolicyOrigin::Remote);
        assert_eq!(context.audit_correlation_id.as_deref(), Some("corr-header"));
    }

    #[test]
    fn progress_token_rejects_complex_values() {
        let request = json!({
            "params": {
                "_meta": { "progressToken": { "nested": true } }
            }
        });

        assert_eq!(progress_token_from_request(&request), None);
    }

    #[test]
    fn request_context_guard_restores_previous_context() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "ctx-1",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": { "action": "doctor" }
            }
        });
        let context = McpRequestContext::from_request(&request, McpTransportKind::Legacy);
        let guard = set_current_request_context(context.clone());

        assert_eq!(
            current_request_context()
                .as_ref()
                .and_then(|value| value.request_id.as_ref())
                .and_then(|value| value.as_str()),
            Some("ctx-1")
        );

        drop(guard);
        assert!(current_request_context().is_none());
    }

    #[test]
    fn request_context_exposes_openai_widget_origin_as_app_origin() {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "ctx-2",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": { "action": "doctor" },
                "_meta": {
                    "openai/widgetDomain": "https://widget.example"
                }
            }
        });

        let context = McpRequestContext::from_request(&request, McpTransportKind::Http);
        assert_eq!(
            context.app_origin.as_deref(),
            Some("https://widget.example")
        );
        assert_eq!(context.policy_origin, PolicyOrigin::App);
    }
}

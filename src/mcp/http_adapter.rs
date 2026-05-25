//! In-process Streamable HTTP adapter model.
//!
//! This module intentionally does not start an HTTP listener. It captures the
//! transport/session boundary that a real listener can call into: headers are
//! validated, request metadata is converted into `McpRequestContext`, and JSON-RPC
//! bodies are routed through the same handlers used by STDIO and the worker.

use crate::mcp::protocol::{tool_error_content, tool_success_content};
use crate::mcp::request_context::{
    McpRequestContext, McpTransportKind, McpTransportMetadata, PolicyOrigin,
};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};

pub const MCP_ENDPOINT: &str = "/mcp";
pub const HEADER_ACCEPT: &str = "accept";
pub const HEADER_CONTENT_TYPE: &str = "content-type";
pub const HEADER_LAST_EVENT_ID: &str = "last-event-id";
pub const HEADER_METHOD: &str = "mcp-method";
pub const HEADER_NAME: &str = "mcp-name";
pub const HEADER_ORIGIN: &str = "origin";
pub const HEADER_PROTOCOL_VERSION: &str = "mcp-protocol-version";
pub const HEADER_SESSION_ID: &str = "mcp-session-id";
pub const HEADER_STREAM_ID: &str = "mcp-stream-id";

const EVENT_REPLAY_LIMIT: usize = 128;
const SUPPORTED_LEGACY_HTTP_VERSION: &str = "2025-03-26";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Post,
    Get,
    Delete,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Get => "GET",
            Self::Delete => "DELETE",
        }
    }
}

impl TryFrom<&str> for HttpMethod {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.trim().to_ascii_uppercase().as_str() {
            "POST" => Ok(Self::Post),
            "GET" => Ok(Self::Get),
            "DELETE" => Ok(Self::Delete),
            other => Err(format!("Unsupported HTTP method '{}'", other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn post_json(body: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, MCP_ENDPOINT)
            .with_header(HEADER_ACCEPT, "application/json, text/event-stream")
            .with_header(HEADER_CONTENT_TYPE, "application/json")
            .with_header(
                HEADER_PROTOCOL_VERSION,
                crate::mcp::protocol::PROTOCOL_VERSION,
            )
            .with_body(body)
    }

    pub fn get_sse() -> Self {
        Self::new(HttpMethod::Get, MCP_ENDPOINT)
            .with_header(HEADER_ACCEPT, "text/event-stream")
            .with_header(
                HEADER_PROTOCOL_VERSION,
                crate::mcp::protocol::PROTOCOL_VERSION,
            )
    }

    pub fn delete_session(session_id: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, MCP_ENDPOINT)
            .with_header(HEADER_SESSION_ID, session_id.into())
            .with_header(
                HEADER_PROTOCOL_VERSION,
                crate::mcp::protocol::PROTOCOL_VERSION,
            )
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl HttpResponse {
    fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: None,
        }
    }

    fn json(status: u16, value: Value) -> Self {
        Self::new(status)
            .with_header("content-type", "application/json")
            .with_body(value.to_string())
    }

    fn sse(events: Vec<SseEvent>) -> Self {
        let body = if events.is_empty() {
            "event: ready\ndata: {}\n\n".to_string()
        } else {
            events
                .iter()
                .map(SseEvent::to_frame)
                .collect::<Vec<_>>()
                .join("")
        };

        Self::new(200)
            .with_header("content-type", "text/event-stream")
            .with_header("cache-control", "no-cache")
            .with_header("x-accel-buffering", "no")
            .with_body(body)
    }

    fn no_content(status: u16) -> Self {
        Self::new(status)
    }

    fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    pub fn body_text(&self) -> &str {
        self.body.as_deref().unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub id: String,
    pub stream_id: String,
    pub data: String,
}

impl SseEvent {
    fn to_frame(&self) -> String {
        format!("id: {}\ndata: {}\n\n", self.id, self.data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSessionMode {
    /// Draft-compatible mode: no protocol-level sessions or GET streams.
    StatelessDraft,
    /// Compatibility mode for MCP 2025-11-25 Streamable HTTP sessions.
    Stateful2025_11_25,
}

#[derive(Debug, Clone)]
struct HttpSession {
    protocol_version: Option<String>,
    replay: VecDeque<SseEvent>,
    next_event_seq: u64,
}

#[derive(Debug)]
pub struct StreamableHttpAdapter {
    session_mode: HttpSessionMode,
    sessions: HashMap<String, HttpSession>,
    next_session_seq: u64,
    replay_limit: usize,
    allowed_origins: Vec<String>,
}

impl Default for StreamableHttpAdapter {
    fn default() -> Self {
        Self::stateless()
    }
}

impl StreamableHttpAdapter {
    pub fn stateless() -> Self {
        Self {
            session_mode: HttpSessionMode::StatelessDraft,
            sessions: HashMap::new(),
            next_session_seq: 1,
            replay_limit: EVENT_REPLAY_LIMIT,
            allowed_origins: Vec::new(),
        }
    }

    pub fn stateful_2025_11_25() -> Self {
        Self {
            session_mode: HttpSessionMode::Stateful2025_11_25,
            ..Self::stateless()
        }
    }

    pub fn with_allowed_origin(mut self, origin: impl Into<String>) -> Self {
        self.allowed_origins.push(origin.into());
        self
    }

    pub fn handle(&mut self, request: HttpRequest) -> HttpResponse {
        if request.path != MCP_ENDPOINT {
            return HttpResponse::json(
                404,
                crate::mcp::protocol::json_rpc_error_value(
                    -32601,
                    "Streamable HTTP endpoint not found",
                    None,
                ),
            );
        }
        if let Some(origin) = request.header(HEADER_ORIGIN) {
            if !self.origin_allowed(origin) {
                return HttpResponse::json(
                    403,
                    crate::mcp::protocol::json_rpc_error_value(
                        -32000,
                        "Forbidden Origin for Streamable HTTP adapter",
                        None,
                    ),
                );
            }
        }

        match request.method {
            HttpMethod::Post => self.handle_post(request),
            HttpMethod::Get => self.handle_get(request),
            HttpMethod::Delete => self.handle_delete(request),
        }
    }

    pub fn push_stream_event(
        &mut self,
        session_id: &str,
        stream_id: &str,
        message: &Value,
    ) -> Result<String, String> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| format!("Unknown HTTP session '{}'", session_id))?;
        if stream_id.trim().is_empty() {
            return Err("Missing stream_id".to_string());
        }
        session.next_event_seq = session.next_event_seq.saturating_add(1);
        let event_id = format!("{}:{}:{}", session_id, stream_id, session.next_event_seq);
        session.replay.push_back(SseEvent {
            id: event_id.clone(),
            stream_id: stream_id.to_string(),
            data: message.to_string(),
        });
        while session.replay.len() > self.replay_limit {
            session.replay.pop_front();
        }
        Ok(event_id)
    }

    fn handle_post(&mut self, request: HttpRequest) -> HttpResponse {
        if !accepts_json_or_sse(request.header(HEADER_ACCEPT)) {
            return HttpResponse::json(
                406,
                crate::mcp::protocol::json_rpc_error_value(
                    -32000,
                    "HTTP POST must accept application/json or text/event-stream",
                    None,
                ),
            );
        }
        if let Err(response) = validate_protocol_version(&request) {
            return response;
        }

        let body = request.body.as_deref().unwrap_or_default();
        let value: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(err) => {
                return HttpResponse::json(
                    400,
                    crate::mcp::protocol::json_rpc_error_value(
                        -32700,
                        &format!("Parse error: {}", err),
                        None,
                    ),
                );
            }
        };

        if let Err(response) = validate_mirrored_headers(&request, &value) {
            return response;
        }

        let parts = match crate::mcp::protocol::validate_json_rpc_request(&value) {
            Ok(parts) => parts,
            Err(error) => return HttpResponse::json(400, error),
        };

        let session_id = match self.validate_or_create_session(&request, parts.method) {
            Ok(session_id) => session_id,
            Err(response) => return response,
        };

        if !parts.expects_response {
            return HttpResponse::no_content(202);
        }

        let metadata = self.transport_metadata(&request, session_id.as_deref());
        let id = parts.id.clone();
        let response = dispatch_http_json_rpc(&value, metadata);
        let status = if response.get("error").is_some()
            && response["error"]["code"].as_i64() == Some(-32601)
        {
            404
        } else {
            200
        };
        let mut http = HttpResponse::json(status, response);
        if parts.method == "initialize" {
            if let Some(session_id) = session_id {
                http.headers
                    .push((HEADER_SESSION_ID.to_string(), session_id.to_string()));
            }
        }
        if id.is_none() {
            http.status = 202;
            http.body = None;
        }
        http
    }

    fn handle_get(&mut self, request: HttpRequest) -> HttpResponse {
        if self.session_mode == HttpSessionMode::StatelessDraft {
            return HttpResponse::json(
                405,
                crate::mcp::protocol::json_rpc_error_value(
                    -32601,
                    "GET SSE streams are disabled in stateless Streamable HTTP mode",
                    None,
                ),
            );
        }
        if !accepts_sse(request.header(HEADER_ACCEPT)) {
            return HttpResponse::json(
                406,
                crate::mcp::protocol::json_rpc_error_value(
                    -32000,
                    "HTTP GET must accept text/event-stream",
                    None,
                ),
            );
        }

        let session_id = match request.header(HEADER_SESSION_ID) {
            Some(value) => value.to_string(),
            None => {
                return HttpResponse::json(
                    400,
                    crate::mcp::protocol::json_rpc_error_value(
                        -32602,
                        "Missing Mcp-Session-Id header",
                        None,
                    ),
                );
            }
        };
        let Some(session) = self.sessions.get(&session_id) else {
            return HttpResponse::json(
                404,
                crate::mcp::protocol::json_rpc_error_value(-32602, "Unknown Mcp-Session-Id", None),
            );
        };

        let events = replay_events(
            &session.replay,
            request.header(HEADER_LAST_EVENT_ID),
            request.header(HEADER_STREAM_ID),
        );
        HttpResponse::sse(events)
    }

    fn handle_delete(&mut self, request: HttpRequest) -> HttpResponse {
        if self.session_mode == HttpSessionMode::StatelessDraft {
            return HttpResponse::no_content(204);
        }
        let Some(session_id) = request.header(HEADER_SESSION_ID) else {
            return HttpResponse::json(
                400,
                crate::mcp::protocol::json_rpc_error_value(
                    -32602,
                    "Missing Mcp-Session-Id header",
                    None,
                ),
            );
        };
        self.sessions.remove(session_id);
        HttpResponse::no_content(204)
    }

    fn validate_or_create_session(
        &mut self,
        request: &HttpRequest,
        method: &str,
    ) -> Result<Option<String>, HttpResponse> {
        if self.session_mode == HttpSessionMode::StatelessDraft {
            return Ok(None);
        }

        if method == "initialize" && request.header(HEADER_SESSION_ID).is_none() {
            let session_id = self.new_session_id();
            self.sessions.insert(
                session_id.clone(),
                HttpSession {
                    protocol_version: request
                        .header(HEADER_PROTOCOL_VERSION)
                        .map(ToString::to_string),
                    replay: VecDeque::new(),
                    next_event_seq: 0,
                },
            );
            return Ok(Some(session_id));
        }

        let Some(session_id) = request.header(HEADER_SESSION_ID) else {
            return Err(HttpResponse::json(
                400,
                crate::mcp::protocol::json_rpc_error_value(
                    -32602,
                    "Missing Mcp-Session-Id header",
                    None,
                ),
            ));
        };
        if self.sessions.contains_key(session_id) {
            Ok(Some(session_id.to_string()))
        } else {
            Err(HttpResponse::json(
                404,
                crate::mcp::protocol::json_rpc_error_value(-32602, "Unknown Mcp-Session-Id", None),
            ))
        }
    }

    fn transport_metadata(
        &self,
        request: &HttpRequest,
        session_id: Option<&str>,
    ) -> McpTransportMetadata {
        let protocol_version = request
            .header(HEADER_PROTOCOL_VERSION)
            .map(ToString::to_string)
            .or_else(|| {
                session_id.and_then(|id| {
                    self.sessions
                        .get(id)
                        .and_then(|session| session.protocol_version.clone())
                })
            });
        McpTransportMetadata {
            protocol_version,
            session_id: session_id
                .map(ToString::to_string)
                .or_else(|| request.header(HEADER_SESSION_ID).map(ToString::to_string)),
            stream_id: request.header(HEADER_STREAM_ID).map(ToString::to_string),
            last_event_id: request
                .header(HEADER_LAST_EVENT_ID)
                .map(ToString::to_string),
            app_origin: request
                .header("openai-widget-domain")
                .or_else(|| request.header("x-memoric-app-origin"))
                .map(ToString::to_string),
            policy_origin: Some(PolicyOrigin::Remote),
            audit_correlation_id: request
                .header("traceparent")
                .or_else(|| request.header("x-request-id"))
                .map(ToString::to_string),
        }
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        if self
            .allowed_origins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(origin))
        {
            return true;
        }
        let normalized = origin.trim().to_ascii_lowercase();
        normalized == "null"
            || normalized.starts_with("http://localhost")
            || normalized.starts_with("https://localhost")
            || normalized.starts_with("http://127.0.0.1")
            || normalized.starts_with("https://127.0.0.1")
            || normalized.starts_with("http://[::1]")
            || normalized.starts_with("https://[::1]")
    }

    fn new_session_id(&mut self) -> String {
        let seq = self.next_session_seq;
        self.next_session_seq = self.next_session_seq.saturating_add(1);
        let nonce = fastrand::u64(..);
        format!("memoric-http-{}-{}-{:016x}", std::process::id(), seq, nonce)
    }
}

fn dispatch_http_json_rpc(request: &Value, metadata: McpTransportMetadata) -> Value {
    let context =
        McpRequestContext::from_request_with_metadata(request, McpTransportKind::Http, metadata);
    crate::mcp::request_context::with_current_request_context(context, || {
        let parts = match crate::mcp::protocol::validate_json_rpc_request(request) {
            Ok(parts) => parts,
            Err(error) => return error,
        };
        let id = parts.id.clone().unwrap_or(Value::Null);
        let result = match parts.method {
            "initialize" => Ok(crate::mcp::protocol::initialize_result("memoric-http")),
            "tools/list" => crate::mcp::tools::list_request(request),
            "tools/call" => handle_tools_call(request),
            "resources/list" => crate::mcp::resources::list_request(request),
            "resources/templates/list" => crate::mcp::resources::templates_list_request(request),
            "resources/read" => crate::mcp::resources::read_request(request),
            "tasks/list" => crate::mcp::tasks::list_request(request),
            "tasks/get" => crate::mcp::tasks::get_request(request),
            "tasks/result" => crate::mcp::tasks::result_request(request),
            "tasks/cancel" => crate::mcp::tasks::cancel_request(request),
            "tasks/input_response" => crate::mcp::tasks::input_response_request(request),
            "tasks/update" => crate::mcp::tasks::update_request(request),
            "ping" => Ok(Value::Null),
            method if crate::mcp::protocol::is_app_bridge_host_only_method(method) => {
                return crate::mcp::protocol::app_bridge_unsupported_error_value(method, Some(id));
            }
            method => {
                return crate::mcp::protocol::json_rpc_error_value(
                    -32601,
                    &format!("Method not found: {}", method),
                    Some(id),
                );
            }
        };

        match result {
            Ok(result) => json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": id,
            }),
            Err(err) => crate::mcp::protocol::json_rpc_error_value(
                json_rpc_code_for_handler_error(&err),
                &err,
                Some(id),
            ),
        }
    })
}

fn handle_tools_call(request: &Value) -> Result<Value, String> {
    crate::observability::record_mcp_request(McpTransportKind::Http, request);
    let params = request.get("params").ok_or("Missing params")?;
    let name = params
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or("Missing tool name")?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let task_augmented = crate::mcp::tasks::is_task_augmented_request(request);
    let as_task = args
        .get("as_task")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if task_augmented || as_task {
        let options = if task_augmented {
            crate::mcp::tasks::task_options_from_request(request)
        } else {
            crate::mcp::tasks::TaskOptions::default()
        };
        return match crate::mcp::tasks::spawn_tool_task_with_options(name, &args, options) {
            Ok(task_id) if task_augmented => Ok(crate::mcp::tasks::task_create_result(&task_id)),
            Ok(task_id) => Ok(crate::mcp::tasks::task_accepted_content(
                name, &args, &task_id,
            )),
            Err(err) => Ok(tool_error_content(name, &args, &err)),
        };
    }

    let name_owned = name.to_string();
    let args_for_call = args.clone();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::mcp::tool_call::call_tool(&name_owned, args_for_call)
    })) {
        Ok(Ok(value)) => Ok(tool_success_content(&name_owned, &args, &value)),
        Ok(Err(err)) => Ok(tool_error_content(&name_owned, &args, &err)),
        Err(panic_info) => {
            let panic_msg = if let Some(value) = panic_info.downcast_ref::<String>() {
                value.clone()
            } else if let Some(value) = panic_info.downcast_ref::<&str>() {
                value.to_string()
            } else {
                "Unknown panic in tool handler".to_string()
            };
            Ok(tool_error_content(
                &name_owned,
                &args,
                &format!("Internal error in tool '{}': {}", name_owned, panic_msg),
            ))
        }
    }
}

fn validate_protocol_version(request: &HttpRequest) -> Result<(), HttpResponse> {
    let Some(version) = request.header(HEADER_PROTOCOL_VERSION) else {
        return Ok(());
    };
    if version == crate::mcp::protocol::PROTOCOL_VERSION || version == SUPPORTED_LEGACY_HTTP_VERSION
    {
        Ok(())
    } else {
        Err(HttpResponse::json(
            400,
            crate::mcp::protocol::json_rpc_error_value(
                -32000,
                &format!(
                    "Unsupported MCP-Protocol-Version '{}'; supported versions are {}, {}",
                    version,
                    crate::mcp::protocol::PROTOCOL_VERSION,
                    SUPPORTED_LEGACY_HTTP_VERSION
                ),
                None,
            ),
        ))
    }
}

fn validate_mirrored_headers(request: &HttpRequest, value: &Value) -> Result<(), HttpResponse> {
    if let Some(method_header) = request.header(HEADER_METHOD) {
        let body_method = value
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !body_method.is_empty() && method_header != body_method {
            return Err(header_mismatch("Mcp-Method", method_header, body_method));
        }
    }

    if let Some(name_header) = request.header(HEADER_NAME) {
        let body_name = value
            .get("params")
            .and_then(|params| {
                params
                    .get("name")
                    .or_else(|| params.get("uri"))
                    .or_else(|| params.get("id"))
            })
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !body_name.is_empty() && name_header != body_name {
            return Err(header_mismatch("Mcp-Name", name_header, body_name));
        }
    }

    Ok(())
}

fn header_mismatch(header: &str, header_value: &str, body_value: &str) -> HttpResponse {
    HttpResponse::json(
        400,
        crate::mcp::protocol::json_rpc_error_value(
            -32600,
            &format!(
                "HeaderMismatch: {} value '{}' does not match JSON-RPC body '{}'",
                header, header_value, body_value
            ),
            None,
        ),
    )
}

fn replay_events(
    replay: &VecDeque<SseEvent>,
    last_event_id: Option<&str>,
    stream_id: Option<&str>,
) -> Vec<SseEvent> {
    let target_stream = stream_id.or_else(|| last_event_id.and_then(stream_id_from_event_id));
    replay
        .iter()
        .filter(|event| {
            if let Some(stream_id) = target_stream {
                event.stream_id == stream_id
            } else {
                true
            }
        })
        .filter(|event| {
            last_event_id
                .map(|last_id| event_after_last_id(&event.id, last_id))
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

fn event_after_last_id(event_id: &str, last_id: &str) -> bool {
    match (event_seq(event_id), event_seq(last_id)) {
        (Some(event_seq), Some(last_seq)) => event_seq > last_seq,
        _ => event_id > last_id,
    }
}

fn event_seq(event_id: &str) -> Option<u64> {
    event_id.rsplit(':').next()?.parse().ok()
}

fn stream_id_from_event_id(event_id: &str) -> Option<&str> {
    let mut parts = event_id.rsplitn(3, ':');
    let _seq = parts.next()?;
    let stream = parts.next()?;
    if stream.is_empty() {
        None
    } else {
        Some(stream)
    }
}

fn accepts_json_or_sse(accept: Option<&str>) -> bool {
    accept
        .map(|value| {
            let lower = value.to_ascii_lowercase();
            lower.contains("application/json") || lower.contains("text/event-stream")
        })
        .unwrap_or(true)
}

fn accepts_sse(accept: Option<&str>) -> bool {
    accept
        .map(|value| value.to_ascii_lowercase().contains("text/event-stream"))
        .unwrap_or(false)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .rev()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn json_rpc_code_for_handler_error(message: &str) -> i64 {
    if message.starts_with("Missing ")
        || message.starts_with("Invalid ")
        || message.contains("not found")
    {
        -32602
    } else {
        -32603
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_post(raw: &str) -> HttpRequest {
        let mut request = HttpRequest::post_json(raw.to_string())
            .with_header(HEADER_ORIGIN, "http://localhost")
            .with_header(HEADER_METHOD, method_from_raw(raw).unwrap_or("fixture"));
        if let Some(name) = name_from_raw(raw) {
            request = request.with_header(HEADER_NAME, name);
        }
        request
    }

    fn method_from_raw(raw: &str) -> Option<&str> {
        serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|value| {
                value
                    .get("method")
                    .and_then(|method| method.as_str())
                    .map(str::to_string)
            })
            .map(|value| Box::leak(value.into_boxed_str()) as &str)
    }

    fn name_from_raw(raw: &str) -> Option<&str> {
        serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|value| {
                value
                    .get("params")
                    .and_then(|params| {
                        params
                            .get("name")
                            .or_else(|| params.get("uri"))
                            .or_else(|| params.get("id"))
                    })
                    .and_then(|name| name.as_str())
                    .map(str::to_string)
            })
            .map(|value| Box::leak(value.into_boxed_str()) as &str)
    }

    #[test]
    fn streamable_http_conformance_fixtures_cover_core_methods() {
        let mut adapter = StreamableHttpAdapter::stateless();
        crate::mcp::conformance::run_conformance("streamable-http", |case| {
            adapter
                .handle(fixture_post(&case.request))
                .body_text()
                .to_string()
        });
    }

    #[test]
    fn streamable_http_adversarial_fixtures_are_stable() {
        let mut adapter = StreamableHttpAdapter::stateless();
        crate::mcp::conformance::run_adversarial_conformance("streamable-http", |case| {
            adapter
                .handle(fixture_post(&case.request))
                .body_text()
                .to_string()
        });
    }

    #[test]
    fn stateful_2025_11_25_mode_mints_and_requires_session_ids() {
        let mut adapter = StreamableHttpAdapter::stateful_2025_11_25();
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": "init-http",
            "method": "initialize",
            "params": {}
        });

        let init_response = adapter.handle(
            HttpRequest::post_json(initialize.to_string())
                .with_header(HEADER_METHOD, "initialize")
                .with_header(HEADER_ORIGIN, "http://localhost"),
        );

        assert_eq!(init_response.status, 200);
        let session_id = init_response
            .header(HEADER_SESSION_ID)
            .expect("stateful initialize returns session id")
            .to_string();
        assert!(session_id.starts_with("memoric-http-"));

        let missing_session = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "ping-missing-session",
                    "method": "ping"
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "ping")
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );
        assert_eq!(missing_session.status, 400);
        assert!(missing_session
            .body_text()
            .contains("Missing Mcp-Session-Id"));

        let ping = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "ping-with-session",
                    "method": "ping"
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "ping")
            .with_header(HEADER_SESSION_ID, session_id.clone())
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );
        assert_eq!(ping.status, 200);
        assert_eq!(
            serde_json::from_str::<Value>(ping.body_text()).unwrap()["result"],
            Value::Null
        );

        let delete = adapter.handle(HttpRequest::delete_session(session_id.clone()));
        assert_eq!(delete.status, 204);

        let expired = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "ping-expired-session",
                    "method": "ping"
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "ping")
            .with_header(HEADER_SESSION_ID, session_id)
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );
        assert_eq!(expired.status, 404);
    }

    #[test]
    fn sse_replay_is_bound_to_the_originating_stream() {
        let mut adapter = StreamableHttpAdapter::stateful_2025_11_25();
        let init = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "init-replay",
                    "method": "initialize",
                    "params": {}
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "initialize")
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );
        let session_id = init.header(HEADER_SESSION_ID).unwrap().to_string();

        let first_a = adapter
            .push_stream_event(
                &session_id,
                "stream-a",
                &json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}),
            )
            .expect("first event");
        let second_a = adapter
            .push_stream_event(
                &session_id,
                "stream-a",
                &json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 2}}),
            )
            .expect("second event");
        let _stream_b = adapter
            .push_stream_event(
                &session_id,
                "stream-b",
                &json!({"jsonrpc": "2.0", "method": "notifications/message"}),
            )
            .expect("other stream event");

        let replay = adapter.handle(
            HttpRequest::get_sse()
                .with_header(HEADER_SESSION_ID, session_id)
                .with_header(HEADER_LAST_EVENT_ID, first_a)
                .with_header(HEADER_ORIGIN, "http://localhost"),
        );

        assert_eq!(replay.status, 200);
        let body = replay.body_text();
        assert!(body.contains(&format!("id: {}", second_a)));
        assert!(body.contains("\"progress\":2"));
        assert!(!body.contains("stream-b"));
    }

    #[test]
    fn mirrored_http_headers_are_validated_before_dispatch() {
        let mut adapter = StreamableHttpAdapter::stateless();
        let response = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "header-mismatch",
                    "method": "tools/list"
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "ping")
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );

        assert_eq!(response.status, 400);
        assert!(response.body_text().contains("HeaderMismatch"));
    }

    #[test]
    fn invalid_origin_is_forbidden() {
        let mut adapter = StreamableHttpAdapter::stateless();
        let response = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "bad-origin",
                    "method": "ping"
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "ping")
            .with_header(HEADER_ORIGIN, "https://attacker.example"),
        );

        assert_eq!(response.status, 403);
    }

    #[test]
    fn http_request_context_reaches_tool_audit_timeline() {
        let mut adapter = StreamableHttpAdapter::stateful_2025_11_25();
        let init = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "init-context",
                    "method": "initialize",
                    "params": {}
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "initialize")
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );
        let session_id = init.header(HEADER_SESSION_ID).unwrap().to_string();

        let response = adapter.handle(
            HttpRequest::post_json(
                json!({
                    "jsonrpc": "2.0",
                    "id": "http-context",
                    "method": "tools/call",
                    "params": {
                        "name": "self",
                        "arguments": {
                            "action": "version",
                            "request_id": "http-context"
                        }
                    }
                })
                .to_string(),
            )
            .with_header(HEADER_METHOD, "tools/call")
            .with_header(HEADER_NAME, "self")
            .with_header(HEADER_SESSION_ID, session_id)
            .with_header(HEADER_STREAM_ID, "stream-context")
            .with_header(HEADER_ORIGIN, "http://localhost"),
        );
        assert_eq!(response.status, 200);

        let timeline = crate::observability::timeline_json(&json!({
            "correlation_id": "http-context",
            "limit": 20,
            "redaction": "strict"
        }));
        let events = timeline["events"].as_array().expect("timeline events");
        assert!(events.iter().any(|event| {
            event["kind"] == "mcp.request"
                && event["details"]["transport"] == "http"
                && event["details"]["policy_origin"] == "remote"
                && event["details"]["session_present"] == true
                && event["details"]["stream_present"] == true
        }));
    }
}

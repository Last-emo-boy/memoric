//! Read-only observability timeline assembly.
//!
//! Timeline events intentionally carry summaries, correlation handles, task
//! state, artifact resource references, and hashes. They do not carry raw tool
//! results, raw memory, progress tokens, or local filesystem paths.

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const MAX_LIVE_EVENTS: usize = 1024;
const DEFAULT_TIMELINE_LIMIT: usize = 100;
const MAX_TIMELINE_LIMIT: usize = 500;
const MAX_SUMMARY_CHARS: usize = 240;

static LIVE_EVENTS: Lazy<Mutex<VecDeque<Value>>> = Lazy::new(|| Mutex::new(VecDeque::new()));
static TASK_CORRELATIONS: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static ARTIFACT_CORRELATIONS: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct TimelineFilters {
    correlation_id: Option<String>,
    request_id: Option<String>,
    task_id: Option<String>,
    artifact_uri: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: usize,
    redaction: crate::redaction::RedactionProfile,
}

pub fn timeline_json(args: &Value) -> Value {
    let filters = TimelineFilters::from_args(args);
    let mut events = Vec::new();
    let mut sources = serde_json::Map::new();

    let live_events = live_events_snapshot();
    let worker_ipc_live_count = live_events
        .iter()
        .filter(|event| {
            event["source"]
                .as_str()
                .is_some_and(|source| source == "worker.ipc")
        })
        .count();
    let notification_live_count = live_events
        .iter()
        .filter(|event| {
            event["source"]
                .as_str()
                .is_some_and(|source| source == "tasks.notification")
        })
        .count();
    sources.insert(
        "in_memory".to_string(),
        json!({
            "configured": true,
            "mode": "process-local-ring-buffer",
            "count": live_events.len(),
            "max": MAX_LIVE_EVENTS
        }),
    );
    sources.insert(
        "worker_ipc".to_string(),
        json!({
            "configured": true,
            "source": "process-local-ring-buffer",
            "count": worker_ipc_live_count
        }),
    );
    sources.insert(
        "notifications".to_string(),
        json!({
            "configured": true,
            "source": "process-local-ring-buffer",
            "count": notification_live_count
        }),
    );
    events.extend(live_events);

    let (audit_events, audit_source) = audit_timeline_events(args);
    sources.insert("audit".to_string(), audit_source);
    events.extend(audit_events);

    let (task_events, task_source) = task_timeline_events();
    sources.insert("tasks".to_string(), task_source);
    events.extend(task_events);

    let (artifact_events, artifact_source) = artifact_timeline_events();
    sources.insert("artifacts".to_string(), artifact_source);
    events.extend(artifact_events);

    events = events
        .into_iter()
        .filter(|event| event_matches_filters(event, &filters))
        .map(|event| sanitize_event(event, filters.redaction))
        .collect();

    sort_events(&mut events);
    let total_matched = events.len();
    if events.len() > filters.limit {
        events = events
            .into_iter()
            .skip(total_matched.saturating_sub(filters.limit))
            .collect();
    }

    json!({
        "success": true,
        "timeline_version": 1,
        "generated_at": crate::state::chrono_now_public(),
        "filters": filters.to_json(),
        "events": events,
        "count": events.len(),
        "total_matched": total_matched,
        "sources": Value::Object(sources),
        "redaction": {
            "profile": filters.redaction.as_str(),
            "classification_aware": true,
            "omits": ["raw results", "raw memory", "credentials", "progress tokens", "local paths"]
        },
        "message": "Observability timeline assembled from safe metadata only"
    })
}

pub fn correlation_id_from_args(args: &Value) -> Option<String> {
    string_field(Some(args), "correlation_id")
        .or_else(|| string_field(Some(args), "correlationId"))
        .or_else(|| string_field(Some(args), "request_id"))
        .or_else(|| string_field(Some(args), "chain_id"))
        .or_else(|| string_field(Some(args), "task_id"))
}

pub fn correlation_id_from_request(request: &Value) -> Option<String> {
    let context = crate::mcp::request_context::McpRequestContext::from_request(
        request,
        crate::mcp::request_context::McpTransportKind::Unknown("timeline".to_string()),
    );
    context
        .audit_correlation_id
        .or_else(|| context.task_id)
        .or_else(|| context.request_id.as_ref().and_then(json_id_to_string))
}

pub fn link_task_from_args(task_id: &str, args: &Value) {
    if let Some(correlation_id) = correlation_id_from_args(args) {
        link_task(task_id, &correlation_id);
    }
}

pub fn link_task(task_id: &str, correlation_id: &str) {
    if task_id.trim().is_empty() || correlation_id.trim().is_empty() {
        return;
    }
    if let Ok(mut map) = TASK_CORRELATIONS.lock() {
        map.insert(task_id.to_string(), correlation_id.to_string());
    }
}

pub fn link_artifact(uri: &str, correlation_id: &str) {
    if uri.trim().is_empty() || correlation_id.trim().is_empty() {
        return;
    }
    if let Ok(mut map) = ARTIFACT_CORRELATIONS.lock() {
        map.insert(uri.to_string(), correlation_id.to_string());
    }
}

pub fn record_mcp_request(
    transport: crate::mcp::request_context::McpTransportKind,
    request: &Value,
) {
    let context = crate::mcp::request_context::current_request_context()
        .filter(|context| context.transport.as_str() == transport.as_str())
        .unwrap_or_else(|| {
            crate::mcp::request_context::McpRequestContext::from_request(request, transport.clone())
        });
    let params = request.get("params");
    let args = params
        .and_then(|params| params.get("arguments"))
        .filter(|value| value.is_object())
        .unwrap_or(&Value::Null);
    let tool = params
        .and_then(|params| params.get("name"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let correlation_id = context
        .audit_correlation_id
        .clone()
        .or_else(|| context.task_id.clone())
        .or_else(|| context.request_id.as_ref().and_then(json_id_to_string));
    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or("tools/call");

    push_event(json!({
        "kind": "mcp.request",
        "source": format!("mcp.{}", transport.as_str()),
        "correlation_id": correlation_id,
        "request_id": context.request_id.as_ref().and_then(json_id_to_string),
        "task_id": context.task_id,
        "tool": null_if_empty(tool),
        "action": null_if_empty(action),
        "status": "received",
        "summary": truncate_summary(&format!(
            "{} request received{}",
            method,
            if tool.is_empty() { String::new() } else { format!(" for {}", tool) }
        )),
        "data_classification": "local-sensitive-redacted",
        "details": {
            "method": method,
            "transport": transport.as_str(),
            "protocol_version": context.protocol_version,
            "session_present": context.session_id.is_some(),
            "stream_present": context.stream_id.is_some(),
            "last_event_present": context.last_event_id.is_some(),
            "progress_available": context.progress_token.is_some(),
            "app_origin_present": context.app_origin.is_some(),
            "app_origin": context.app_origin,
            "policy_origin": context.policy_origin.as_str(),
            "argument_keys": object_keys(args)
        }
    }));
}

pub fn record_tool_dispatch(tool: &str, args: &Value) {
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let traits = crate::mcp::action_registry::classify_action(tool, action);
    let request_context = crate::mcp::request_context::current_request_context();
    push_event(json!({
        "kind": "mcp.tool.dispatch",
        "source": "mcp.dispatch",
        "correlation_id": correlation_id_from_args(args),
        "request_id": string_field(Some(args), "request_id"),
        "task_id": string_field(Some(args), "task_id"),
        "tool": tool,
        "action": action,
        "status": "started",
        "summary": truncate_summary(&format!("{} action '{}' dispatch started", tool, action)),
        "data_classification": "local-sensitive-redacted",
        "details": {
            "argument_keys": object_keys(args),
            "read_only": traits.read_only,
            "state_changing": traits.state_changing,
            "required_policy": traits.required_policy.as_str(),
            "app_origin": request_context
                .as_ref()
                .and_then(|context| context.app_origin.as_deref())
                .unwrap_or_default(),
            "policy_origin": request_context
                .as_ref()
                .map(|context| context.policy_origin.as_str())
                .unwrap_or("unknown")
        }
    }));
}

pub fn record_tool_result(tool: &str, args: &Value, status: &str, message: Option<&str>) {
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let request_context = crate::mcp::request_context::current_request_context();
    push_event(json!({
        "kind": "mcp.tool.result",
        "source": "mcp.dispatch",
        "correlation_id": correlation_id_from_args(args),
        "request_id": string_field(Some(args), "request_id"),
        "task_id": string_field(Some(args), "task_id"),
        "tool": tool,
        "action": action,
        "status": status,
        "summary": truncate_summary(message.unwrap_or_else(|| {
            if status == "success" { "tool call completed" } else { "tool call did not complete successfully" }
        })),
        "data_classification": "local-sensitive-redacted",
        "details": {
            "result_payload_included": false,
            "app_origin": request_context
                .as_ref()
                .and_then(|context| context.app_origin.as_deref())
                .unwrap_or_default(),
            "policy_origin": request_context
                .as_ref()
                .map(|context| context.policy_origin.as_str())
                .unwrap_or("unknown")
        }
    }));
}

pub fn record_task_event(kind: &str, task: &crate::mcp::tasks::TaskRecord, details: Value) {
    let correlation_id = task_correlation_id(&task.task_id).unwrap_or_else(|| task.task_id.clone());
    push_event(json!({
        "kind": kind,
        "source": "tasks",
        "correlation_id": correlation_id,
        "task_id": task.task_id,
        "tool": task.tool,
        "action": task.action,
        "status": task.status.as_str(),
        "summary": truncate_summary(&task.summary),
        "data_classification": "local-sensitive-redacted",
        "details": redact_timeline_details(json!({
            "progress": {
                "current": task.progress_current,
                "total": task.progress_total
            },
            "retry": {
                "count": task.retry_count,
                "max": task.max_retries
            },
            "ttl": task.ttl_ms,
            "result_retention_ms": task.result_retention_ms,
            "result_payload_included": false,
            "event": details
        }))
    }));
}

pub fn record_audit_entry(entry: &Value) {
    push_event(audit_entry_event(entry));
}

pub fn record_artifact_registered(artifact: &Value, correlation_id: Option<&str>) {
    let uri = artifact["uri"].as_str().unwrap_or_default();
    if let Some(correlation_id) = correlation_id {
        link_artifact(uri, correlation_id);
    }
    let correlation_id = correlation_id
        .map(str::to_string)
        .or_else(|| artifact_correlation_id(uri))
        .or_else(|| {
            if uri.is_empty() {
                None
            } else {
                Some(uri.to_string())
            }
        });
    push_event(json!({
        "ts": artifact.get("last_modified").cloned().unwrap_or(Value::Null),
        "kind": "artifact.registered",
        "source": "artifacts",
        "correlation_id": correlation_id,
        "artifact_uri": null_if_empty(uri),
        "status": "registered",
        "summary": truncate_summary(&format!(
            "Artifact {} registered",
            artifact["name"].as_str().unwrap_or("artifact")
        )),
        "data_classification": "artifact-reference",
        "details": {
            "artifact": safe_artifact_ref(artifact),
            "path_included": false
        }
    }));
}

pub fn record_worker_ipc_event(direction: &str, stage: &str, message: &Value) {
    let method = message
        .get("method")
        .and_then(|value| value.as_str())
        .or_else(|| {
            message
                .get("result")
                .and_then(|result| result.get("method"))
                .and_then(|value| value.as_str())
        })
        .unwrap_or_default();
    let correlation_id = correlation_id_from_ipc_message(message);
    let task_id = task_id_from_value(message);
    push_event(json!({
        "kind": "worker.ipc",
        "source": "worker.ipc",
        "correlation_id": correlation_id,
        "request_id": message.get("id").and_then(json_id_to_string),
        "task_id": task_id,
        "status": stage,
        "summary": truncate_summary(&format!(
            "Worker IPC {} {}",
            direction,
            if method.is_empty() { stage.to_string() } else { method.to_string() }
        )),
        "data_classification": "local-sensitive-redacted",
        "details": {
            "direction": direction,
            "stage": stage,
            "method": null_if_empty(method),
            "has_error": message.get("error").is_some(),
            "payload_included": false
        }
    }));
}

pub fn record_task_notification(notification: &Value) {
    let method = notification
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if method != "notifications/progress" && method != "notifications/tasks/status" {
        return;
    }
    let params = notification.get("params").unwrap_or(&Value::Null);
    let task_id = string_field(Some(params), "taskId")
        .or_else(|| string_field(Some(params), "task_id"))
        .or_else(|| {
            params
                .pointer("/_meta/io.modelcontextprotocol/related-task/taskId")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
        });
    let correlation_id = task_id
        .as_deref()
        .and_then(task_correlation_id)
        .or_else(|| string_field(Some(params), "progressToken"))
        .or_else(|| {
            params
                .pointer("/_meta/io.modelcontextprotocol/related-task/taskId")
                .and_then(|value| value.as_str())
                .map(ToString::to_string)
        });
    push_event(json!({
        "kind": if method == "notifications/progress" { "task.notification.progress" } else { "task.notification.status" },
        "source": "tasks.notification",
        "correlation_id": correlation_id,
        "task_id": task_id,
        "status": if method == "notifications/progress" { "progress" } else { "status" },
        "summary": truncate_summary(&format!("{} emitted", method)),
        "data_classification": "local-sensitive-redacted",
        "details": {
            "method": method,
            "has_progress_token": method == "notifications/progress",
            "task_status": params.get("status").cloned().unwrap_or(Value::Null),
            "task_progress": params.pointer("/progress").cloned().unwrap_or(Value::Null),
            "result_payload_included": false
        }
    }));
}

fn live_events_snapshot() -> Vec<Value> {
    LIVE_EVENTS
        .lock()
        .map(|events| events.iter().cloned().collect())
        .unwrap_or_default()
}

fn push_event(mut event: Value) {
    let sequence = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    if !event
        .get("ts")
        .is_some_and(|value| value.as_str().is_some_and(|text| !text.is_empty()))
    {
        event["ts"] = json!(crate::state::chrono_now_public());
    }
    event["sequence"] = json!(sequence);
    if let Ok(mut events) = LIVE_EVENTS.lock() {
        events.push_back(event);
        while events.len() > MAX_LIVE_EVENTS {
            events.pop_front();
        }
    }
}

fn audit_timeline_events(args: &Value) -> (Vec<Value>, Value) {
    let Some(path) = audit_path_from_args(args) else {
        return (
            Vec::new(),
            json!({
                "configured": false,
                "count": 0
            }),
        );
    };

    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let events = content
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .map(|entry| audit_entry_event(&entry))
                .collect::<Vec<_>>();
            let count = events.len();
            (
                events,
                json!({
                    "configured": true,
                    "path": safe_path_info(&path),
                    "count": count
                }),
            )
        }
        Err(err) => (
            Vec::new(),
            json!({
                "configured": true,
                "path": safe_path_info(&path),
                "count": 0,
                "error": truncate_summary(&err.to_string())
            }),
        ),
    }
}

fn audit_entry_event(entry: &Value) -> Value {
    let correlation_id = string_field(Some(entry), "correlation_id")
        .or_else(|| string_field(Some(entry), "correlationId"))
        .or_else(|| string_field(Some(entry), "request_id"))
        .or_else(|| string_field(entry.get("args"), "task_id"));
    let artifacts = entry
        .get("artifacts")
        .and_then(|value| value.as_array())
        .map(|items| items.iter().map(safe_artifact_ref).collect::<Vec<_>>())
        .unwrap_or_default();
    let tool = entry
        .get("tool")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let action = entry
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let status = entry
        .get("result_status")
        .or_else(|| entry.get("status"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    json!({
        "ts": entry.get("ts").cloned().unwrap_or(Value::Null),
        "kind": "audit.tool_call",
        "source": "audit",
        "correlation_id": correlation_id,
        "request_id": entry.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": string_field(entry.get("args"), "task_id"),
        "tool": null_if_empty(tool),
        "action": null_if_empty(action),
        "status": status,
        "summary": truncate_summary(&format!("{} action '{}' audit status {}", tool, action, status)),
        "data_classification": "local-sensitive-redacted",
        "details": {
            "purpose_present": entry.get("purpose").is_some_and(|value| !value.is_null()),
            "argument_keys": object_keys(entry.get("args").unwrap_or(&Value::Null)),
            "artifacts": artifacts,
            "integrity": safe_integrity_ref(entry.get("integrity").unwrap_or(&Value::Null)),
            "error_present": entry.get("error").is_some_and(|value| !value.is_null()),
            "args_included": false,
            "result_payload_included": false
        }
    })
}

fn task_timeline_events() -> (Vec<Value>, Value) {
    let tasks = crate::mcp::tasks::resource_json();
    let task_items = tasks["tasks"].as_array().cloned().unwrap_or_default();
    let mut events = Vec::new();
    for task in &task_items {
        let task_id = task["task_id"]
            .as_str()
            .or_else(|| task["taskId"].as_str())
            .unwrap_or_default();
        if task_id.is_empty() {
            continue;
        }
        let correlation_id = task_correlation_id(task_id).unwrap_or_else(|| task_id.to_string());
        let tool = task["tool"].as_str().unwrap_or_default();
        let action = task["action"].as_str().unwrap_or_default();
        let status = task["status"].as_str().unwrap_or("unknown");
        events.push(json!({
            "ts": task.get("createdAt").or_else(|| task.get("created_at")).cloned().unwrap_or(Value::Null),
            "kind": "task.created",
            "source": "tasks.snapshot",
            "correlation_id": correlation_id,
            "task_id": task_id,
            "tool": null_if_empty(tool),
            "action": null_if_empty(action),
            "status": "created",
            "summary": truncate_summary(&format!("Task {} created", task_id)),
            "data_classification": "local-sensitive-redacted",
            "details": safe_task_details(task)
        }));
        events.push(json!({
            "ts": task.get("lastUpdatedAt").or_else(|| task.get("updated_at")).cloned().unwrap_or(Value::Null),
            "kind": "task.status",
            "source": "tasks.snapshot",
            "correlation_id": task_correlation_id(task_id).unwrap_or_else(|| task_id.to_string()),
            "task_id": task_id,
            "tool": null_if_empty(tool),
            "action": null_if_empty(action),
            "status": status,
            "summary": truncate_summary(task["summary"].as_str().or_else(|| task["statusMessage"].as_str()).unwrap_or("task status updated")),
            "data_classification": "local-sensitive-redacted",
            "details": safe_task_details(task)
        }));
        if task
            .pointer("/progress/current")
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            > 0
        {
            events.push(json!({
                "ts": task.get("lastUpdatedAt").or_else(|| task.get("updated_at")).cloned().unwrap_or(Value::Null),
                "kind": "task.progress",
                "source": "tasks.snapshot",
                "correlation_id": task_correlation_id(task_id).unwrap_or_else(|| task_id.to_string()),
                "task_id": task_id,
                "tool": null_if_empty(tool),
                "action": null_if_empty(action),
                "status": status,
                "summary": truncate_summary("Task progress snapshot"),
                "data_classification": "local-sensitive-redacted",
                "details": safe_task_details(task)
            }));
        }
    }

    (
        events,
        json!({
            "configured": true,
            "mode": tasks.get("persistence").cloned().unwrap_or(Value::Null),
            "count": task_items.len()
        }),
    )
}

fn artifact_timeline_events() -> (Vec<Value>, Value) {
    let registry = crate::artifact::registry_json();
    let artifacts = registry["artifacts"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let events = artifacts
        .iter()
        .filter_map(|artifact| {
            let uri = artifact["uri"].as_str()?;
            Some(json!({
                "ts": artifact.get("last_modified").cloned().unwrap_or(Value::Null),
                "kind": "artifact.registered",
                "source": "artifacts.snapshot",
                "correlation_id": artifact_correlation_id(uri).unwrap_or_else(|| uri.to_string()),
                "artifact_uri": uri,
                "status": "registered",
                "summary": truncate_summary(&format!(
                    "Artifact {} retained",
                    artifact["name"].as_str().unwrap_or("artifact")
                )),
                "data_classification": "artifact-reference",
                "details": {
                    "artifact": safe_artifact_ref(artifact),
                    "path_included": false
                }
            }))
        })
        .collect::<Vec<_>>();
    (
        events,
        json!({
            "configured": true,
            "mode": "process-local-registry",
            "count": artifacts.len(),
            "retention": registry.get("retention").cloned().unwrap_or(Value::Null)
        }),
    )
}

fn safe_task_details(task: &Value) -> Value {
    json!({
        "progress": task.get("progress").cloned().unwrap_or(Value::Null),
        "retry": task.get("retry").cloned().unwrap_or(Value::Null),
        "ttl": task.get("ttl").cloned().unwrap_or(Value::Null),
        "pollInterval": task.get("pollInterval").cloned().unwrap_or(Value::Null),
        "expiresAtEpochSecs": task.get("expiresAtEpochSecs").cloned().unwrap_or(Value::Null),
        "resultRetentionMs": task.get("resultRetentionMs").cloned().unwrap_or(Value::Null),
        "error_present": task.get("error").is_some_and(|value| !value.is_null()),
        "result_payload_included": false
    })
}

fn safe_artifact_ref(artifact: &Value) -> Value {
    json!({
        "kind": artifact.get("kind").cloned().unwrap_or(Value::Null),
        "uri": artifact.get("uri").cloned().unwrap_or(Value::Null),
        "name": artifact.get("name").cloned().unwrap_or(Value::Null),
        "mimeType": artifact.get("mimeType").cloned().unwrap_or(Value::Null),
        "size_bytes": artifact.get("size_bytes").cloned().unwrap_or(Value::Null),
        "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
        "classification": artifact.get("classification").cloned().unwrap_or(json!("artifact-reference")),
        "created_at": artifact.get("created_at").cloned().unwrap_or(Value::Null),
        "last_modified": artifact.get("last_modified").cloned().unwrap_or(Value::Null),
        "expires_at": artifact.get("expires_at").cloned().unwrap_or(Value::Null),
        "retention_secs": artifact.get("retention_secs").cloned().unwrap_or(Value::Null),
        "verified": artifact.get("verified").cloned().unwrap_or(Value::Null),
        "path_included": false
    })
}

fn safe_integrity_ref(integrity: &Value) -> Value {
    json!({
        "algorithm": integrity.get("algorithm").cloned().unwrap_or(Value::Null),
        "result_sha256": integrity.get("result_sha256").cloned().unwrap_or(Value::Null),
        "result_bytes": integrity.get("result_bytes").cloned().unwrap_or(Value::Null)
    })
}

fn sanitize_event(event: Value, profile: crate::redaction::RedactionProfile) -> Value {
    let redacted = crate::redaction::redact_value(&event, profile);
    remove_forbidden_timeline_keys(redacted)
}

fn redact_timeline_details(value: Value) -> Value {
    crate::redaction::redact_value(&value, crate::redaction::RedactionProfile::Strict)
}

fn remove_forbidden_timeline_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "result" | "structuredcontent" | "content" | "progresstoken"
                ) || lower == "progress_token"
                    || lower == "path"
                    || lower.ends_with("_path")
                {
                    continue;
                }
                out.insert(key, remove_forbidden_timeline_keys(child));
            }
            Value::Object(out)
        }
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(remove_forbidden_timeline_keys)
                .collect(),
        ),
        other => other,
    }
}

fn event_matches_filters(event: &Value, filters: &TimelineFilters) -> bool {
    matches_text_filter(event, "correlation_id", filters.correlation_id.as_deref())
        && matches_text_filter(event, "request_id", filters.request_id.as_deref())
        && matches_text_filter(event, "task_id", filters.task_id.as_deref())
        && matches_artifact_filter(event, filters.artifact_uri.as_deref())
        && matches_time_filter(event, filters.since.as_deref(), filters.until.as_deref())
}

fn matches_text_filter(event: &Value, field: &str, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    event
        .get(field)
        .and_then(|value| value.as_str())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn matches_artifact_filter(event: &Value, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    event
        .get("artifact_uri")
        .and_then(|value| value.as_str())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
        || event
            .pointer("/details/artifact/uri")
            .and_then(|value| value.as_str())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
        || event
            .pointer("/details/artifacts")
            .and_then(|value| value.as_array())
            .is_some_and(|artifacts| {
                artifacts.iter().any(|artifact| {
                    artifact
                        .get("uri")
                        .and_then(|value| value.as_str())
                        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                })
            })
}

fn matches_time_filter(event: &Value, since: Option<&str>, until: Option<&str>) -> bool {
    let ts = event
        .get("ts")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if let Some(since) = since {
        if ts < since {
            return false;
        }
    }
    if let Some(until) = until {
        if ts > until {
            return false;
        }
    }
    true
}

fn sort_events(events: &mut [Value]) {
    events.sort_by(|left, right| {
        event_ts(left)
            .cmp(event_ts(right))
            .then_with(|| event_sequence(left).cmp(&event_sequence(right)))
    });
}

fn event_ts(event: &Value) -> &str {
    event
        .get("ts")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
}

fn event_sequence(event: &Value) -> u64 {
    event
        .get("sequence")
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
}

fn audit_path_from_args(args: &Value) -> Option<String> {
    string_field(Some(args), "audit_path").or_else(crate::policy::audit_path)
}

fn safe_path_info(path: &str) -> Value {
    let path = Path::new(path);
    let display = path.display().to_string();
    json!({
        "basename": path.file_name().and_then(|value| value.to_str()).unwrap_or(""),
        "sha256": crate::artifact::sha256_bytes(display.as_bytes()),
        "full_path_included": false
    })
}

pub fn task_correlation_id(task_id: &str) -> Option<String> {
    TASK_CORRELATIONS
        .lock()
        .ok()
        .and_then(|map| map.get(task_id).cloned())
}

fn artifact_correlation_id(uri: &str) -> Option<String> {
    ARTIFACT_CORRELATIONS
        .lock()
        .ok()
        .and_then(|map| map.get(uri).cloned())
}

pub fn artifact_registered_with_correlation(uri: &str, correlation_id: &str) -> bool {
    artifact_correlation_id(uri)
        .as_deref()
        .is_some_and(|current| current == correlation_id)
}

#[cfg(test)]
pub fn clear_artifact_correlation_for_test(uri: &str) {
    if let Ok(mut map) = ARTIFACT_CORRELATIONS.lock() {
        map.remove(uri);
    }
}

fn correlation_id_from_ipc_message(message: &Value) -> Option<String> {
    correlation_id_from_request(message)
        .or_else(|| {
            message
                .pointer("/result/structuredContent/context/request_id")
                .and_then(json_id_to_string)
        })
        .or_else(|| string_field(message.pointer("/result/structuredContent"), "task_id"))
        .or_else(|| {
            string_field(
                message.pointer("/result/_meta/io.modelcontextprotocol~1related-task"),
                "taskId",
            )
        })
        .or_else(|| message.get("id").and_then(json_id_to_string))
}

fn task_id_from_value(value: &Value) -> Option<String> {
    string_field(Some(value), "task_id")
        .or_else(|| string_field(Some(value), "taskId"))
        .or_else(|| string_field(value.pointer("/params"), "taskId"))
        .or_else(|| string_field(value.pointer("/params"), "task_id"))
        .or_else(|| string_field(value.pointer("/params/arguments"), "task_id"))
        .or_else(|| string_field(value.pointer("/result/task"), "taskId"))
        .or_else(|| string_field(value.pointer("/result"), "task_id"))
        .or_else(|| string_field(value.pointer("/result/structuredContent"), "task_id"))
}

fn object_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|object| {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            keys
        })
        .unwrap_or_default()
}

fn null_if_empty(value: &str) -> Value {
    if value.trim().is_empty() {
        Value::Null
    } else {
        json!(value)
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

fn json_id_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn truncate_summary(text: &str) -> String {
    let mut value = text
        .chars()
        .filter(|ch| !ch.is_control() || ch.is_ascii_whitespace())
        .take(MAX_SUMMARY_CHARS)
        .collect::<String>();
    if text.chars().count() > MAX_SUMMARY_CHARS {
        value.push_str("...");
    }
    value
}

impl TimelineFilters {
    fn from_args(args: &Value) -> Self {
        let limit = crate::args::parse_u64_value(args.get("limit"))
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(DEFAULT_TIMELINE_LIMIT)
            .clamp(1, MAX_TIMELINE_LIMIT);
        let redaction = args
            .get("redaction")
            .and_then(|value| value.as_str())
            .and_then(crate::redaction::parse_profile)
            .unwrap_or(crate::redaction::RedactionProfile::Strict);

        Self {
            correlation_id: string_field(Some(args), "correlation_id")
                .or_else(|| string_field(Some(args), "correlationId")),
            request_id: string_field(Some(args), "request_id"),
            task_id: string_field(Some(args), "task_id")
                .or_else(|| string_field(Some(args), "taskId")),
            artifact_uri: string_field(Some(args), "artifact_uri")
                .or_else(|| string_field(Some(args), "uri")),
            since: string_field(Some(args), "since"),
            until: string_field(Some(args), "until"),
            limit,
            redaction,
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "correlation_id": self.correlation_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "artifact_uri": self.artifact_uri,
            "since": self.since,
            "until": self.until,
            "limit": self.limit
        })
    }
}

#[cfg(test)]
pub fn clear_for_test() {
    if let Ok(mut events) = LIVE_EVENTS.lock() {
        events.clear();
    }
    if let Ok(mut map) = TASK_CORRELATIONS.lock() {
        map.clear();
    }
    if let Ok(mut map) = ARTIFACT_CORRELATIONS.lock() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn timeline_links_audit_and_artifacts_without_paths_or_raw_payloads() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_for_test();
        let audit_path = std::env::temp_dir().join(format!(
            "memoric-timeline-audit-{}-{}.jsonl",
            std::process::id(),
            NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let artifact_path = std::env::temp_dir().join(format!(
            "memoric-timeline-artifact-{}-{}.txt",
            std::process::id(),
            NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&artifact_path, "operator local payload").unwrap();
        let artifact = crate::artifact::register_file_artifact_with_correlation(
            &artifact_path,
            60,
            Some("corr-audit"),
        )
        .expect("artifact");
        let uri = artifact["uri"].as_str().unwrap().to_string();
        std::fs::write(
            &audit_path,
            format!(
                "{}\n",
                json!({
                    "ts": "2026-05-22T00:00:01Z",
                    "tool": "memory",
                    "action": "read",
                    "correlation_id": "corr-audit",
                    "request_id": "req-audit",
                    "args": {
                        "pid": 123,
                        "bytes": [1, 2, 3, 4],
                        "output_path": artifact_path.display().to_string()
                    },
                    "result_status": "success",
                    "artifacts": [{
                        "uri": uri,
                        "name": "dump.txt",
                        "path": artifact_path.display().to_string(),
                        "sha256": artifact["sha256"].clone(),
                        "classification": "artifact-reference"
                    }],
                    "integrity": {
                        "algorithm": "sha256",
                        "result_sha256": "abc",
                        "result_bytes": 12
                    }
                })
            ),
        )
        .unwrap();

        let timeline = timeline_json(&json!({
            "audit_path": audit_path.display().to_string(),
            "correlation_id": "corr-audit",
            "redaction": "strict",
            "limit": 20
        }));
        let text = serde_json::to_string(&timeline).unwrap();

        assert_eq!(timeline["success"], true);
        assert!(timeline["events"].as_array().unwrap().iter().any(|event| {
            event["kind"] == "audit.tool_call" && event["correlation_id"] == "corr-audit"
        }));
        assert!(timeline["events"].as_array().unwrap().iter().any(|event| {
            event["kind"] == "artifact.registered" && event["artifact_uri"] == uri
        }));
        assert!(!text.contains(&artifact_path.display().to_string()));
        assert!(!text.contains("progress_token"));
        assert!(!text.contains("operator local payload"));

        let _ = crate::artifact::forget(&uri);
        let _ = std::fs::remove_file(artifact_path);
        let _ = std::fs::remove_file(audit_path);
    }

    #[test]
    fn task_timeline_omits_result_payloads() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_for_test();
        let task_id = crate::mcp::tasks::create_with_options(
            "self",
            "version",
            "queued",
            crate::mcp::tasks::TaskOptions {
                correlation_id: Some("corr-task".to_string()),
                request_context: None,
                ..crate::mcp::tasks::TaskOptions::default()
            },
        )
        .expect("task");
        crate::mcp::tasks::complete(
            &task_id,
            json!({
                "message": "done",
                "token": "super-secret-token",
                "bytes": [1, 2, 3, 4]
            }),
        );

        let timeline = timeline_json(&json!({
            "correlation_id": "corr-task",
            "redaction": "strict",
            "limit": 20
        }));
        let text = serde_json::to_string(&timeline).unwrap();

        assert!(timeline["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| { event["kind"] == "task.created" && event["task_id"] == task_id }));
        assert!(timeline["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| { event["kind"] == "task.completed" && event["task_id"] == task_id }));
        assert!(!text.contains("super-secret-token"));
        assert!(!text.contains("\"result\""));
    }

    #[test]
    fn mcp_and_worker_events_share_request_correlation() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_for_test();
        let request = json!({
            "jsonrpc": "2.0",
            "id": "jsonrpc-1",
            "method": "tools/call",
            "params": {
                "name": "self",
                "arguments": {
                    "action": "version",
                    "request_id": "corr-req"
                },
                "_meta": {
                    "progressToken": "do-not-return"
                }
            }
        });
        record_mcp_request(
            crate::mcp::request_context::McpTransportKind::Stdio,
            &request,
        );
        record_worker_ipc_event("inbound", "request", &request);

        let timeline = timeline_json(&json!({
            "correlation_id": "corr-req",
            "redaction": "strict",
            "limit": 20
        }));
        let text = serde_json::to_string(&timeline).unwrap();

        assert!(timeline["events"].as_array().unwrap().iter().any(|event| {
            event["kind"] == "mcp.request" && event["correlation_id"] == "corr-req"
        }));
        assert!(timeline["events"].as_array().unwrap().iter().any(|event| {
            event["kind"] == "worker.ipc" && event["correlation_id"] == "corr-req"
        }));
        assert!(!text.contains("do-not-return"));
        assert!(!text.contains("progressToken"));
    }
}

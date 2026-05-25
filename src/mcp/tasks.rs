//! Lightweight in-memory MCP task registry.
//!
//! This is the foundation for MCP Tasks support. The first implementation is
//! process-local and suitable for polling task records created by the current
//! server/worker process.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::{Duration, Instant};

lazy_static! {
    static ref TASKS: Mutex<Vec<TaskRecord>> =
        Mutex::new(load_persisted_task_records().unwrap_or_else(|err| {
            tracing::warn!("failed to load persisted task registry: {}", err);
            Vec::new()
        }));
    static ref NOTIFICATION_SENDER: Mutex<Option<Sender<Value>>> = Mutex::new(None);
    static ref PROGRESS_NOTIFICATION_STATE: Mutex<HashMap<String, ProgressNotificationState>> =
        Mutex::new(HashMap::new());
}
static NEXT_TASK_SEQ: AtomicU64 = AtomicU64::new(1);

pub const TASKS_PATH_ENV: &str = "MEMORIC_TASKS_PATH";
const TASK_SNAPSHOT_VERSION: u32 = 1;
pub const DEFAULT_TASK_TTL_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_RESULT_RETENTION_MS: u64 = 15 * 60 * 1000;
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;
pub const DEFAULT_RESULT_WAIT_MS: u64 = 5 * 1000;
pub const MAX_RESULT_WAIT_MS: u64 = 30 * 1000;
pub const DEFAULT_TASK_LIST_LIMIT: usize = 100;
pub const MAX_TASK_LIST_LIMIT: usize = 500;
pub const PROGRESS_NOTIFICATION_MIN_INTERVAL_MS: u64 = 250;
const TASK_CURSOR_PREFIX: &str = "task-cursor:";

#[derive(Debug, Clone)]
struct ProgressNotificationState {
    last_sent_at: Instant,
    last_progress: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Working,
    InputRequired,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::InputRequired => "input_required",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task_id: String,
    pub tool: String,
    pub action: String,
    pub status: TaskStatus,
    pub created_at: String,
    pub updated_at: String,
    pub created_at_epoch_secs: u64,
    pub updated_at_epoch_secs: u64,
    pub ttl_ms: Option<u64>,
    pub poll_interval_ms: Option<u64>,
    pub result_retention_ms: Option<u64>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub progress_current: u64,
    pub progress_total: Option<u64>,
    pub progress_token: Option<Value>,
    pub summary: String,
    #[serde(default)]
    pub input_requests: Vec<InputRequestRecord>,
    #[serde(default)]
    pub input_responses: Vec<InputResponseRecord>,
    #[serde(default)]
    pub request_state: Option<Value>,
    #[serde(default)]
    pub visibility: TaskVisibility,
    pub result: Option<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TaskVisibility {
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub app_origin: Option<String>,
    #[serde(default)]
    pub policy_origin: Option<String>,
    #[serde(default)]
    pub request_id: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputRequestRecord {
    pub request_id: String,
    pub prompt: String,
    pub mode: String,
    pub schema: Value,
    pub created_at: String,
    pub created_at_epoch_secs: u64,
    pub responded: bool,
    pub response_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputResponseRecord {
    pub response_id: String,
    pub request_id: String,
    pub submitted_at: String,
    pub submitted_at_epoch_secs: u64,
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaskSnapshotFile {
    version: u32,
    generated_at: String,
    generated_at_epoch_secs: u64,
    records: Vec<PersistedTaskRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTaskRecord {
    task_id: String,
    tool: String,
    action: String,
    status: String,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    created_at_epoch_secs: u64,
    #[serde(default)]
    updated_at_epoch_secs: u64,
    ttl_ms: Option<u64>,
    poll_interval_ms: Option<u64>,
    result_retention_ms: Option<u64>,
    #[serde(default)]
    retry_count: u32,
    #[serde(default)]
    max_retries: u32,
    progress_current: u64,
    progress_total: Option<u64>,
    summary: String,
    #[serde(default)]
    input_requests: Vec<InputRequestRecord>,
    #[serde(default)]
    input_responses: Vec<InputResponseRecord>,
    #[serde(default)]
    request_state: Option<Value>,
    #[serde(default)]
    visibility: TaskVisibility,
    error: Option<String>,
    artifacts: Vec<Value>,
    integrity: Value,
    snapshot_epoch_secs: u64,
}

pub fn create(tool: &str, action: &str, summary: impl Into<String>) -> Result<String, String> {
    create_with_options(tool, action, summary, TaskOptions::default())
}

#[derive(Debug, Clone)]
pub struct TaskOptions {
    pub ttl_ms: Option<u64>,
    pub result_retention_ms: Option<u64>,
    pub max_retries: u32,
    pub progress_token: Option<Value>,
    pub correlation_id: Option<String>,
    pub request_context: Option<crate::mcp::request_context::McpRequestContext>,
    pub input_required_on_policy: bool,
}

impl Default for TaskOptions {
    fn default() -> Self {
        Self {
            ttl_ms: Some(DEFAULT_TASK_TTL_MS),
            result_retention_ms: Some(DEFAULT_RESULT_RETENTION_MS),
            max_retries: 0,
            progress_token: None,
            correlation_id: None,
            request_context: None,
            input_required_on_policy: false,
        }
    }
}

pub fn create_with_options(
    tool: &str,
    action: &str,
    summary: impl Into<String>,
    options: TaskOptions,
) -> Result<String, String> {
    let now = crate::state::chrono_now_public();
    let now_epoch = current_epoch_secs();
    let seq = NEXT_TASK_SEQ.fetch_add(1, Ordering::Relaxed);
    let visibility = options
        .request_context
        .as_ref()
        .map(task_visibility_from_context)
        .unwrap_or_default();
    let task_id = format!(
        "task-{}-{}-{}",
        std::process::id(),
        now.replace([':', '-'], "")
            .replace('T', "-")
            .replace('Z', ""),
        seq
    );
    let record = TaskRecord {
        task_id: task_id.clone(),
        tool: tool.to_string(),
        action: action.to_string(),
        status: TaskStatus::Working,
        created_at: now.clone(),
        updated_at: now,
        created_at_epoch_secs: now_epoch,
        updated_at_epoch_secs: now_epoch,
        ttl_ms: options.ttl_ms,
        poll_interval_ms: Some(DEFAULT_POLL_INTERVAL_MS),
        result_retention_ms: options.result_retention_ms,
        retry_count: 0,
        max_retries: options.max_retries,
        progress_current: 0,
        progress_total: None,
        progress_token: options.progress_token,
        summary: summary.into(),
        input_requests: Vec::new(),
        input_responses: Vec::new(),
        request_state: None,
        visibility,
        result: None,
        error: None,
    };

    with_tasks(|tasks| tasks.push(record))?;
    if let Some(correlation_id) = options.correlation_id.as_deref() {
        crate::observability::link_task(&task_id, correlation_id);
    }
    if let Ok(task) = task_record(&task_id) {
        crate::observability::record_task_event(
            "task.created",
            &task,
            json!({
                "ttl_ms": task.ttl_ms,
                "result_retention_ms": task.result_retention_ms,
                "correlation_id": options.correlation_id
            }),
        );
    }
    Ok(task_id)
}

pub fn mark_running(task_id: &str, total: Option<u64>, summary: impl Into<String>) {
    let summary = summary.into();
    let notifications = with_task(task_id, |task| {
        let previous_status = match transition_task_status(
            task,
            TaskStatus::Working,
            crate::state::chrono_now_public(),
            current_epoch_secs(),
        ) {
            Ok(previous_status) => previous_status,
            Err(_) => return Vec::new(),
        };
        task.progress_total = total;
        task.summary = summary;
        crate::observability::record_task_event(
            "task.running",
            task,
            json!({
                "progress_total": total
            }),
        );
        status_notification_if_changed(task, previous_status)
    })
    .unwrap_or_default();
    emit_notifications(notifications);
}

pub fn update_progress(
    task_id: &str,
    current: u64,
    total: Option<u64>,
    summary: impl Into<String>,
) {
    let summary = summary.into();
    let notifications = with_task(task_id, |task| {
        if task.status.is_terminal() {
            return Vec::new();
        }
        let previous_current = task.progress_current;
        task.progress_current = current;
        if total.is_some() {
            task.progress_total = total;
        }
        task.summary = summary;
        task.updated_at = crate::state::chrono_now_public();
        task.updated_at_epoch_secs = current_epoch_secs();
        crate::observability::record_task_event(
            "task.progress",
            task,
            json!({
                "previous_current": previous_current,
                "current": current,
                "total": task.progress_total,
                "notification_available": task.progress_token.is_some()
            }),
        );
        progress_notification_if_advanced(task, previous_current, false)
            .into_iter()
            .collect()
    })
    .unwrap_or_default();
    emit_notifications(notifications);
}

pub fn mark_input_required(
    task_id: &str,
    request_id: impl Into<String>,
    prompt: impl Into<String>,
    mode: impl Into<String>,
    schema: Value,
    request_state: Option<Value>,
) -> Result<Value, String> {
    let request_id = request_id.into();
    if request_id.trim().is_empty() {
        return Err("Missing input_request_id".to_string());
    }
    let prompt = prompt.into();
    if prompt.trim().is_empty() {
        return Err("Missing input prompt".to_string());
    }
    let mode = mode.into();
    let now = crate::state::chrono_now_public();
    let now_epoch_secs = current_epoch_secs();
    let (task, notifications) = with_task(task_id, |task| {
        if task.status.is_terminal() {
            return Err(format!(
                "Cannot request input for terminal task status '{}'",
                task.status.as_str()
            ));
        }
        if task
            .input_requests
            .iter()
            .any(|request| request.request_id == request_id)
        {
            return Err(format!(
                "input request '{}' already exists for task {}",
                request_id, task_id
            ));
        }

        let previous_status =
            transition_task_status(task, TaskStatus::InputRequired, now.clone(), now_epoch_secs)?;
        task.summary = prompt.clone();
        task.request_state = request_state.clone();
        task.input_requests.push(InputRequestRecord {
            request_id: request_id.clone(),
            prompt: prompt.clone(),
            mode: normalize_input_mode(&mode),
            schema: normalize_input_schema(schema.clone()),
            created_at: now.clone(),
            created_at_epoch_secs: now_epoch_secs,
            responded: false,
            response_id: None,
        });
        crate::observability::record_task_event(
            "task.input_required",
            task,
            json!({
                "request_id": request_id,
                "mode": mode,
                "request_state_present": task.request_state.is_some()
            }),
        );
        Ok((
            task_to_json(task.clone()),
            status_notification_if_changed(task, previous_status),
        ))
    })??;
    emit_notifications(notifications);
    Ok(task)
}

pub fn complete(task_id: &str, result: Value) {
    let summary = result
        .get("summary")
        .and_then(|v| v.as_str())
        .or_else(|| result.get("message").and_then(|v| v.as_str()))
        .unwrap_or("task completed")
        .to_string();
    let notifications = with_task(task_id, |task| {
        if task.status.is_terminal() {
            return Vec::new();
        }
        let previous_status = match transition_task_status(
            task,
            TaskStatus::Completed,
            crate::state::chrono_now_public(),
            current_epoch_secs(),
        ) {
            Ok(previous_status) => previous_status,
            Err(_) => return Vec::new(),
        };
        let previous_current = task.progress_current;
        task.progress_current = task.progress_total.unwrap_or(task.progress_current.max(1));
        task.summary = summary;
        let artifacts = crate::artifact::collect_artifact_references(&result);
        for artifact in &artifacts {
            if let Some(uri) = artifact["uri"].as_str() {
                crate::observability::link_artifact(uri, &task.task_id);
            }
        }
        task.result = Some(result);
        crate::observability::record_task_event(
            "task.completed",
            task,
            json!({
                "artifacts": artifacts,
                "result_payload_included": false
            }),
        );
        let mut notifications = Vec::new();
        notifications.extend(progress_notification_if_advanced(
            task,
            previous_current,
            true,
        ));
        notifications.extend(status_notification_if_changed(task, previous_status));
        notifications
    })
    .unwrap_or_default();
    emit_notifications(notifications);
}

pub fn fail(task_id: &str, error: impl Into<String>) {
    fail_with_result(task_id, error, None)
}

pub fn fail_with_result(task_id: &str, error: impl Into<String>, result: Option<Value>) {
    let error = error.into();
    let notifications = with_task(task_id, |task| {
        if task.status.is_terminal() {
            return Vec::new();
        }
        let previous_status = match transition_task_status(
            task,
            TaskStatus::Failed,
            crate::state::chrono_now_public(),
            current_epoch_secs(),
        ) {
            Ok(previous_status) => previous_status,
            Err(_) => return Vec::new(),
        };
        task.summary = error.clone();
        task.result = result;
        task.error = Some(error);
        crate::observability::record_task_event(
            "task.failed",
            task,
            json!({
                "error_present": true,
                "result_payload_included": false
            }),
        );
        status_notification_if_changed(task, previous_status)
    })
    .unwrap_or_default();
    emit_notifications(notifications);
}

pub fn mark_cancelled(task_id: &str, summary: impl Into<String>) {
    let summary = summary.into();
    let notifications = with_task(task_id, |task| {
        let previous_status = match transition_task_status(
            task,
            TaskStatus::Cancelled,
            crate::state::chrono_now_public(),
            current_epoch_secs(),
        ) {
            Ok(previous_status) => previous_status,
            Err(_) => return Vec::new(),
        };
        task.summary = summary;
        crate::observability::record_task_event(
            "task.cancelled",
            task,
            json!({
                "requested": true
            }),
        );
        status_notification_if_changed(task, previous_status)
    })
    .unwrap_or_default();
    emit_notifications(notifications);
}

pub fn is_cancel_requested(task_id: &str) -> bool {
    TASKS
        .lock()
        .ok()
        .and_then(|tasks| {
            tasks
                .iter()
                .find(|task| task.task_id == task_id)
                .map(|task| matches!(task.status, TaskStatus::Cancelled))
        })
        .unwrap_or(false)
}

pub fn cancel(task_id: &str) -> Result<Value, String> {
    let (result, notifications) = with_task(task_id, |task| {
        if task.status.is_terminal() {
            return Err(format!(
                "Cannot cancel task: already in terminal status '{}'",
                task.status.as_str()
            ));
        }

        let previous_status = transition_task_status(
            task,
            TaskStatus::Cancelled,
            crate::state::chrono_now_public(),
            current_epoch_secs(),
        )?;
        task.summary = "The task was cancelled by request.".to_string();
        task.error = Some("cancelled by request".to_string());
        crate::observability::record_task_event(
            "task.cancelled",
            task,
            json!({
                "requested": true,
                "error_present": true
            }),
        );
        Ok((
            task_to_json(task.clone()),
            status_notification_if_changed(task, previous_status),
        ))
    })??;
    emit_notifications(notifications);
    Ok(result)
}

pub fn spawn_tool_task(tool: &str, args: &Value) -> Result<String, String> {
    spawn_tool_task_with_options(tool, args, TaskOptions::default())
}

pub fn spawn_tool_task_with_options(
    tool: &str,
    args: &Value,
    options: TaskOptions,
) -> Result<String, String> {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if options.input_required_on_policy {
        if let Some(task_id) =
            crate::mcp::consent::maybe_create_input_required_task(tool, args, options.clone())?
        {
            return Ok(task_id);
        }
    }
    ensure_background_eligible(tool, &action, args)?;
    let correlation_id = crate::observability::correlation_id_from_args(args);
    let request_context = options
        .request_context
        .clone()
        .or_else(crate::mcp::request_context::current_request_context);
    let task_id = create_with_options(
        tool,
        &action,
        format!("{} action='{}' queued", tool, action),
        TaskOptions {
            correlation_id,
            request_context: request_context.clone(),
            ..options
        },
    )?;
    mark_running(&task_id, None, "running in background");

    let tool_name = tool.to_string();
    let task_args = inject_task_id(args.clone(), &task_id);
    let task_id_for_thread = task_id.clone();
    std::thread::Builder::new()
        .name(format!("memoric-task-{}", task_id))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(context) = request_context.clone() {
                    crate::mcp::request_context::with_current_request_context(context, || {
                        crate::mcp::tool_call::call_tool(&tool_name, task_args.clone())
                    })
                } else {
                    crate::mcp::tool_call::call_tool(&tool_name, task_args.clone())
                }
            }));

            match result {
                Ok(Ok(value)) => {
                    if is_cancel_requested(&task_id_for_thread) {
                        mark_cancelled(
                            &task_id_for_thread,
                            "task cancelled after completion boundary",
                        );
                    } else {
                        complete(
                            &task_id_for_thread,
                            crate::mcp::protocol::tool_success_content(
                                &tool_name, &task_args, &value,
                            ),
                        );
                    }
                }
                Ok(Err(error)) => {
                    let result =
                        crate::mcp::protocol::tool_error_content(&tool_name, &task_args, &error);
                    if crate::error::classify_tool_error(&error).code == "cancelled" {
                        mark_cancelled(&task_id_for_thread, error);
                    } else {
                        fail_with_result(&task_id_for_thread, error, Some(result));
                    }
                }
                Err(panic_info) => {
                    let panic_msg = if let Some(text) = panic_info.downcast_ref::<String>() {
                        text.clone()
                    } else if let Some(text) = panic_info.downcast_ref::<&str>() {
                        text.to_string()
                    } else {
                        "Unknown panic".to_string()
                    };
                    fail(
                        &task_id_for_thread,
                        format!("Tool '{}' panicked: {}", tool_name, panic_msg),
                    );
                }
            }
        })
        .map_err(|err| format!("failed to spawn task thread: {}", err))?;

    Ok(task_id)
}

fn ensure_background_eligible(tool: &str, action: &str, args: &Value) -> Result<(), String> {
    let dry_run = args
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let traits = crate::mcp::action_registry::classify_action(tool, action);
    if traits.state_changing && !dry_run {
        return Err(format!(
            "as_task background execution currently requires read-only action metadata or dry_run=true; {}(action='{}') is state-changing",
            tool, action
        ));
    }
    Ok(())
}

pub fn task_create_result(task_id: &str) -> Value {
    let task = get_task_json(task_id).unwrap_or_else(|err| {
        json!({
            "taskId": task_id,
            "status": "failed",
            "statusMessage": err,
            "createdAt": crate::state::chrono_now_public(),
            "lastUpdatedAt": crate::state::chrono_now_public(),
            "ttl": DEFAULT_TASK_TTL_MS,
            "pollInterval": DEFAULT_POLL_INTERVAL_MS
        })
    });
    json!({
        "task": task,
        "_meta": crate::mcp::meta::task_model_immediate_response(task_id)
    })
}

pub fn task_accepted_content(tool: &str, args: &Value, task_id: &str) -> Value {
    let task = get_task_json(task_id).unwrap_or_else(|_| json!({}));
    crate::mcp::protocol::tool_success_content(
        "tasks",
        &json!({
            "action": "get",
            "task_id": task_id,
            "source_tool": tool,
            "source_action": args.get("action").cloned().unwrap_or(json!(null))
        }),
        &json!({
            "success": true,
            "task_id": task_id,
            "taskId": task_id,
            "status": "working",
            "task": task,
            "message": "Task accepted for background execution"
        }),
    )
}

pub fn task_options_from_request(request: &Value) -> TaskOptions {
    let request_context = crate::mcp::request_context::current_request_context().or_else(|| {
        Some(
            crate::mcp::request_context::McpRequestContext::from_request(
                request,
                crate::mcp::request_context::McpTransportKind::Unknown("task-options".to_string()),
            ),
        )
    });
    let ttl_ms = request
        .get("params")
        .and_then(|params| params.get("task"))
        .and_then(|task| task.get("ttl"))
        .and_then(|value| value.as_u64())
        .or(Some(DEFAULT_TASK_TTL_MS));
    let result_retention_ms = request
        .get("params")
        .and_then(|params| params.get("task"))
        .and_then(|task| {
            task.get("resultRetentionMs")
                .or_else(|| task.get("result_retention_ms"))
        })
        .and_then(|value| value.as_u64())
        .or(Some(DEFAULT_RESULT_RETENTION_MS));
    let max_retries = request
        .get("params")
        .and_then(|params| params.get("task"))
        .and_then(|task| task.get("maxRetries").or_else(|| task.get("max_retries")))
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0);
    let progress_token = crate::mcp::request_context::progress_token_from_request(request);
    let correlation_id = crate::observability::correlation_id_from_request(request);

    TaskOptions {
        ttl_ms,
        result_retention_ms,
        max_retries,
        progress_token,
        correlation_id,
        request_context,
        input_required_on_policy: true,
    }
}

pub fn is_task_augmented_request(request: &Value) -> bool {
    request
        .get("params")
        .and_then(|params| params.get("task"))
        .is_some()
}

pub fn cancel_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params").unwrap_or(request);
    let task_id = params
        .get("taskId")
        .or_else(|| params.get("task_id"))
        .or_else(|| params.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing task_id".to_string())?;
    cancel(task_id)
}

pub fn input_response_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params").unwrap_or(request);
    let task_id = parse_task_id(params)?;
    let request_id = parse_input_request_id(params)?;
    let input = params
        .get("input")
        .or_else(|| params.get("response"))
        .or_else(|| params.get("value"))
        .cloned()
        .ok_or_else(|| "Missing input response".to_string())?;
    apply_input_response(task_id, request_id, input)
}

pub fn update_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params").unwrap_or(request);
    let kind = params
        .get("kind")
        .or_else(|| params.get("type"))
        .or_else(|| params.get("updateType"))
        .and_then(|value| value.as_str())
        .unwrap_or("input_response");
    match kind {
        "input_response" | "inputResponse" | "input" => input_response_request(request),
        _ => Err(format!("Invalid tasks/update kind '{}'", kind)),
    }
}

pub fn list_json(limit: usize) -> Value {
    let _ = cleanup_expired_tasks();
    list_page(limit, None).unwrap_or_else(|err| {
        json!({
            "success": false,
            "code": "invalid_param",
            "error": err
        })
    })
}

pub fn list_page(limit: usize, cursor: Option<&str>) -> Result<Value, String> {
    cleanup_expired_tasks()?;
    let limit = limit.clamp(1, MAX_TASK_LIST_LIMIT);
    let start = decode_cursor(cursor)?;
    let visibility_scope = current_visibility_scope();
    match TASKS.lock() {
        Ok(tasks) => {
            let mut records = tasks
                .iter()
                .filter(|task| task_visible_to_scope(task, visibility_scope.as_ref()))
                .cloned()
                .collect::<Vec<_>>();
            records.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| b.task_id.cmp(&a.task_id))
            });
            if start > records.len() {
                return Err("Invalid cursor: pagination position is outside task list".to_string());
            }

            let total = records.len();
            let page = records
                .into_iter()
                .skip(start)
                .take(limit)
                .map(task_to_json)
                .collect::<Vec<_>>();
            let mut response = json!({
                "success": true,
                "count": page.len(),
                "tasks": page,
                "visibility": visibility_scope_json(visibility_scope.as_ref())
            });
            let next_offset = start.saturating_add(limit);
            if next_offset < total {
                response["nextCursor"] = json!(encode_cursor(next_offset));
            }
            Ok(response)
        }
        Err(err) => Err(format!("Task registry lock error: {}", err)),
    }
}

pub fn get_json(task_id: &str) -> Value {
    let _ = cleanup_expired_tasks();
    get_task_json(task_id)
        .map(|task| {
            json!({
                "success": true,
                "task": task
            })
        })
        .unwrap_or_else(|err| {
            json!({
                "success": false,
                "code": "not_found",
                "error": err
            })
        })
}

fn get_task_json(task_id: &str) -> Result<Value, String> {
    cleanup_expired_tasks()?;
    match TASKS.lock() {
        Ok(tasks) => tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .map(|task| task_to_json(task.clone()))
            .ok_or_else(|| format!("task not found: {}", task_id)),
        Err(err) => Err(format!("Task registry lock error: {}", err)),
    }
}

fn apply_input_response(task_id: &str, request_id: &str, input: Value) -> Result<Value, String> {
    let now = crate::state::chrono_now_public();
    let now_epoch_secs = current_epoch_secs();
    let response_id = format!(
        "input-response-{}-{}",
        now_epoch_secs,
        NEXT_TASK_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let input_for_resume = input.clone();
    let (result, notifications, response_id_for_resume) = with_task(task_id, |task| {
        if task.status.is_terminal() {
            return Err(format!(
                "Cannot submit input for terminal task status '{}'",
                task.status.as_str()
            ));
        }
        if task.status != TaskStatus::InputRequired {
            return Err(format!(
                "Task {} is not waiting for input; current status is '{}'",
                task_id,
                task.status.as_str()
            ));
        }
        let request_index = task
            .input_requests
            .iter()
            .position(|request| request.request_id == request_id)
            .ok_or_else(|| {
                format!(
                    "input request '{}' not found for task {}",
                    request_id, task_id
                )
            })?;
        if task.input_requests[request_index].responded {
            return Err(format!(
                "input request '{}' already has a response",
                request_id
            ));
        }

        task.input_requests[request_index].responded = true;
        task.input_requests[request_index].response_id = Some(response_id.clone());
        task.input_responses.push(InputResponseRecord {
            response_id: response_id.clone(),
            request_id: request_id.to_string(),
            submitted_at: now.clone(),
            submitted_at_epoch_secs: now_epoch_secs,
            input,
        });
        let previous_status =
            transition_task_status(task, TaskStatus::Working, now.clone(), now_epoch_secs)?;
        task.summary = format!("Input response accepted for request '{}'", request_id);
        task.request_state = Some(json!({
            "state": "input_received",
            "requestId": request_id,
            "responseId": response_id,
            "updatedAt": now
        }));
        crate::observability::record_task_event(
            "task.input_response",
            task,
            json!({
                "request_id": request_id,
                "response_id": response_id,
                "input_payload_included": false
            }),
        );
        Ok((
            json!({
                "success": true,
                "task": task_to_json(task.clone()),
                "taskId": task.task_id,
                "requestId": request_id,
                "responseId": response_id,
                "status": task.status.as_str()
            }),
            status_notification_if_changed(task, previous_status),
            response_id.clone(),
        ))
    })??;
    emit_notifications(notifications);
    crate::mcp::consent::resume_after_input_response(
        task_id,
        request_id,
        &input_for_resume,
        &response_id_for_resume,
    )?;
    Ok(result)
}

pub fn get_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params").unwrap_or(request);
    let task_id = params
        .get("taskId")
        .or_else(|| params.get("task_id"))
        .or_else(|| params.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing task_id".to_string())?;
    get_task_json(task_id)
}

pub fn result_request(request: &Value) -> Result<Value, String> {
    cleanup_expired_tasks()?;
    let params = request.get("params").unwrap_or(request);
    let task_id = params
        .get("taskId")
        .or_else(|| params.get("task_id"))
        .or_else(|| params.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing task_id".to_string())?;
    let wait_ms = params
        .get("wait_ms")
        .or_else(|| params.get("timeout_ms"))
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_RESULT_WAIT_MS)
        .min(MAX_RESULT_WAIT_MS);
    let deadline = Instant::now() + Duration::from_millis(wait_ms);

    loop {
        let snapshot = task_record(task_id)?;
        match snapshot.status {
            TaskStatus::Completed | TaskStatus::Failed => {
                let result = snapshot.result.ok_or_else(|| {
                    format!(
                        "Task {} reached terminal status '{}' without a result payload",
                        task_id,
                        snapshot.status.as_str()
                    )
                })?;
                return Ok(attach_related_task_meta(result, task_id));
            }
            TaskStatus::Cancelled => {
                return Err(format!("Task {} was cancelled", task_id));
            }
            TaskStatus::InputRequired => {
                return Ok(input_required_result(&snapshot));
            }
            TaskStatus::Working => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "Task {} result is not ready; current status is '{}'",
                        task_id,
                        snapshot.status.as_str()
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

pub fn list_request(request: &Value) -> Result<Value, String> {
    let params = request.get("params");
    let limit = parse_list_limit(params)?;
    let cursor = match params.and_then(|params| params.get("cursor")) {
        Some(Value::String(cursor)) => Some(cursor.as_str()),
        Some(_) => return Err("Invalid cursor: expected opaque string token".to_string()),
        None => None,
    };
    list_page(limit, cursor)
}

pub fn resource_json() -> Value {
    let mut value = list_json(DEFAULT_TASK_LIST_LIMIT);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("persistence".to_string(), persistence_status_json());
    }
    value
}

pub fn set_notification_sender(sender: Option<Sender<Value>>) {
    if let Ok(mut slot) = NOTIFICATION_SENDER.lock() {
        *slot = sender;
    }
}

fn persistence_status_json() -> Value {
    match task_snapshot_path() {
        Some(path) => json!({
            "configured": true,
            "path": path,
            "mode": "snapshot-metadata-only",
            "result_payloads_persisted": false
        }),
        None => json!({
            "configured": false,
            "mode": "process-local"
        }),
    }
}

fn task_snapshot_path() -> Option<String> {
    std::env::var(TASKS_PATH_ENV)
        .ok()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
}

fn inject_task_id(mut args: Value, task_id: &str) -> Value {
    if let Some(obj) = args.as_object_mut() {
        obj.insert("task_id".to_string(), json!(task_id));
        obj.insert("as_task".to_string(), json!(false));
    }
    args
}

fn task_record(task_id: &str) -> Result<TaskRecord, String> {
    TASKS
        .lock()
        .map_err(|err| format!("Task registry lock error: {}", err))?
        .iter()
        .find(|task| task.task_id == task_id)
        .cloned()
        .ok_or_else(|| format!("task not found: {}", task_id))
}

fn parse_task_id(params: &Value) -> Result<&str, String> {
    params
        .get("taskId")
        .or_else(|| params.get("task_id"))
        .or_else(|| params.get("id"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Missing task_id".to_string())
}

fn parse_input_request_id(params: &Value) -> Result<&str, String> {
    params
        .get("requestId")
        .or_else(|| params.get("request_id"))
        .or_else(|| params.get("inputRequestId"))
        .or_else(|| params.get("input_request_id"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Missing input_request_id".to_string())
}

fn normalize_input_mode(mode: &str) -> String {
    match mode.trim() {
        "url" => "url".to_string(),
        "form" | "" => "form".to_string(),
        other => other.to_string(),
    }
}

fn normalize_input_schema(schema: Value) -> Value {
    if schema.is_object() {
        schema
    } else {
        json!({
            "type": "object",
            "additionalProperties": true
        })
    }
}

fn parse_list_limit(params: Option<&Value>) -> Result<usize, String> {
    match params.and_then(|params| params.get("limit")) {
        Some(value) => {
            let raw = value
                .as_u64()
                .ok_or_else(|| "Invalid limit: expected positive integer".to_string())?;
            let limit = usize::try_from(raw).map_err(|_| "Invalid limit: too large".to_string())?;
            Ok(limit.clamp(1, MAX_TASK_LIST_LIMIT))
        }
        None => Ok(DEFAULT_TASK_LIST_LIMIT),
    }
}

fn encode_cursor(offset: usize) -> String {
    format!("{}{}", TASK_CURSOR_PREFIX, offset)
}

fn decode_cursor(cursor: Option<&str>) -> Result<usize, String> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let raw = cursor
        .strip_prefix(TASK_CURSOR_PREFIX)
        .ok_or_else(|| "Invalid cursor: unrecognized opaque token".to_string())?;
    if raw.is_empty() {
        return Err("Invalid cursor: empty pagination position".to_string());
    }
    raw.parse::<usize>()
        .map_err(|_| "Invalid cursor: malformed pagination position".to_string())
}

fn load_persisted_task_records() -> Result<Vec<TaskRecord>, String> {
    let Some(path) = task_snapshot_path() else {
        return Ok(Vec::new());
    };
    load_persisted_task_records_from_path(Path::new(&path))
}

fn load_persisted_task_records_from_path(path: &Path) -> Result<Vec<TaskRecord>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content =
        std::fs::read_to_string(path).map_err(|err| format!("read {}: {}", path.display(), err))?;
    let snapshot: TaskSnapshotFile = serde_json::from_str(&content)
        .map_err(|err| format!("parse {}: {}", path.display(), err))?;
    if snapshot.version != TASK_SNAPSHOT_VERSION {
        return Err(format!(
            "unsupported task snapshot version {} in {}",
            snapshot.version,
            path.display()
        ));
    }

    Ok(snapshot
        .records
        .into_iter()
        .map(task_from_persisted_record)
        .collect())
}

fn persist_task_records(tasks: &[TaskRecord]) {
    let Some(path) = task_snapshot_path() else {
        return;
    };
    if let Err(err) = write_task_snapshot_to_path(Path::new(&path), tasks) {
        tracing::warn!("failed to persist task registry {}: {}", path, err);
    }
}

fn write_task_snapshot_to_path(path: &Path, tasks: &[TaskRecord]) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create {}: {}", parent.display(), err))?;
    }

    let now_epoch = current_epoch_secs();
    let snapshot = TaskSnapshotFile {
        version: TASK_SNAPSHOT_VERSION,
        generated_at: crate::state::chrono_now_public(),
        generated_at_epoch_secs: now_epoch,
        records: tasks
            .iter()
            .map(|task| persisted_record_from_task(task, now_epoch))
            .collect(),
    };
    let content = serde_json::to_string_pretty(&snapshot)
        .map_err(|err| format!("serialize task snapshot: {}", err))?;
    std::fs::write(path, content).map_err(|err| format!("write {}: {}", path.display(), err))
}

fn persisted_record_from_task(task: &TaskRecord, snapshot_epoch_secs: u64) -> PersistedTaskRecord {
    let artifacts = task
        .result
        .as_ref()
        .map(crate::artifact::collect_artifacts)
        .unwrap_or_default();
    let integrity = task
        .result
        .as_ref()
        .map(crate::artifact::json_integrity)
        .unwrap_or(Value::Null);

    PersistedTaskRecord {
        task_id: task.task_id.clone(),
        tool: task.tool.clone(),
        action: task.action.clone(),
        status: task.status.as_str().to_string(),
        created_at: task.created_at.clone(),
        updated_at: task.updated_at.clone(),
        created_at_epoch_secs: task.created_at_epoch_secs,
        updated_at_epoch_secs: task.updated_at_epoch_secs,
        ttl_ms: task.ttl_ms,
        poll_interval_ms: task.poll_interval_ms,
        result_retention_ms: task.result_retention_ms,
        retry_count: task.retry_count,
        max_retries: task.max_retries,
        progress_current: task.progress_current,
        progress_total: task.progress_total,
        summary: truncate_snapshot_text(&task.summary),
        input_requests: task
            .input_requests
            .iter()
            .map(safe_input_request_snapshot)
            .collect(),
        input_responses: task
            .input_responses
            .iter()
            .map(safe_input_response_snapshot)
            .collect(),
        request_state: task.request_state.as_ref().map(safe_request_state_snapshot),
        visibility: task.visibility.clone(),
        error: task.error.as_deref().map(truncate_snapshot_text),
        artifacts,
        integrity,
        snapshot_epoch_secs,
    }
}

fn safe_input_request_snapshot(request: &InputRequestRecord) -> InputRequestRecord {
    let mut request = request.clone();
    request.prompt = truncate_snapshot_text(&request.prompt);
    request.schema = safe_schema_snapshot(&request.schema);
    request
}

fn safe_input_response_snapshot(response: &InputResponseRecord) -> InputResponseRecord {
    let mut response = response.clone();
    response.input = json!({
        "persisted": false,
        "omitted": "input payload omitted from task metadata snapshot"
    });
    response
}

fn safe_request_state_snapshot(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(text) => json!(truncate_snapshot_text(text)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .take(16)
                .map(safe_request_state_snapshot)
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .take(32)
                .map(|(key, value)| (key.clone(), safe_request_state_snapshot(value)))
                .collect(),
        ),
    }
}

fn safe_schema_snapshot(schema: &Value) -> Value {
    safe_request_state_snapshot(schema)
}

fn task_from_persisted_record(record: PersistedTaskRecord) -> TaskRecord {
    let (status, summary, error, result_code) = match record.status.as_str() {
        "completed" => (
            TaskStatus::Completed,
            record.summary.clone(),
            record.error.clone(),
            "task_snapshot_only",
        ),
        "failed" => (
            TaskStatus::Failed,
            record.summary.clone(),
            record.error.clone(),
            "task_snapshot_only",
        ),
        "cancelled" => (
            TaskStatus::Cancelled,
            record.summary.clone(),
            record.error.clone(),
            "task_snapshot_only",
        ),
        "working" | "input_required" => (
            TaskStatus::Failed,
            "Task was in progress when Memoric stopped; live execution cannot be resumed."
                .to_string(),
            Some("persisted task was not resumable after process restart".to_string()),
            "task_not_resumable",
        ),
        _ => (
            TaskStatus::Failed,
            format!(
                "Persisted task had unknown status '{}'; treating as failed.",
                record.status
            ),
            Some(format!("unknown persisted task status '{}'", record.status)),
            "task_snapshot_invalid",
        ),
    };
    let success = status == TaskStatus::Completed;
    let created_at_epoch_secs = if record.created_at_epoch_secs == 0 {
        record.snapshot_epoch_secs
    } else {
        record.created_at_epoch_secs
    };
    let updated_at_epoch_secs = if record.updated_at_epoch_secs == 0 {
        record.snapshot_epoch_secs
    } else {
        record.updated_at_epoch_secs
    };

    TaskRecord {
        task_id: record.task_id.clone(),
        tool: record.tool.clone(),
        action: record.action.clone(),
        status,
        created_at: record.created_at.clone(),
        updated_at: record.updated_at.clone(),
        created_at_epoch_secs,
        updated_at_epoch_secs,
        ttl_ms: record.ttl_ms,
        poll_interval_ms: record.poll_interval_ms,
        result_retention_ms: record.result_retention_ms,
        retry_count: record.retry_count,
        max_retries: record.max_retries,
        progress_current: record.progress_current,
        progress_total: record.progress_total,
        progress_token: None,
        summary,
        input_requests: record.input_requests,
        input_responses: record.input_responses,
        request_state: record.request_state,
        visibility: record.visibility,
        result: Some(json!({
            "success": success,
            "code": result_code,
            "message": "Persisted task metadata only; original result payload was not persisted.",
            "taskId": record.task_id,
            "tool": record.tool,
            "action": record.action,
            "status": record.status,
            "summary": record.summary,
            "artifacts": record.artifacts,
            "integrity": record.integrity,
            "snapshot": {
                "persisted": true,
                "result_payload_persisted": false,
                "snapshot_epoch_secs": record.snapshot_epoch_secs
            }
        })),
        error,
    }
}

fn truncate_snapshot_text(text: &str) -> String {
    const MAX_CHARS: usize = 2048;
    let mut value = text
        .chars()
        .filter(|ch| !ch.is_control() || ch.is_ascii_whitespace())
        .take(MAX_CHARS)
        .collect::<String>();
    if text.chars().count() > MAX_CHARS {
        value.push_str("...");
    }
    value
}

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn with_tasks<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut Vec<TaskRecord>) -> R,
{
    let mut tasks = TASKS
        .lock()
        .map_err(|err| format!("Task registry lock error: {}", err))?;
    let result = f(&mut tasks);
    persist_task_records(&tasks);
    Ok(result)
}

fn cleanup_expired_tasks() -> Result<(), String> {
    let mut tasks = TASKS
        .lock()
        .map_err(|err| format!("Task registry lock error: {}", err))?;
    if cleanup_expired_tasks_locked(&mut tasks, current_epoch_secs()) {
        persist_task_records(&tasks);
    }
    Ok(())
}

fn cleanup_expired_tasks_locked(tasks: &mut Vec<TaskRecord>, now_epoch_secs: u64) -> bool {
    let mut changed = false;
    let now_text = crate::state::chrono_now_public();

    for task in tasks.iter_mut() {
        if !task.status.is_terminal() && task_ttl_expired(task, now_epoch_secs) {
            let _ =
                transition_task_status(task, TaskStatus::Failed, now_text.clone(), now_epoch_secs);
            task.summary = format!(
                "Task expired after ttl_ms={}",
                task.ttl_ms.unwrap_or(DEFAULT_TASK_TTL_MS)
            );
            task.error = Some("task expired before reaching a terminal result".to_string());
            task.progress_token = None;
            task.request_state = Some(json!({
                "state": "expired",
                "updatedAt": now_text
            }));
            task.result = Some(json!({
                "success": false,
                "code": "task_expired",
                "message": task.summary,
                "taskId": task.task_id,
                "tool": task.tool,
                "action": task.action,
                "metadata": {
                    "ttl_ms": task.ttl_ms,
                    "result_retention_ms": task.result_retention_ms,
                    "retry_count": task.retry_count,
                    "max_retries": task.max_retries
                }
            }));
            changed = true;
        }
    }

    let before = tasks.len();
    tasks.retain(|task| !terminal_result_expired(task, now_epoch_secs));
    changed || before != tasks.len()
}

fn task_ttl_expired(task: &TaskRecord, now_epoch_secs: u64) -> bool {
    let Some(ttl_ms) = task.ttl_ms else {
        return false;
    };
    let ttl_secs = ttl_ms.div_ceil(1000);
    now_epoch_secs >= task.created_at_epoch_secs.saturating_add(ttl_secs)
}

fn terminal_result_expired(task: &TaskRecord, now_epoch_secs: u64) -> bool {
    if !task.status.is_terminal() {
        return false;
    }
    let Some(retention_ms) = task.result_retention_ms else {
        return false;
    };
    let retention_secs = retention_ms.div_ceil(1000);
    now_epoch_secs >= task.updated_at_epoch_secs.saturating_add(retention_secs)
}

fn task_expires_at_epoch_secs(task: &TaskRecord) -> Option<u64> {
    task.ttl_ms.map(|ttl_ms| {
        task.created_at_epoch_secs
            .saturating_add(ttl_ms.div_ceil(1000))
    })
}

fn with_task<F, R>(task_id: &str, f: F) -> Result<R, String>
where
    F: FnOnce(&mut TaskRecord) -> R,
{
    with_tasks(|tasks| {
        tasks
            .iter_mut()
            .find(|task| task.task_id == task_id)
            .map(f)
            .ok_or_else(|| format!("task not found: {}", task_id))
    })?
}

fn transition_task_status(
    task: &mut TaskRecord,
    next_status: TaskStatus,
    updated_at: String,
    updated_at_epoch_secs: u64,
) -> Result<TaskStatus, String> {
    let previous_status = task.status.clone();
    if previous_status == next_status {
        task.updated_at = updated_at;
        task.updated_at_epoch_secs = updated_at_epoch_secs;
        return Ok(previous_status);
    }
    if previous_status.is_terminal() {
        return Err(format!(
            "Cannot transition task {} from terminal status '{}' to '{}'",
            task.task_id,
            previous_status.as_str(),
            next_status.as_str()
        ));
    }
    if !task_status_transition_allowed(&previous_status, &next_status) {
        return Err(format!(
            "Cannot transition task {} from status '{}' to '{}'",
            task.task_id,
            previous_status.as_str(),
            next_status.as_str()
        ));
    }

    task.status = next_status;
    task.updated_at = updated_at;
    task.updated_at_epoch_secs = updated_at_epoch_secs;
    Ok(previous_status)
}

fn task_status_transition_allowed(previous: &TaskStatus, next: &TaskStatus) -> bool {
    match previous {
        TaskStatus::Working | TaskStatus::InputRequired => matches!(
            next,
            TaskStatus::Working
                | TaskStatus::InputRequired
                | TaskStatus::Completed
                | TaskStatus::Failed
                | TaskStatus::Cancelled
        ),
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled => false,
    }
}

fn task_visibility_from_context(
    context: &crate::mcp::request_context::McpRequestContext,
) -> TaskVisibility {
    TaskVisibility {
        transport: Some(context.transport.as_str().to_string()),
        session_id: context.session_id.clone(),
        app_origin: context.app_origin.clone(),
        policy_origin: Some(context.policy_origin.as_str().to_string()),
        request_id: context.request_id.clone(),
    }
}

fn current_visibility_scope() -> Option<TaskVisibility> {
    crate::mcp::request_context::current_request_context()
        .as_ref()
        .map(task_visibility_from_context)
}

fn task_visible_to_scope(task: &TaskRecord, scope: Option<&TaskVisibility>) -> bool {
    let Some(scope) = scope else {
        return true;
    };

    let origin = scope.policy_origin.as_deref().unwrap_or("unknown");
    if matches!(origin, "local" | "unknown") {
        return true;
    }

    if scope.session_id.is_some() && task.visibility.session_id == scope.session_id {
        return true;
    }
    if scope.app_origin.is_some() && task.visibility.app_origin == scope.app_origin {
        return true;
    }
    false
}

fn visibility_scope_json(scope: Option<&TaskVisibility>) -> Value {
    match scope {
        Some(scope) => json!({
            "scoped": !matches!(
                scope.policy_origin.as_deref().unwrap_or("unknown"),
                "local" | "unknown"
            ),
            "transport": scope.transport,
            "session_id_present": scope.session_id.is_some(),
            "app_origin_present": scope.app_origin.is_some(),
            "policy_origin": scope.policy_origin,
        }),
        None => json!({
            "scoped": false,
            "policy_origin": "local",
            "reason": "no request context"
        }),
    }
}

fn task_to_json(task: TaskRecord) -> Value {
    let expires_at_epoch_secs = task_expires_at_epoch_secs(&task);
    json!({
        "taskId": task.task_id,
        "task_id": task.task_id,
        "tool": task.tool,
        "action": task.action,
        "status": task.status.as_str(),
        "statusMessage": task.summary,
        "createdAt": task.created_at,
        "lastUpdatedAt": task.updated_at,
        "ttl": task.ttl_ms,
        "pollInterval": task.poll_interval_ms,
        "expiresAtEpochSecs": expires_at_epoch_secs,
        "resultRetentionMs": task.result_retention_ms,
        "retryCount": task.retry_count,
        "maxRetries": task.max_retries,
        "created_at": task.created_at,
        "updated_at": task.updated_at,
        "created_at_epoch_secs": task.created_at_epoch_secs,
        "updated_at_epoch_secs": task.updated_at_epoch_secs,
        "expires_at_epoch_secs": expires_at_epoch_secs,
        "result_retention_ms": task.result_retention_ms,
        "retry": {
            "count": task.retry_count,
            "max": task.max_retries,
        },
        "progress": {
            "current": task.progress_current,
            "total": task.progress_total,
        },
        "inputRequests": task.input_requests,
        "input_requests": task.input_requests,
        "inputResponses": task.input_responses,
        "input_responses": task.input_responses,
        "requestState": task.request_state,
        "request_state": task.request_state,
        "visibility": task.visibility,
        "summary": task.summary,
        "result": task.result,
        "error": task.error,
    })
}

fn input_required_result(task: &TaskRecord) -> Value {
    json!({
        "resultType": "input_required",
        "task": task_to_json(task.clone()),
        "taskId": task.task_id,
        "task_id": task.task_id,
        "status": task.status.as_str(),
        "inputRequests": task.input_requests,
        "input_requests": task.input_requests,
        "requestState": task.request_state,
        "request_state": task.request_state,
        "visibility": task.visibility,
        "_meta": crate::mcp::meta::input_required_meta(&task.task_id)
    })
}

fn status_notification_if_changed(task: &TaskRecord, previous_status: TaskStatus) -> Vec<Value> {
    if previous_status == task.status {
        Vec::new()
    } else {
        vec![task_status_notification(task)]
    }
}

fn progress_notification_if_advanced(
    task: &TaskRecord,
    previous_current: u64,
    force: bool,
) -> Option<Value> {
    if task.progress_current <= previous_current {
        return None;
    }
    let token = task.progress_token.as_ref()?;
    if !force && !should_emit_progress_notification(task) {
        return None;
    }
    Some(task_progress_notification(task, token))
}

fn should_emit_progress_notification(task: &TaskRecord) -> bool {
    let now = Instant::now();
    let Ok(mut state) = PROGRESS_NOTIFICATION_STATE.lock() else {
        return true;
    };
    match state.get_mut(&task.task_id) {
        Some(previous)
            if task.progress_current > previous.last_progress
                && now.duration_since(previous.last_sent_at)
                    >= Duration::from_millis(PROGRESS_NOTIFICATION_MIN_INTERVAL_MS) =>
        {
            previous.last_sent_at = now;
            previous.last_progress = task.progress_current;
            true
        }
        Some(_) => false,
        None => {
            state.insert(
                task.task_id.clone(),
                ProgressNotificationState {
                    last_sent_at: now,
                    last_progress: task.progress_current,
                },
            );
            true
        }
    }
}

fn task_status_notification(task: &TaskRecord) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/tasks/status",
        "params": task_to_json(task.clone()),
    })
}

fn task_progress_notification(task: &TaskRecord, progress_token: &Value) -> Value {
    let mut params = serde_json::Map::new();
    params.insert("progressToken".to_string(), progress_token.clone());
    params.insert("progress".to_string(), json!(task.progress_current));
    if let Some(total) = task.progress_total {
        params.insert("total".to_string(), json!(total));
    }
    if !task.summary.trim().is_empty() {
        params.insert("message".to_string(), json!(task.summary));
    }
    params.insert(
        "_meta".to_string(),
        crate::mcp::meta::related_task_meta(&task.task_id),
    );

    json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": Value::Object(params),
    })
}

fn emit_notifications(notifications: Vec<Value>) {
    if notifications.is_empty() {
        return;
    }

    let sender = NOTIFICATION_SENDER
        .lock()
        .ok()
        .and_then(|slot| slot.clone());
    if let Some(sender) = sender {
        for notification in notifications {
            crate::observability::record_task_notification(&notification);
            let _ = sender.send(notification);
        }
    }
}

fn attach_related_task_meta(mut result: Value, task_id: &str) -> Value {
    let related = crate::mcp::meta::related_task_meta(task_id);

    if let Some(obj) = result.as_object_mut() {
        match obj.get_mut("_meta") {
            Some(meta) if meta.is_object() => {
                if let Some(meta_obj) = meta.as_object_mut() {
                    meta_obj.insert(
                        crate::mcp::meta::MCP_RELATED_TASK.to_string(),
                        related[crate::mcp::meta::MCP_RELATED_TASK].clone(),
                    );
                }
            }
            _ => {
                obj.insert("_meta".to_string(), related);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    static NOTIFICATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn task_lifecycle_records_result() {
        let task_id = create("self", "doctor", "starting").expect("create task");
        mark_running(&task_id, Some(1), "running");
        complete(&task_id, json!({"message": "done"}));

        let task = get_json(&task_id);
        assert_eq!(task["success"], true);
        assert_eq!(task["task"]["status"], "completed");
        assert_eq!(task["task"]["result"]["message"], "done");
    }

    #[test]
    fn task_cancellation_is_queryable() {
        let task_id = create("memory", "scan_new", "queued").expect("create task");
        mark_running(&task_id, None, "running");
        assert!(!is_cancel_requested(&task_id));
        cancel(&task_id).expect("cancel");
        assert!(is_cancel_requested(&task_id));
        mark_cancelled(&task_id, "cancelled");
        let task = get_json(&task_id);
        assert_eq!(task["task"]["status"], "cancelled");
    }

    #[test]
    fn terminal_completed_task_ignores_late_status_updates() {
        let task_id = create("self", "doctor", "queued").expect("create task");
        complete(&task_id, json!({"message": "original result"}));

        mark_running(&task_id, Some(10), "late running");
        fail(&task_id, "late failure");
        mark_cancelled(&task_id, "late cancellation");
        complete(&task_id, json!({"message": "late replacement"}));

        let task = get_json(&task_id);
        assert_eq!(task["task"]["status"], "completed");
        assert_eq!(task["task"]["statusMessage"], "original result");
        assert_eq!(task["task"]["result"]["message"], "original result");
        assert!(task["task"]["error"].is_null());
    }

    #[test]
    fn cancelled_task_ignores_late_completion_and_failure() {
        let task_id = create("memory", "scan_new", "queued").expect("create task");
        cancel(&task_id).expect("cancel");

        complete(&task_id, json!({"message": "late completion"}));
        fail(&task_id, "late failure");
        mark_cancelled(&task_id, "cancelled after completion boundary");

        let task = get_json(&task_id);
        assert_eq!(task["task"]["status"], "cancelled");
        assert_eq!(
            task["task"]["statusMessage"],
            "cancelled after completion boundary"
        );
        assert_eq!(task["task"]["error"], "cancelled by request");
        assert!(task["task"]["result"].is_null());
    }

    #[test]
    fn task_status_transition_helper_rejects_terminal_reopen() {
        let mut task = TaskRecord {
            task_id: "task-terminal-helper".to_string(),
            tool: "self".to_string(),
            action: "doctor".to_string(),
            status: TaskStatus::Failed,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            updated_at: "2026-05-22T00:00:01Z".to_string(),
            created_at_epoch_secs: 1,
            updated_at_epoch_secs: 2,
            ttl_ms: Some(1000),
            poll_interval_ms: Some(100),
            result_retention_ms: Some(DEFAULT_RESULT_RETENTION_MS),
            retry_count: 0,
            max_retries: 0,
            progress_current: 0,
            progress_total: None,
            progress_token: None,
            summary: "failed".to_string(),
            input_requests: Vec::new(),
            input_responses: Vec::new(),
            request_state: None,
            visibility: TaskVisibility::default(),
            result: None,
            error: Some("failed".to_string()),
        };

        let err = transition_task_status(
            &mut task,
            TaskStatus::Working,
            "2026-05-22T00:00:02Z".to_string(),
            3,
        )
        .expect_err("terminal task should not reopen");

        assert!(err.contains("terminal status"));
        assert_eq!(task.status, TaskStatus::Failed);
        assert_eq!(task.updated_at_epoch_secs, 2);
    }

    #[test]
    fn task_list_uses_cursor_pagination() {
        create("self", "doctor", "pagination-1").expect("create task 1");
        create("self", "doctor", "pagination-2").expect("create task 2");
        create("self", "doctor", "pagination-3").expect("create task 3");

        let first = list_request(&json!({
            "params": {
                "limit": 1
            }
        }))
        .expect("first page");
        assert_eq!(first["success"], true);
        assert_eq!(first["count"], 1);
        let first_page_ids = first["tasks"]
            .as_array()
            .expect("first page tasks")
            .iter()
            .filter_map(|task| task["taskId"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(first_page_ids.len(), 1);
        let cursor = first["nextCursor"]
            .as_str()
            .expect("cursor for remaining task list");

        let second = list_request(&json!({
            "params": {
                "limit": 2,
                "cursor": cursor
            }
        }))
        .expect("second page");
        assert!(second["tasks"].as_array().expect("tasks").len() <= 2);
        let second_page_ids = second["tasks"]
            .as_array()
            .expect("tasks")
            .iter()
            .filter_map(|task| task["taskId"].as_str())
            .collect::<Vec<_>>();
        assert!(second_page_ids
            .iter()
            .all(|task_id| !first_page_ids.contains(task_id)));
    }

    #[test]
    fn task_list_rejects_invalid_cursor() {
        let err = list_request(&json!({
            "params": {
                "cursor": "not-a-task-cursor"
            }
        }))
        .expect_err("invalid cursor should fail");

        assert!(err.contains("Invalid cursor"));
    }

    #[test]
    fn task_list_scopes_remote_sessions_without_breaking_local_visibility() {
        let remote_a = crate::mcp::request_context::McpRequestContext::from_request(
            &json!({
                "jsonrpc": "2.0",
                "id": "remote-a",
                "method": "tools/call",
                "params": {
                    "session_id": "session-a",
                    "name": "self",
                    "arguments": { "action": "doctor" }
                }
            }),
            crate::mcp::request_context::McpTransportKind::Http,
        );
        let remote_b = crate::mcp::request_context::McpRequestContext::from_request(
            &json!({
                "jsonrpc": "2.0",
                "id": "remote-b",
                "method": "tools/call",
                "params": {
                    "session_id": "session-b",
                    "name": "self",
                    "arguments": { "action": "doctor" }
                }
            }),
            crate::mcp::request_context::McpTransportKind::Http,
        );

        let task_a =
            crate::mcp::request_context::with_current_request_context(remote_a.clone(), || {
                create_with_options(
                    "self",
                    "doctor",
                    "remote a",
                    TaskOptions {
                        request_context: Some(remote_a.clone()),
                        ..TaskOptions::default()
                    },
                )
            })
            .expect("create remote task a");
        let task_b =
            crate::mcp::request_context::with_current_request_context(remote_b.clone(), || {
                create_with_options(
                    "self",
                    "doctor",
                    "remote b",
                    TaskOptions {
                        request_context: Some(remote_b.clone()),
                        ..TaskOptions::default()
                    },
                )
            })
            .expect("create remote task b");

        let visible_to_a =
            crate::mcp::request_context::with_current_request_context(remote_a.clone(), || {
                list_page(100, None).expect("remote scoped list")
            });
        let visible_ids = visible_to_a["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|task| task["taskId"].as_str())
            .collect::<Vec<_>>();
        assert!(visible_ids.contains(&task_a.as_str()));
        assert!(!visible_ids.contains(&task_b.as_str()));
        assert_eq!(visible_to_a["visibility"]["scoped"], true);

        let local = list_page(100, None).expect("local unscoped list");
        let local_ids = local["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|task| task["taskId"].as_str())
            .collect::<Vec<_>>();
        assert!(local_ids.contains(&task_a.as_str()));
        assert!(local_ids.contains(&task_b.as_str()));
        assert_eq!(local["visibility"]["scoped"], false);
    }

    #[test]
    fn task_snapshot_persists_metadata_without_raw_result_payload() {
        let path = temp_snapshot_path("metadata-only");
        let task = TaskRecord {
            task_id: "task-snapshot-completed".to_string(),
            tool: "memory".to_string(),
            action: "read".to_string(),
            status: TaskStatus::Completed,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            updated_at: "2026-05-22T00:00:01Z".to_string(),
            created_at_epoch_secs: 1,
            updated_at_epoch_secs: 2,
            ttl_ms: Some(1000),
            poll_interval_ms: Some(100),
            result_retention_ms: Some(2000),
            retry_count: 0,
            max_retries: 2,
            progress_current: 1,
            progress_total: Some(1),
            progress_token: Some(json!("do-not-persist-progress-token")),
            summary: "safe summary".to_string(),
            input_requests: Vec::new(),
            input_responses: Vec::new(),
            request_state: None,
            visibility: TaskVisibility::default(),
            result: Some(json!({
                "summary": "safe summary",
                "bytes": [222, 173, 190, 239],
                "raw_marker": "DO_NOT_PERSIST_RAW_RESULT"
            })),
            error: None,
        };

        write_task_snapshot_to_path(&path, &[task]).expect("write snapshot");
        let content = std::fs::read_to_string(&path).expect("snapshot content");
        let _ = std::fs::remove_file(&path);

        assert!(content.contains("safe summary"));
        assert!(content.contains("result_sha256"));
        assert!(!content.contains("DO_NOT_PERSIST_RAW_RESULT"));
        assert!(!content.contains("do-not-persist-progress-token"));
        assert!(!content.contains("\"bytes\""));
    }

    #[test]
    fn task_snapshot_load_marks_live_tasks_not_resumable() {
        let path = temp_snapshot_path("not-resumable");
        let snapshot = TaskSnapshotFile {
            version: TASK_SNAPSHOT_VERSION,
            generated_at: "2026-05-22T00:00:00Z".to_string(),
            generated_at_epoch_secs: 1,
            records: vec![PersistedTaskRecord {
                task_id: "task-live-before-restart".to_string(),
                tool: "memory".to_string(),
                action: "scan_new".to_string(),
                status: "working".to_string(),
                created_at: "2026-05-22T00:00:00Z".to_string(),
                updated_at: "2026-05-22T00:00:01Z".to_string(),
                created_at_epoch_secs: 1,
                updated_at_epoch_secs: 2,
                ttl_ms: Some(1000),
                poll_interval_ms: Some(100),
                result_retention_ms: Some(2000),
                retry_count: 1,
                max_retries: 2,
                progress_current: 4,
                progress_total: Some(10),
                summary: "scan in progress".to_string(),
                input_requests: Vec::new(),
                input_responses: Vec::new(),
                request_state: None,
                visibility: TaskVisibility::default(),
                error: None,
                artifacts: Vec::new(),
                integrity: Value::Null,
                snapshot_epoch_secs: 1,
            }],
        };
        std::fs::write(&path, serde_json::to_string(&snapshot).unwrap()).expect("write snapshot");

        let records = load_persisted_task_records_from_path(&path).expect("load snapshot");
        let _ = std::fs::remove_file(&path);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, TaskStatus::Failed);
        assert!(records[0]
            .summary
            .contains("live execution cannot be resumed"));
        assert_eq!(records[0].progress_token, None);
        assert_eq!(
            records[0].result.as_ref().unwrap()["code"],
            "task_not_resumable"
        );
    }

    #[test]
    fn background_tasks_reject_live_state_changing_actions() {
        let err = spawn_tool_task(
            "memory",
            &json!({
                "action": "write",
                "pid": std::process::id(),
                "address": "0x1000",
                "bytes": [1]
            }),
        )
        .expect_err("live mutation should not be backgrounded");
        assert!(err.contains("dry_run=true"));
    }

    #[test]
    fn background_task_accepts_read_only_call() {
        let task_id = spawn_tool_task("self", &json!({"action": "version"}))
            .expect("read-only call should be accepted");
        let task = get_json(&task_id);
        assert_eq!(task["success"], true);
        assert!(matches!(
            task["task"]["status"].as_str().unwrap_or_default(),
            "working" | "completed"
        ));
    }

    #[test]
    fn task_augmented_result_returns_tool_payload_with_related_task_meta() {
        let task_id = create("self", "version", "starting").expect("create task");
        let payload = crate::mcp::protocol::tool_success_content(
            "self",
            &json!({"action": "version"}),
            &json!({"message": "version ok"}),
        );
        complete(&task_id, payload);

        let result = result_request(&json!({
            "params": {
                "taskId": task_id,
                "wait_ms": 0
            }
        }))
        .expect("result should be ready");

        assert_eq!(result["structuredContent"]["success"], true);
        assert_eq!(
            result["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            task_id
        );
    }

    #[test]
    fn input_required_result_and_response_updates_task_state() {
        let task_id = create("self", "elicitation", "queued").expect("create task");
        mark_input_required(
            &task_id,
            "input-1",
            "Provide approval",
            "form",
            json!({
                "type": "object",
                "properties": {
                    "approved": { "type": "boolean" }
                },
                "required": ["approved"]
            }),
            Some(json!({ "continuation": "dry-run" })),
        )
        .expect("mark input required");

        let task = get_json(&task_id);
        assert_eq!(task["task"]["status"], "input_required");
        assert_eq!(task["task"]["inputRequests"][0]["request_id"], "input-1");
        assert_eq!(task["task"]["requestState"]["continuation"], "dry-run");

        let result = result_request(&json!({
            "params": {
                "taskId": task_id,
                "wait_ms": 0
            }
        }))
        .expect("input-required result");
        assert_eq!(result["resultType"], "input_required");
        assert_eq!(result["inputRequests"][0]["request_id"], "input-1");

        let response = input_response_request(&json!({
            "params": {
                "taskId": task_id,
                "requestId": "input-1",
                "input": { "approved": true }
            }
        }))
        .expect("input response");

        assert_eq!(response["success"], true);
        assert_eq!(response["task"]["status"], "working");
        assert_eq!(response["task"]["inputRequests"][0]["responded"], true);
        assert_eq!(
            response["task"]["inputResponses"][0]["input"]["approved"],
            true
        );
        assert_eq!(response["task"]["requestState"]["state"], "input_received");
    }

    #[test]
    fn tasks_update_accepts_input_response_compat_shape() {
        let task_id = create("self", "elicitation", "queued").expect("create task");
        mark_input_required(
            &task_id,
            "input-compat",
            "Provide approval",
            "form",
            json!({ "type": "object" }),
            None,
        )
        .expect("mark input required");

        let response = update_request(&json!({
            "params": {
                "kind": "input_response",
                "taskId": task_id,
                "requestId": "input-compat",
                "input": { "approved": true }
            }
        }))
        .expect("compat input response");

        assert_eq!(response["task"]["status"], "working");
        assert_eq!(
            response["task"]["inputResponses"][0]["request_id"],
            "input-compat"
        );
    }

    #[test]
    fn input_response_rejects_wrong_request_binding() {
        let task_id = create("self", "elicitation", "queued").expect("create task");
        mark_input_required(
            &task_id,
            "input-expected",
            "Provide approval",
            "form",
            json!({ "type": "object" }),
            None,
        )
        .expect("mark input required");

        let err = input_response_request(&json!({
            "params": {
                "taskId": task_id,
                "requestId": "input-other",
                "input": { "approved": true }
            }
        }))
        .expect_err("wrong request id should fail");

        assert!(err.contains("not found"));
        assert_eq!(get_json(&task_id)["task"]["status"], "input_required");
    }

    #[test]
    fn task_augmented_create_result_uses_mcp_task_shape() {
        let task_id = create_with_options(
            "self",
            "doctor",
            "queued",
            TaskOptions {
                ttl_ms: Some(1234),
                result_retention_ms: Some(5678),
                max_retries: 2,
                progress_token: None,
                correlation_id: None,
                request_context: None,
                input_required_on_policy: false,
            },
        )
        .expect("create task");
        let result = task_create_result(&task_id);

        assert_eq!(result["task"]["taskId"], task_id);
        assert_eq!(result["task"]["status"], "working");
        assert_eq!(result["task"]["ttl"], 1234);
        assert_eq!(result["task"]["pollInterval"], DEFAULT_POLL_INTERVAL_MS);
        assert_eq!(result["task"]["resultRetentionMs"], 5678);
        assert_eq!(result["task"]["retryCount"], 0);
        assert_eq!(result["task"]["maxRetries"], 2);
        assert!(result["task"]["expiresAtEpochSecs"].is_u64());
        assert!(
            result["_meta"]["io.modelcontextprotocol/model-immediate-response"]
                .as_str()
                .unwrap_or_default()
                .contains("poll tasks/get or tasks/result")
        );
    }

    #[test]
    fn task_options_extract_progress_token() {
        let options = task_options_from_request(&json!({
            "params": {
                "_meta": { "progressToken": "progress-1" },
                "task": {
                    "ttl": 5000,
                    "resultRetentionMs": 7000,
                    "maxRetries": 2
                }
            }
        }));

        assert_eq!(options.ttl_ms, Some(5000));
        assert_eq!(options.result_retention_ms, Some(7000));
        assert_eq!(options.max_retries, 2);
        assert_eq!(options.progress_token, Some(json!("progress-1")));
    }

    #[test]
    fn task_cleanup_marks_expired_working_tasks_failed() {
        let mut tasks = vec![TaskRecord {
            task_id: "task-expired-working".to_string(),
            tool: "memory".to_string(),
            action: "scan_new".to_string(),
            status: TaskStatus::Working,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            updated_at: "2026-05-22T00:00:01Z".to_string(),
            created_at_epoch_secs: 10,
            updated_at_epoch_secs: 11,
            ttl_ms: Some(1000),
            poll_interval_ms: Some(100),
            result_retention_ms: Some(10_000),
            retry_count: 1,
            max_retries: 2,
            progress_current: 4,
            progress_total: Some(10),
            progress_token: Some(json!("token-to-clear")),
            summary: "running".to_string(),
            input_requests: Vec::new(),
            input_responses: Vec::new(),
            request_state: None,
            visibility: TaskVisibility::default(),
            result: None,
            error: None,
        }];

        assert!(cleanup_expired_tasks_locked(&mut tasks, 12));

        let task = &tasks[0];
        assert_eq!(task.status, TaskStatus::Failed);
        assert_eq!(task.progress_token, None);
        assert_eq!(task.result.as_ref().unwrap()["code"], "task_expired");
        assert_eq!(task.result.as_ref().unwrap()["metadata"]["retry_count"], 1);
        assert_eq!(task.result.as_ref().unwrap()["metadata"]["max_retries"], 2);
    }

    #[test]
    fn task_cleanup_removes_terminal_tasks_after_result_retention() {
        let mut tasks = vec![TaskRecord {
            task_id: "task-expired-result".to_string(),
            tool: "self".to_string(),
            action: "doctor".to_string(),
            status: TaskStatus::Completed,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            updated_at: "2026-05-22T00:00:01Z".to_string(),
            created_at_epoch_secs: 10,
            updated_at_epoch_secs: 20,
            ttl_ms: Some(1000),
            poll_interval_ms: Some(100),
            result_retention_ms: Some(1000),
            retry_count: 0,
            max_retries: 0,
            progress_current: 1,
            progress_total: Some(1),
            progress_token: None,
            summary: "done".to_string(),
            input_requests: Vec::new(),
            input_responses: Vec::new(),
            request_state: None,
            visibility: TaskVisibility::default(),
            result: Some(json!({"message": "done"})),
            error: None,
        }];

        assert!(cleanup_expired_tasks_locked(&mut tasks, 21));

        assert!(tasks.is_empty());
    }

    #[test]
    fn progress_notification_uses_mcp_shape_and_related_task_meta() {
        let task = TaskRecord {
            task_id: "task-test".to_string(),
            tool: "memory".to_string(),
            action: "scan_new".to_string(),
            status: TaskStatus::Working,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            updated_at: "2026-05-22T00:00:01Z".to_string(),
            created_at_epoch_secs: 1,
            updated_at_epoch_secs: 2,
            ttl_ms: Some(1000),
            poll_interval_ms: Some(100),
            result_retention_ms: Some(DEFAULT_RESULT_RETENTION_MS),
            retry_count: 0,
            max_retries: 0,
            progress_current: 4,
            progress_total: Some(10),
            progress_token: Some(json!("token-1")),
            summary: "scan_new: scanned 4/10 regions, 2 matches".to_string(),
            input_requests: Vec::new(),
            input_responses: Vec::new(),
            request_state: None,
            visibility: TaskVisibility::default(),
            result: None,
            error: None,
        };

        let notification = task_progress_notification(&task, task.progress_token.as_ref().unwrap());
        assert_eq!(notification["jsonrpc"], "2.0");
        assert_eq!(notification["method"], "notifications/progress");
        assert_eq!(notification["params"]["progressToken"], "token-1");
        assert_eq!(notification["params"]["progress"], 4);
        assert_eq!(notification["params"]["total"], 10);
        assert_eq!(
            notification["params"]["_meta"]["io.modelcontextprotocol/related-task"]["taskId"],
            "task-test"
        );
    }

    #[test]
    fn task_status_notification_contains_full_task_without_related_task_meta() {
        let task_id = create("self", "doctor", "queued").expect("create task");
        let task = task_record(&task_id).expect("task record");
        let notification = task_status_notification(&task);

        assert_eq!(notification["jsonrpc"], "2.0");
        assert_eq!(notification["method"], "notifications/tasks/status");
        assert_eq!(notification["params"]["taskId"], task_id);
        assert!(notification["params"]["_meta"].is_null());
    }

    #[test]
    fn progress_and_status_notifications_are_emitted_to_sender() {
        let _guard = NOTIFICATION_TEST_LOCK
            .lock()
            .expect("notification test lock");
        let (tx, rx) = std::sync::mpsc::channel::<Value>();
        set_notification_sender(Some(tx));

        let task_id = create_with_options(
            "memory",
            "scan_new",
            "queued",
            TaskOptions {
                ttl_ms: Some(1000),
                result_retention_ms: Some(DEFAULT_RESULT_RETENTION_MS),
                max_retries: 0,
                progress_token: Some(json!("progress-token")),
                correlation_id: None,
                request_context: None,
                input_required_on_policy: false,
            },
        )
        .expect("create task");
        update_progress(&task_id, 1, Some(3), "scan_new: scanned 1/3 regions");
        complete(&task_id, json!({ "message": "scan complete" }));
        set_notification_sender(None);

        let mut saw_initial_progress = false;
        let mut saw_final_progress = false;
        let mut saw_completed_status = false;
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline
            && !(saw_initial_progress && saw_final_progress && saw_completed_status)
        {
            let notification = rx
                .recv_timeout(Duration::from_millis(50))
                .expect("notification");
            match notification["method"].as_str().unwrap_or_default() {
                "notifications/progress"
                    if notification["params"]["progressToken"] == "progress-token" =>
                {
                    saw_initial_progress |= notification["params"]["progress"] == 1;
                    saw_final_progress |= notification["params"]["progress"] == 3;
                }
                "notifications/tasks/status" if notification["params"]["taskId"] == task_id => {
                    saw_completed_status |= notification["params"]["status"] == "completed";
                }
                _ => {}
            }
        }

        assert!(saw_initial_progress);
        assert!(saw_final_progress);
        assert!(saw_completed_status);
    }

    #[test]
    fn progress_notifications_are_rate_limited_but_completion_is_sent() {
        let _guard = NOTIFICATION_TEST_LOCK
            .lock()
            .expect("notification test lock");
        let (tx, rx) = std::sync::mpsc::channel::<Value>();
        set_notification_sender(Some(tx));

        let task_id = create_with_options(
            "memory",
            "scan_new",
            "queued",
            TaskOptions {
                ttl_ms: Some(1000),
                result_retention_ms: Some(DEFAULT_RESULT_RETENTION_MS),
                max_retries: 0,
                progress_token: Some(json!("rate-limit-token")),
                correlation_id: None,
                request_context: None,
                input_required_on_policy: false,
            },
        )
        .expect("create task");
        update_progress(&task_id, 1, Some(5), "step 1");
        update_progress(&task_id, 2, Some(5), "step 2");
        update_progress(&task_id, 3, Some(5), "step 3");
        update_progress(&task_id, 4, Some(5), "step 4");
        complete(&task_id, json!({ "message": "scan complete" }));
        set_notification_sender(None);

        let notifications = drain_notifications(&rx, Duration::from_millis(500));
        let progress_values = notifications
            .iter()
            .filter(|notification| {
                notification["method"] == "notifications/progress"
                    && notification["params"]["progressToken"] == "rate-limit-token"
            })
            .filter_map(|notification| notification["params"]["progress"].as_u64())
            .collect::<Vec<_>>();

        assert!(progress_values.contains(&1));
        assert!(progress_values.contains(&5));
        assert!(
            progress_values.len() <= 2,
            "high-frequency progress notifications were not rate-limited: {:?}",
            progress_values
        );
        assert!(notifications.iter().any(|notification| {
            notification["method"] == "notifications/tasks/status"
                && notification["params"]["taskId"] == task_id
                && notification["params"]["status"] == "completed"
        }));
    }

    fn temp_snapshot_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "memoric-task-snapshot-{}-{}-{}.json",
            name,
            std::process::id(),
            current_epoch_secs()
        ))
    }

    fn drain_notifications(rx: &std::sync::mpsc::Receiver<Value>, timeout: Duration) -> Vec<Value> {
        let deadline = Instant::now() + timeout;
        let mut notifications = Vec::new();
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok(notification) => notifications.push(notification),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if !notifications.is_empty() {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        notifications
    }
}

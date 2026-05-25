//! MCP Session State Management
//!
//! Global session state tracking for the MCP server lifecycle. Instruments
//! stealth, detection, injection, and kernel tools to maintain a coherent
//! view of the operator's current position on the target.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Mutex;

lazy_static! {
    static ref SESSION: Mutex<SessionState> = Mutex::new(SessionState::new());
}

#[cfg(test)]
lazy_static! {
    pub(crate) static ref TEST_ENV_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub started_at: String,
    pub target_pid: Option<u32>,
    pub detected_edrs: Vec<EdrRecord>,
    pub loaded_driver: Option<DriverRecord>,
    pub evasion_applied: Vec<EvasionRecord>,
    pub active_injections: Vec<InjectionRecord>,
    pub stealth_score: Option<StealthAssessment>,
    pub kernel_callbacks_status: KernelCallbackStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrRecord {
    pub product: String,
    pub process_name: String,
    pub pid: u32,
    pub detected_at: String,
    pub confidence: String, // "high", "medium", "low"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverRecord {
    pub name: String,
    pub device_path: String,
    pub loaded_at: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionRecord {
    pub technique: String,
    pub target: String,
    pub applied_at: String,
    pub status: String, // "applied", "failed", "reverted"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionRecord {
    pub pid: u32,
    pub technique: String,
    pub shellcode_size: usize,
    pub injected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAssessment {
    pub total_score: u32, // 0-100
    pub etw_patched: bool,
    pub amsi_patched: bool,
    pub ntdll_unhooked: bool,
    pub modules_hidden: bool,
    pub callbacks_removed: u32,
    pub minifilters_detached: u32,
    pub edr_processes_detected: u32,
    pub assessed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCallbackStatus {
    pub process_callbacks: u32,
    pub thread_callbacks: u32,
    pub image_callbacks: u32,
    pub object_callbacks: u32,
    pub registry_callbacks: u32,
    pub etw_ti_enabled: bool,
    pub last_enum_at: Option<String>,
}

impl Default for KernelCallbackStatus {
    fn default() -> Self {
        Self {
            process_callbacks: 0,
            thread_callbacks: 0,
            image_callbacks: 0,
            object_callbacks: 0,
            registry_callbacks: 0,
            etw_ti_enabled: true,
            last_enum_at: None,
        }
    }
}

impl SessionState {
    fn new() -> Self {
        let now = chrono_now();
        Self {
            session_id: uuid_v4(),
            started_at: now.clone(),
            target_pid: None,
            detected_edrs: Vec::new(),
            loaded_driver: None,
            evasion_applied: Vec::new(),
            active_injections: Vec::new(),
            stealth_score: None,
            kernel_callbacks_status: KernelCallbackStatus::default(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

fn chrono_now() -> String {
    chrono_now_public()
}

/// Public re-export for other modules that need ISO timestamps
pub fn chrono_now_public() -> String {
    use std::time::SystemTime;
    // ISO-8601 UTC timestamp via SystemTime (no chrono dependency)
    let dur = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Rough ISO-8601: seconds since epoch as UTC date
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let secs_part = time_of_day % 60;
    // Days since 1970-01-01 to year/month/day (simplified but correct)
    let (y, m, d) = days_to_ymd(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, mins, secs_part
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant, works for 1970-2100
    days += 719468; // shift epoch to 0000-03-01
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("memoric-{:016x}", ts.as_secs())
}

// ─── Public getter ───────────────────────────────────────────────────────────

pub fn get_state() -> Result<SessionState, String> {
    SESSION
        .lock()
        .map(|s| s.clone())
        .map_err(|e| format!("Session lock error: {}", e))
}

pub fn get_state_json() -> Result<serde_json::Value, String> {
    let state = get_state()?;
    let mut value = serde_json::to_value(&state).map_err(|e| format!("Serialize error: {}", e))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "rollback_opportunities".to_string(),
            rollback_opportunities_json(),
        );
        obj.insert("cleanup_scope".to_string(), cleanup_scope_json(None, None));
    }
    Ok(value)
}

pub fn rollback_opportunities_json() -> Value {
    let state = get_state().unwrap_or_default();
    let mut opportunities = Vec::new();

    for evasion in &state.evasion_applied {
        let opportunity = match evasion.technique.as_str() {
            tech if tech.contains("etw") => json!({
                "kind": "evasion",
                "tool": "stealth",
                "action": evasion.technique,
                "target": evasion.target,
                "status": evasion.status,
                "available": evasion.status == "applied",
                "strategy": "explicit_restore_or_restart",
                "captured_fields": ["target", "status"],
                "detail": "ETW changes are process-local and may be reversible only through explicit restore or restart"
            }),
            tech if tech.contains("amsi") => json!({
                "kind": "evasion",
                "tool": "stealth",
                "action": evasion.technique,
                "target": evasion.target,
                "status": evasion.status,
                "available": evasion.status == "applied",
                "strategy": "explicit_restore_or_restart",
                "captured_fields": ["target", "status"],
                "detail": "AMSI patches are tracked as reversible only when explicit restore data exists"
            }),
            tech if tech.contains("unhook") => json!({
                "kind": "evasion",
                "tool": "stealth",
                "action": evasion.technique,
                "target": evasion.target,
                "status": evasion.status,
                "available": evasion.status == "applied",
                "strategy": "restore_original_bytes_or_restart",
                "captured_fields": ["target", "status"],
                "detail": "Unhook operations are only partially reversible without saved bytes"
            }),
            tech if tech.contains("hide_module") => json!({
                "kind": "evasion",
                "tool": "stealth",
                "action": evasion.technique,
                "target": evasion.target,
                "status": evasion.status,
                "available": false,
                "strategy": "process_restart",
                "captured_fields": ["target", "status"],
                "detail": "Module hiding is usually not safely reversible in-place"
            }),
            _ => json!({
                "kind": "evasion",
                "tool": "stealth",
                "action": evasion.technique,
                "target": evasion.target,
                "status": evasion.status,
                "available": evasion.status == "applied",
                "strategy": "action_specific",
                "captured_fields": ["target", "status"],
                "detail": "Rollback availability depends on the specific mutation"
            }),
        };
        opportunities.push(opportunity);
    }

    for injection in &state.active_injections {
        opportunities.push(json!({
            "kind": "injection",
            "tool": "inject",
            "action": injection.technique,
            "target_pid": injection.pid,
            "available": true,
            "strategy": "terminate_remote_state_or_restore_session",
            "captured_fields": ["pid", "technique", "shellcode_size"],
            "detail": "Active injection is tracked as a rollback candidate when the operator still controls the target session"
        }));
    }

    if state.loaded_driver.is_some() {
        opportunities.push(json!({
            "kind": "driver",
            "tool": "kernel",
            "action": "driver_load",
            "available": true,
            "strategy": "driver_unload",
            "captured_fields": ["name", "device_path", "loaded_at"],
            "detail": "Loaded driver state can be paired with unload or cleanup actions"
        }));
    }

    json!(opportunities)
}

pub fn cleanup_scope_json(task_id: Option<&str>, chain_id: Option<&str>) -> Value {
    let state = get_state().unwrap_or_default();
    let task_targets = task_id
        .and_then(crate::observability::task_correlation_id)
        .map(|id| vec![id])
        .unwrap_or_default();
    json!({
        "available": true,
        "task_id": task_id,
        "chain_id": chain_id,
        "targets": {
            "task_ids": task_targets,
            "chain_ids": chain_id.map(|id| vec![id.to_string()]).unwrap_or_default(),
            "session_id": state.session_id,
        },
        "message": "Cleanup can be scoped by task_id or chain_id when the caller supplies matching correlation metadata"
    })
}

pub fn operation_history_json(args: &Value) -> Value {
    let Some(path) = audit_history_path(args) else {
        return json!({
            "success": true,
            "configured": false,
            "entries": [],
            "count": 0,
            "total_count": 0,
            "offset": 0,
            "limit": 0,
            "has_more": false,
            "message": "MEMORIC_AUDIT_PATH is not configured"
        });
    };

    let limit = crate::args::parse_limit(args, "limit", 50, 500).unwrap_or(50);
    let offset = crate::args::parse_limit(args, "offset", 0, usize::MAX).unwrap_or(0);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            return json!({
                "success": false,
                "configured": true,
                "path": path,
                "entries": [],
                "count": 0,
                "total_count": 0,
                "offset": offset,
                "limit": limit,
                "has_more": false,
                "error": err.to_string()
            })
        }
    };

    let mut entries = content
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| operation_history_matches(entry, args))
        .collect::<Vec<_>>();

    entries.reverse();
    let total_count = entries.len();
    let paginated = entries
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let count = paginated.len();

    json!({
        "success": true,
        "configured": true,
        "path": path,
        "filters": operation_history_filters_json(args),
        "count": count,
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + count < total_count,
        "entries": paginated,
    })
}

pub fn mutation_history_json(args: &Value) -> Value {
    let Some(path) = audit_history_path(args) else {
        return json!({
            "success": true,
            "configured": false,
            "entries": [],
            "count": 0,
            "total_count": 0,
            "offset": 0,
            "limit": 0,
            "has_more": false,
            "message": "MEMORIC_AUDIT_PATH is not configured"
        });
    };

    let limit = crate::args::parse_limit(args, "limit", 50, 500).unwrap_or(50);
    let offset = crate::args::parse_limit(args, "offset", 0, usize::MAX).unwrap_or(0);
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            return json!({
                "success": false,
                "configured": true,
                "path": path,
                "entries": [],
                "count": 0,
                "total_count": 0,
                "offset": offset,
                "limit": limit,
                "has_more": false,
                "error": err.to_string()
            })
        }
    };

    let mut entries = content
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| operation_history_matches(entry, args))
        .filter(|entry| !entry.get("state_change").unwrap_or(&Value::Null).is_null())
        .map(mutation_history_entry)
        .collect::<Vec<_>>();

    entries.reverse();
    let total_count = entries.len();
    let paginated = entries
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let count = paginated.len();

    json!({
        "success": true,
        "configured": true,
        "path": path,
        "filters": operation_history_filters_json(args),
        "count": count,
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + count < total_count,
        "entries": paginated,
        "redaction": {
            "summary_only": true,
            "omits": ["raw rollback bytes", "raw memory", "credentials", "full result payloads"]
        },
        "message": "Mutation history summarizes audit state_change metadata without raw result payloads"
    })
}

pub fn workflow_replay_dry_run_json(args: &Value) -> Value {
    let Some(path) = audit_history_path(args) else {
        return json!({
            "success": false,
            "configured": false,
            "mode": "audit_replay_dry_run",
            "steps": [],
            "message": "MEMORIC_AUDIT_PATH is not configured and audit_path was not provided"
        });
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            return json!({
                "success": false,
                "configured": true,
                "path": path,
                "mode": "audit_replay_dry_run",
                "steps": [],
                "error": err.to_string()
            })
        }
    };

    let limit = crate::args::parse_limit(args, "limit", 25, 64).unwrap_or(25);
    let mut entries = content
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| operation_history_matches(entry, args))
        .filter(|entry| replayable_audit_entry(entry))
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        left.get("ts")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .cmp(
                right
                    .get("ts")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default(),
            )
    });
    if entries.len() > limit {
        entries = entries.into_iter().rev().take(limit).collect::<Vec<_>>();
        entries.reverse();
    }

    let replay_steps = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| audit_entry_to_plan_step(index, entry))
        .collect::<Vec<_>>();

    let plan = crate::orchestration::engine::plan_chain(&json!({
        "action": "plan",
        "steps": replay_steps
    }));

    let plan_json = match plan {
        Ok(value) => value,
        Err(err) => json!({
            "success": false,
            "validation_errors": [err.to_string()],
            "plan": [],
            "effective_plan": [],
            "blocked_steps": []
        }),
    };
    let replay_summary = replay_summary_json(&plan_json);

    json!({
        "success": plan_json["success"].as_bool().unwrap_or(false),
        "configured": true,
        "path": path,
        "mode": "audit_replay_dry_run",
        "executes_live_actions": false,
        "filters": operation_history_filters_json(args),
        "entries_considered": entries.len(),
        "steps": plan_json["plan"].clone(),
        "effective_plan": plan_json["effective_plan"].clone(),
        "blocked_steps": plan_json["blocked_steps"].clone(),
        "validation_errors": plan_json["validation_errors"].clone(),
        "validation_warnings": plan_json["validation_warnings"].clone(),
        "policy_planner": plan_json["policy_planner"].clone(),
        "summary": replay_summary,
        "message": "Audit workflow replay dry-run completed without executing recorded operations"
    })
}

fn operation_history_matches(entry: &Value, args: &Value) -> bool {
    matches_optional_str(entry, args, "tool", &["tool"])
        && matches_optional_str(entry, args, "action", &["action"])
        && matches_optional_str(entry, args, "status", &["result_status", "status"])
        && matches_optional_str(entry, args, "request_id", &["request_id"])
        && matches_chain_id(entry, args)
        && matches_pid(entry, args)
        && matches_time_range(entry, args)
}

fn audit_history_path(args: &Value) -> Option<String> {
    args.get("audit_path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(crate::policy::audit_path)
}

fn operation_history_filters_json(args: &Value) -> Value {
    let mut filters = serde_json::Map::new();
    for key in [
        "tool",
        "action",
        "status",
        "pid",
        "request_id",
        "chain_id",
        "since",
        "until",
    ] {
        if let Some(value) = args.get(key) {
            filters.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(filters)
}

fn mutation_history_entry(entry: Value) -> Value {
    let state_change = entry.get("state_change").cloned().unwrap_or(Value::Null);
    json!({
        "ts": entry.get("ts").cloned().unwrap_or(Value::Null),
        "tool": entry.get("tool").cloned().unwrap_or(Value::Null),
        "action": entry.get("action").cloned().unwrap_or(Value::Null),
        "result_status": entry.get("result_status").cloned().unwrap_or(Value::Null),
        "correlation_id": entry.get("correlation_id").cloned().unwrap_or(Value::Null),
        "request_id": entry.get("request_id").cloned().unwrap_or(Value::Null),
        "purpose": entry.get("purpose").cloned().unwrap_or(Value::Null),
        "provenance": state_change.get("provenance").cloned().unwrap_or(Value::Null),
        "mutation": state_change.get("mutation").cloned().unwrap_or(Value::Null),
        "rollback": state_change.get("rollback").cloned().unwrap_or(Value::Null),
        "artifacts": entry.get("artifacts").cloned().unwrap_or_else(|| json!([])),
        "integrity": entry.get("integrity").cloned().unwrap_or(Value::Null),
    })
}

fn matches_optional_str(entry: &Value, args: &Value, arg_key: &str, entry_keys: &[&str]) -> bool {
    let Some(expected) = args
        .get(arg_key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return true;
    };

    entry_keys.iter().any(|entry_key| {
        entry
            .get(*entry_key)
            .and_then(|value| value.as_str())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
    })
}

fn matches_chain_id(entry: &Value, args: &Value) -> bool {
    let Some(expected) = args
        .get("chain_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return true;
    };

    entry
        .get("chain_id")
        .or_else(|| entry.pointer("/args/chain_id"))
        .or_else(|| entry.pointer("/context/chain_id"))
        .and_then(|value| value.as_str())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
}

fn matches_pid(entry: &Value, args: &Value) -> bool {
    let Some(expected) = crate::args::parse_u64_value(args.get("pid")) else {
        return true;
    };

    [
        "/args/pid",
        "/args/target_pid",
        "/args/protect_pid",
        "/context/pid",
        "/context/target_pid",
    ]
    .iter()
    .filter_map(|pointer| entry.pointer(pointer))
    .filter_map(crate::args::parse_u64)
    .any(|actual| actual == expected)
}

fn matches_time_range(entry: &Value, args: &Value) -> bool {
    let ts = entry
        .get("ts")
        .and_then(|value| value.as_str())
        .unwrap_or_default();

    if let Some(since) = args
        .get("since")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
    {
        if ts < since {
            return false;
        }
    }

    if let Some(until) = args
        .get("until")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
    {
        if ts > until {
            return false;
        }
    }

    true
}

fn replayable_audit_entry(entry: &Value) -> bool {
    let tool = entry
        .get("tool")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let action = entry
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();

    !tool.is_empty()
        && !action.is_empty()
        && crate::mcp::action_registry::is_known_tool_action(tool, action)
        && !matches!(tool, "memoric")
}

fn audit_entry_to_plan_step(index: usize, entry: &Value) -> Option<Value> {
    let tool = entry.get("tool").and_then(|value| value.as_str())?;
    let action = entry.get("action").and_then(|value| value.as_str())?;
    let mut step_args = entry.get("args").cloned().unwrap_or_else(|| json!({}));
    if let Some(object) = step_args.as_object_mut() {
        object.insert("action".to_string(), json!(action));
        object.insert("dry_run".to_string(), json!(true));
    }

    Some(json!({
        "tool": tool,
        "action": action,
        "args": step_args,
        "description": format!(
            "audit replay step {} from {}",
            index + 1,
            entry.get("ts").and_then(|value| value.as_str()).unwrap_or("unknown timestamp")
        ),
        "required": true,
        "audit": {
            "ts": entry.get("ts").cloned().unwrap_or(Value::Null),
            "request_id": entry.get("request_id").cloned().unwrap_or(Value::Null),
            "result_status": entry.get("result_status").cloned().unwrap_or(Value::Null),
        }
    }))
}

fn replay_summary_json(plan: &Value) -> Value {
    let steps = plan["plan"]
        .as_array()
        .map(|steps| steps.len())
        .unwrap_or(0);
    let effective = plan["effective_plan"]
        .as_array()
        .map(|steps| steps.len())
        .unwrap_or(0);
    let blocked = plan["blocked_steps"]
        .as_array()
        .map(|steps| steps.len())
        .unwrap_or(0);
    let validation_errors = plan["validation_errors"]
        .as_array()
        .map(|errors| errors.len())
        .unwrap_or(0);

    json!({
        "steps": steps,
        "would_now_be_allowed": effective,
        "would_now_be_blocked": blocked,
        "validation_errors": validation_errors,
        "changed": blocked > 0 || validation_errors > 0,
    })
}

// ─── Mutation helpers ────────────────────────────────────────────────────────

fn with_state<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut SessionState) -> R,
{
    SESSION
        .lock()
        .map(|mut s| f(&mut s))
        .map_err(|e| format!("Session lock error: {}", e))
}

pub fn set_target(pid: u32) {
    let _ = with_state(|s| {
        s.target_pid = Some(pid);
    });
}

pub fn record_edr_detection(products: &[EdrRecord]) {
    let _ = with_state(|s| {
        for p in products {
            if !s.detected_edrs.iter().any(|e| e.product == p.product) {
                s.detected_edrs.push(p.clone());
            }
        }
    });
}

pub fn record_driver(name: &str, device_path: &str, capabilities: &[&str]) {
    let _ = with_state(|s| {
        s.loaded_driver = Some(DriverRecord {
            name: name.to_string(),
            device_path: device_path.to_string(),
            loaded_at: chrono_now(),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        });
    });
}

pub fn record_evasion(technique: &str, target: &str, status: &str) {
    let _ = with_state(|s| {
        s.evasion_applied.push(EvasionRecord {
            technique: technique.to_string(),
            target: target.to_string(),
            applied_at: chrono_now(),
            status: status.to_string(),
        });
    });
}

pub fn record_injection(pid: u32, technique: &str, shellcode_size: usize) {
    let _ = with_state(|s| {
        s.active_injections.push(InjectionRecord {
            pid,
            technique: technique.to_string(),
            shellcode_size,
            injected_at: chrono_now(),
        });
    });
}

pub fn update_stealth_score(assessment: StealthAssessment) {
    let _ = with_state(|s| {
        s.stealth_score = Some(assessment);
    });
}

pub fn update_kernel_callbacks(status: KernelCallbackStatus) {
    let _ = with_state(|s| {
        s.kernel_callbacks_status = status;
    });
}

/// Reset the session to defaults (for fresh start)
pub fn reset_session() {
    let _ = with_state(|s| s.reset());
}

/// Compute a fresh stealth score from current state
pub fn compute_stealth_score() -> StealthAssessment {
    let state = get_state().unwrap_or_default();
    let mut score: u32 = 0;

    // ETW patched: +20
    let etw_patched = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("etw") && e.status == "applied");
    if etw_patched {
        score += 20;
    }

    // AMSI patched: +20
    let amsi_patched = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("amsi") && e.status == "applied");
    if amsi_patched {
        score += 20;
    }

    // ntdll unhooked: +15
    let ntdll_unhooked = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("unhook") && e.status == "applied");
    if ntdll_unhooked {
        score += 15;
    }

    // Modules hidden: +10
    let modules_hidden = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("hide_module") && e.status == "applied");
    if modules_hidden {
        score += 10;
    }

    // Kernel callbacks removed (each ~5 points, max 20)
    let cb = &state.kernel_callbacks_status;
    let callbacks_removed = cb.process_callbacks + cb.thread_callbacks + cb.image_callbacks;
    score += std::cmp::min(callbacks_removed * 5, 20);

    // Minifilters detached (each ~3 points, max 10)
    let minifilter_bonus = state
        .evasion_applied
        .iter()
        .filter(|e| e.technique.contains("minifilter"))
        .count() as u32
        * 3;
    score += std::cmp::min(minifilter_bonus, 10);

    // EDR penalty: -5 per EDR still detected
    let edr_penalty = std::cmp::min(state.detected_edrs.len() as u32 * 5, 25);
    score = score.saturating_sub(edr_penalty);

    // Cap at 100
    score = std::cmp::min(score, 100);

    StealthAssessment {
        total_score: score,
        etw_patched,
        amsi_patched,
        ntdll_unhooked,
        modules_hidden,
        callbacks_removed,
        minifilters_detached: minifilter_bonus / 3,
        edr_processes_detected: state.detected_edrs.len() as u32,
        assessed_at: chrono_now(),
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FIXTURE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct AuditPathGuard {
        previous: Option<String>,
    }

    impl AuditPathGuard {
        fn set(path: Option<&std::path::Path>) -> Self {
            let previous = std::env::var("MEMORIC_AUDIT_PATH").ok();
            match path {
                Some(path) => std::env::set_var("MEMORIC_AUDIT_PATH", path),
                None => std::env::remove_var("MEMORIC_AUDIT_PATH"),
            }
            Self { previous }
        }
    }

    impl Drop for AuditPathGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(previous) => std::env::set_var("MEMORIC_AUDIT_PATH", previous),
                None => std::env::remove_var("MEMORIC_AUDIT_PATH"),
            }
        }
    }

    fn write_audit_fixture() -> std::path::PathBuf {
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "memoric-operation-history-{}-{}.jsonl",
            std::process::id(),
            fixture_id
        ));
        let content = [
            r#"{"ts":"2026-05-22T00:00:01Z","tool":"memory","action":"read","result_status":"success","args":{"pid":123},"request_id":"r1"}"#,
            r#"{"ts":"2026-05-22T00:00:02Z","tool":"memory","action":"write","result_status":"denied","args":{"pid":456,"chain_id":"c1"},"request_id":"r2"}"#,
            r#"{"ts":"2026-05-22T00:00:03Z","tool":"self","action":"doctor","result_status":"success"}"#,
        ]
        .join("\n");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn write_mutation_audit_fixture() -> std::path::PathBuf {
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "memoric-mutation-history-{}-{}.jsonl",
            std::process::id(),
            fixture_id
        ));
        let content = [
            r#"{"ts":"2026-05-22T00:00:01Z","tool":"memory","action":"write","result_status":"success","correlation_id":"corr-1","request_id":"r1","args":{"pid":123,"chain_id":"c1"},"state_change":{"provenance":{"request_id":"r1","task_id":"task-1","chain_id":"c1"},"mutation":{"kind":"memory_write","target_pid":123},"rollback":{"available":true,"strategy":"restore_original_bytes","captured_fields":["original_bytes"],"action":{"tool":"memory","action":"write","args_present":true}}}}"#,
            r#"{"ts":"2026-05-22T00:00:02Z","tool":"memory","action":"read","result_status":"success","args":{"pid":123},"request_id":"r2"}"#,
            r#"{"ts":"2026-05-22T00:00:03Z","tool":"kernel","action":"driver_notify_routine","result_status":"success","correlation_id":"corr-2","request_id":"r3","args":{"pid":456,"chain_id":"c2"},"state_change":{"provenance":{"request_id":"r3","chain_id":"c2"},"mutation":{"kind":"kernel_live_mutation","resource":"notify_routine"},"rollback":{"available":"partial","strategy":"paired_restore_action"}}}"#,
        ]
        .join("\n");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn operation_history_reports_unconfigured_audit_path() {
        let _env_lock = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _audit_path = AuditPathGuard::set(None);
        let history = operation_history_json(&json!({}));

        assert_eq!(history["success"], true);
        assert_eq!(history["configured"], false);
        assert_eq!(history["entries"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn state_json_includes_rollback_and_cleanup_views() {
        let _env_lock = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let state = get_state_json().expect("state json");
        assert!(state.get("rollback_opportunities").is_some());
        assert!(state.get("cleanup_scope").is_some());
        assert!(state["cleanup_scope"]["available"]
            .as_bool()
            .unwrap_or(false));
    }

    #[test]
    fn cleanup_scope_json_expands_task_and_chain_ids() {
        let _env_lock = crate::state::TEST_ENV_LOCK.lock().unwrap();
        crate::observability::link_task("task-scope-fixture", "corr-task-scope");

        let scope = cleanup_scope_json(Some("task-scope-fixture"), Some("chain-scope"));
        assert_eq!(scope["task_id"], "task-scope-fixture");
        assert_eq!(scope["chain_id"], "chain-scope");
        assert_eq!(scope["targets"]["task_ids"][0], "corr-task-scope");
        assert_eq!(scope["targets"]["chain_ids"][0], "chain-scope");
    }

    #[test]
    fn operation_history_filters_by_identity_and_time_range() {
        let path = write_audit_fixture();

        let audit_path = path.display().to_string();
        let by_tool = operation_history_json(&json!({"audit_path": audit_path, "tool": "memory"}));
        assert_eq!(by_tool["total_count"], 2);
        assert_eq!(by_tool["entries"][0]["action"], "write");
        assert_eq!(by_tool["entries"][1]["action"], "read");

        let by_action =
            operation_history_json(&json!({"audit_path": audit_path, "action": "doctor"}));
        assert_eq!(by_action["total_count"], 1);
        assert_eq!(by_action["entries"][0]["tool"], "self");

        let by_status =
            operation_history_json(&json!({"audit_path": audit_path, "status": "denied"}));
        assert_eq!(by_status["total_count"], 1);
        assert_eq!(by_status["entries"][0]["request_id"], "r2");

        let by_pid = operation_history_json(&json!({"audit_path": audit_path, "pid": 123}));
        assert_eq!(by_pid["total_count"], 1);
        assert_eq!(by_pid["entries"][0]["request_id"], "r1");

        let by_request =
            operation_history_json(&json!({"audit_path": audit_path, "request_id": "r1"}));
        assert_eq!(by_request["total_count"], 1);
        assert_eq!(by_request["entries"][0]["args"]["pid"], 123);

        let by_chain = operation_history_json(&json!({"audit_path": audit_path, "chain_id": "c1"}));
        assert_eq!(by_chain["total_count"], 1);
        assert_eq!(by_chain["entries"][0]["request_id"], "r2");

        let by_time = operation_history_json(&json!({
            "audit_path": audit_path,
            "since": "2026-05-22T00:00:02Z",
            "until": "2026-05-22T00:00:03Z"
        }));
        assert_eq!(by_time["total_count"], 2);
        assert_eq!(by_time["entries"][0]["action"], "doctor");
        assert_eq!(by_time["entries"][1]["action"], "write");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn operation_history_paginates_newest_first() {
        let path = write_audit_fixture();
        let page = operation_history_json(&json!({
            "audit_path": path.display().to_string(),
            "offset": 1,
            "limit": 1
        }));

        assert_eq!(page["count"], 1);
        assert_eq!(page["total_count"], 3);
        assert_eq!(page["offset"], 1);
        assert_eq!(page["limit"], 1);
        assert_eq!(page["has_more"], true);
        assert_eq!(page["entries"][0]["action"], "write");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mutation_history_summarizes_state_change_entries() {
        let path = write_mutation_audit_fixture();

        let mutations = mutation_history_json(&json!({
            "audit_path": path.display().to_string(),
            "chain_id": "c1"
        }));

        assert_eq!(mutations["success"], true);
        assert_eq!(mutations["total_count"], 1);
        assert_eq!(mutations["entries"][0]["tool"], "memory");
        assert_eq!(mutations["entries"][0]["mutation"]["kind"], "memory_write");
        assert_eq!(
            mutations["entries"][0]["rollback"]["strategy"],
            "restore_original_bytes"
        );
        assert!(mutations["entries"][0]["rollback"]
            .get("original_bytes")
            .is_none());
        assert_eq!(mutations["entries"][0]["provenance"]["task_id"], "task-1");
        assert_eq!(mutations["redaction"]["summary_only"], true);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn workflow_replay_dry_run_plans_audit_steps_without_execution() {
        let path = write_audit_fixture();

        let replay = workflow_replay_dry_run_json(&json!({
            "audit_path": path.display().to_string(),
            "chain_id": "c1"
        }));

        assert_eq!(replay["mode"], "audit_replay_dry_run");
        assert_eq!(replay["executes_live_actions"], false);
        assert_eq!(replay["entries_considered"], 1);
        assert_eq!(replay["steps"].as_array().unwrap().len(), 1);
        assert_eq!(replay["steps"][0]["tool"], "memory");
        assert_eq!(replay["steps"][0]["action"], "write");
        assert_eq!(replay["steps"][0]["args"]["dry_run"], true);
        assert_eq!(replay["summary"]["steps"], 1);

        let _ = std::fs::remove_file(path);
    }
}

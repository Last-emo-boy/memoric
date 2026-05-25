//! Cooperative runtime controls for long-running tool calls.
//!
//! This module intentionally does not kill threads. Handlers opt in by checking
//! the runtime context at safe boundaries and returning a stable error.

use serde_json::Value;
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT_MS: u64 = 10 * 60 * 1000;
pub const MAX_TIMEOUT_MS: u64 = 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct RuntimeContext {
    task_id: Option<String>,
    deadline: Option<Instant>,
    timeout_ms: Option<u64>,
}

impl RuntimeContext {
    pub fn from_args(args: &Value) -> Result<Self, String> {
        let timeout_ms = crate::args::parse_timeout_ms(args, DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS)?;
        Ok(Self {
            task_id: args
                .get("task_id")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string),
            deadline: Some(Instant::now() + Duration::from_millis(timeout_ms)),
            timeout_ms: Some(timeout_ms),
        })
    }

    pub fn check(&self) -> Result<(), String> {
        if let Some(task_id) = self.task_id.as_deref() {
            if crate::mcp::tasks::is_cancel_requested(task_id) {
                return Err(cancelled_error(task_id));
            }
        }

        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(timeout_error(self.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)));
        }

        Ok(())
    }

    pub fn task_id(&self) -> Option<&str> {
        self.task_id.as_deref()
    }

    pub fn mark_running(&self, total: Option<u64>, summary: impl Into<String>) {
        if let Some(task_id) = self.task_id() {
            crate::mcp::tasks::mark_running(task_id, total, summary);
        }
    }

    pub fn update_progress(&self, current: u64, total: Option<u64>, summary: impl Into<String>) {
        if let Some(task_id) = self.task_id() {
            crate::mcp::tasks::update_progress(task_id, current, total, summary);
        }
    }
}

pub fn check_args(args: &Value) -> Result<(), String> {
    RuntimeContext::from_args(args)?.check()
}

pub fn timeout_error(timeout_ms: u64) -> String {
    format!("timeout: operation exceeded timeout_ms={}", timeout_ms)
}

pub fn cancelled_error(task_id: &str) -> String {
    format!("cancelled: task {} cancellation requested", task_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_context_rejects_excessive_timeout() {
        let err = RuntimeContext::from_args(&json!({"timeout_ms": MAX_TIMEOUT_MS + 1}))
            .expect_err("excessive timeout should fail");
        assert!(err.contains("timeout_ms"));
    }

    #[test]
    fn runtime_context_detects_cancelled_task() {
        let task_id = crate::mcp::tasks::create("self", "doctor", "test").expect("task");
        crate::mcp::tasks::cancel(&task_id).expect("cancel");
        let context = RuntimeContext::from_args(&json!({
            "task_id": task_id
        }))
        .expect("runtime context");

        let err = context.check().expect_err("cancel should be visible");
        assert!(err.contains("cancelled"));
    }

    #[test]
    fn runtime_context_updates_task_progress() {
        let task_id = crate::mcp::tasks::create("memory", "scan_new", "queued").expect("task");
        let context = RuntimeContext::from_args(&json!({
            "task_id": task_id
        }))
        .expect("runtime context");

        context.mark_running(Some(10), "scan_new: scanning regions");
        context.update_progress(4, Some(10), "scan_new: scanned 4/10 regions");

        let task = crate::mcp::tasks::get_json(context.task_id().expect("task id"));
        assert_eq!(task["task"]["progress"]["current"], 4);
        assert_eq!(task["task"]["progress"]["total"], 10);
        assert_eq!(
            task["task"]["statusMessage"],
            "scan_new: scanned 4/10 regions"
        );
    }
}

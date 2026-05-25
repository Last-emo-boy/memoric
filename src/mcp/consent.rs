//! Task-augmented consent and input continuation helpers.
//!
//! The task registry owns lifecycle state. This module owns the in-process
//! continuation data needed to resume a policy-gated operation after an
//! operator response. Continuations are intentionally not persisted.

use lazy_static::lazy_static;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::mcp::action_registry::{self, ActionTraits};
use crate::mcp::tool_args::normalize_common_args;

const CONSENT_STATE_KIND: &str = "policy_consent";
const CONSENT_GRANT_KEY: &str = "_memoric_consent_grant";

lazy_static! {
    static ref CONTINUATIONS: Mutex<HashMap<String, ConsentContinuation>> =
        Mutex::new(HashMap::new());
    static ref GRANTS: Mutex<HashMap<String, ConsentGrant>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Clone)]
struct ConsentContinuation {
    tool: String,
    action: String,
    args: Value,
    args_sha256: String,
    request_context: Option<crate::mcp::request_context::McpRequestContext>,
}

#[derive(Debug, Clone)]
struct ConsentGrant {
    tool: String,
    action: String,
    task_id: String,
    request_id: String,
    args_sha256: String,
}

pub(crate) fn maybe_create_input_required_task(
    tool: &str,
    args: &Value,
    options: crate::mcp::tasks::TaskOptions,
) -> Result<Option<String>, String> {
    let mut normalized_args = normalize_common_args(tool, args);
    let action = normalized_args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();
    if action.is_empty() || !action_registry::is_known_tool_action(tool, &action) {
        return Ok(None);
    }
    let traits = action_registry::classify_action(tool, &action);
    if !should_request_consent(&normalized_args, traits) {
        return Ok(None);
    }

    let request_context = options
        .request_context
        .clone()
        .or_else(crate::mcp::request_context::current_request_context);
    let policy_decision = crate::policy::evaluate_tool_call(tool, &normalized_args);
    let task_id = crate::mcp::tasks::create_with_options(
        tool,
        &action,
        format!("{} action='{}' waiting for operator consent", tool, action),
        crate::mcp::tasks::TaskOptions {
            request_context: request_context.clone(),
            ..options
        },
    )?;

    if let Some(obj) = normalized_args.as_object_mut() {
        obj.insert("task_id".to_string(), json!(task_id));
        obj.insert("as_task".to_string(), json!(false));
    }
    let args_sha256 = args_sha256(&normalized_args);
    let request_id = consent_request_id(&task_id, &args_sha256);
    let prompt = consent_prompt(tool, &action, traits, &policy_decision);
    let request_state = json!({
        "state": "awaiting_input",
        "kind": CONSENT_STATE_KIND,
        "tool": tool,
        "action": action,
        "arguments_sha256": args_sha256,
        "policy": policy_decision.as_json(),
        "consent": {
            "requestId": request_id,
            "required": true,
            "approval_does_not_elevate_policy": true
        },
        "continuation": {
            "stored": "process-local",
            "persisted": false,
            "arguments": crate::redaction::redact_value(
                &normalized_args,
                crate::redaction::RedactionProfile::Strict
            )
        }
    });

    crate::mcp::tasks::mark_input_required(
        &task_id,
        request_id.clone(),
        prompt,
        "form",
        consent_input_schema(traits),
        Some(request_state),
    )?;
    store_continuation(
        &task_id,
        &request_id,
        ConsentContinuation {
            tool: tool.to_string(),
            action,
            args: normalized_args,
            args_sha256,
            request_context,
        },
    )?;

    crate::audit::record_tool_call(
        tool,
        args,
        &policy_decision.as_json(),
        "input_required",
        Some("operator consent required before task execution"),
        None,
    );
    Ok(Some(task_id))
}

pub(crate) fn resume_after_input_response(
    task_id: &str,
    request_id: &str,
    input: &Value,
    response_id: &str,
) -> Result<(), String> {
    let Some(continuation) = take_continuation(task_id, request_id)? else {
        return Ok(());
    };

    if !input_approved(input) {
        let message = format!(
            "policy_denied: {}(action='{}') operator consent was denied",
            continuation.tool, continuation.action
        );
        let result = crate::mcp::protocol::tool_error_content(
            &continuation.tool,
            &continuation.args,
            &message,
        );
        crate::mcp::tasks::fail_with_result(task_id, message, Some(result));
        return Ok(());
    }

    let grant_id = register_grant(task_id, request_id, &continuation)?;
    let mut args = continuation.args.clone();
    inject_grant(
        &mut args,
        task_id,
        request_id,
        response_id,
        &grant_id,
        &continuation.args_sha256,
    );
    let task_id_for_thread = task_id.to_string();
    let tool = continuation.tool.clone();
    let context = continuation.request_context.clone();

    std::thread::Builder::new()
        .name(format!("memoric-consent-{}", task_id))
        .spawn(move || {
            if crate::mcp::tasks::is_cancel_requested(&task_id_for_thread) {
                crate::mcp::tasks::mark_cancelled(
                    &task_id_for_thread,
                    "task cancelled before consent continuation resumed",
                );
                return;
            }

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(context) = context {
                    crate::mcp::request_context::with_current_request_context(context, || {
                        crate::mcp::tool_call::call_tool(&tool, args.clone())
                    })
                } else {
                    crate::mcp::tool_call::call_tool(&tool, args.clone())
                }
            }));

            match result {
                Ok(Ok(value)) => {
                    if crate::mcp::tasks::is_cancel_requested(&task_id_for_thread) {
                        crate::mcp::tasks::mark_cancelled(
                            &task_id_for_thread,
                            "task cancelled after consent continuation completed",
                        );
                    } else {
                        crate::mcp::tasks::complete(
                            &task_id_for_thread,
                            crate::mcp::protocol::tool_success_content(&tool, &args, &value),
                        );
                    }
                }
                Ok(Err(error)) => {
                    let result = crate::mcp::protocol::tool_error_content(&tool, &args, &error);
                    if crate::error::classify_tool_error(&error).code == "cancelled" {
                        crate::mcp::tasks::mark_cancelled(&task_id_for_thread, error);
                    } else {
                        crate::mcp::tasks::fail_with_result(
                            &task_id_for_thread,
                            error,
                            Some(result),
                        );
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
                    crate::mcp::tasks::fail(
                        &task_id_for_thread,
                        format!("Tool '{}' panicked after consent: {}", tool, panic_msg),
                    );
                }
            }
        })
        .map_err(|err| format!("failed to spawn consent continuation: {}", err))?;

    Ok(())
}

pub(crate) fn consume_matching_grant(tool: &str, action: &str, args: &Value) -> bool {
    let Some(grant) = args
        .get(CONSENT_GRANT_KEY)
        .and_then(|value| value.as_object())
    else {
        return false;
    };
    let Some(grant_id) = grant.get("grant_id").and_then(|value| value.as_str()) else {
        return false;
    };
    let Some(task_id) = grant.get("task_id").and_then(|value| value.as_str()) else {
        return false;
    };
    let Some(request_id) = grant.get("request_id").and_then(|value| value.as_str()) else {
        return false;
    };
    let Some(args_hash) = grant
        .get("arguments_sha256")
        .and_then(|value| value.as_str())
    else {
        return false;
    };

    let Ok(mut grants) = GRANTS.lock() else {
        return false;
    };
    let Some(stored) = grants.remove(grant_id) else {
        return false;
    };
    stored.tool == tool
        && stored.action == action
        && stored.task_id == task_id
        && stored.request_id == request_id
        && stored.args_sha256 == args_hash
        && args_sha256_without_grant(args) == stored.args_sha256
}

fn should_request_consent(args: &Value, traits: ActionTraits) -> bool {
    if args
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    traits.state_changing
}

fn consent_prompt(
    tool: &str,
    action: &str,
    traits: ActionTraits,
    decision: &crate::policy::PolicyDecision,
) -> String {
    format!(
        "Approve {}(action='{}') requiring policy '{}'. Current policy is '{}'. Approval records operator intent but does not elevate policy.",
        tool,
        action,
        traits.required_policy.as_str(),
        decision.configured_level.as_str()
    )
}

fn consent_input_schema(traits: ActionTraits) -> Value {
    json!({
        "type": "object",
        "properties": {
            "approved": {
                "type": "boolean",
                "description": "Set true to continue the task, false to deny it."
            },
            "reason": {
                "type": "string",
                "description": "Optional operator-visible reason for the decision."
            },
            "expected_policy": {
                "type": "string",
                "const": traits.required_policy.as_str()
            }
        },
        "required": ["approved"],
        "additionalProperties": true
    })
}

fn input_approved(input: &Value) -> bool {
    input
        .get("approved")
        .or_else(|| input.get("approve"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || input
            .get("decision")
            .and_then(|value| value.as_str())
            .is_some_and(|value| matches!(value, "approved" | "approve" | "allow" | "yes"))
}

fn store_continuation(
    task_id: &str,
    request_id: &str,
    continuation: ConsentContinuation,
) -> Result<(), String> {
    let key = continuation_key(task_id, request_id);
    CONTINUATIONS
        .lock()
        .map_err(|err| format!("consent continuation lock error: {}", err))?
        .insert(key, continuation);
    Ok(())
}

fn take_continuation(
    task_id: &str,
    request_id: &str,
) -> Result<Option<ConsentContinuation>, String> {
    let key = continuation_key(task_id, request_id);
    Ok(CONTINUATIONS
        .lock()
        .map_err(|err| format!("consent continuation lock error: {}", err))?
        .remove(&key))
}

fn register_grant(
    task_id: &str,
    request_id: &str,
    continuation: &ConsentContinuation,
) -> Result<String, String> {
    let seed = format!(
        "{}:{}:{}:{}:{}",
        task_id, request_id, continuation.tool, continuation.action, continuation.args_sha256
    );
    let grant_id = format!("consent-grant-{}", short_hash(seed.as_bytes(), 24));
    GRANTS
        .lock()
        .map_err(|err| format!("consent grant lock error: {}", err))?
        .insert(
            grant_id.clone(),
            ConsentGrant {
                tool: continuation.tool.clone(),
                action: continuation.action.clone(),
                task_id: task_id.to_string(),
                request_id: request_id.to_string(),
                args_sha256: continuation.args_sha256.clone(),
            },
        );
    Ok(grant_id)
}

fn inject_grant(
    args: &mut Value,
    task_id: &str,
    request_id: &str,
    response_id: &str,
    grant_id: &str,
    args_sha256: &str,
) {
    if let Some(obj) = args.as_object_mut() {
        obj.insert(
            CONSENT_GRANT_KEY.to_string(),
            json!({
                "grant_id": grant_id,
                "task_id": task_id,
                "request_id": request_id,
                "response_id": response_id,
                "arguments_sha256": args_sha256
            }),
        );
    }
}

fn args_sha256(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    crate::artifact::sha256_bytes(&bytes)
}

fn args_sha256_without_grant(value: &Value) -> String {
    let mut value = value.clone();
    if let Some(obj) = value.as_object_mut() {
        obj.remove(CONSENT_GRANT_KEY);
    }
    args_sha256(&value)
}

fn consent_request_id(task_id: &str, args_sha256: &str) -> String {
    let seed = format!("{}:{}", task_id, args_sha256);
    format!("consent-{}", short_hash(seed.as_bytes(), 16))
}

fn continuation_key(task_id: &str, request_id: &str) -> String {
    format!("{}:{}", task_id, request_id)
}

fn short_hash(bytes: &[u8], chars: usize) -> String {
    let hash = crate::artifact::sha256_bytes(bytes);
    hash.chars().take(chars).collect()
}

#[cfg(test)]
pub(crate) fn has_pending_continuation_for_test(task_id: &str, request_id: &str) -> bool {
    CONTINUATIONS.lock().ok().is_some_and(|continuations| {
        continuations.contains_key(&continuation_key(task_id, request_id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Duration, Instant};

    fn clear_policy_env() {
        std::env::remove_var("MEMORIC_POLICY");
        std::env::remove_var("MEMORIC_TARGET_ALLOWLIST");
        std::env::remove_var("MEMORIC_CONSENT_TOKEN");
        std::env::remove_var("MEMORIC_ALLOW_PROTECTED_TARGETS");
        std::env::remove_var("MEMORIC_POLICY_PROFILE_PATH");
        std::env::remove_var("MEMORIC_POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE");
    }

    #[test]
    fn state_changing_task_pauses_for_consent_without_leaking_raw_args() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let task_id = spawn_consent_task(
            "memory",
            &json!({
                "action": "write",
                "pid": std::process::id(),
                "address": "0x1000",
                "bytes": [1, 2, 3, 4]
            }),
        )
        .expect("state-changing task should pause for consent");

        let task = crate::mcp::tasks::get_json(&task_id);
        assert_eq!(task["task"]["status"], "input_required");
        assert_eq!(task["task"]["requestState"]["kind"], CONSENT_STATE_KIND);
        assert!(task["task"]["requestState"]["arguments_sha256"]
            .as_str()
            .is_some());
        assert_eq!(
            task["task"]["requestState"]["continuation"]["arguments"]["bytes"]["redacted"],
            true
        );
        let request_id = task["task"]["inputRequests"][0]["request_id"]
            .as_str()
            .expect("request id");
        assert!(has_pending_continuation_for_test(&task_id, request_id));
        clear_policy_env();
    }

    #[test]
    fn denied_input_fails_consent_task() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let task_id = spawn_consent_task(
            "memory",
            &json!({
                "action": "write",
                "pid": std::process::id(),
                "address": "0x1000",
                "bytes": [1, 2, 3, 4]
            }),
        )
        .expect("state-changing task should pause for consent");
        let request_id = crate::mcp::tasks::get_json(&task_id)["task"]["inputRequests"][0]
            ["request_id"]
            .as_str()
            .unwrap()
            .to_string();

        crate::mcp::tasks::input_response_request(&json!({
            "params": {
                "taskId": task_id,
                "requestId": request_id,
                "input": { "approved": false, "reason": "fixture denial" }
            }
        }))
        .expect("denial response should be accepted");

        let task = wait_for_terminal(&task_id);
        assert_eq!(task["task"]["status"], "failed");
        assert_eq!(
            task["task"]["result"]["structuredContent"]["code"],
            "policy_denied"
        );
        clear_policy_env();
    }

    #[test]
    fn approval_resumes_without_elevating_policy() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let task_id = spawn_consent_task(
            "memory",
            &json!({
                "action": "write",
                "pid": std::process::id(),
                "address": "0x1000",
                "bytes": [1, 2, 3, 4]
            }),
        )
        .expect("state-changing task should pause for consent");
        let request_id = crate::mcp::tasks::get_json(&task_id)["task"]["inputRequests"][0]
            ["request_id"]
            .as_str()
            .unwrap()
            .to_string();

        crate::mcp::tasks::input_response_request(&json!({
            "params": {
                "taskId": task_id,
                "requestId": request_id,
                "input": { "approved": true }
            }
        }))
        .expect("approval response should be accepted");

        let task = wait_for_terminal(&task_id);
        assert_eq!(task["task"]["status"], "failed");
        assert_eq!(
            task["task"]["result"]["structuredContent"]["code"],
            "policy_denied"
        );
        clear_policy_env();
    }

    #[test]
    fn approval_resumes_state_changing_task_when_policy_allows() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        std::env::set_var("MEMORIC_POLICY", "lab-write");
        let mut buffer = [0u8; 8];
        let task_id = spawn_consent_task(
            "memory",
            &json!({
                "action": "write",
                "pid": std::process::id(),
                "address": buffer.as_mut_ptr() as u64,
                "bytes": [0x41, 0x42, 0x43, 0x44],
                "bypass_protect": false
            }),
        )
        .expect("state-changing task should pause for consent");
        let request_id = crate::mcp::tasks::get_json(&task_id)["task"]["inputRequests"][0]
            ["request_id"]
            .as_str()
            .unwrap()
            .to_string();

        crate::mcp::tasks::input_response_request(&json!({
            "params": {
                "taskId": task_id,
                "requestId": request_id,
                "input": { "approved": true }
            }
        }))
        .expect("approval response should be accepted");

        let task = wait_for_terminal(&task_id);
        assert_eq!(task["task"]["status"], "completed");
        assert_eq!(&buffer[..4], &[0x41, 0x42, 0x43, 0x44]);
        clear_policy_env();
    }

    fn spawn_consent_task(tool: &str, args: &Value) -> Result<String, String> {
        crate::mcp::tasks::spawn_tool_task_with_options(
            tool,
            args,
            crate::mcp::tasks::TaskOptions {
                input_required_on_policy: true,
                ..crate::mcp::tasks::TaskOptions::default()
            },
        )
    }

    fn wait_for_terminal(task_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let task = crate::mcp::tasks::get_json(task_id);
            let status = task["task"]["status"].as_str().unwrap_or_default();
            if matches!(status, "completed" | "failed" | "cancelled") {
                return task;
            }
            assert!(
                Instant::now() < deadline,
                "task did not reach terminal state: {task}"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

//! MCP tool-call facade.
//!
//! This module owns the cross-cutting call path: legacy alias resolution,
//! common argument normalization, runtime checks, policy, dry-run previews,
//! dispatch, state tracing, audit, and observability.

use serde_json::{json, Value};

use crate::mcp::tool_args::{
    normalize_common_args, validate_choice_parameters, validate_common_input_bounds,
    validate_parameter_bounds, validate_parser_hints, validate_required_parameters,
};

fn resolve_legacy_tool(name: &str, args: Value) -> Result<(String, Value), String> {
    crate::mcp::legacy_tools::resolve(name, args)
}

pub fn call_tool(name: &str, args: Value) -> Result<Value, String> {
    let (resolved_name, resolved_args) = if crate::mcp::tool_dispatch::is_standard_tool(name) {
        (name.to_string(), args)
    } else {
        resolve_legacy_tool(name, args)?
    };

    let normalized_args = normalize_common_args(&resolved_name, &resolved_args);
    crate::observability::record_tool_dispatch(&resolved_name, &normalized_args);
    validate_required_parameters(&resolved_name, &normalized_args)?;
    validate_choice_parameters(&resolved_name, &normalized_args)?;
    validate_common_input_bounds(&resolved_name, &normalized_args)?;
    validate_parameter_bounds(&resolved_name, &normalized_args)?;
    validate_parser_hints(&resolved_name, &normalized_args)?;
    crate::runtime::check_args(&normalized_args)?;
    crate::mcp::platform_gate::validate_tool_call(&resolved_name, &normalized_args)?;
    let policy_decision = crate::policy::evaluate_tool_call(&resolved_name, &normalized_args);
    if !policy_decision.allowed {
        let error = crate::policy::denial_error(&resolved_name, &normalized_args, &policy_decision);
        crate::observability::record_tool_result(
            &resolved_name,
            &normalized_args,
            "denied",
            Some(&error),
        );
        crate::audit::record_tool_call(
            &resolved_name,
            &normalized_args,
            &policy_decision.as_json(),
            "denied",
            Some(&error),
            None,
        );
        return Err(error);
    }

    if should_return_dry_run_preview(&resolved_name, &normalized_args) {
        let preview = crate::mcp::dry_run::preview(&resolved_name, &normalized_args);
        crate::observability::record_tool_result(
            &resolved_name,
            &normalized_args,
            "dry_run",
            Some("dry-run preview returned"),
        );
        crate::audit::record_tool_call(
            &resolved_name,
            &normalized_args,
            &policy_decision.as_json(),
            "dry_run",
            None,
            Some(&preview),
        );
        return Ok(preview);
    }

    let result = crate::mcp::tool_dispatch::dispatch(&resolved_name, &normalized_args)
        .map(|value| attach_live_state_change_provenance(&resolved_name, &normalized_args, value));

    if result.is_ok() {
        crate::mcp::tool_state::record_trace(&resolved_name, &normalized_args);
    }

    crate::observability::record_tool_result(
        &resolved_name,
        &normalized_args,
        if result.is_ok() { "success" } else { "error" },
        result
            .as_ref()
            .err()
            .map(|message| message.as_str())
            .or(Some("tool call completed")),
    );

    crate::audit::record_tool_call(
        &resolved_name,
        &normalized_args,
        &policy_decision.as_json(),
        if result.is_ok() { "success" } else { "error" },
        result.as_ref().err().map(|s| s.as_str()),
        result.as_ref().ok(),
    );

    result
}

fn should_return_dry_run_preview(tool: &str, args: &Value) -> bool {
    crate::mcp::dry_run::should_preview(tool, args)
}

fn attach_live_state_change_provenance(tool: &str, args: &Value, mut result: Value) -> Value {
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if !crate::mcp::action_registry::classify_action(tool, action).state_changing {
        return result;
    }

    if let Some(obj) = result.as_object_mut() {
        obj.entry("provenance".to_string())
            .or_insert_with(|| provenance_json(args));
    }

    result
}

fn provenance_json(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn standard_tool_calls_are_dispatched_after_normalization() {
        let result = call_tool(
            "self",
            json!({
                "action": "explain_error",
                "error": "timeout: operation exceeded timeout_ms=5"
            }),
        )
        .expect("self explain_error should dispatch");

        assert_eq!(result["code"], "timeout");
    }

    #[test]
    fn legacy_tool_calls_are_resolved_before_dispatch() {
        let result = call_tool("status", json!({})).expect("legacy status should dispatch to self");

        assert_eq!(result["name"], "memoric");
        assert!(result["version"].as_str().is_some());
        assert_eq!(result["tools"], 12);
    }

    #[test]
    fn dry_run_preview_short_circuits_live_dispatch() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        std::env::remove_var("MEMORIC_POLICY");

        let result = call_tool(
            "memory",
            json!({
                "action": "write",
                "pid": 999999,
                "address": "0x1000",
                "bytes": [1, 2, 3],
                "dry_run": true
            }),
        )
        .expect("dry run preview should be allowed");

        assert_eq!(result["success"], true);
        assert_eq!(result["dry_run"], true);
        assert_eq!(result["would_execute"], false);
    }

    #[test]
    fn required_parameter_preflight_uses_action_registry_before_dispatch() {
        let error = call_tool("memory", json!({"action": "alloc", "pid": 999999}))
            .expect_err("missing registry-declared size should fail before dispatch");

        assert!(error.contains("memory(action='alloc')"));
        assert!(error.contains("requires 'size'"));
        assert!(error.contains("action registry"));
    }

    #[test]
    fn memory_write_required_parameter_preflight_runs_before_dry_run_preview() {
        let error = call_tool(
            "memory",
            json!({
                "action": "write",
                "pid": 999999,
                "address": "0x1000",
                "dry_run": true
            }),
        )
        .expect_err("missing write payload should fail before dry-run preview");

        assert!(error.contains("memory(action='write')"));
        assert!(error.contains("requires 'bytes' or 'text'"));
        assert!(error.contains("either a byte payload or deprecated text"));
    }

    #[test]
    fn parameter_bounds_preflight_runs_before_dry_run_preview() {
        let error = call_tool(
            "orchestrate",
            json!({
                "action": "plan",
                "limit": crate::orchestration::engine::MAX_ORCHESTRATION_PAGE_LIMIT as u64 + 1,
                "dry_run": true
            }),
        )
        .expect_err("registry-declared bounds should fail before dry-run preview");

        assert!(error.contains("orchestrate(action='plan')"));
        assert!(error.contains("limit"));
        assert!(error.contains("<= 100"));
    }

    #[test]
    fn common_input_bounds_preflight_uses_registry_before_runtime() {
        let error = call_tool(
            "memory",
            json!({
                "action": "read",
                "pid": 999999,
                "address": "0x1000",
                "size": 1,
                "timeout_ms": 0
            }),
        )
        .expect_err("registry common input bounds should fail before runtime timeout checks");

        assert!(error.contains("memory(action='read')"));
        assert!(error.contains("timeout_ms"));
        assert!(error.contains(">= 1"));
    }

    #[test]
    fn live_state_changing_success_result_receives_provenance() {
        let result = attach_live_state_change_provenance(
            "stealth",
            &json!({
                "action": "patch_etw",
                "request_id": "req-state",
                "task_id": "task-state",
                "chain_id": "chain-state",
                "purpose": "test state provenance"
            }),
            json!({
                "success": true,
                "technique": "unit-test"
            }),
        );

        assert_eq!(result["provenance"]["correlation_id"], "req-state");
        assert_eq!(result["provenance"]["request_id"], "req-state");
        assert_eq!(result["provenance"]["task_id"], "task-state");
        assert_eq!(result["provenance"]["chain_id"], "chain-state");
        assert_eq!(result["provenance"]["purpose"], "test state provenance");
    }

    #[test]
    fn live_state_changing_success_preserves_handler_provenance() {
        let result = attach_live_state_change_provenance(
            "kernel",
            &json!({
                "action": "driver_load",
                "request_id": "req-wrapper"
            }),
            json!({
                "success": true,
                "provenance": {
                    "request_id": "req-handler"
                }
            }),
        );

        assert_eq!(result["provenance"]["request_id"], "req-handler");
    }

    #[test]
    fn read_only_success_result_is_not_annotated_as_mutation_provenance() {
        let result = attach_live_state_change_provenance(
            "self",
            &json!({
                "action": "info",
                "request_id": "req-read"
            }),
            json!({
                "success": true,
                "name": "memoric"
            }),
        );

        assert!(result["provenance"].is_null());
    }

    #[test]
    fn unsupported_platform_gate_keeps_status_available_and_blocks_windows_handlers() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        struct EnvRestore(Option<String>);
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                if let Some(previous) = &self.0 {
                    std::env::set_var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM", previous);
                } else {
                    std::env::remove_var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM");
                }
            }
        }
        let _env = EnvRestore(std::env::var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM").ok());
        std::env::set_var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM", "1");

        let status = call_tool("self", json!({"action": "status"}))
            .expect("self status should remain available as platform fallback");
        assert_eq!(status["name"], "memoric");

        let error = call_tool(
            "memory",
            json!({
                "action": "read",
                "pid": std::process::id(),
                "address": "0x1000",
                "size": 4
            }),
        )
        .expect_err("Windows-backed memory read should be platform-gated");

        assert!(error.contains("unsupported_platform"));
        assert!(error.contains("memory(action='read')"));
    }
}

//! Kernel action metadata helpers.

use serde_json::{json, Value};

use crate::mcp::action_registry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelDriverSourceRequirement {
    Memoric,
    Byovd,
    MemoricOrByovd,
    ServiceControl,
    LocalKernelPrimitive,
}

impl KernelDriverSourceRequirement {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memoric => "memoric",
            Self::Byovd => "byovd",
            Self::MemoricOrByovd => "memoric_or_byovd",
            Self::ServiceControl => "service_control",
            Self::LocalKernelPrimitive => "local_kernel_primitive",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelOffsetRequirement {
    None,
    CallbackRegistry,
    EprocessRuntime,
    PageTableOrVad,
    DriverReported,
}

impl KernelOffsetRequirement {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CallbackRegistry => "callback_registry",
            Self::EprocessRuntime => "eprocess_runtime",
            Self::PageTableOrVad => "page_table_or_vad",
            Self::DriverReported => "driver_reported",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelPreflightRequirements {
    driver_source: KernelDriverSourceRequirement,
    offset_requirement: KernelOffsetRequirement,
    requires_driver_version: bool,
    requires_os_build: bool,
    requires_driver_capabilities: bool,
    requires_explicit_device_path: bool,
    requires_service_control: bool,
}

impl KernelPreflightRequirements {
    fn for_action(action: &str, explicit_byovd: bool) -> Self {
        let driver_source = if matches!(action, "driver_load" | "driver_unload" | "driver_auto") {
            KernelDriverSourceRequirement::ServiceControl
        } else if matches!(
            action,
            "physical_read" | "physical_write" | "sniff_start" | "sniff_stop"
        ) {
            KernelDriverSourceRequirement::LocalKernelPrimitive
        } else if is_hybrid_kernel_action(action) {
            if explicit_byovd {
                KernelDriverSourceRequirement::Byovd
            } else {
                KernelDriverSourceRequirement::MemoricOrByovd
            }
        } else if is_memoric_direct_kernel_action(action) {
            KernelDriverSourceRequirement::Memoric
        } else {
            KernelDriverSourceRequirement::Byovd
        };

        let offset_requirement = match action {
            "enum_callbacks"
            | "remove_callback"
            | "object_callback_enum"
            | "object_callback_remove"
            | "registry_callback_enum"
            | "registry_callback_remove" => KernelOffsetRequirement::CallbackRegistry,
            "ppl_bypass"
            | "dkom_hide"
            | "token_escalate"
            | "driver_ppl_bypass"
            | "driver_token_swap"
            | "driver_token_dup"
            | "driver_eprocess_spoof"
            | "driver_process_protect"
            | "driver_thread_hide"
            | "driver_handle_strip"
            | "driver_force_kill"
            | "driver_set_debug_port"
            | "driver_impersonate" => KernelOffsetRequirement::EprocessRuntime,
            "pte_modify" | "vad_hide" | "driver_pte_rw" | "driver_cr_rw" | "driver_idt_rw"
            | "driver_msr_rw" => KernelOffsetRequirement::PageTableOrVad,
            action if action.starts_with("driver_") => KernelOffsetRequirement::DriverReported,
            _ => KernelOffsetRequirement::None,
        };

        let requires_driver_capabilities = matches!(
            driver_source,
            KernelDriverSourceRequirement::Memoric | KernelDriverSourceRequirement::MemoricOrByovd
        );
        let requires_driver_version = matches!(
            driver_source,
            KernelDriverSourceRequirement::Memoric | KernelDriverSourceRequirement::MemoricOrByovd
        );

        Self {
            driver_source,
            offset_requirement,
            requires_driver_version,
            requires_os_build: offset_requirement != KernelOffsetRequirement::None,
            requires_driver_capabilities,
            requires_explicit_device_path: matches!(
                driver_source,
                KernelDriverSourceRequirement::Byovd
            ),
            requires_service_control: matches!(
                driver_source,
                KernelDriverSourceRequirement::ServiceControl
            ),
        }
    }

    fn to_json(self) -> Value {
        json!({
            "driver_source": self.driver_source.as_str(),
            "offset_requirement": self.offset_requirement.as_str(),
            "requires_driver_version": self.requires_driver_version,
            "requires_os_build": self.requires_os_build,
            "requires_driver_capabilities": self.requires_driver_capabilities,
            "requires_explicit_device_path": self.requires_explicit_device_path,
            "requires_service_control": self.requires_service_control,
        })
    }
}

pub(crate) fn is_hybrid_kernel_action(action: &str) -> bool {
    matches!(action, "ppl_bypass" | "dkom_hide" | "token_escalate")
}

pub(crate) fn is_memoric_direct_kernel_action(action: &str) -> bool {
    action.starts_with("driver_")
        && !matches!(
            action,
            "driver_load" | "driver_unload" | "driver_discover" | "driver_auto"
        )
}

pub(crate) fn annotate_kernel_result(
    mut result: Value,
    action: &str,
    args: &Value,
    memoric_available_before: bool,
) -> Value {
    let Some(obj) = result.as_object_mut() else {
        return result;
    };

    if is_hybrid_kernel_action(action) {
        let explicit_byovd = args
            .get("device_path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some();

        obj.entry("driver_source".to_string())
            .or_insert(json!(if explicit_byovd { "byovd" } else { "memoric" }));
        obj.entry("driver_auto_installed".to_string())
            .or_insert(json!(!explicit_byovd && !memoric_available_before));
        obj.entry("fallback_used".to_string())
            .or_insert(json!(false));
        obj.entry("memoric_preferred".to_string())
            .or_insert(json!(true));
    } else if is_memoric_direct_kernel_action(action) {
        obj.entry("driver_source".to_string())
            .or_insert(json!("memoric"));
        obj.entry("driver_auto_installed".to_string())
            .or_insert(json!(!memoric_available_before));
        obj.entry("fallback_used".to_string())
            .or_insert(json!(false));
        obj.entry("memoric_preferred".to_string())
            .or_insert(json!(true));
    }

    result
}

pub(crate) fn kernel_mutation_preflight(action: &str, args: &Value) -> Option<Value> {
    let traits = action_registry::classify_action("kernel", action);
    if !traits.state_changing {
        return None;
    }

    let policy = crate::policy::evaluate_tool_call("kernel", args);
    let required_parameters = action_registry::required_parameters("kernel", action);
    let missing_parameters = required_parameters
        .iter()
        .filter(|parameter| !has_preflight_value(args, parameter))
        .copied()
        .collect::<Vec<_>>();
    let skip_capability_probe = !policy.allowed || !missing_parameters.is_empty();
    let runtime = if skip_capability_probe {
        None
    } else {
        Some(crate::capability::runtime_readiness_json(args))
    };
    let driver = runtime
        .as_ref()
        .map(|value| value["driver"].clone())
        .unwrap_or_else(|| {
            json!({
                "device": {
                    "path": "\\\\.\\Memoric",
                    "reachable": null,
                    "probe_only": true,
                    "probe_skipped": true
                },
                "payload": Value::Null,
                "signing": Value::Null,
                "wdac": Value::Null,
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": false
                },
                "message": "capability probe skipped because policy or required-parameter preflight already blocked execution"
            })
        });
    let explicit_byovd = args
        .get("device_path")
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty());
    let requirements = KernelPreflightRequirements::for_action(action, explicit_byovd);
    let byovd_preflight = if matches!(
        requirements.driver_source,
        KernelDriverSourceRequirement::Byovd | KernelDriverSourceRequirement::MemoricOrByovd
    ) && explicit_byovd
    {
        Some(crate::kernel::byovd_preflight_json(args))
    } else {
        None
    };
    let driver_reachable = driver["device"]["reachable"].as_bool().unwrap_or(false);
    let driver_load_possible = driver["readiness"]["driver_load_possible"]
        .as_bool()
        .unwrap_or(false);
    let build_number = runtime.as_ref().and_then(|value| {
        value["platform"]["windows"]["current_build"]
            .as_str()
            .and_then(|value| value.parse::<u32>().ok())
    });

    let offset_profile = build_number
        .map(|build| crate::kernel_offsets::driver_offset_profile_json(build, false))
        .unwrap_or_else(|| {
            json!({
                "build_number": null,
                "known_build": false,
                "source": "windows_build_unavailable",
                "supported_builds": crate::kernel_offsets::supported_builds_summary(),
                "eprocess": {
                    "strategy": "driver_dynamic_discovery",
                    "resolved": null,
                    "confidence": "unknown",
                    "note": "EPROCESS runtime offsets are only confirmed after the driver reports capabilities."
                },
                "callback_offsets": {
                    "strategy": "kernel_offset_registry",
                    "confidence": "unknown",
                    "supported_builds": crate::kernel_offsets::supported_builds_summary()
                }
            })
        });

    let requirement_blockers = kernel_requirement_blockers(
        requirements,
        &driver,
        explicit_byovd,
        byovd_preflight.as_ref(),
        build_number,
    );
    let safe_to_attempt = policy.allowed
        && missing_parameters.is_empty()
        && requirement_blockers.is_empty()
        && (action == "driver_load"
            || action == "driver_auto"
            || explicit_byovd
            || driver_reachable
            || driver_load_possible);

    let status = if safe_to_attempt { "ready" } else { "blocked" };

    Some(json!({
        "schema_version": 1,
        "kind": "kernel_mutation_preflight",
        "tool": "kernel",
        "action": action,
        "status": status,
        "safe_to_attempt": safe_to_attempt,
        "checked_before_mutation": true,
        "capability_probe": {
            "executed": !skip_capability_probe,
            "probe_only": true,
            "skipped_reason": if skip_capability_probe {
                "policy_or_required_parameter_blocker"
            } else {
                "not_skipped"
            }
        },
        "policy": policy.as_json(),
        "traits": {
            "read_only": traits.read_only,
            "state_changing": traits.state_changing,
            "privileged": traits.privileged,
            "kernel": traits.kernel,
            "destructive": traits.destructive,
            "risk": traits.risk.as_str(),
            "required_policy": traits.required_policy.as_str(),
        },
        "required_parameters": required_parameters,
        "missing_parameters": missing_parameters,
        "requirements": requirements.to_json(),
        "driver": {
            "source": requirements.driver_source.as_str(),
            "explicit_byovd": explicit_byovd,
            "device": driver["device"].clone(),
            "payload": driver["payload"].clone(),
            "signing": driver["signing"].clone(),
            "wdac": driver["wdac"].clone(),
            "readiness": driver["readiness"].clone(),
            "message": driver["message"].clone(),
        },
        "byovd": byovd_preflight.clone().unwrap_or(Value::Null),
        "platform": runtime
            .as_ref()
            .map(|value| value["platform"].clone())
            .unwrap_or(Value::Null),
        "privilege": runtime
            .as_ref()
            .map(|value| value["privilege"].clone())
            .unwrap_or(Value::Null),
        "offset_profile": offset_profile,
        "blockers": kernel_preflight_blockers(
            &policy,
            &missing_parameters,
            &driver,
            explicit_byovd,
            action,
            &requirement_blockers
        ),
        "message": if safe_to_attempt {
            "kernel mutation preflight passed; live handler may attempt execution"
        } else {
            "kernel mutation preflight blocked execution before the live mutation handler"
        }
    }))
}

pub(crate) fn require_kernel_mutation_preflight(
    action: &str,
    args: &Value,
) -> Result<Option<Value>, String> {
    let Some(preflight) = kernel_mutation_preflight(action, args) else {
        return Ok(None);
    };

    if preflight["safe_to_attempt"].as_bool().unwrap_or(false) {
        Ok(Some(preflight))
    } else {
        Err(format!(
            "kernel_preflight_failed: kernel(action='{}') blocked before live mutation. {}",
            action, preflight["blockers"]
        ))
    }
}

pub(crate) fn attach_kernel_preflight(mut result: Value, preflight: Option<Value>) -> Value {
    let Some(preflight) = preflight else {
        return result;
    };

    if let Some(obj) = result.as_object_mut() {
        obj.entry("preflight".to_string()).or_insert(preflight);
    }

    result
}

pub(crate) fn attach_kernel_live_metadata(mut result: Value, action: &str, args: &Value) -> Value {
    let provenance = kernel_provenance(args);
    let state_changing = kernel_live_state_changing(action, args, &result);
    let mutation = state_changing.then(|| kernel_mutation_metadata(action, args, &result));
    let rollback = state_changing.then(|| kernel_rollback_metadata(action, args, &result));

    if let Some(obj) = result.as_object_mut() {
        obj.entry("provenance".to_string()).or_insert(provenance);
        if let Some(mutation) = mutation {
            obj.entry("mutation".to_string()).or_insert(mutation);
        }
        if let Some(rollback) = rollback {
            obj.entry("rollback".to_string()).or_insert(rollback);
        }
    }

    result
}

fn kernel_provenance(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn kernel_live_state_changing(action: &str, args: &Value, result: &Value) -> bool {
    if !action_registry::classify_action("kernel", action).state_changing {
        return false;
    }
    if kernel_observation_action(action) {
        return false;
    }
    kernel_leaf_action(args, result)
        .as_deref()
        .map_or(true, |leaf| !kernel_read_only_leaf_action(leaf))
}

fn kernel_observation_action(action: &str) -> bool {
    matches!(
        action,
        "status"
            | "driver_discover"
            | "driver_stats"
            | "driver_enum_process"
            | "driver_callback_enum"
            | "driver_memory_pool"
            | "driver_minifilter_enum"
            | "driver_process_dump"
            | "driver_hypervisor_detect"
            | "driver_pe_dump"
            | "driver_cred_dump"
            | "read"
            | "physical_read"
            | "enum_callbacks"
            | "object_callback_enum"
            | "registry_callback_enum"
            | "minifilter_enum"
    )
}

fn kernel_read_only_leaf_action(leaf: &str) -> bool {
    matches!(
        leaf,
        "query" | "list" | "enum" | "read" | "dump" | "find_lsass" | "status"
    )
}

fn kernel_leaf_action(args: &Value, result: &Value) -> Option<String> {
    result
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| {
            [
                "reg_action",
                "notify_action",
                "obj_action",
                "debug_action",
                "dpc_action",
                "port_action",
                "token_action",
                "testsign_action",
                "hook_action",
                "inject_action",
                "infhook_action",
                "ci_action",
                "pte_action",
                "msr_action",
                "cloak_action",
                "kill_method",
                "thread_action",
                "exec_action",
                "ppl_action",
                "cr_action",
                "idt_action",
                "unloaded_action",
                "swap_action",
                "protect_action",
                "keylog_action",
                "lock_action",
                "etw_action",
                "spoof_action",
                "log_action",
                "cred_action",
                "imp_action",
                "cb_action",
                "mf_action",
                "apc_action",
                "wfp_action",
            ]
            .iter()
            .find_map(|field| args.get(field).and_then(Value::as_str))
        })
        .map(str::to_string)
}

fn kernel_mutation_metadata(action: &str, args: &Value, result: &Value) -> Value {
    json!({
        "kind": "kernel_live_mutation",
        "tool": "kernel",
        "action": action,
        "subaction": kernel_leaf_action(args, result).map(Value::from).unwrap_or(Value::Null),
        "technique": result.get("technique").cloned().unwrap_or_else(|| json!(action)),
        "state_change": kernel_state_change(action, args, result),
        "captured_fields": captured_kernel_fields(args, result),
        "driver_source": result.get("driver_source")
            .or_else(|| result.get("driver"))
            .cloned()
            .unwrap_or(Value::Null),
        "target": {
            "pid": result.get("pid")
                .or_else(|| result.get("target_pid"))
                .or_else(|| result.get("process_id"))
                .or_else(|| args.get("pid"))
                .or_else(|| args.get("target_pid"))
                .cloned()
                .unwrap_or(Value::Null),
            "tid": result.get("tid")
                .or_else(|| result.get("thread_id"))
                .or_else(|| args.get("tid"))
                .or_else(|| args.get("thread_id"))
                .cloned()
                .unwrap_or(Value::Null),
            "address": result.get("address")
                .or_else(|| result.get("virtual_address"))
                .or_else(|| result.get("target_address"))
                .or_else(|| args.get("address"))
                .cloned()
                .unwrap_or(Value::Null),
            "driver": result.get("driver_name")
                .or_else(|| result.get("hidden_module"))
                .or_else(|| args.get("driver_name"))
                .or_else(|| args.get("driver"))
                .cloned()
                .unwrap_or(Value::Null),
        },
        "handler_boundary": "src/mcp/kernel_tool.rs",
    })
}

fn kernel_state_change(action: &str, args: &Value, result: &Value) -> &'static str {
    let leaf = kernel_leaf_action(args, result);
    match action {
        "driver_load" | "driver_unload" | "driver_auto" => "driver_service_state",
        "write" | "physical_write" => "kernel_memory_write",
        "pte_modify" | "driver_pte_rw" => "page_table_entry_mutation",
        "vad_hide" => "vad_tree_mutation",
        "sniff_start" | "sniff_stop" => "kernel_memory_sniffer_state",
        "remove_callback"
        | "object_callback_remove"
        | "registry_callback_remove"
        | "driver_callback_remove"
        | "driver_callback_nuke" => "kernel_callback_table_mutation",
        "driver_notify_routine" => "kernel_notification_registration",
        "driver_reg_protect" | "driver_reg_hide" => "registry_filter_state",
        "driver_object_hook" => "object_callback_state",
        "driver_port_hide" => "network_port_filter_state",
        "driver_global_hook" | "driver_infinity_hook" => "kernel_hook_state",
        "driver_auto_inject" | "driver_apc_inject" | "driver_kernel_apc" => {
            "kernel_injection_state"
        }
        "ppl_bypass" | "driver_ppl_bypass" | "driver_process_protect" => {
            "process_protection_mutation"
        }
        "token_escalate" | "driver_token_dup" | "driver_token_swap" => "kernel_token_mutation",
        "dkom_hide" | "module_hide" | "driver_module_hide" | "driver_cloak" => "kernel_list_unlink",
        "driver_patch_kernel"
        | "dse_bypass"
        | "driver_ci_callback_patch"
        | "driver_ci_func_patch" => "code_integrity_patch_state",
        "driver_msr_rw" => "model_specific_register_write",
        "driver_cr_rw" => "control_register_write",
        "driver_idt_rw" => "interrupt_descriptor_table_write",
        "driver_unloaded_drv_clear" => "kernel_artifact_history_mutation",
        "driver_keylogger" => "kernel_keylogger_state",
        "driver_file_lock" => "filesystem_filter_state",
        "driver_etw_blind" | "etw_ti_remove" => "kernel_telemetry_blinding",
        "driver_eprocess_spoof" => "eprocess_identity_mutation",
        "driver_event_log_clear" => "event_log_tampering",
        "driver_impersonate" => "driver_image_impersonation",
        "driver_minifilter_detach" | "minifilter_remove" => "minifilter_attachment_state",
        "driver_wfp_remove" => "wfp_callout_state",
        "driver_force_kill" => "kernel_process_termination",
        "driver_force_delete" => "kernel_file_delete",
        "driver_system_thread" => "kernel_thread_state",
        "driver_kernel_exec" => match leaf.as_deref() {
            Some("alloc") | Some("free") => "kernel_allocation_state",
            _ => "kernel_code_execution",
        },
        _ => "kernel_state_mutation",
    }
}

fn kernel_rollback_metadata(action: &str, args: &Value, result: &Value) -> Value {
    if let Some(rollback) = exact_kernel_rollback(action, args, result) {
        return rollback;
    }
    if let Some(rollback) = original_value_kernel_rollback(action, args, result) {
        return rollback;
    }
    if let Some(rollback) = callback_pointer_kernel_rollback(action, args, result) {
        return rollback;
    }
    if destructive_kernel_action(action, args, result) {
        return json!({
            "available": false,
            "strategy": "irreversible_or_external_recovery",
            "captured_fields": captured_kernel_fields(args, result),
            "reason": "destructive_kernel_mutation",
            "detail": "kernel live handler reports a destructive mutation that cannot be automatically rolled back from captured handler state",
        });
    }

    json!({
        "available": "partial",
        "strategy": "manual_kernel_recovery",
        "captured_fields": captured_kernel_fields(args, result),
        "reason": "insufficient_kernel_rollback_state",
        "detail": "kernel live handler did not expose enough state for a stable executable rollback action",
    })
}

fn exact_kernel_rollback(action: &str, args: &Value, result: &Value) -> Option<Value> {
    let leaf = kernel_leaf_action(args, result);
    let leaf = leaf.as_deref();

    let (rollback_action, args_builder, strategy, detail): (&str, Value, &str, &str) =
        match (action, leaf) {
            ("driver_load", _) => (
                "driver_unload",
                copy_kernel_args("driver_unload", args, result, &["driver", "service_name"]),
                "unload_loaded_driver_service",
                "driver_load can be reversed through kernel(action='driver_unload') when the service name is captured",
            ),
            ("driver_notify_routine", Some("register")) => (
                "driver_notify_routine",
                copy_kernel_args(
                    "driver_notify_routine",
                    args,
                    result,
                    &["notify_type"],
                )
                .with_field("notify_action", json!("unregister")),
                "unregister_notify_routine",
                "registered notify callback can be unregistered with the same notify_type",
            ),
            ("driver_object_hook", Some("register")) => (
                "driver_object_hook",
                json!({"action": "driver_object_hook", "obj_action": "unregister"}),
                "unregister_object_callback",
                "registered object callback can be unregistered",
            ),
            ("driver_dpc_timer", Some("schedule")) => (
                "driver_dpc_timer",
                copy_kernel_args("driver_dpc_timer", args, result, &["timer_index"])
                    .with_field("dpc_action", json!("cancel")),
                "cancel_dpc_timer",
                "scheduled DPC timer can be cancelled by timer_index",
            ),
            ("driver_global_hook", Some("install")) => (
                "driver_global_hook",
                copy_kernel_args(
                    "driver_global_hook",
                    args,
                    result,
                    &[
                        "hook_index",
                        "hook_type",
                        "target_module",
                        "target_function",
                    ],
                )
                .with_field("hook_action", json!("remove")),
                "remove_global_hook",
                "installed global hook can be removed by hook metadata",
            ),
            ("driver_auto_inject", Some("enable")) => (
                "driver_auto_inject",
                json!({"action": "driver_auto_inject", "inject_action": "disable"}),
                "disable_auto_inject",
                "auto injection can be disabled after enable",
            ),
            ("driver_infinity_hook", Some("enable")) => (
                "driver_infinity_hook",
                copy_kernel_args(
                    "driver_infinity_hook",
                    args,
                    result,
                    &["syscall_number"],
                )
                .with_field("infhook_action", json!("disable")),
                "disable_infinity_hook",
                "enabled infinity hook can be disabled; original_handler is retained when exposed by the live result",
            ),
            ("driver_ci_callback_patch", Some("patch")) => (
                "driver_ci_callback_patch",
                json!({"action": "driver_ci_callback_patch", "ci_action": "restore"}),
                "restore_ci_callback",
                "CI callback patch exposes a restore subaction",
            ),
            ("driver_ci_func_patch", Some("patch")) => (
                "driver_ci_func_patch",
                json!({"action": "driver_ci_func_patch", "ci_action": "restore"}),
                "restore_ci_function",
                "CI function patch exposes a restore subaction",
            ),
            ("driver_testsign_hide", Some("hide_shared") | Some("hide_ci")) => (
                "driver_testsign_hide",
                json!({"action": "driver_testsign_hide", "testsign_action": "restore"}),
                "restore_testsigning_visibility",
                "testsign hide operation exposes a restore subaction",
            ),
            ("driver_keylogger", Some("start")) => (
                "driver_keylogger",
                json!({"action": "driver_keylogger", "keylog_action": "stop"}),
                "stop_keylogger",
                "started keylogger can be stopped",
            ),
            ("driver_kernel_exec", Some("alloc")) => {
                let address = result.get("allocated_address").cloned().or_else(|| {
                    args.get("alloc_address")
                        .cloned()
                        .or_else(|| result.get("address").cloned())
                })?;
                (
                    "driver_kernel_exec",
                    json!({
                        "action": "driver_kernel_exec",
                        "exec_action": "free",
                        "alloc_address": address
                    }),
                    "free_kernel_allocation",
                    "kernel allocation result exposed an allocated address that can be freed",
                )
            }
            ("driver_file_lock", Some("add")) => (
                "driver_file_lock",
                copy_kernel_args("driver_file_lock", args, result, &["file_path", "allowed_pid"])
                    .with_field("lock_action", json!("remove")),
                "remove_file_lock",
                "file lock add can be reversed with lock_action='remove' for the same path",
            ),
            ("driver_reg_hide", Some("add")) => (
                "driver_reg_hide",
                copy_kernel_args(
                    "driver_reg_hide",
                    args,
                    result,
                    &["key_path", "value_name", "hide_type"],
                )
                .with_field("reg_action", json!("remove")),
                "remove_registry_hide_rule",
                "registry hide add can be reversed with reg_action='remove'",
            ),
            ("driver_port_hide", Some("add")) => (
                "driver_port_hide",
                copy_kernel_args("driver_port_hide", args, result, &["port", "protocol"])
                    .with_field("port_action", json!("remove")),
                "remove_port_hide_rule",
                "port hide add can be reversed with port_action='remove'",
            ),
            ("driver_etw_blind", Some("disable")) => (
                "driver_etw_blind",
                copy_kernel_args("driver_etw_blind", args, result, &["provider_guid"])
                    .with_field("etw_action", json!("enable")),
                "reenable_etw_provider",
                "ETW provider disable can be paired with etw_action='enable'",
            ),
            ("driver_callback_nuke", Some("remove") | Some("nuke_all")) => (
                "driver_callback_nuke",
                copy_kernel_args("driver_callback_nuke", args, result, &["cb_type"])
                    .with_field("cb_action", json!("restore")),
                "restore_callback_entries",
                "callback nuke exposes a restore subaction, but exact recovery depends on driver-captured callback state",
            ),
            _ => return None,
        };

    let mut rollback = json!({
        "available": true,
        "strategy": strategy,
        "captured_fields": captured_kernel_fields(args, result),
        "action": {
            "tool": "kernel",
            "action": rollback_action,
            "args": args_builder,
        },
        "detail": detail,
    });

    if action == "driver_infinity_hook" {
        if let (Some(obj), Some(original_handler)) =
            (rollback.as_object_mut(), result.get("original_handler"))
        {
            obj.insert("original_handler".to_string(), original_handler.clone());
        }
    }

    Some(rollback)
}

fn original_value_kernel_rollback(action: &str, args: &Value, result: &Value) -> Option<Value> {
    match action {
        "driver_pte_rw" => {
            let address = result
                .get("virtual_address")
                .or_else(|| args.get("address"))?
                .clone();
            let original_pte = result.get("original_pte_value")?.clone();
            Some(json!({
                "available": true,
                "strategy": "restore_pte_value",
                "captured_fields": captured_kernel_fields(args, result),
                "action": {
                    "tool": "kernel",
                    "action": "driver_pte_rw",
                    "args": {
                        "action": "driver_pte_rw",
                        "pte_action": "restore",
                        "address": address,
                        "new_pte": original_pte,
                    }
                },
                "detail": "driver_pte_rw exposed original_pte_value and restore subaction metadata",
            }))
        }
        "driver_msr_rw" => {
            let msr_index = result
                .get("msr_index")
                .or_else(|| args.get("msr_index"))?
                .clone();
            let old_value = result.get("old_value")?.clone();
            Some(json!({
                "available": true,
                "strategy": "restore_msr_value",
                "captured_fields": captured_kernel_fields(args, result),
                "action": {
                    "tool": "kernel",
                    "action": "driver_msr_rw",
                    "args": {
                        "action": "driver_msr_rw",
                        "msr_action": "write",
                        "msr_index": msr_index,
                        "msr_value": old_value,
                    }
                },
                "detail": "driver_msr_rw exposed old_value and can write it back to the same MSR index",
            }))
        }
        "driver_cr_rw" => {
            let cr_index = result
                .get("cr_index")
                .or_else(|| args.get("cr_index"))?
                .clone();
            let old_value = result.get("old_value")?.clone();
            Some(json!({
                "available": true,
                "strategy": "restore_control_register_value",
                "captured_fields": captured_kernel_fields(args, result),
                "action": {
                    "tool": "kernel",
                    "action": "driver_cr_rw",
                    "args": {
                        "action": "driver_cr_rw",
                        "cr_action": "write",
                        "cr_index": cr_index,
                        "value": old_value,
                    }
                },
                "detail": "driver_cr_rw exposed old_value and can write it back to the same control register",
            }))
        }
        "driver_token_dup" | "driver_token_swap" | "token_escalate" => {
            let old_token = result
                .get("original_token")
                .or_else(|| result.get("old_token"))?
                .clone();
            Some(json!({
                "available": "partial",
                "strategy": "restore_kernel_token",
                "captured_fields": captured_kernel_fields(args, result),
                "original_token": old_token,
                "detail": "kernel token mutation exposed the original token value, but executable restore depends on driver-side token restore semantics",
            }))
        }
        "driver_ppl_bypass" | "driver_process_protect" | "ppl_bypass" => {
            let old_protection = result.get("old_protection")?.clone();
            Some(json!({
                "available": "partial",
                "strategy": "restore_process_protection",
                "captured_fields": captured_kernel_fields(args, result),
                "old_protection": old_protection,
                "detail": "process protection mutation exposed old protection metadata, but full restore also depends on signer/audit fields and driver support",
            }))
        }
        "driver_idt_rw" => {
            let old_handler = result.get("old_handler")?.clone();
            Some(json!({
                "available": "partial",
                "strategy": "restore_idt_handler",
                "captured_fields": captured_kernel_fields(args, result),
                "old_handler": old_handler,
                "detail": "IDT write exposed old_handler, but exact rollback also needs the previous descriptor flags and DPL",
            }))
        }
        "driver_etw_blind" => {
            let old_enable_info = result.get("old_enable_info")?.clone();
            Some(json!({
                "available": "partial",
                "strategy": "restore_etw_enable_info",
                "captured_fields": captured_kernel_fields(args, result),
                "old_enable_info": old_enable_info,
                "detail": "ETW blinding exposed old_enable_info; executable restore depends on provider-specific driver support",
            }))
        }
        "driver_eprocess_spoof" => Some(json!({
            "available": "partial",
            "strategy": "restore_eprocess_identity",
            "captured_fields": captured_kernel_fields(args, result),
            "detail": "EPROCESS spoofing exposed prior identity fields where available, but complete restore depends on spoof type and full captured string state",
        })),
        "driver_ci_func_patch" => {
            let original_bytes = result.get("original_bytes")?.clone();
            Some(json!({
                "available": "partial",
                "strategy": "restore_original_kernel_bytes",
                "captured_fields": captured_kernel_fields(args, result),
                "original_bytes": original_bytes,
                "action": {
                    "tool": "kernel",
                    "action": "driver_ci_func_patch",
                    "args": {
                        "action": "driver_ci_func_patch",
                        "ci_action": "restore",
                    }
                },
                "detail": "CI function patch exposed original bytes and a restore subaction",
            }))
        }
        _ => None,
    }
}

fn callback_pointer_kernel_rollback(action: &str, args: &Value, result: &Value) -> Option<Value> {
    match action {
        "driver_callback_remove" => {
            let callback_type = result
                .get("callback_type")
                .or_else(|| args.get("callback_type"))?
                .clone();
            let index = result.get("index").or_else(|| args.get("index"))?.clone();
            let callback_address = result
                .get("callback_address")
                .or_else(|| args.get("callback_address"))
                .cloned()
                .unwrap_or(Value::Null);
            Some(json!({
                "available": "partial",
                "strategy": "restore_removed_callback_pointer",
                "captured_fields": captured_kernel_fields(args, result),
                "callback_type": callback_type,
                "index": index,
                "callback_address": callback_address,
                "detail": "driver_callback_remove identified the callback slot and optional prior callback address; executable restore depends on driver support for writing the captured pointer back to the callback table",
            }))
        }
        _ => None,
    }
}

fn destructive_kernel_action(action: &str, args: &Value, result: &Value) -> bool {
    let leaf = kernel_leaf_action(args, result);
    matches!(
        action,
        "driver_force_kill"
            | "driver_force_delete"
            | "driver_event_log_clear"
            | "physical_write"
            | "write"
    ) || matches!(
        (action, leaf.as_deref()),
        (
            "driver_unloaded_drv_clear",
            Some("clear_all" | "clear_name")
        ) | ("driver_file_lock", Some("clear"))
            | ("driver_reg_hide", Some("clear"))
            | ("driver_port_hide", Some("clear"))
            | ("driver_wfp_remove", Some("remove" | "nuke"))
            | ("driver_minifilter_detach", Some("detach" | "nuke"))
    )
}

fn copy_kernel_args(action: &str, args: &Value, result: &Value, fields: &[&str]) -> Value {
    let mut value = json!({ "action": action });
    if let Some(obj) = value.as_object_mut() {
        for field in fields {
            if let Some(field_value) = result.get(*field).or_else(|| args.get(*field)) {
                obj.insert((*field).to_string(), field_value.clone());
            }
        }
    }
    value
}

trait JsonObjectExt {
    fn with_field(self, key: &str, value: Value) -> Value;
}

impl JsonObjectExt for Value {
    fn with_field(mut self, key: &str, value: Value) -> Value {
        if let Some(obj) = self.as_object_mut() {
            obj.insert(key.to_string(), value);
        }
        self
    }
}

fn captured_kernel_fields(args: &Value, result: &Value) -> Vec<&'static str> {
    let mut fields = Vec::new();
    for (field, source) in [
        ("pid", result),
        ("target_pid", result),
        ("process_id", result),
        ("source_pid", result),
        ("tid", result),
        ("thread_id", result),
        ("address", result),
        ("virtual_address", result),
        ("target_address", result),
        ("allocated_address", result),
        ("eprocess", result),
        ("target_eprocess", result),
        ("system_eprocess", result),
        ("driver", result),
        ("driver_source", result),
        ("driver_name", result),
        ("hidden_module", result),
        ("module_base", result),
        ("file_path", result),
        ("callback_type", result),
        ("callback_address", result),
        ("index", result),
        ("hook_index", result),
        ("hook_type", result),
        ("timer_index", result),
        ("notify_type", result),
        ("key_path", result),
        ("value_name", result),
        ("port", result),
        ("protocol", result),
        ("provider_guid", result),
        ("provider_addr", result),
        ("msr_index", result),
        ("cr_index", result),
        ("vector", result),
        ("original_token", result),
        ("old_token", result),
        ("original_handler", result),
        ("original_ptr", result),
        ("original_bytes", result),
        ("old_value", result),
        ("old_handler", result),
        ("old_protection", result),
        ("original_pte_value", result),
        ("old_enable_info", result),
        ("old_image_name", result),
        ("old_parent_pid", result),
        ("preflight", result),
        ("pid", args),
        ("target_pid", args),
        ("source_pid", args),
        ("tid", args),
        ("thread_id", args),
        ("address", args),
        ("target_address", args),
        ("alloc_address", args),
        ("driver", args),
        ("driver_name", args),
        ("file_path", args),
        ("callback_type", args),
        ("callback_address", args),
        ("index", args),
        ("hook_index", args),
        ("hook_type", args),
        ("timer_index", args),
        ("notify_type", args),
        ("key_path", args),
        ("value_name", args),
        ("port", args),
        ("protocol", args),
        ("provider_guid", args),
        ("msr_index", args),
        ("cr_index", args),
        ("vector", args),
    ] {
        if source.get(field).is_some() {
            fields.push(field);
        }
    }
    fields.sort_unstable();
    fields.dedup();
    fields
}

fn kernel_preflight_blockers(
    policy: &crate::policy::PolicyDecision,
    missing_parameters: &[&str],
    driver: &Value,
    explicit_byovd: bool,
    action: &str,
    requirement_blockers: &[Value],
) -> Vec<Value> {
    let mut blockers = Vec::new();

    if !policy.allowed {
        blockers.push(json!({
            "code": "policy_denied",
            "message": policy.reason,
            "required_policy": policy.required_level.as_str(),
            "configured_policy": policy.configured_level.as_str(),
        }));
    }

    for parameter in missing_parameters {
        blockers.push(json!({
            "code": "missing_parameter",
            "parameter": parameter,
            "message": format!("kernel(action='{}') requires {}", action, parameter),
        }));
    }

    let device_reachable = driver["device"]["reachable"].as_bool().unwrap_or(false);
    let driver_load_possible = driver["readiness"]["driver_load_possible"]
        .as_bool()
        .unwrap_or(false);
    if !matches!(action, "driver_load" | "driver_auto")
        && !explicit_byovd
        && !device_reachable
        && !driver_load_possible
    {
        blockers.push(json!({
            "code": "driver_unavailable",
            "message": driver["message"].clone(),
        }));
    }

    blockers.extend(requirement_blockers.iter().cloned());

    blockers
}

fn kernel_requirement_blockers(
    requirements: KernelPreflightRequirements,
    driver: &Value,
    explicit_byovd: bool,
    byovd_preflight: Option<&Value>,
    build_number: Option<u32>,
) -> Vec<Value> {
    let mut blockers = Vec::new();
    let driver_reachable = driver["device"]["reachable"].as_bool().unwrap_or(false);
    let driver_load_possible = driver["readiness"]["driver_load_possible"]
        .as_bool()
        .unwrap_or(false);
    let payload_exists = driver["payload"]["exists"].as_bool().unwrap_or(false);
    let driver_ready = driver_reachable || driver_load_possible;

    if requirements.requires_explicit_device_path && !explicit_byovd {
        blockers.push(json!({
            "code": "missing_byovd_device",
            "message": "This kernel action requires an explicit BYOVD device_path and IOCTL contract.",
        }));
    }

    if requirements.requires_explicit_device_path {
        let ioctl_available = byovd_preflight
            .and_then(|preflight| preflight["contract"]["ioctl_contract_available"].as_bool())
            .unwrap_or(false);
        if !ioctl_available {
            blockers.push(json!({
                "code": "byovd_ioctl_contract_missing",
                "message": "Explicit BYOVD actions require a read/write/ioctl code contract before mutation.",
            }));
        }
    }

    if requirements.requires_service_control && !driver_reachable && !driver_load_possible {
        blockers.push(json!({
            "code": "service_control_not_ready",
            "message": driver["message"].clone(),
        }));
    }

    if requirements.requires_driver_capabilities && !driver_ready {
        blockers.push(json!({
            "code": "driver_capability_unavailable",
            "message": "memoric.sys capabilities cannot be verified until the device is reachable or load readiness is satisfied.",
        }));
    }

    if requirements.requires_driver_version && !driver_ready {
        blockers.push(json!({
            "code": "driver_version_unverified",
            "message": "memoric.sys ABI/version cannot be verified before a reachable or loadable driver is available.",
        }));
    }

    if requirements.requires_os_build && build_number.is_none() {
        blockers.push(json!({
            "code": "os_build_unknown",
            "message": "Windows build number is required for offset-sensitive kernel mutation preflight.",
        }));
    }

    if requirements.offset_requirement == KernelOffsetRequirement::CallbackRegistry
        && build_number
            .and_then(crate::kernel_offsets::profile_for_build)
            .is_none()
    {
        blockers.push(json!({
            "code": "callback_offset_profile_unavailable",
            "message": "No callback offset profile is available for this Windows build.",
            "supported_builds": crate::kernel_offsets::supported_builds_summary(),
        }));
    }

    if requirements.offset_requirement == KernelOffsetRequirement::EprocessRuntime && !driver_ready
    {
        blockers.push(json!({
            "code": "eprocess_offsets_unverified",
            "message": "EPROCESS offsets require memoric.sys runtime capability data before mutation.",
        }));
    }

    if requirements.offset_requirement == KernelOffsetRequirement::DriverReported && !driver_ready {
        blockers.push(json!({
            "code": "driver_reported_offsets_unverified",
            "message": "This driver_* operation depends on driver-reported capability or offset readiness.",
        }));
    }

    if requirements.requires_service_control && !payload_exists && !driver_reachable {
        blockers.push(json!({
            "code": "driver_payload_missing",
            "message": "Driver service mutation needs an existing driver payload or reachable installed device.",
        }));
    }

    blockers
}

fn has_preflight_value(args: &Value, key: &str) -> bool {
    match args.get(key) {
        Some(Value::Null) | None => false,
        Some(Value::String(value)) => !value.trim().is_empty(),
        Some(Value::Array(values)) => !values.is_empty(),
        Some(Value::Object(values)) => !values.is_empty(),
        Some(_) => true,
    }
}

pub(crate) fn kernel_action_help(action: &str) -> String {
    format!(
        "Unknown kernel action: {}. Route groups: status=[status], generic=[driver_load, driver_unload, driver_discover, driver_auto, read, write, physical_read, physical_write, pte_modify, vad_hide, enum_callbacks, remove_callback], hybrid=[ppl_bypass, dkom_hide, token_escalate], direct_memoric=[driver_enum_process, driver_callback_enum, driver_reg_protect, driver_notify_routine, driver_process_dump, driver_global_hook, driver_ppl_bypass, driver_kernel_apc, driver_wfp_remove]. Prefer canonical driver_* names. Legacy aliases notify_routine/reg_protect/object_hook/port_hide are normalized automatically. Examples: kernel(action='status'), kernel(action='driver_notify_routine', notify_action='query'), kernel(action='driver_reg_protect', reg_action='list'), kernel(action='driver_process_dump', pid=1234, max_size=1048576). Call `memoric` with domain='kernel' for the current grouped action catalog.",
        action
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_kernel_driver_actions() {
        assert!(is_hybrid_kernel_action("ppl_bypass"));
        assert!(is_memoric_direct_kernel_action("driver_enum_process"));
        assert!(!is_memoric_direct_kernel_action("driver_load"));
        assert!(!is_memoric_direct_kernel_action("read"));
    }

    #[test]
    fn annotates_hybrid_kernel_results_without_overwriting_existing_fields() {
        let result = annotate_kernel_result(
            json!({"success": true, "driver_source": "custom"}),
            "ppl_bypass",
            &json!({"device_path": "\\\\.\\RTCore64"}),
            false,
        );

        assert_eq!(result["driver_source"], json!("custom"));
        assert_eq!(result["driver_auto_installed"], json!(false));
        assert_eq!(result["fallback_used"], json!(false));
        assert_eq!(result["memoric_preferred"], json!(true));
    }

    #[test]
    fn annotates_memoric_direct_kernel_results() {
        let result = annotate_kernel_result(
            json!({"success": true}),
            "driver_enum_process",
            &json!({}),
            false,
        );

        assert_eq!(result["driver_source"], json!("memoric"));
        assert_eq!(result["driver_auto_installed"], json!(true));
        assert_eq!(result["fallback_used"], json!(false));
        assert_eq!(result["memoric_preferred"], json!(true));
    }

    #[test]
    fn leaves_non_object_results_unchanged() {
        let result =
            annotate_kernel_result(json!(["ok"]), "driver_enum_process", &json!({}), false);
        assert_eq!(result, json!(["ok"]));
    }

    #[test]
    fn read_only_kernel_actions_do_not_have_mutation_preflight() {
        assert!(kernel_mutation_preflight("status", &json!({"action": "status"})).is_none());
    }

    #[test]
    fn kernel_mutation_preflight_reports_policy_and_missing_fields_before_driver_open() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        std::env::remove_var("MEMORIC_POLICY");

        let preflight = kernel_mutation_preflight("write", &json!({"action": "write"}))
            .expect("write is state-changing");

        assert_eq!(preflight["kind"], "kernel_mutation_preflight");
        assert_eq!(preflight["safe_to_attempt"], false);
        assert_eq!(preflight["checked_before_mutation"], true);
        assert_eq!(preflight["capability_probe"]["executed"], false);
        assert_eq!(preflight["policy"]["allowed"], false);
        assert_eq!(preflight["policy"]["required_policy"], "kernel");
        assert_eq!(preflight["requirements"]["driver_source"], "byovd");
        assert_eq!(
            preflight["requirements"]["requires_explicit_device_path"],
            true
        );
        assert!(preflight["byovd"].is_null());
        assert!(preflight["missing_parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "device_path"));
        assert!(preflight["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["code"] == "policy_denied"));
    }

    #[test]
    fn kernel_mutation_preflight_classifies_source_and_offset_requirements() {
        let direct = KernelPreflightRequirements::for_action("driver_token_dup", false);
        assert_eq!(direct.driver_source, KernelDriverSourceRequirement::Memoric);
        assert_eq!(
            direct.offset_requirement,
            KernelOffsetRequirement::EprocessRuntime
        );
        assert!(direct.requires_driver_capabilities);
        assert!(direct.requires_driver_version);

        let byovd = KernelPreflightRequirements::for_action("remove_callback", true);
        assert_eq!(byovd.driver_source, KernelDriverSourceRequirement::Byovd);
        assert_eq!(
            byovd.offset_requirement,
            KernelOffsetRequirement::CallbackRegistry
        );
        assert!(byovd.requires_explicit_device_path);

        let service = KernelPreflightRequirements::for_action("driver_load", false);
        assert_eq!(
            service.driver_source,
            KernelDriverSourceRequirement::ServiceControl
        );
        assert!(service.requires_service_control);
    }

    #[test]
    fn explicit_byovd_preflight_records_contract_without_ioctl_execution() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        std::env::set_var("MEMORIC_POLICY", "kernel");

        let preflight = kernel_mutation_preflight(
            "write",
            &json!({
                "action": "write",
                "device_path": "\\\\.\\RTCore64",
                "ioctl_code": 0x8000204C_u64,
                "address": "0x1000",
                "bytes": [1, 2, 3],
            }),
        )
        .expect("write is state-changing");

        assert_eq!(preflight["byovd"]["kind"], "byovd_preflight");
        assert_eq!(preflight["byovd"]["ioctl_executed"], false);
        assert_eq!(preflight["byovd"]["device_open"]["attempted"], false);
        assert_eq!(
            preflight["byovd"]["contract"]["write_ioctl_matches_database"],
            true
        );
        assert_eq!(
            preflight["byovd"]["contract"]["ioctl_contract_available"],
            true
        );

        std::env::remove_var("MEMORIC_POLICY");
    }

    #[test]
    fn attaches_kernel_preflight_to_object_results_only() {
        let result = attach_kernel_preflight(
            json!({"success": true}),
            Some(json!({"kind": "kernel_mutation_preflight"})),
        );

        assert_eq!(result["preflight"]["kind"], "kernel_mutation_preflight");

        let non_object = attach_kernel_preflight(json!(["ok"]), Some(json!({"kind": "ignored"})));
        assert_eq!(non_object, json!(["ok"]));
    }

    #[test]
    fn kernel_live_metadata_adds_provenance_and_restore_action() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "memoric_driver_notify_routine",
                "driver": "memoric.sys",
                "action": "register",
                "notify_type": "process"
            }),
            "driver_notify_routine",
            &json!({
                "action": "driver_notify_routine",
                "notify_action": "register",
                "notify_type": "process",
                "request_id": "req-kernel",
                "task_id": "task-kernel",
                "chain_id": "chain-kernel",
                "purpose": "test kernel metadata"
            }),
        );

        assert_eq!(result["provenance"]["correlation_id"], "req-kernel");
        assert_eq!(result["provenance"]["request_id"], "req-kernel");
        assert_eq!(result["provenance"]["task_id"], "task-kernel");
        assert_eq!(result["provenance"]["chain_id"], "chain-kernel");
        assert_eq!(result["provenance"]["purpose"], "test kernel metadata");
        assert_eq!(result["mutation"]["kind"], "kernel_live_mutation");
        assert_eq!(
            result["mutation"]["state_change"],
            "kernel_notification_registration"
        );
        assert_eq!(result["mutation"]["subaction"], "register");
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "unregister_notify_routine");
        assert_eq!(result["rollback"]["action"]["tool"], "kernel");
        assert_eq!(
            result["rollback"]["action"]["action"],
            "driver_notify_routine"
        );
        assert_eq!(
            result["rollback"]["action"]["args"]["notify_action"],
            "unregister"
        );
        assert_eq!(
            result["rollback"]["action"]["args"]["notify_type"],
            "process"
        );
    }

    #[test]
    fn kernel_auto_inject_metadata_only_exposes_handler_supported_restore_action() {
        let enable = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "memoric_driver_auto_inject",
                "action": "enable"
            }),
            "driver_auto_inject",
            &json!({
                "action": "driver_auto_inject",
                "inject_action": "enable",
                "request_id": "req-auto-inject"
            }),
        );

        assert_eq!(enable["rollback"]["available"], true);
        assert_eq!(enable["rollback"]["strategy"], "disable_auto_inject");
        assert_eq!(
            enable["rollback"]["action"]["args"]["inject_action"],
            "disable"
        );

        let unsupported_selector = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "memoric_driver_auto_inject",
                "action": "set_payload"
            }),
            "driver_auto_inject",
            &json!({
                "action": "driver_auto_inject",
                "inject_action": "set_payload",
                "request_id": "req-auto-inject"
            }),
        );

        assert_ne!(
            unsupported_selector["rollback"]["strategy"], "disable_auto_inject",
            "unsupported selectors should not advertise an executable exact rollback action"
        );
        assert_eq!(unsupported_selector["rollback"]["available"], "partial");
        assert_eq!(
            unsupported_selector["rollback"]["reason"],
            "insufficient_kernel_rollback_state"
        );
    }

    #[test]
    fn kernel_live_metadata_suppresses_read_only_leaf_actions() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "memoric_driver_reg_protect",
                "driver": "memoric.sys",
                "action": "list",
                "count": 0
            }),
            "driver_reg_protect",
            &json!({
                "action": "driver_reg_protect",
                "reg_action": "list",
                "request_id": "req-list"
            }),
        );

        assert_eq!(result["provenance"]["request_id"], "req-list");
        assert!(result.get("mutation").is_none());
        assert!(result.get("rollback").is_none());
    }

    #[test]
    fn kernel_live_metadata_uses_original_pte_for_executable_restore() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "pte_manipulation",
                "action": "write",
                "virtual_address": "0x0000000012345000",
                "pte_value": "0x0000000000000003",
                "original_pte_value": "0x0000000000000001"
            }),
            "driver_pte_rw",
            &json!({
                "action": "driver_pte_rw",
                "pte_action": "write",
                "address": "0x0000000012345000",
                "request_id": "req-pte"
            }),
        );

        assert_eq!(
            result["mutation"]["state_change"],
            "page_table_entry_mutation"
        );
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "restore_pte_value");
        assert_eq!(result["rollback"]["action"]["action"], "driver_pte_rw");
        assert_eq!(
            result["rollback"]["action"]["args"]["pte_action"],
            "restore"
        );
        assert_eq!(
            result["rollback"]["action"]["args"]["new_pte"],
            "0x0000000000000001"
        );
    }

    #[test]
    fn kernel_live_metadata_describes_callback_pointer_restore_state() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "memoric_driver_callback_remove",
                "callback_type": "process",
                "index": 2,
                "callback_address": "0x0000000012345678"
            }),
            "driver_callback_remove",
            &json!({
                "action": "driver_callback_remove",
                "callback_type": "process",
                "index": 2,
                "request_id": "req-callback"
            }),
        );

        assert_eq!(
            result["mutation"]["state_change"],
            "kernel_callback_table_mutation"
        );
        assert_eq!(result["rollback"]["available"], "partial");
        assert_eq!(
            result["rollback"]["strategy"],
            "restore_removed_callback_pointer"
        );
        assert_eq!(result["rollback"]["callback_type"], "process");
        assert_eq!(result["rollback"]["index"], 2);
        assert_eq!(result["rollback"]["callback_address"], "0x0000000012345678");
        assert!(result["rollback"]["captured_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "callback_address"));
    }

    #[test]
    fn kernel_live_metadata_retains_infinity_hook_original_handler() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "memoric_kernel_infinity_hook",
                "action": "enable",
                "syscall_number": 80,
                "original_handler": "0x00000000ABCDEF00"
            }),
            "driver_infinity_hook",
            &json!({
                "action": "driver_infinity_hook",
                "infhook_action": "enable",
                "syscall_number": 80,
                "handler_address": "0x0000000011111111",
                "request_id": "req-inf"
            }),
        );

        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "disable_infinity_hook");
        assert_eq!(
            result["rollback"]["action"]["args"]["infhook_action"],
            "disable"
        );
        assert_eq!(result["rollback"]["action"]["args"]["syscall_number"], 80);
        assert_eq!(result["rollback"]["original_handler"], "0x00000000ABCDEF00");
        assert!(result["rollback"]["captured_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "original_handler"));
    }

    #[test]
    fn kernel_live_metadata_marks_destructive_mutations_irreversible() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "technique": "kernel_file_delete",
                "file_path": "\\??\\C:\\temp\\sample.bin"
            }),
            "driver_force_delete",
            &json!({
                "action": "driver_force_delete",
                "file_path": "\\??\\C:\\temp\\sample.bin",
                "request_id": "req-delete"
            }),
        );

        assert_eq!(result["mutation"]["state_change"], "kernel_file_delete");
        assert_eq!(result["rollback"]["available"], false);
        assert_eq!(
            result["rollback"]["strategy"],
            "irreversible_or_external_recovery"
        );
        assert_eq!(result["rollback"]["reason"], "destructive_kernel_mutation");
    }

    #[test]
    fn kernel_live_metadata_preserves_handler_supplied_fields() {
        let result = attach_kernel_live_metadata(
            json!({
                "success": true,
                "provenance": {"request_id": "handler"},
                "mutation": {"kind": "handler_mutation"},
                "rollback": {"available": "handler"}
            }),
            "driver_keylogger",
            &json!({
                "action": "driver_keylogger",
                "keylog_action": "start",
                "request_id": "wrapper"
            }),
        );

        assert_eq!(result["provenance"]["request_id"], "handler");
        assert_eq!(result["mutation"]["kind"], "handler_mutation");
        assert_eq!(result["rollback"]["available"], "handler");
    }

    #[test]
    fn kernel_action_help_points_to_grouped_catalog() {
        let help = kernel_action_help("unknown");
        assert!(help.contains("Unknown kernel action: unknown"));
        assert!(help.contains("Route groups:"));
        assert!(help.contains("Call `memoric` with domain='kernel'"));
    }
}

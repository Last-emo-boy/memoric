//! Hardware Breakpoint Hooks - use debug registers (DR0-DR3) to intercept syscalls
//! without patching code. Invisible to integrity checks that scan .text sections.

use crate::error::MemoricError;
use crate::util::parse_address;
use serde_json::{json, Value};

fn provenance_json(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn hwbp_control_bits(dr7: u64, register: usize) -> u64 {
    (dr7 >> (16 + register * 4)) & 0xF
}

fn hwbp_condition_from_control(control_bits: u64) -> u64 {
    control_bits & 0x3
}

fn hwbp_local_enabled(dr7: u64, register: usize) -> bool {
    dr7 & (1u64 << (register * 2)) != 0
}

fn hwbp_global_enabled(dr7: u64, register: usize) -> bool {
    dr7 & (1u64 << (register * 2 + 1)) != 0
}

fn hwbp_remove_args(tid: u32, register: usize) -> Value {
    json!({
        "tid": tid,
        "dr_index": register,
    })
}

fn hwbp_install_args(tid: u32, register: usize, address: u64, condition: u64) -> Value {
    json!({
        "tid": tid,
        "target_address": crate::memory::rollback::format_address(address),
        "dr_index": register,
        "condition": condition,
    })
}

fn hwbp_install_rollback(tid: u32, register: usize, previous_dr: u64, previous_dr7: u64) -> Value {
    let previous_local_enabled = hwbp_local_enabled(previous_dr7, register);
    let previous_global_enabled = hwbp_global_enabled(previous_dr7, register);
    let previous_control_bits = hwbp_control_bits(previous_dr7, register);
    let previous_condition = hwbp_condition_from_control(previous_control_bits);

    let mut rollback = json!({
        "available": true,
        "strategy": "remove_hardware_breakpoint",
        "captured_fields": [
            "tid",
            "dr_index",
            "previous_dr",
            "previous_dr7",
            "previous_control_bits",
            "previous_local_enabled",
            "previous_global_enabled"
        ],
        "previous_dr": crate::memory::rollback::format_address(previous_dr),
        "previous_dr7": format!("0x{:016X}", previous_dr7),
        "previous_control_bits": previous_control_bits,
        "previous_local_enabled": previous_local_enabled,
        "previous_global_enabled": previous_global_enabled,
        "args": hwbp_remove_args(tid, register),
        "action": {
            "tool": "hook",
            "action": "remove_hwbp",
            "args": hwbp_remove_args(tid, register),
        },
        "detail": "new hardware breakpoint can be removed with hook(action='remove_hwbp')",
    });

    if previous_local_enabled
        || previous_global_enabled
        || previous_dr != 0
        || previous_control_bits != 0
    {
        let args = hwbp_install_args(tid, register, previous_dr, previous_condition);
        rollback["available"] = json!("partial");
        rollback["strategy"] = json!("restore_previous_hardware_breakpoint");
        rollback["reason"] = json!("debug_register_previously_configured");
        rollback["args"] = args.clone();
        rollback["action"] = json!({
            "tool": "hook",
            "action": "install_hwbp",
            "args": args,
        });
        rollback["detail"] = json!("previous debug-register state was captured, but install_hwbp can only restore the address and condition, not every DR7 flag exactly");
    }

    rollback
}

fn hwbp_remove_rollback(tid: u32, register: usize, previous_dr: u64, previous_dr7: u64) -> Value {
    let previous_local_enabled = hwbp_local_enabled(previous_dr7, register);
    let previous_global_enabled = hwbp_global_enabled(previous_dr7, register);
    let previous_control_bits = hwbp_control_bits(previous_dr7, register);
    let previous_condition = hwbp_condition_from_control(previous_control_bits);

    let mut rollback = json!({
        "available": false,
        "strategy": "noop_no_previous_breakpoint",
        "captured_fields": [
            "tid",
            "dr_index",
            "previous_dr",
            "previous_dr7",
            "previous_control_bits",
            "previous_local_enabled",
            "previous_global_enabled"
        ],
        "previous_dr": crate::memory::rollback::format_address(previous_dr),
        "previous_dr7": format!("0x{:016X}", previous_dr7),
        "previous_control_bits": previous_control_bits,
        "previous_local_enabled": previous_local_enabled,
        "previous_global_enabled": previous_global_enabled,
        "action": Value::Null,
        "detail": "no active hardware breakpoint was captured before removal",
    });

    if previous_dr != 0
        || previous_local_enabled
        || previous_global_enabled
        || previous_control_bits != 0
    {
        let args = hwbp_install_args(tid, register, previous_dr, previous_condition);
        rollback["available"] = json!("partial");
        rollback["strategy"] = json!("restore_previous_hardware_breakpoint");
        rollback["reason"] = json!("debug_register_restore_is_partial");
        rollback["args"] = args.clone();
        rollback["action"] = json!({
            "tool": "hook",
            "action": "install_hwbp",
            "args": args,
        });
        rollback["detail"] = json!("previous debug-register state was captured, but install_hwbp can only restore the address and condition, not every DR7 flag exactly");
    }

    rollback
}

/// Set hardware breakpoint on a function using debug registers
/// DR0-DR3 can each hold one address. DR7 controls enable/condition/length.
pub fn hwbp_hook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext};
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing tid (thread ID)".to_string()))?
        as u32;
    let address = args
        .get("target_address")
        .and_then(parse_address)
        .or_else(|| args.get("address").and_then(parse_address))
        .ok_or_else(|| MemoricError::WindowsApi("Missing target_address or address".to_string()))?;
    let register = args
        .get("dr_index")
        .and_then(|v| v.as_u64())
        .or_else(|| args.get("register").and_then(|v| v.as_u64()))
        .unwrap_or(0) as usize; // DR0-DR3
    let condition = args.get("condition").and_then(|v| v.as_u64()).unwrap_or(0) as u64; // 0=exec, 1=write, 3=rw

    if register > 3 {
        return Err(MemoricError::WindowsApi(
            "register must be 0-3 (DR0-DR3)".to_string(),
        ));
    }

    tracing::warn!(
        "[EVASION] Setting HWBP on TID {} at 0x{:X} (DR{})",
        tid,
        address,
        register
    );

    unsafe {
        let thread = OpenThread(THREAD_ALL_ACCESS, false, tid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenThread: {}", e)))?;
        let thread = crate::safe_handle::SafeHandle::new(thread);

        SuspendThread(*thread);

        // CONTEXT_DEBUG_REGISTERS = 0x00100010
        let mut ctx: std::mem::MaybeUninit<[u8; 1232]> = std::mem::MaybeUninit::zeroed();
        let ctx_ptr = ctx.as_mut_ptr() as *mut u8;
        // Set ContextFlags at offset 0x30 (48) for x64 CONTEXT
        *(ctx_ptr.add(0x30) as *mut u32) = 0x00100010; // CONTEXT_DEBUG_REGISTERS

        GetThreadContext(*thread, ctx_ptr as *mut _).map_err(|e| {
            let _ = ResumeThread(*thread);
            MemoricError::WindowsApi(format!("GetThreadContext: {}", e))
        })?;

        // Debug registers in x64 CONTEXT:
        // Dr0 at offset 0x350 (848)
        // Dr1 at offset 0x358 (856)
        // Dr2 at offset 0x360 (864)
        // Dr3 at offset 0x368 (872)
        // Dr6 at offset 0x370 (880)
        // Dr7 at offset 0x378 (888)
        let dr_base: usize = 0x350;
        let dr7_offset: usize = 0x378;

        let previous_dr = *(ctx_ptr.add(dr_base + register * 8) as *mut u64);
        let previous_dr7 = *(ctx_ptr.add(dr7_offset) as *mut u64);

        // Set DRn to target address
        *(ctx_ptr.add(dr_base + register * 8) as *mut u64) = address as u64;

        // Configure DR7
        let mut dr7 = previous_dr7;

        // Enable local breakpoint for DRn: set bit (register * 2)
        dr7 |= 1u64 << (register * 2);

        // Set condition and length in bits 16-31
        // Each DRn has 4 bits: condition(2) + length(2) at offset 16 + register*4
        let shift = 16 + register * 4;
        dr7 &= !(0xFu64 << shift); // clear existing
        dr7 |= (condition & 0x3) << shift; // condition (0=exec, 1=write, 3=rw)
                                           // length = 0 for 1-byte (execution breakpoint)

        *(ctx_ptr.add(dr7_offset) as *mut u64) = dr7;

        SetThreadContext(*thread, ctx_ptr as *const _).map_err(|e| {
            let _ = ResumeThread(*thread);
            MemoricError::WindowsApi(format!("SetThreadContext: {}", e))
        })?;

        ResumeThread(*thread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "hwbp_hook",
            "tid": tid,
            "address": format!("0x{:016X}", address),
            "register": format!("DR{}", register),
            "condition": match condition {
                0 => "execution",
                1 => "write",
                3 => "read_write",
                _ => "unknown",
            },
            "dr7": format!("0x{:016X}", dr7),
            "previous_dr": crate::memory::rollback::format_address(previous_dr),
            "previous_dr7": format!("0x{:016X}", previous_dr7),
            "rollback": hwbp_install_rollback(tid, register, previous_dr, previous_dr7),
            "provenance": provenance_json(args),
            "message": format!("Hardware breakpoint set on DR{} — no code patching, invisible to integrity checks", register)
        }))
    }
}

/// Remove hardware breakpoint from a thread
pub fn hwbp_unhook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext};
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS,
    };

    let tid = args
        .get("tid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing tid".to_string()))? as u32;
    let register = args
        .get("dr_index")
        .and_then(|v| v.as_u64())
        .or_else(|| args.get("register").and_then(|v| v.as_u64()))
        .unwrap_or(0) as usize;

    if register > 3 {
        return Err(MemoricError::WindowsApi("register must be 0-3".to_string()));
    }

    tracing::warn!("[EVASION] Removing HWBP DR{} from TID {}", register, tid);

    unsafe {
        let thread = OpenThread(THREAD_ALL_ACCESS, false, tid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenThread: {}", e)))?;
        let thread = crate::safe_handle::SafeHandle::new(thread);

        SuspendThread(*thread);

        let mut ctx: std::mem::MaybeUninit<[u8; 1232]> = std::mem::MaybeUninit::zeroed();
        let ctx_ptr = ctx.as_mut_ptr() as *mut u8;
        *(ctx_ptr.add(0x30) as *mut u32) = 0x00100010;

        GetThreadContext(*thread, ctx_ptr as *mut _).map_err(|e| {
            let _ = ResumeThread(*thread);
            MemoricError::WindowsApi(format!("GetThreadContext: {}", e))
        })?;

        let dr_base: usize = 0x350;
        let dr7_offset: usize = 0x378;

        let previous_dr = *(ctx_ptr.add(dr_base + register * 8) as *mut u64);
        let previous_dr7 = *(ctx_ptr.add(dr7_offset) as *mut u64);

        // Clear DRn
        *(ctx_ptr.add(dr_base + register * 8) as *mut u64) = 0;

        // Disable in DR7
        let mut dr7 = previous_dr7;
        dr7 &= !(1u64 << (register * 2)); // disable local enable
        dr7 &= !(0xFu64 << (16 + register * 4)); // clear condition/length
        *(ctx_ptr.add(dr7_offset) as *mut u64) = dr7;

        SetThreadContext(*thread, ctx_ptr as *const _).map_err(|e| {
            let _ = ResumeThread(*thread);
            MemoricError::WindowsApi(format!("SetThreadContext: {}", e))
        })?;

        ResumeThread(*thread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "hwbp_unhook",
            "tid": tid,
            "register": format!("DR{}", register),
            "previous_dr": crate::memory::rollback::format_address(previous_dr),
            "previous_dr7": format!("0x{:016X}", previous_dr7),
            "dr7": format!("0x{:016X}", dr7),
            "rollback": hwbp_remove_rollback(tid, register, previous_dr, previous_dr7),
            "provenance": provenance_json(args),
            "message": format!("Hardware breakpoint DR{} removed from thread {}", register, tid)
        }))
    }
}

/// Set VEH (Vectored Exception Handler) + HWBP for syscall interception
/// This combines HWBP with a vectored exception handler to redirect execution
pub fn hwbp_syscall_hook(args: &Value) -> Result<Value, MemoricError> {
    let function_name = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function name".to_string()))?;
    let redirect_address = args.get("redirect_address").and_then(parse_address);

    tracing::warn!("[EVASION] HWBP syscall hook on {}", function_name);

    unsafe {
        // Resolve function address
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
            b"ntdll.dll\0".as_ptr(),
        ))
        .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle: {}", e)))?;

        let mut name_buf = function_name.as_bytes().to_vec();
        name_buf.push(0);

        let func_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(name_buf.as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi(format!("{} not found", function_name)))?;

        let target_addr = func_addr as usize as u64;

        // Get current thread ID and set HWBP
        let tid = windows::Win32::System::Threading::GetCurrentThreadId();
        let hook_args = serde_json::json!({
            "tid": tid,
            "address": target_addr,
            "register": 0,
            "condition": 0,  // execution breakpoint
            "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
            "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
            "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
            "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
        });

        let result = hwbp_hook(&hook_args)?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "hwbp_syscall_hook",
            "function": function_name,
            "function_address": format!("0x{:016X}", target_addr),
            "redirect_address": redirect_address.map(|a| format!("0x{:016X}", a)),
            "breakpoint_set": result,
            "rollback": result.get("rollback").cloned().unwrap_or(Value::Null),
            "provenance": provenance_json(args),
            "message": format!("HWBP execution breakpoint set on {}. Combine with VEH for full interception.", function_name)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn install_rollback_removes_new_hwbp_when_register_was_empty() {
        let rollback = hwbp_install_rollback(77, 2, 0, 0);

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "remove_hardware_breakpoint");
        assert_eq!(rollback["action"]["tool"], "hook");
        assert_eq!(rollback["action"]["action"], "remove_hwbp");
        assert_eq!(rollback["action"]["args"]["tid"], 77);
        assert_eq!(rollback["action"]["args"]["dr_index"], 2);
    }

    #[test]
    fn install_rollback_reports_partial_restore_when_register_was_configured() {
        let previous_dr7 = 1u64 << 0 | 3u64 << 16;
        let rollback = hwbp_install_rollback(77, 0, 0x1234, previous_dr7);

        assert_eq!(rollback["available"], "partial");
        assert_eq!(rollback["strategy"], "restore_previous_hardware_breakpoint");
        assert_eq!(rollback["previous_local_enabled"], true);
        assert_eq!(rollback["action"]["action"], "install_hwbp");
        assert_eq!(
            rollback["action"]["args"]["target_address"],
            "0x0000000000001234"
        );
        assert_eq!(rollback["action"]["args"]["condition"], 3);
    }

    #[test]
    fn remove_rollback_reinstalls_previous_hwbp_partially() {
        let previous_dr7 = 1u64 << 2 | 1u64 << 20;
        let rollback = hwbp_remove_rollback(88, 1, 0x4567, previous_dr7);

        assert_eq!(rollback["available"], "partial");
        assert_eq!(rollback["strategy"], "restore_previous_hardware_breakpoint");
        assert_eq!(rollback["action"]["tool"], "hook");
        assert_eq!(rollback["action"]["action"], "install_hwbp");
        assert_eq!(rollback["action"]["args"]["dr_index"], 1);
        assert_eq!(rollback["action"]["args"]["condition"], 1);
    }

    #[test]
    fn hwbp_provenance_carries_request_task_chain_and_purpose() {
        let provenance = provenance_json(&json!({
            "request_id": "req-hwbp",
            "task_id": "task-hwbp",
            "chain_id": "chain-hwbp",
            "purpose": "test hwbp provenance"
        }));

        assert_eq!(provenance["correlation_id"], "req-hwbp");
        assert_eq!(provenance["request_id"], "req-hwbp");
        assert_eq!(provenance["task_id"], "task-hwbp");
        assert_eq!(provenance["chain_id"], "chain-hwbp");
        assert_eq!(provenance["purpose"], "test hwbp provenance");
    }
}

//! Hardware Breakpoint Hooks - use debug registers (DR0-DR3) to intercept syscalls
//! without patching code. Invisible to integrity checks that scan .text sections.

use crate::error::MemoricError;
use crate::util::parse_address;
use serde_json::Value;

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

        // Set DRn to target address
        *(ctx_ptr.add(dr_base + register * 8) as *mut u64) = address as u64;

        // Configure DR7
        let mut dr7 = *(ctx_ptr.add(dr7_offset) as *mut u64);

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
    let register = args.get("register").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

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

        // Clear DRn
        *(ctx_ptr.add(dr_base + register * 8) as *mut u64) = 0;

        // Disable in DR7
        let mut dr7 = *(ctx_ptr.add(dr7_offset) as *mut u64);
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
            "condition": 0  // execution breakpoint
        });

        let result = hwbp_hook(&hook_args)?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "hwbp_syscall_hook",
            "function": function_name,
            "function_address": format!("0x{:016X}", target_addr),
            "redirect_address": redirect_address.map(|a| format!("0x{:016X}", a)),
            "breakpoint_set": result,
            "message": format!("HWBP execution breakpoint set on {}. Combine with VEH for full interception.", function_name)
        }))
    }
}

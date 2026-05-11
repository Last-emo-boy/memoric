//! Return Address Spoofing — manipulate return addresses on the stack to evade stack-based detection

use crate::error::MemoricError;
use serde_json::Value;

/// Spoof return addresses on the call stack for the current thread
/// Builds a JMP trampoline that replaces return address before calling target
pub fn return_address_spoof(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    let target_function = args
        .get("target_function")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing target_function address".to_string()))?;
    let spoof_module = args
        .get("spoof_module")
        .and_then(|v| v.as_str())
        .unwrap_or("kernel32.dll");
    let spoof_function = args
        .get("spoof_function")
        .and_then(|v| v.as_str())
        .unwrap_or("BaseThreadInitThunk");

    tracing::warn!(
        "[EVASION] Return address spoof: target=0x{:X}, spoof={}!{}",
        target_function,
        spoof_module,
        spoof_function
    );

    unsafe {
        // Resolve the spoofed return address
        let mut mod_buf = spoof_module.as_bytes().to_vec();
        mod_buf.push(0);
        let hmod = GetModuleHandleA(windows::core::PCSTR(mod_buf.as_ptr())).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to get {}: {}", spoof_module, e))
        })?;

        let mut fn_buf = spoof_function.as_bytes().to_vec();
        fn_buf.push(0);
        let spoof_addr =
            GetProcAddress(hmod, windows::core::PCSTR(fn_buf.as_ptr())).ok_or_else(|| {
                MemoricError::WindowsApi(format!(
                    "{} not found in {}",
                    spoof_function, spoof_module
                ))
            })?;

        // Find a 'jmp [rsp]' or 'ret' gadget in the spoof module for the trampoline
        // We'll build code that:
        // 1. Pushes fake return address (spoof_addr)
        // 2. Pushes real target address
        // 3. Uses RET to "call" the target with spoofed return address on stack

        let trampoline_size = 128usize;
        let trampoline = VirtualAlloc(
            None,
            trampoline_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if trampoline.is_null() {
            return Err(MemoricError::MemoryAccess(
                "Failed to allocate trampoline".to_string(),
            ));
        }

        let mut code = Vec::new();

        // Save nonvolatile registers
        code.extend_from_slice(&[0x55]); // push rbp
        code.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp

        // Shadow space for the call (0x20 = 32 bytes)
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x30]); // sub rsp, 0x30

        // Push fake return address (what stack walkers will see)
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, spoof_addr
        code.extend_from_slice(&(spoof_addr as u64).to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, 0x28]); // mov [rsp+0x28], rax (fake return addr above shadow space)

        // Load target function address
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, target_function
        code.extend_from_slice(&(target_function as u64).to_le_bytes());

        // Call target — when it returns, the stack frame looks like it was called from spoof_addr
        code.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // Cleanup
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x30]); // add rsp, 0x30
        code.extend_from_slice(&[0x5D]); // pop rbp
        code.extend_from_slice(&[0xC3]); // ret

        std::ptr::copy_nonoverlapping(code.as_ptr(), trampoline as *mut u8, code.len());

        Ok(serde_json::json!({
            "success": true,
            "technique": "return_address_spoof",
            "trampoline_address": format!("0x{:016X}", trampoline as usize),
            "target_function": format!("0x{:016X}", target_function),
            "spoofed_return": format!("0x{:016X}", spoof_addr as usize),
            "spoof_source": format!("{}!{}", spoof_module, spoof_function),
            "code_size": code.len(),
            "message": format!("Trampoline ready at 0x{:016X}. Call it to invoke target with spoofed return address from {}!{}.", trampoline as usize, spoof_module, spoof_function)
        }))
    }
}

/// Build a synthetic call stack trampoline chain for deep spoofing
/// Creates multiple nested trampolines mimicking a legitimate thread call stack
pub fn deep_stack_spoof(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    let target_function = args
        .get("target_function")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing target_function address".to_string()))?;

    // Default stack frames that look like a legitimate Windows thread
    let default_frames = vec![
        ("ntdll.dll", "RtlUserThreadStart"),
        ("kernel32.dll", "BaseThreadInitThunk"),
        ("ntdll.dll", "NtWaitForSingleObject"),
        ("kernelbase.dll", "WaitForSingleObjectEx"),
    ];

    tracing::warn!(
        "[EVASION] Deep stack spoof: {} synthetic frames for 0x{:X}",
        default_frames.len(),
        target_function
    );

    unsafe {
        // Resolve all frame addresses
        let mut frame_addrs: Vec<(String, u64)> = Vec::new();
        for (module, func) in &default_frames {
            let mut mod_buf = module.as_bytes().to_vec();
            mod_buf.push(0);
            if let Ok(hmod) = GetModuleHandleA(windows::core::PCSTR(mod_buf.as_ptr())) {
                let mut fn_buf = func.as_bytes().to_vec();
                fn_buf.push(0);
                if let Some(addr) = GetProcAddress(hmod, windows::core::PCSTR(fn_buf.as_ptr())) {
                    frame_addrs.push((format!("{}!{}", module, func), addr as u64));
                }
            }
        }

        if frame_addrs.is_empty() {
            return Err(MemoricError::WindowsApi(
                "Could not resolve any spoof frame addresses".to_string(),
            ));
        }

        // Build trampoline that sets up synthetic stack frames
        let trampoline_size = 512usize;
        let trampoline = VirtualAlloc(
            None,
            trampoline_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if trampoline.is_null() {
            return Err(MemoricError::MemoryAccess(
                "Failed to allocate trampoline".to_string(),
            ));
        }

        let mut code = Vec::new();

        // Save original RSP
        code.extend_from_slice(&[0x48, 0x89, 0xE0]); // mov rax, rsp
        code.extend_from_slice(&[0x50]); // push rax (save original rsp)

        // Push synthetic frames (bottom to top)
        for (_, addr) in frame_addrs.iter().rev() {
            code.extend_from_slice(&[0x48, 0xB8]); // mov rax, frame_addr
            code.extend_from_slice(&addr.to_le_bytes());
            code.extend_from_slice(&[0x50]); // push rax
        }

        // Shadow space
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28

        // Call target
        code.extend_from_slice(&[0x48, 0xB8]); // mov rax, target
        code.extend_from_slice(&(target_function as u64).to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]); // call rax

        // Cleanup shadow space + synthetic frames
        let cleanup_size = 0x28 + (frame_addrs.len() * 8);
        code.extend_from_slice(&[0x48, 0x81, 0xC4]); // add rsp, imm32
        code.extend_from_slice(&(cleanup_size as u32).to_le_bytes());

        // Restore original rsp
        code.extend_from_slice(&[0x58]); // pop rax
        code.extend_from_slice(&[0x48, 0x89, 0xC4]); // mov rsp, rax
        code.extend_from_slice(&[0xC3]); // ret

        std::ptr::copy_nonoverlapping(code.as_ptr(), trampoline as *mut u8, code.len());

        let frame_info: Vec<Value> = frame_addrs.iter()
            .map(|(name, addr)| serde_json::json!({ "frame": name, "address": format!("0x{:016X}", addr) }))
            .collect();

        Ok(serde_json::json!({
            "success": true,
            "technique": "deep_stack_spoof",
            "trampoline_address": format!("0x{:016X}", trampoline as usize),
            "target_function": format!("0x{:016X}", target_function),
            "synthetic_frames": frame_info,
            "frame_count": frame_addrs.len(),
            "code_size": code.len(),
            "message": format!("Deep stack spoof trampoline at 0x{:016X} with {} synthetic frames. Stack trace mimics a legitimate waiting thread.", trampoline as usize, frame_addrs.len())
        }))
    }
}

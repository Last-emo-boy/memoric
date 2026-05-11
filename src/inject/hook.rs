//! Hook implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;
#[allow(unused_imports)]
use std::ffi::c_void;

/// IAT Hook — full implementation with PE header parsing
/// Parses the remote process IAT, finds the target import, and patches it
pub fn hook_function_iat(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::HookFailed("Missing pid".to_string()))?;
    let module = args
        .get("module")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::HookFailed("Missing module".to_string()))?;
    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::HookFailed("Missing function".to_string()))?;
    let hook_address = args
        .get("hook_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::HookFailed("Missing hook_address".to_string()))?;

    tracing::warn!(
        "[HOOK] IAT hook for {}!{} in PID {} -> 0x{:016X}",
        module,
        function,
        pid,
        hook_address
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Get module base address from target process via pe_parse / find_iat_entry approach
        // Use EnumProcessModulesEx to find the target module
        use windows::Win32::System::ProcessStatus::{
            EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL,
        };
        let mut modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut needed = 0u32;
        EnumProcessModulesEx(
            *handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<windows::Win32::Foundation::HMODULE>()) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
        .map_err(|e| MemoricError::HookFailed(format!("EnumProcessModulesEx: {}", e)))?;

        let module_count =
            needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
        let mut mod_base = 0u64;
        let module_lower = module.to_lowercase();

        for i in 0..module_count {
            let mut name_buf = [0u16; 260];
            let len = GetModuleBaseNameW(*handle, modules[i], &mut name_buf);
            if len > 0 {
                let name = String::from_utf16_lossy(&name_buf[..len as usize]).to_lowercase();
                if name == module_lower
                    || name.trim_end_matches(".dll") == module_lower.trim_end_matches(".dll")
                {
                    mod_base = modules[i].0 as u64;
                    break;
                }
            }
        }

        if mod_base == 0 {
            // If searching target process modules fails, try using module as the main exe
            if module_count > 0 {
                mod_base = modules[0].0 as u64;
            } else {
                return Err(MemoricError::HookFailed(format!(
                    "Module '{}' not found",
                    module
                )));
            }
        }

        // Read DOS header
        let mut dos_header = [0u8; 64];
        ReadProcessMemory(
            *handle,
            mod_base as *const _,
            dos_header.as_mut_ptr() as *mut _,
            64,
            None,
        )
        .map_err(|e| MemoricError::HookFailed(format!("Read DOS header: {}", e)))?;

        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as u64;
        let nt_headers_addr = mod_base + e_lfanew;

        // Read NT headers — get import directory RVA
        let mut nt_buf = [0u8; 264]; // enough for signature + file header + optional header
        ReadProcessMemory(
            *handle,
            nt_headers_addr as *const _,
            nt_buf.as_mut_ptr() as *mut _,
            nt_buf.len(),
            None,
        )
        .map_err(|e| MemoricError::HookFailed(format!("Read NT headers: {}", e)))?;

        // Import directory is at optional header offset 0x78 (PE32+)
        let import_rva =
            u32::from_le_bytes([nt_buf[0x90], nt_buf[0x91], nt_buf[0x92], nt_buf[0x93]]) as u64;
        let import_size =
            u32::from_le_bytes([nt_buf[0x94], nt_buf[0x95], nt_buf[0x96], nt_buf[0x97]]) as u64;

        if import_rva == 0 {
            return Err(MemoricError::HookFailed("No import directory".to_string()));
        }

        let import_dir_addr = mod_base + import_rva;

        // Walk IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each)
        let mut original_iat_value = 0u64;
        let mut iat_entry_addr = 0u64;
        let mut found = false;

        let module_lower = module.to_lowercase();
        let mut desc_offset = 0u64;

        loop {
            let mut desc = [0u8; 20];
            if ReadProcessMemory(
                *handle,
                (import_dir_addr + desc_offset) as *const _,
                desc.as_mut_ptr() as *mut _,
                20,
                None,
            )
            .is_err()
            {
                break;
            }

            let original_first_thunk =
                u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]) as u64;
            let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]) as u64;
            let first_thunk = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]) as u64;

            if original_first_thunk == 0 && first_thunk == 0 {
                break; // end of import descriptors
            }

            if name_rva == 0 {
                desc_offset += 20;
                continue;
            }

            // Read DLL name
            let mut dll_name_buf = [0u8; 256];
            if ReadProcessMemory(
                *handle,
                (mod_base + name_rva) as *const _,
                dll_name_buf.as_mut_ptr() as *mut _,
                256,
                None,
            )
            .is_ok()
            {
                let dll_name = std::ffi::CStr::from_bytes_until_nul(&dll_name_buf)
                    .map(|s| s.to_string_lossy().to_lowercase())
                    .unwrap_or_default();

                if dll_name.contains(&module_lower)
                    || module_lower.contains(&dll_name.trim_end_matches(".dll"))
                {
                    // Found the target DLL — walk its thunks
                    let mut thunk_idx = 0u64;
                    loop {
                        // Read original thunk (for name) and thunk (for address)
                        let oft_addr = mod_base + original_first_thunk + thunk_idx * 8;
                        let ft_addr = mod_base + first_thunk + thunk_idx * 8;

                        let mut oft_val = 0u64;
                        let mut ft_val = 0u64;
                        if ReadProcessMemory(
                            *handle,
                            oft_addr as *const _,
                            &mut oft_val as *mut _ as *mut _,
                            8,
                            None,
                        )
                        .is_err()
                        {
                            break;
                        }
                        if oft_val == 0 {
                            break;
                        }

                        // Check if ordinal import (bit 63 set)
                        if oft_val & (1u64 << 63) != 0 {
                            thunk_idx += 1;
                            continue;
                        }

                        // Read import name (skip 2-byte hint)
                        let hint_name_addr = mod_base + oft_val + 2;
                        let mut fn_name_buf = [0u8; 256];
                        if ReadProcessMemory(
                            *handle,
                            hint_name_addr as *const _,
                            fn_name_buf.as_mut_ptr() as *mut _,
                            256,
                            None,
                        )
                        .is_ok()
                        {
                            let fn_name = std::ffi::CStr::from_bytes_until_nul(&fn_name_buf)
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();

                            if fn_name == function {
                                // Found it! Read current IAT value
                                ReadProcessMemory(
                                    *handle,
                                    ft_addr as *const _,
                                    &mut ft_val as *mut _ as *mut _,
                                    8,
                                    None,
                                )
                                .map_err(|e| {
                                    MemoricError::HookFailed(format!("Read IAT: {}", e))
                                })?;

                                original_iat_value = ft_val;
                                iat_entry_addr = ft_addr;
                                found = true;
                                break;
                            }
                        }
                        thunk_idx += 1;
                    }
                }
            }

            if found {
                break;
            }
            desc_offset += 20;
        }

        if !found {
            return Err(MemoricError::HookFailed(format!(
                "Import {}!{} not found in target module IAT",
                module, function
            )));
        }

        // Patch IAT entry: change protection, write new address, restore
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            iat_entry_addr as *mut _,
            8,
            PAGE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::HookFailed(format!("VirtualProtectEx IAT: {}", e)))?;

        WriteProcessMemory(
            *handle,
            iat_entry_addr as *const _,
            &hook_address as *const _ as *const _,
            8,
            None,
        )
        .map_err(|e| MemoricError::HookFailed(format!("WriteProcessMemory IAT: {}", e)))?;

        let _ = VirtualProtectEx(
            *handle,
            iat_entry_addr as *mut _,
            8,
            old_protect,
            &mut old_protect,
        );

        Ok(serde_json::json!({
            "success": true,
            "technique": "iat_hook",
            "module": module,
            "function": function,
            "iat_entry_address": format!("0x{:016X}", iat_entry_addr),
            "original_value": format!("0x{:016X}", original_iat_value),
            "new_value": format!("0x{:016X}", hook_address),
            "pid": pid,
            "message": format!("IAT hook installed: {}!{} -> 0x{:016X}", module, function, hook_address)
        }))
    }
}

/// Inline Hook - install a JMP instruction to redirect execution
pub fn inline_hook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::HookFailed("Missing pid".to_string()))?;
    let target_address = args
        .get("target_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::HookFailed("Missing target_address".to_string()))?;
    let hook_address = args
        .get("hook_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::HookFailed("Missing hook_address".to_string()))?;

    tracing::info!(
        "Setting up inline hook at 0x{:016X} -> 0x{:016X}",
        target_address,
        hook_address
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let rel_offset_i64 = hook_address as i64 - (target_address as i64 + 5);
        if rel_offset_i64 > i32::MAX as i64 || rel_offset_i64 < i32::MIN as i64 {
            // Distance > 2GB: use 14-byte absolute JMP (mov rax, addr; jmp rax)
            let mut abs_hook = Vec::with_capacity(14);
            abs_hook.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
            abs_hook.extend_from_slice(&hook_address.to_le_bytes());
            abs_hook.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

            let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            VirtualProtectEx(
                *handle,
                target_address as *mut _,
                abs_hook.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to change protection: {}", e)))?;

            WriteProcessMemory(
                *handle,
                target_address as *const _,
                abs_hook.as_ptr() as *const _,
                abs_hook.len(),
                None,
            )
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to write hook: {}", e)))?;

            let _ = VirtualProtectEx(
                *handle,
                target_address as *mut _,
                abs_hook.len(),
                old_protect,
                &mut old_protect,
            );

            return Ok(serde_json::json!({
                "success": true,
                "target_address": format!("0x{:016X}", target_address),
                "hook_address": format!("0x{:016X}", hook_address),
                "hook_bytes": "mov rax + jmp rax (14-byte absolute)",
                "hook_size": 14
            }));
        }

        let rel_offset = rel_offset_i64 as u32;
        let hook_bytes: [u8; 5] = [
            0xE9,
            (rel_offset & 0xFF) as u8,
            ((rel_offset >> 8) & 0xFF) as u8,
            ((rel_offset >> 16) & 0xFF) as u8,
            ((rel_offset >> 24) & 0xFF) as u8,
        ];

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            target_address as *mut _,
            hook_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to change protection: {}", e)))?;

        WriteProcessMemory(
            *handle,
            target_address as *const _,
            hook_bytes.as_ptr() as *const _,
            hook_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to write hook: {}", e)))?;

        // Restore protection
        let _ = VirtualProtectEx(
            *handle,
            target_address as *mut _,
            hook_bytes.len(),
            old_protect,
            &mut old_protect,
        );

        tracing::info!("Inline hook installed successfully");

        Ok(serde_json::json!({
            "success": true,
            "target_address": format!("0x{:016X}", target_address),
            "hook_address": format!("0x{:016X}", hook_address),
            "hook_bytes": "E9 + rel32"
        }))
    }
}

/// Generate trampoline for original function execution
pub fn generate_trampoline(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::HookFailed("Missing pid".to_string()))?;
    let target_address = args
        .get("target_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::HookFailed("Missing target_address".to_string()))?;
    let hook_size = args.get("hook_size").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

    tracing::info!("Generating trampoline for 0x{:016X}", target_address);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut original_bytes = vec![0u8; hook_size];
        ReadProcessMemory(
            *handle,
            target_address as *const _,
            original_bytes.as_mut_ptr() as *mut _,
            hook_size,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to read original bytes: {}", e)))?;

        // W^X: allocate trampoline as RW
        let trampoline_size = hook_size + 5;
        let trampoline_mem = VirtualAllocEx(
            *handle,
            None,
            trampoline_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if trampoline_mem.is_null() {
            return Err(MemoricError::HookFailed(
                "Failed to allocate trampoline memory".to_string(),
            ));
        }

        // Write original bytes to trampoline
        WriteProcessMemory(
            *handle,
            trampoline_mem,
            original_bytes.as_ptr() as *const _,
            hook_size,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to write trampoline: {}", e)))?;

        // Add JMP back to original function
        let return_addr = target_address + hook_size as u64;
        let rel_offset =
            (return_addr as i64 - ((trampoline_mem as u64 + hook_size as u64) as i64 + 5)) as u32;

        let jmp_back: [u8; 5] = [
            0xE9,
            (rel_offset & 0xFF) as u8,
            ((rel_offset >> 8) & 0xFF) as u8,
            ((rel_offset >> 16) & 0xFF) as u8,
            ((rel_offset >> 24) & 0xFF) as u8,
        ];

        WriteProcessMemory(
            *handle,
            (trampoline_mem as usize + hook_size) as *mut _,
            jmp_back.as_ptr() as *const _,
            jmp_back.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to write JMP back: {}", e)))?;

        // W^X: mark trampoline as RX
        let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            trampoline_mem,
            trampoline_size,
            PAGE_EXECUTE_READ,
            &mut old_prot,
        )
        .map_err(|e| MemoricError::HookFailed(format!("VirtualProtectEx trampoline RX: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "trampoline_address": format!("0x{:016X}", trampoline_mem as usize),
            "original_bytes": format!("{:02X?}", original_bytes),
            "hook_size": hook_size
        }))
    }
}

/// Detour-style transactional hook — install multiple hooks atomically
/// Suspends all threads, applies hooks, resumes. All-or-nothing semantics.
pub fn detour_transaction(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_SUSPEND_RESUME,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::HookFailed("Missing pid".to_string()))?;
    let hooks = args
        .get("hooks")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::HookFailed("Missing hooks array".to_string()))?;

    tracing::info!("Detour transaction: {} hooks in PID {}", hooks.len(), pid);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Phase 1: Suspend all threads
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;
        let _snap = SafeHandle::new(snapshot);

        let mut suspended_threads = Vec::new();
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        if Thread32First(*_snap, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid as u32 {
                    if let Ok(th) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                        SuspendThread(th);
                        suspended_threads.push((entry.th32ThreadID, SafeHandle::new(th)));
                    }
                }
                if Thread32Next(*_snap, &mut entry).is_err() {
                    break;
                }
            }
        }

        // Phase 2: Apply all hooks, collecting rollback info
        let mut applied = Vec::new();
        let mut rollback_needed = false;

        for hook_def in hooks {
            let target = hook_def.get("target_address").and_then(parse_address);
            let dest = hook_def.get("hook_address").and_then(parse_address);
            if target.is_none() || dest.is_none() {
                rollback_needed = true;
                break;
            }
            let target = target.unwrap();
            let dest = dest.unwrap();

            // Read original bytes
            let mut orig = [0u8; 14];
            if ReadProcessMemory(
                *handle,
                target as *const _,
                orig.as_mut_ptr() as *mut _,
                14,
                None,
            )
            .is_err()
            {
                rollback_needed = true;
                break;
            }

            // Build JMP
            let mut hook_bytes = Vec::new();
            let rel = dest as i64 - (target as i64 + 5);
            if rel >= i32::MIN as i64 && rel <= i32::MAX as i64 {
                hook_bytes.push(0xE9);
                hook_bytes.extend_from_slice(&(rel as u32).to_le_bytes());
            } else {
                hook_bytes.extend_from_slice(&[0x48, 0xB8]);
                hook_bytes.extend_from_slice(&dest.to_le_bytes());
                hook_bytes.extend_from_slice(&[0xFF, 0xE0]);
            }

            let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            if VirtualProtectEx(
                *handle,
                target as *mut _,
                hook_bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            )
            .is_err()
            {
                rollback_needed = true;
                break;
            }

            if WriteProcessMemory(
                *handle,
                target as *const _,
                hook_bytes.as_ptr() as *const _,
                hook_bytes.len(),
                None,
            )
            .is_err()
            {
                let _ = VirtualProtectEx(
                    *handle,
                    target as *mut _,
                    hook_bytes.len(),
                    old_prot,
                    &mut old_prot,
                );
                rollback_needed = true;
                break;
            }

            let _ = VirtualProtectEx(
                *handle,
                target as *mut _,
                hook_bytes.len(),
                old_prot,
                &mut old_prot,
            );
            applied.push((target, orig, hook_bytes.len()));
        }

        // Phase 3: Rollback if any hook failed
        if rollback_needed {
            for (addr, orig, size) in &applied {
                let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
                let _ = VirtualProtectEx(
                    *handle,
                    *addr as *mut _,
                    *size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_prot,
                );
                let _ = WriteProcessMemory(
                    *handle,
                    *addr as *const _,
                    orig.as_ptr() as *const _,
                    *size,
                    None,
                );
                let _ = VirtualProtectEx(*handle, *addr as *mut _, *size, old_prot, &mut old_prot);
            }
        }

        // Phase 4: Resume all threads
        for (_tid, th) in &suspended_threads {
            ResumeThread(**th);
        }

        if rollback_needed {
            return Err(MemoricError::HookFailed(format!(
                "Transaction failed after {} hooks, rolled back",
                applied.len()
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "hooks_applied": applied.len(),
            "threads_suspended": suspended_threads.len(),
            "transactional": true
        }))
    }
}

/// Hook restoration
pub fn restore_hook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::HookFailed("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::HookFailed("Missing address".to_string()))?;
    let original_bytes = args
        .get("original_bytes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::HookFailed("Missing original_bytes".to_string()))?;

    let bytes: Vec<u8> = original_bytes
        .iter()
        .filter_map(|b| b.as_u64().map(|v| v as u8))
        .collect();

    tracing::info!("Restoring hook at 0x{:016X}", address);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            address as *mut _,
            bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .ok();

        WriteProcessMemory(
            *handle,
            address as *const _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to restore bytes: {}", e)))?;

        // Restore protection
        let _ = VirtualProtectEx(
            *handle,
            address as *mut _,
            bytes.len(),
            old_protect,
            &mut old_protect,
        );

        Ok(serde_json::json!({
            "success": true,
            "message": "Hook restored"
        }))
    }
}

/// SetWindowsHookEx injection — load DLL globally via a Windows hook
/// Injects DLL into all processes that receive the hooked message type
pub fn set_windows_hook_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows::Win32::UI::WindowsAndMessaging::{SetWindowsHookExW, WINDOWS_HOOK_ID};

    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing dll_path".to_string()))?;
    let hook_type_str = args
        .get("hook_type")
        .and_then(|v| v.as_str())
        .unwrap_or("WH_GETMESSAGE");
    let export_name = args
        .get("export_name")
        .and_then(|v| v.as_str())
        .unwrap_or("HookProc");

    // Map hook type string to Windows constant
    let hook_id = match hook_type_str {
        "WH_GETMESSAGE" => WINDOWS_HOOK_ID(3),
        "WH_CALLWNDPROC" => WINDOWS_HOOK_ID(4),
        "WH_CBT" => WINDOWS_HOOK_ID(5),
        "WH_KEYBOARD" => WINDOWS_HOOK_ID(2),
        "WH_MOUSE" => WINDOWS_HOOK_ID(7),
        "WH_KEYBOARD_LL" => WINDOWS_HOOK_ID(13),
        "WH_MOUSE_LL" => WINDOWS_HOOK_ID(14),
        _ => WINDOWS_HOOK_ID(3), // default WH_GETMESSAGE
    };

    tracing::warn!(
        "[INJECTION] SetWindowsHookEx inject: {} hook={} export={}",
        dll_path,
        hook_type_str,
        export_name
    );

    unsafe {
        // Load the DLL into our own process first
        let dll_wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
        let module = LoadLibraryW(windows::core::PCWSTR(dll_wide.as_ptr()))
            .map_err(|e| MemoricError::InjectionFailed(format!("LoadLibraryW failed: {}", e)))?;

        // Get the hook procedure address
        let export_cstr = std::ffi::CString::new(export_name)
            .map_err(|_| MemoricError::InjectionFailed("Invalid export name".to_string()))?;
        let proc_addr = GetProcAddress(
            module,
            windows::core::PCSTR(export_cstr.as_ptr() as *const u8),
        )
        .ok_or_else(|| {
            MemoricError::InjectionFailed(format!("GetProcAddress({}) failed", export_name))
        })?;

        // Install global hook — tid=0 means all threads in desktop
        let hook_fn: unsafe extern "system" fn(
            i32,
            windows::Win32::Foundation::WPARAM,
            windows::Win32::Foundation::LPARAM,
        ) -> windows::Win32::Foundation::LRESULT = std::mem::transmute(proc_addr);
        let hook = SetWindowsHookExW(hook_id, Some(hook_fn), module, 0).map_err(|e| {
            MemoricError::InjectionFailed(format!("SetWindowsHookExW failed: {}", e))
        })?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "set_windows_hook_inject",
            "hook_handle": hook.0 as u64,
            "hook_type": hook_type_str,
            "dll_path": dll_path,
            "export_name": export_name,
            "scope": "global",
            "message": format!("Global {} hook installed from {}", hook_type_str, dll_path)
        }))
    }
}

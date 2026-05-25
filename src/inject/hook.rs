//! Hook implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::{json, Value};
#[allow(unused_imports)]
use std::ffi::c_void;

#[derive(Debug, Clone)]
struct AppliedHookRollback {
    address: u64,
    original_bytes: Vec<u8>,
}

fn provenance_json(args: &Value) -> Value {
    json!({
        "correlation_id": crate::observability::correlation_id_from_args(args),
        "request_id": args.get("request_id").cloned().unwrap_or(Value::Null),
        "task_id": args.get("task_id").cloned().unwrap_or(Value::Null),
        "chain_id": args.get("chain_id").cloned().unwrap_or(Value::Null),
        "purpose": args.get("purpose").cloned().unwrap_or(Value::Null),
    })
}

fn restore_hook_rollback(pid: u64, address: u64, original_bytes: &[u8], detail: &str) -> Value {
    let args = json!({
        "pid": pid,
        "address": crate::memory::rollback::format_address(address),
        "original_bytes": original_bytes,
    });

    json!({
        "available": true,
        "strategy": "restore_hook_original_bytes",
        "captured_fields": ["pid", "address", "original_bytes"],
        "original_bytes": original_bytes,
        "args": args.clone(),
        "action": {
            "tool": "hook",
            "action": "restore",
            "args": args,
        },
        "detail": detail,
    })
}

fn restore_hook_capture_rollback(
    pid: u64,
    address: u64,
    capture: &crate::memory::rollback::OriginalBytesCapture,
    old_protection: Option<u32>,
    detail: &str,
) -> Value {
    let mut rollback = crate::memory::rollback::restore_original_bytes_rollback(
        pid,
        address,
        capture,
        old_protection,
        true,
    );

    rollback["strategy"] = json!("restore_hook_original_bytes");
    rollback["detail"] = json!(detail);
    if let Some(action) = rollback.get_mut("action") {
        action["tool"] = json!("hook");
        action["action"] = json!("restore");
        if let Some(args) = action.get_mut("args") {
            args["original_bytes"] = args.get("bytes").cloned().unwrap_or(Value::Null);
            if let Some(obj) = args.as_object_mut() {
                obj.remove("bytes");
                obj.remove("bypass_protect");
            }
        }
    }
    if let Some(args) = rollback.get_mut("args") {
        args["original_bytes"] = args.get("bytes").cloned().unwrap_or(Value::Null);
        if let Some(obj) = args.as_object_mut() {
            obj.remove("bytes");
            obj.remove("bypass_protect");
        }
    }

    rollback
}

fn restore_iat_pointer_rollback(
    pid: u64,
    iat_address: u64,
    original_address: u64,
    detail: &str,
) -> Value {
    let args = json!({
        "pid": pid,
        "iat_address": crate::memory::rollback::format_address(iat_address),
        "original_address": crate::memory::rollback::format_address(original_address),
    });

    json!({
        "available": true,
        "strategy": "restore_iat_pointer",
        "captured_fields": ["pid", "iat_address", "original_address"],
        "iat_address": crate::memory::rollback::format_address(iat_address),
        "original_address": crate::memory::rollback::format_address(original_address),
        "args": args.clone(),
        "action": {
            "tool": "hook",
            "action": "remove_iat",
            "args": args,
        },
        "detail": detail,
    })
}

fn reinstall_iat_pointer_rollback(
    pid: u64,
    iat_address: u64,
    hook_address: u64,
    detail: &str,
) -> Value {
    let args = json!({
        "pid": pid,
        "iat_address": crate::memory::rollback::format_address(iat_address),
        "original_address": crate::memory::rollback::format_address(hook_address),
    });

    json!({
        "available": true,
        "strategy": "restore_removed_iat_hook_pointer",
        "captured_fields": ["pid", "iat_address", "hook_address"],
        "iat_address": crate::memory::rollback::format_address(iat_address),
        "hook_address": crate::memory::rollback::format_address(hook_address),
        "args": args.clone(),
        "action": {
            "tool": "hook",
            "action": "remove_iat",
            "args": args,
        },
        "detail": detail,
    })
}

fn restore_pre_restore_hook_bytes_rollback(
    pid: u64,
    address: u64,
    capture: &crate::memory::rollback::OriginalBytesCapture,
) -> Value {
    let mut rollback = restore_hook_capture_rollback(
        pid,
        address,
        capture,
        None,
        "hook(action='restore') captured the bytes present before restoring the original hook bytes",
    );

    rollback["strategy"] = json!("restore_pre_restore_hook_bytes");

    rollback
}

fn detour_transaction_rollback(pid: u64, applied: &[AppliedHookRollback]) -> Value {
    let steps = applied
        .iter()
        .map(|hook| {
            let rollback = restore_hook_rollback(
                pid,
                hook.address,
                &hook.original_bytes,
                "detour transaction captured original bytes before patching this target",
            );
            json!({
                "address": crate::memory::rollback::format_address(hook.address),
                "hook_size": hook.original_bytes.len(),
                "rollback": rollback,
            })
        })
        .collect::<Vec<_>>();
    let actions = steps
        .iter()
        .filter_map(|step| step["rollback"].get("action").cloned())
        .collect::<Vec<_>>();

    json!({
        "available": !applied.is_empty(),
        "strategy": "restore_detour_original_bytes",
        "captured_fields": ["pid", "hooks[].address", "hooks[].original_bytes"],
        "hooks": steps,
        "actions": actions,
        "detail": "detour transaction captured original bytes for each applied hook; rollback should restore each hook target",
    })
}

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
            "rollback": restore_iat_pointer_rollback(
                pid,
                iat_entry_addr,
                original_iat_value,
                "IAT hook can be removed by writing the captured original pointer back to the IAT entry",
            ),
            "provenance": provenance_json(args),
            "message": format!("IAT hook installed: {}!{} -> 0x{:016X}", module, function, hook_address)
        }))
    }
}

/// Inline Hook - install a JMP instruction to redirect execution
pub fn inline_hook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
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
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let rel_offset_i64 = hook_address as i64 - (target_address as i64 + 5);
        let (hook_bytes, hook_description) =
            if rel_offset_i64 > i32::MAX as i64 || rel_offset_i64 < i32::MIN as i64 {
                // Distance > 2GB: use 14-byte absolute JMP (mov rax, addr; jmp rax)
                let mut abs_hook = Vec::with_capacity(14);
                abs_hook.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
                abs_hook.extend_from_slice(&hook_address.to_le_bytes());
                abs_hook.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
                (abs_hook, "mov rax + jmp rax (14-byte absolute)")
            } else {
                let rel_offset = rel_offset_i64 as u32;
                (
                    vec![
                        0xE9,
                        (rel_offset & 0xFF) as u8,
                        ((rel_offset >> 8) & 0xFF) as u8,
                        ((rel_offset >> 16) & 0xFF) as u8,
                        ((rel_offset >> 24) & 0xFF) as u8,
                    ],
                    "E9 + rel32",
                )
            };

        let original = crate::memory::rollback::capture_original_bytes(
            *handle,
            target_address,
            hook_bytes.len(),
        );

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
            "hook_bytes": hook_description,
            "hook_size": hook_bytes.len(),
            "old_protect": old_protect.0,
            "rollback": restore_hook_capture_rollback(
                pid,
                target_address,
                &original,
                Some(old_protect.0),
                "inline hook captured original bytes before patching the target function",
            ),
            "provenance": provenance_json(args)
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
            applied.push(AppliedHookRollback {
                address: target,
                original_bytes: orig[..hook_bytes.len()].to_vec(),
            });
        }

        // Phase 3: Rollback if any hook failed
        if rollback_needed {
            for hook in &applied {
                let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
                let _ = VirtualProtectEx(
                    *handle,
                    hook.address as *mut _,
                    hook.original_bytes.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut old_prot,
                );
                let _ = WriteProcessMemory(
                    *handle,
                    hook.address as *const _,
                    hook.original_bytes.as_ptr() as *const _,
                    hook.original_bytes.len(),
                    None,
                );
                let _ = VirtualProtectEx(
                    *handle,
                    hook.address as *mut _,
                    hook.original_bytes.len(),
                    old_prot,
                    &mut old_prot,
                );
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
            "transactional": true,
            "rollback": detour_transaction_rollback(pid, &applied),
            "provenance": provenance_json(args)
        }))
    }
}

/// Hook restoration
pub fn restore_hook(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
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
            PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let previous_hook_bytes =
            crate::memory::rollback::capture_original_bytes(*handle, address, bytes.len());

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
            "pid": pid,
            "address": crate::memory::rollback::format_address(address),
            "bytes_restored": bytes.len(),
            "old_protect": old_protect.0,
            "rollback": restore_pre_restore_hook_bytes_rollback(
                pid,
                address,
                &previous_hook_bytes,
            ),
            "provenance": provenance_json(args),
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
            "rollback": {
                "available": "partial",
                "strategy": "unhook_windows_hook",
                "captured_fields": ["hook_handle", "hook_type", "dll_path", "export_name"],
                "hook_handle": hook.0 as u64,
                "reason": "no_remove_winhook_tool_action",
                "action": Value::Null,
                "detail": "Windows hook handle was captured, but the MCP hook tool does not yet expose a remove_winhook action for automated rollback"
            },
            "provenance": provenance_json(args),
            "message": format!("Global {} hook installed from {}", hook_type_str, dll_path)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn restore_hook_rollback_emits_executable_restore_action() {
        let rollback =
            restore_hook_rollback(1234, 0x401000, &[0x90, 0x90, 0xC3], "captured before patch");

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "restore_hook_original_bytes");
        assert_eq!(rollback["original_bytes"], json!([0x90, 0x90, 0xC3]));
        assert_eq!(rollback["action"]["tool"], "hook");
        assert_eq!(rollback["action"]["action"], "restore");
        assert_eq!(rollback["action"]["args"]["pid"], 1234);
        assert_eq!(rollback["action"]["args"]["address"], "0x0000000000401000");
        assert_eq!(
            rollback["action"]["args"]["original_bytes"],
            json!([0x90, 0x90, 0xC3])
        );
    }

    #[test]
    fn capture_rollback_uses_hook_restore_action() {
        let capture = crate::memory::rollback::OriginalBytesCapture {
            bytes: Some(vec![0xCC, 0x90, 0xC3]),
            bytes_requested: 3,
            bytes_read: 3,
            error: None,
        };
        let rollback =
            restore_hook_capture_rollback(1234, 0x401000, &capture, Some(0x20), "captured");

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "restore_hook_original_bytes");
        assert_eq!(rollback["old_protection"], 0x20);
        assert_eq!(rollback["action"]["tool"], "hook");
        assert_eq!(rollback["action"]["action"], "restore");
        assert!(rollback["action"]["args"]["bytes"].is_null());
        assert_eq!(
            rollback["action"]["args"]["original_bytes"],
            json!([0xCC, 0x90, 0xC3])
        );
    }

    #[test]
    fn iat_install_rollback_restores_original_pointer() {
        let rollback =
            restore_iat_pointer_rollback(1234, 0x500000, 0x700000, "restore original import");

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "restore_iat_pointer");
        assert_eq!(rollback["action"]["tool"], "hook");
        assert_eq!(rollback["action"]["action"], "remove_iat");
        assert_eq!(
            rollback["action"]["args"]["iat_address"],
            "0x0000000000500000"
        );
        assert_eq!(
            rollback["action"]["args"]["original_address"],
            "0x0000000000700000"
        );
    }

    #[test]
    fn iat_remove_rollback_can_reinstall_removed_pointer() {
        let rollback = reinstall_iat_pointer_rollback(
            1234,
            0x500000,
            0x710000,
            "restore removed hook pointer",
        );

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "restore_removed_iat_hook_pointer");
        assert_eq!(rollback["action"]["tool"], "hook");
        assert_eq!(rollback["action"]["action"], "remove_iat");
        assert_eq!(
            rollback["action"]["args"]["original_address"],
            "0x0000000000710000"
        );
    }

    #[test]
    fn detour_transaction_rollback_lists_restore_actions() {
        let applied = vec![
            AppliedHookRollback {
                address: 0x401000,
                original_bytes: vec![0x55, 0x48, 0x89, 0xE5, 0x90],
            },
            AppliedHookRollback {
                address: 0x402000,
                original_bytes: vec![0x48, 0x83, 0xEC, 0x28],
            },
        ];
        let rollback = detour_transaction_rollback(1234, &applied);

        assert_eq!(rollback["available"], true);
        assert_eq!(rollback["strategy"], "restore_detour_original_bytes");
        assert_eq!(rollback["hooks"].as_array().unwrap().len(), 2);
        assert_eq!(rollback["actions"].as_array().unwrap().len(), 2);
        assert_eq!(rollback["actions"][0]["tool"], "hook");
        assert_eq!(rollback["actions"][0]["action"], "restore");
        assert_eq!(
            rollback["actions"][0]["args"]["original_bytes"],
            json!([0x55, 0x48, 0x89, 0xE5, 0x90])
        );
    }

    #[test]
    fn hook_provenance_carries_request_task_chain_and_purpose() {
        let provenance = provenance_json(&json!({
            "request_id": "req-hook",
            "task_id": "task-hook",
            "chain_id": "chain-hook",
            "purpose": "test hook provenance"
        }));

        assert_eq!(provenance["correlation_id"], "req-hook");
        assert_eq!(provenance["request_id"], "req-hook");
        assert_eq!(provenance["task_id"], "task-hook");
        assert_eq!(provenance["chain_id"], "chain-hook");
        assert_eq!(provenance["purpose"], "test hook provenance");
    }
}

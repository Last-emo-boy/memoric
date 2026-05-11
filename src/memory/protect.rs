//! Memory protection implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Query memory regions
pub fn query_regions(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut regions = Vec::new();
        let mut addr = 0usize;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            regions.push(serde_json::json!({
                "base_address": format!("0x{:016X}", mbi.BaseAddress as usize),
                "allocation_base": format!("0x{:016X}", mbi.AllocationBase as usize),
                "region_size": mbi.RegionSize,
                "state": mbi.State.0,
                "protect": mbi.Protect.0,
                "type": mbi.Type.0
            }));

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        let total_count = regions.len();
        let paginated: Vec<_> = regions.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "regions": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": offset + paginated.len() < total_count
        }))
    }
}

/// VirtualAllocEx wrapper
pub fn virtual_alloc_ex(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?;
    let protect = args
        .get("protect")
        .and_then(|v| v.as_str())
        .unwrap_or("RWX");

    let protect_flag = match protect {
        "RWX" => windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        "RW" => windows::Win32::System::Memory::PAGE_READWRITE,
        "RX" => windows::Win32::System::Memory::PAGE_EXECUTE_READ,
        "R" => windows::Win32::System::Memory::PAGE_READONLY,
        _ => windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
    };

    // Auto-enable SeDebugPrivilege (best-effort)
    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            size as usize,
            MEM_COMMIT | MEM_RESERVE,
            protect_flag,
        );

        if remote_mem.is_null() {
            return Err(MemoricError::MemoryAccess(
                "Failed to allocate remote memory".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "address": format!("0x{:016X}", remote_mem as usize),
            "size": size,
            "protect": protect
        }))
    }
}

/// VirtualFreeEx wrapper
pub fn virtual_free_ex(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualFreeEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_FREE, MEM_RELEASE,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let query_result = VirtualQueryEx(
            *handle,
            Some(address as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        if query_result > 0 && mbi.State == MEM_FREE {
            return Ok(serde_json::json!({
                "success": true,
                "freed": false,
                "already_free": true,
                "address": format!("0x{:016X}", address),
                "message": "Address is already free; no action needed"
            }));
        }

        let result = VirtualFreeEx(*handle, address as *mut _, 0, MEM_RELEASE);

        if result.is_ok() {
            Ok(serde_json::json!({
                "success": true,
                "freed": true,
                "already_free": false,
                "address": format!("0x{:016X}", address)
            }))
        } else {
            let err = windows::core::Error::from_win32();
            Ok(serde_json::json!({
                "success": false,
                "freed": false,
                "already_free": false,
                "address": format!("0x{:016X}", address),
                "error": err.to_string()
            }))
        }
    }
}

/// VirtualProtectEx wrapper
pub fn virtual_protect_ex(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4096);
    let protect = args
        .get("protect")
        .and_then(|v| v.as_str())
        .unwrap_or("RWX");

    let protect_flag = match protect {
        "RWX" => PAGE_EXECUTE_READWRITE,
        "RW" => PAGE_READWRITE,
        _ => PAGE_EXECUTE_READWRITE,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            address as *mut _,
            size as usize,
            protect_flag,
            &mut old_protect as *mut _ as *mut _,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to change protection: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "old_protect": old_protect.0
        }))
    }
}

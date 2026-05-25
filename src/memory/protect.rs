//! Memory protection implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;
use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;

fn parse_memory_protect_flag(value: Option<&Value>) -> PAGE_PROTECTION_FLAGS {
    value
        .and_then(crate::args::parse_protection_value)
        .map(PAGE_PROTECTION_FLAGS)
        .unwrap_or(windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE)
}

fn protect_label(value: Option<&Value>) -> String {
    value
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_u64().map(|number| number.to_string()))
        })
        .unwrap_or_else(|| "RWX".to_string())
}

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
    let protect_value = args.get("protect").or_else(|| args.get("protection"));
    let protect = protect_label(protect_value);
    let protect_flag = parse_memory_protect_flag(protect_value);

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

        let address = remote_mem as u64;
        Ok(serde_json::json!({
            "address": crate::memory::rollback::format_address(address),
            "size": size,
            "protect": protect,
            "protect_flag": protect_flag.0,
            "rollback": crate::memory::rollback::free_allocated_region_rollback(pid, address, size)
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
                "message": "Address is already free; no action needed",
                "rollback": crate::memory::rollback::irreversible_free_rollback(pid, address)
            }));
        }

        let result = VirtualFreeEx(*handle, address as *mut _, 0, MEM_RELEASE);

        if result.is_ok() {
            Ok(serde_json::json!({
                "success": true,
                "freed": true,
                "already_free": false,
                "address": format!("0x{:016X}", address),
                "rollback": crate::memory::rollback::irreversible_free_rollback(pid, address)
            }))
        } else {
            let err = windows::core::Error::from_win32();
            Ok(serde_json::json!({
                "success": false,
                "freed": false,
                "already_free": false,
                "address": format!("0x{:016X}", address),
                "error": err.to_string(),
                "rollback": crate::memory::rollback::irreversible_free_rollback(pid, address)
            }))
        }
    }
}

/// VirtualProtectEx wrapper
pub fn virtual_protect_ex(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::VirtualProtectEx;
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
    let protect_value = args.get("protect").or_else(|| args.get("protection"));
    let protect = protect_label(protect_value);
    let protect_flag = parse_memory_protect_flag(protect_value);

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
            "address": crate::memory::rollback::format_address(address),
            "size": size,
            "protect": protect,
            "new_protect": protect,
            "new_protect_flag": protect_flag.0,
            "old_protect": old_protect.0,
            "rollback": crate::memory::rollback::restore_previous_protection_rollback(
                pid,
                address,
                size,
                old_protect.0,
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn virtual_alloc_reports_executable_free_rollback() {
        let _guard = TEST_LOCK.lock().unwrap();
        let result = virtual_alloc_ex(&json!({
            "pid": std::process::id(),
            "size": 4096,
            "protect": "RW"
        }))
        .expect("virtual_alloc_ex should allocate in current process");

        assert_eq!(result["size"], 4096);
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "free_allocated_region");
        assert_eq!(result["rollback"]["action"]["tool"], "memory");
        assert_eq!(result["rollback"]["action"]["action"], "free");
        assert_eq!(
            result["rollback"]["action"]["args"]["address"],
            result["address"]
        );

        let _ = virtual_free_ex(&json!({
            "pid": std::process::id(),
            "address": result["address"].clone()
        }));
    }

    #[test]
    fn virtual_protect_reports_restore_previous_protection_rollback() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = vec![0u8; 4096];
        let address = buffer.as_mut_ptr() as u64;

        let result = virtual_protect_ex(&json!({
            "pid": std::process::id(),
            "address": address,
            "size": 4096,
            "protect": "RW"
        }))
        .expect("virtual_protect_ex should protect current process buffer");

        assert_eq!(result["success"], true);
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(
            result["rollback"]["strategy"],
            "restore_previous_protection"
        );
        assert_eq!(result["rollback"]["old_protection"], result["old_protect"]);
        assert_eq!(result["rollback"]["action"]["tool"], "memory");
        assert_eq!(result["rollback"]["action"]["action"], "protect");
        assert_eq!(
            result["rollback"]["action"]["args"]["protect"],
            result["old_protect"]
        );

        let _ = virtual_protect_ex(&json!({
            "pid": std::process::id(),
            "address": address,
            "size": 4096,
            "protect": result["old_protect"].clone()
        }));
    }

    #[test]
    fn virtual_free_reports_irreversible_rollback_metadata() {
        let _guard = TEST_LOCK.lock().unwrap();
        let alloc = virtual_alloc_ex(&json!({
            "pid": std::process::id(),
            "size": 4096,
            "protect": "RW"
        }))
        .expect("virtual_alloc_ex should allocate in current process");

        let result = virtual_free_ex(&json!({
            "pid": std::process::id(),
            "address": alloc["address"].clone()
        }))
        .expect("virtual_free_ex should free allocation");

        assert_eq!(result["success"], true);
        assert_eq!(result["rollback"]["available"], false);
        assert_eq!(result["rollback"]["reason"], "irreversible_release");
        assert_eq!(
            result["rollback"]["captured_fields"],
            json!(["pid", "address"])
        );
    }

    #[test]
    fn virtual_protect_accepts_numeric_protection_for_rollback_actions() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = vec![0u8; 4096];
        let address = buffer.as_mut_ptr() as u64;

        let result = virtual_protect_ex(&json!({
            "pid": std::process::id(),
            "address": address,
            "size": 4096,
            "protect": 0x04
        }))
        .expect("numeric protection should be accepted");

        assert_eq!(result["new_protect_flag"], 0x04);
    }
}

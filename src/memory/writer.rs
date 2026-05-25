//! Memory writer implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Write memory to a process
pub fn write_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    // Log raw args for MCP debugging
    tracing::info!(
        "[write_memory] RAW ARGS: {}",
        serde_json::to_string(args).unwrap_or_default()
    );

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing or invalid address".to_string()))?;
    let bytes = args
        .get("bytes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing bytes array".to_string()))?;
    let _bypass_protect = args
        .get("bypass_protect")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let byte_vec: Vec<u8> = bytes
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();

    tracing::info!("[write_memory] pid={} address=0x{:016X} (raw json: {:?}) byte_count={} bytes_parsed={} first_bytes={:?}",
        pid, address, args.get("address"), bytes.len(), byte_vec.len(),
        &byte_vec[..byte_vec.len().min(16)]);

    if byte_vec.is_empty() {
        return Err(MemoricError::MemoryAccess(format!(
            "No valid bytes to write. Input array had {} elements but none were valid integers. First few values: {:?}",
            bytes.len(), &bytes[..bytes.len().min(5)]
        )));
    }

    if byte_vec.len() != bytes.len() {
        tracing::warn!(
            "[write_memory] Only {}/{} bytes parsed as valid u8 values",
            byte_vec.len(),
            bytes.len()
        );
    }

    // Auto-enable SeDebugPrivilege (best-effort)
    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            false,
            pid as u32,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!(
                "OpenProcess failed: pid={} access=VM_WRITE|VM_OP|QUERY err={}",
                pid, e
            ))
        })?;
        let handle = SafeHandle::new(handle);

        // Pre-check: verify target address is valid committed memory
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let query_result = VirtualQueryEx(
            *handle,
            Some(address as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if query_result > 0 {
            tracing::info!("[write_memory] VirtualQueryEx: base=0x{:X} size=0x{:X} state=0x{:X} protect=0x{:X} type=0x{:X}",
                mbi.BaseAddress as usize, mbi.RegionSize, mbi.State.0, mbi.Protect.0, mbi.Type.0);
            if mbi.State.0 != 0x1000 {
                return Err(MemoricError::MemoryAccess(format!(
                    "Address 0x{:016X} is not committed memory (state=0x{:X}). Use virtual_alloc_ex to allocate first.",
                    address, mbi.State.0
                )));
            }
            // Check if writable (PAGE_READWRITE=0x04, PAGE_EXECUTE_READWRITE=0x40, PAGE_WRITECOPY=0x08, PAGE_EXECUTE_WRITECOPY=0x80)
            let writable = mbi.Protect.0 & (0x04 | 0x40 | 0x08 | 0x80) != 0;
            if !writable {
                tracing::warn!("[write_memory] Target region protect=0x{:X} is NOT writable. WriteProcessMemory may still succeed (it changes protection internally), but consider using force_write.", mbi.Protect.0);
            }
        } else {
            tracing::warn!(
                "[write_memory] VirtualQueryEx failed for address 0x{:016X}",
                address
            );
        }

        let original =
            crate::memory::rollback::capture_original_bytes(*handle, address, byte_vec.len());

        let ptr = address as *const std::ffi::c_void;
        tracing::info!(
            "[write_memory] handle={:?} ptr={:?} len={}",
            handle.raw(),
            ptr,
            byte_vec.len()
        );

        let mut bytes_written = 0usize;

        WriteProcessMemory(
            *handle,
            ptr,
            byte_vec.as_ptr() as *const _,
            byte_vec.len(),
            Some(&mut bytes_written as *mut _),
        )
        .map_err(|e| {
            let protect_str = if query_result > 0 {
                format!(
                    " (region protect=0x{:X} state=0x{:X})",
                    mbi.Protect.0, mbi.State.0
                )
            } else {
                String::new()
            };
            MemoricError::WindowsApi(format!(
                "WriteProcessMemory failed: pid={} addr=0x{:016X} len={}{} err={}",
                pid,
                address,
                byte_vec.len(),
                protect_str,
                e
            ))
        })?;

        Ok(serde_json::json!({
            "success": true,
            "bytes_written": bytes_written,
            "address": crate::memory::rollback::format_address(address),
            "rollback": crate::memory::rollback::restore_original_bytes_rollback(
                pid,
                address,
                &original,
                if query_result > 0 { Some(mbi.Protect.0) } else { None },
                false,
            )
        }))
    }
}

/// Force write with protection bypass
pub fn force_write(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    tracing::info!(
        "[force_write] RAW ARGS: {}",
        serde_json::to_string(args).unwrap_or_default()
    );

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing or invalid address".to_string()))?;
    let bytes = args
        .get("bytes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing bytes".to_string()))?;

    let byte_vec: Vec<u8> = bytes
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();

    if byte_vec.is_empty() {
        return Err(MemoricError::MemoryAccess(
            "No valid bytes to write".to_string(),
        ));
    }

    // Auto-enable SeDebugPrivilege (best-effort)
    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let original =
            crate::memory::rollback::capture_original_bytes(*handle, address, byte_vec.len());

        // First, change protection to RWX
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            address as *mut _,
            byte_vec.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect as *mut _ as *mut _,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!(
                "VirtualProtectEx failed: addr=0x{:016X} err={}",
                address, e
            ))
        })?;

        // Write the data
        let mut bytes_written = 0usize;
        WriteProcessMemory(
            *handle,
            address as *const _,
            byte_vec.as_ptr() as *const _,
            byte_vec.len(),
            Some(&mut bytes_written as *mut _),
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!(
                "WriteProcessMemory failed: addr=0x{:016X} err={}",
                address, e
            ))
        })?;

        // Restore original protection
        let mut tmp = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(
            *handle,
            address as *mut _,
            byte_vec.len(),
            old_protect,
            &mut tmp as *mut _ as *mut _,
        );

        Ok(serde_json::json!({
            "success": true,
            "bytes_written": bytes_written,
            "address": crate::memory::rollback::format_address(address),
            "old_protect": old_protect.0,
            "rollback": crate::memory::rollback::restore_original_bytes_rollback(
                pid,
                address,
                &original,
                Some(old_protect.0),
                true,
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
    fn write_memory_updates_current_process_buffer_with_integer_address() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = vec![0u8; 8];
        let address = buffer.as_mut_ptr() as u64;

        let result = write_memory(&json!({
            "pid": std::process::id(),
            "address": address,
            "bytes": [0x10, 0x20, 0x30, 0x40]
        }))
        .expect("write_memory should update current process buffer");

        assert_eq!(result["success"], true);
        assert_eq!(result["bytes_written"], 4);
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(result["rollback"]["strategy"], "restore_original_bytes");
        assert_eq!(result["rollback"]["original_bytes"], json!([0, 0, 0, 0]));
        assert_eq!(result["rollback"]["action"]["tool"], "memory");
        assert_eq!(result["rollback"]["action"]["action"], "write");
        assert_eq!(
            result["rollback"]["action"]["args"]["bytes"],
            json!([0, 0, 0, 0])
        );
        assert_eq!(&buffer[..4], &[0x10, 0x20, 0x30, 0x40]);
        assert_eq!(&buffer[4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn write_memory_updates_current_process_buffer_with_hex_address() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = vec![0xAAu8; 6];
        let address = format!("0x{:X}", buffer.as_mut_ptr() as u64);

        let result = write_memory(&json!({
            "pid": std::process::id(),
            "address": address,
            "bytes": [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]
        }))
        .expect("write_memory should parse hex address");

        assert_eq!(result["success"], true);
        assert_eq!(result["bytes_written"], 6);
        assert_eq!(
            result["rollback"]["original_bytes"],
            json!([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA])
        );
        assert_eq!(&buffer, &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
    }

    #[test]
    fn write_memory_rejects_empty_or_non_integer_bytes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = vec![0u8; 4];
        let address = buffer.as_mut_ptr() as u64;

        let err = write_memory(&json!({
            "pid": std::process::id(),
            "address": address,
            "bytes": []
        }))
        .expect_err("empty byte array should be rejected");
        assert!(err.to_string().contains("No valid bytes"));

        let err = write_memory(&json!({
            "pid": std::process::id(),
            "address": address,
            "bytes": ["not-a-byte"]
        }))
        .expect_err("non-integer byte array should be rejected");
        assert!(err.to_string().contains("No valid bytes"));
    }

    #[test]
    fn force_write_updates_current_process_buffer_and_reports_old_protection() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut buffer = vec![0xAAu8; 8];
        let address = buffer.as_mut_ptr() as u64;

        let result = force_write(&json!({
            "pid": std::process::id(),
            "address": address,
            "bytes": [0xFE, 0xED, 0xFA, 0xCE]
        }))
        .expect("force_write should update current process buffer");

        assert_eq!(result["success"], true);
        assert_eq!(result["bytes_written"], 4);
        assert!(result["old_protect"].as_u64().is_some());
        assert_eq!(result["rollback"]["available"], true);
        assert_eq!(
            result["rollback"]["captured_fields"],
            json!(["pid", "address", "size", "original_bytes", "old_protection"])
        );
        assert_eq!(
            result["rollback"]["original_bytes"],
            json!([0xAA, 0xAA, 0xAA, 0xAA])
        );
        assert_eq!(result["rollback"]["old_protection"], result["old_protect"]);
        assert_eq!(&buffer[..4], &[0xFE, 0xED, 0xFA, 0xCE]);
        assert_eq!(&buffer[4..], &[0xAA, 0xAA, 0xAA, 0xAA]);
    }
}

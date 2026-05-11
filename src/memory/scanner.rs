//! Memory scanner implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

// Global scan state storage using Lazy for safe initialization
static SCAN_STATE: Lazy<Mutex<HashMap<u64, ScanSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
struct ScanSession {
    pid: u64,
    value_size: usize,
    addresses: Vec<(usize, Vec<u8>)>, // address -> value bytes
}

// Constants for memory region types
const MEM_COMMIT: u32 = 0x1000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_IMAGE: u32 = 0x1000000;
const MEM_PRIVATE: u32 = 0x20000;

/// Get module base address and size ranges for a named module in a process.
/// Returns Vec<(base, size)> for matching modules.
unsafe fn get_module_regions(
    handle: windows::Win32::Foundation::HANDLE,
    module_name: &str,
) -> Vec<(usize, usize)> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, LIST_MODULES_ALL,
        MODULEINFO,
    };

    let mut modules = vec![HMODULE::default(); 1024];
    let mut cb_needed = 0u32;

    if EnumProcessModulesEx(
        handle,
        modules.as_mut_ptr(),
        (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
        &mut cb_needed,
        LIST_MODULES_ALL,
    )
    .is_err()
    {
        return Vec::new();
    }

    let num_modules = cb_needed as usize / std::mem::size_of::<HMODULE>();
    let target = module_name.to_lowercase();
    let mut results = Vec::new();

    for i in 0..num_modules {
        let mut name_buf = [0u16; 260];
        let name_len = GetModuleBaseNameW(handle, modules[i], &mut name_buf);
        if name_len == 0 {
            continue;
        }

        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_lowercase();
        if name == target || name.contains(&target) {
            let mut mod_info = MODULEINFO::default();
            if GetModuleInformation(
                handle,
                modules[i],
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .is_ok()
            {
                results.push((mod_info.lpBaseOfDll as usize, mod_info.SizeOfImage as usize));
            }
        }
    }
    results
}

/// Check if address falls within any of the module regions
fn in_module_regions(addr: usize, size: usize, regions: &[(usize, usize)]) -> bool {
    for &(base, mod_size) in regions {
        let mod_end = base + mod_size;
        let region_end = addr + size;
        // Region overlaps module if: addr < mod_end && region_end > base
        if addr < mod_end && region_end > base {
            return true;
        }
    }
    false
}

/// Check if a memory region should be scanned based on type filters
fn should_scan_region(region_type: u32, exclude_mapped: bool, exclude_image: bool) -> bool {
    if exclude_mapped && region_type == MEM_MAPPED {
        return false;
    }
    if exclude_image && region_type == MEM_IMAGE {
        return false;
    }
    true
}

/// Scan for exact values
pub fn scan_exact(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let value = args
        .get("value")
        .ok_or_else(|| MemoricError::MemoryAccess("Missing value".to_string()))?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing scan_type".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    // Region type filters (default: skip mapped + image, only scan private)
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    tracing::info!("Scanning process {} for {:?} ({}) timeout={}s start=0x{:X} exclude_mapped={} exclude_image={}", pid, value, scan_type, timeout_secs, start_address, exclude_mapped, exclude_image);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // Determine value size for state storage
    let value_size = match scan_type {
        "int" => 4,
        "float" => 4,
        "string" => value.as_str().map(|s| s.len()).unwrap_or(0),
        "bytes" => value.as_array().map(|a| a.len()).unwrap_or(0),
        _ => 4,
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Resolve module regions if module_name specified
        let module_regions = module_name.map(|name| get_module_regions(*handle, name));

        let mut addresses = Vec::new();
        let mut session_data: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut addr = start_address;
        let mut timed_out = false;
        let mut last_address = 0usize;
        let mut scanned_bytes = 0u64;
        let mut skipped_regions = 0u64;

        loop {
            // Check timeout
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                last_address = addr;
                break;
            }

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

            // Only scan writable committed memory (typical for game values)
            let is_target = mbi.Protect.0 & (PAGE_READWRITE.0 | PAGE_EXECUTE_READWRITE.0) != 0
                && mbi.State.0 == MEM_COMMIT;

            // Apply region type filters
            let passes_type_filter =
                is_target && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);

            // Apply module filter
            let passes_module_filter = if let Some(ref regions) = module_regions {
                !regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, regions)
            } else {
                true
            };

            if passes_type_filter && passes_module_filter {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);
                    scanned_bytes += bytes_read as u64;

                    // Search for value based on type
                    match scan_type {
                        "int" => {
                            if let Some(val) = value.as_i64() {
                                let bytes = (val as i32).to_ne_bytes();
                                for i in 0..buffer.len().saturating_sub(4) {
                                    if buffer[i..i + 4] == bytes[..] {
                                        let found_addr = addr + i;
                                        addresses.push(format!("0x{:016X}", found_addr));
                                        session_data.push((found_addr, buffer[i..i + 4].to_vec()));
                                    }
                                }
                            }
                        }
                        "float" => {
                            if let Some(val) = value.as_f64() {
                                let bytes = (val as f32).to_ne_bytes();
                                for i in 0..buffer.len().saturating_sub(4) {
                                    if buffer[i..i + 4] == bytes[..] {
                                        let found_addr = addr + i;
                                        addresses.push(format!("0x{:016X}", found_addr));
                                        session_data.push((found_addr, buffer[i..i + 4].to_vec()));
                                    }
                                }
                            }
                        }
                        "string" => {
                            if let Some(val) = value.as_str() {
                                let bytes = val.as_bytes();
                                for i in 0..buffer.len().saturating_sub(bytes.len()) {
                                    if buffer[i..i + bytes.len()] == bytes[..] {
                                        let found_addr = addr + i;
                                        addresses.push(format!("0x{:016X}", found_addr));
                                        session_data.push((
                                            found_addr,
                                            buffer[i..i + bytes.len()].to_vec(),
                                        ));
                                    }
                                }
                            }
                        }
                        "bytes" => {
                            if let Some(byte_array) = value.as_array() {
                                let pattern: Vec<u8> = byte_array
                                    .iter()
                                    .filter_map(|v| v.as_u64().map(|b| b as u8))
                                    .collect();
                                for i in 0..buffer.len().saturating_sub(pattern.len()) {
                                    if buffer[i..i + pattern.len()] == pattern[..] {
                                        let found_addr = addr + i;
                                        addresses.push(format!("0x{:016X}", found_addr));
                                        session_data.push((
                                            found_addr,
                                            buffer[i..i + pattern.len()].to_vec(),
                                        ));
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else if is_target {
                skipped_regions += 1;
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        // Store scan state for scan_changed
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size,
                    addresses: session_data,
                },
            );
        }

        tracing::info!(
            "Found {} addresses, stored in scan state (timed_out={}, skipped={})",
            addresses.len(),
            timed_out,
            skipped_regions
        );

        let total_count = addresses.len();
        let paginated: Vec<_> = addresses.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "addresses": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": offset + paginated.len() < total_count,
            "timed_out": timed_out,
            "last_address": format!("0x{:016X}", last_address),
            "scanned_bytes": scanned_bytes,
            "skipped_regions": skipped_regions,
            "filters": {
                "exclude_mapped": exclude_mapped,
                "exclude_image": exclude_image,
                "module_name": module_name
            }
        }))
    }
}

/// Scan for changed values
pub fn scan_changed(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let change = args
        .get("change")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing change".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::info!("Scanning process {} for {} values", pid, change);

    // Get previous scan results
    let prev_session = {
        let state = SCAN_STATE
            .lock()
            .map_err(|_| MemoricError::MemoryAccess("Failed to lock state".to_string()))?;
        state
            .get(&pid)
            .ok_or_else(|| {
                MemoricError::MemoryAccess(
                    "No previous scan found. Run scan_exact first.".to_string(),
                )
            })?
            .clone()
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut new_addresses = Vec::new();
        let mut new_session_data = Vec::new();

        // Re-scan previous addresses and check for changes
        for (addr, old_value) in prev_session.addresses {
            let mut buffer = vec![0u8; old_value.len()];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                *handle,
                addr as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                Some(&mut bytes_read as *mut _),
            )
            .is_ok()
                && bytes_read == old_value.len()
            {
                let changed = match change {
                    "increased" => buffer > old_value,
                    "decreased" => buffer < old_value,
                    "changed" => buffer != old_value,
                    "unchanged" => buffer == old_value,
                    _ => false,
                };

                if changed {
                    new_addresses.push(format!("0x{:016X}", addr));
                    new_session_data.push((addr, buffer));
                }
            }
        }

        // Update scan state with filtered results
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size: prev_session.value_size,
                    addresses: new_session_data,
                },
            );
        }

        tracing::info!("Found {} {} addresses", new_addresses.len(), change);

        let total_count = new_addresses.len();
        let paginated: Vec<_> = new_addresses.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "addresses": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "change_type": change,
            "offset": offset,
            "limit": limit,
            "has_more": offset + paginated.len() < total_count
        }))
    }
}

/// Scan for unknown values (first scan) - scans all readable memory
pub fn scan_unknown(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_READONLY, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;

    // Region type filters
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    tracing::info!(
        "Unknown scan for process {} exclude_mapped={} exclude_image={}",
        pid,
        exclude_mapped,
        exclude_image
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let module_regions = module_name.map(|name| get_module_regions(*handle, name));

        let mut regions = Vec::new();
        let mut addr = 0usize;
        let mut total_readable = 0u64;

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

            // Check if memory is readable and committed
            let is_readable = (mbi.Protect.0
                & (PAGE_READWRITE.0
                    | PAGE_EXECUTE_READWRITE.0
                    | PAGE_READONLY.0
                    | PAGE_EXECUTE_READ.0))
                != 0;

            let passes_type_filter = is_readable
                && mbi.State.0 == MEM_COMMIT
                && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);

            let passes_module_filter = if let Some(ref mod_regions) = module_regions {
                !mod_regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, mod_regions)
            } else {
                true
            };

            if passes_type_filter && passes_module_filter {
                regions.push(serde_json::json!({
                    "base_address": format!("0x{:016X}", mbi.BaseAddress as usize),
                    "size": mbi.RegionSize,
                    "protect": mbi.Protect.0,
                    "type": mbi.Type.0
                }));
                total_readable += mbi.RegionSize as u64;
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        tracing::info!(
            "Unknown scan found {} readable regions, {} bytes total",
            regions.len(),
            total_readable
        );

        Ok(serde_json::json!({
            "regions": regions,
            "count": regions.len(),
            "total_readable_bytes": total_readable,
            "message": "Use scan_changed after modifying values to find what changed",
            "filters": {
                "exclude_mapped": exclude_mapped,
                "exclude_image": exclude_image,
                "module_name": module_name
            }
        }))
    }
}

/// Pattern scan (AOB) - scans ALL readable memory including code and headers
pub fn find_pattern(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let signature = args
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing signature".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset_param = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    // Region type filters (find_pattern defaults to false since AOB commonly targets code)
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    tracing::info!("Scanning process {} for pattern '{}'", pid, signature);

    // Parse signature (e.g., "A1 ?? ?? 00 FF")
    let pattern: Vec<Option<u8>> = signature
        .split_whitespace()
        .map(|s| {
            if s == "??" || s == "?" {
                None
            } else {
                u8::from_str_radix(s, 16).ok()
            }
        })
        .collect();

    if pattern.is_empty() {
        return Err(MemoricError::MemoryAccess("Invalid pattern".to_string()));
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let module_regions = module_name.map(|name| get_module_regions(*handle, name));

        let mut addresses = Vec::new();
        let mut addr = 0usize;

        // All readable page protections (including code/readonly for PE headers)
        let readable = PAGE_READONLY.0
            | PAGE_READWRITE.0
            | PAGE_EXECUTE_READ.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_WRITECOPY.0
            | PAGE_EXECUTE_WRITECOPY.0;

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

            let is_target = mbi.Protect.0 & readable != 0 && mbi.State.0 == MEM_COMMIT;

            let passes_type_filter =
                is_target && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);

            let passes_module_filter = if let Some(ref mod_regions) = module_regions {
                !mod_regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, mod_regions)
            } else {
                true
            };

            // Scan all readable committed memory
            if passes_type_filter && passes_module_filter {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    // Search for pattern
                    for i in 0..buffer.len().saturating_sub(pattern.len()) {
                        let matches = pattern.iter().enumerate().all(|(j, &expected)| {
                            expected.is_none() || buffer[i + j] == expected.unwrap()
                        });

                        if matches {
                            addresses.push(format!("0x{:016X}", addr + i));
                        }
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        tracing::info!("Found {} addresses", addresses.len());

        let total_count = addresses.len();
        let paginated: Vec<_> = addresses
            .into_iter()
            .skip(offset_param)
            .take(limit)
            .collect();

        Ok(serde_json::json!({
            "addresses": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "offset": offset_param,
            "limit": limit,
            "has_more": offset_param + paginated.len() < total_count
        }))
    }
}

/// Pointer scan - find pointers that point to a target address
pub fn pointer_scan(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let target_address = args
        .get("target_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing target_address".to_string()))?;
    let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

    tracing::info!(
        "Pointer scan for target 0x{:016X}, max depth {}",
        target_address,
        max_depth
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut pointers = Vec::new();
        let mut addr = 0usize;
        let pointer_size = 8; // x64

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

            if mbi.Protect.0 & (PAGE_READWRITE.0 | PAGE_EXECUTE_READWRITE.0) != 0
                && mbi.State.0 == MEM_COMMIT
            {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    for i in (0..buffer.len().saturating_sub(pointer_size)).step_by(pointer_size) {
                        let ptr_value =
                            u64::from_ne_bytes(buffer[i..i + 8].try_into().unwrap_or([0; 8]));

                        if ptr_value == target_address {
                            pointers.push(format!("0x{:016X}", addr + i));
                        }
                    }
                }
            }
            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        Ok(serde_json::json!({
            "target_address": format!("0x{:016X}", target_address),
            "pointers": pointers,
            "count": pointers.len(),
            "max_depth": max_depth
        }))
    }
}

/// IDA-style pattern scan with advanced wildcard support
/// Supports: "45 8B ?? ?? 48 89" — ?? is wildcard byte
/// Supports: "45 8B ?0 4? 48 89" — nibble wildcards using ?
/// Returns addresses + context bytes around each match
pub fn ida_pattern_scan(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let pattern_str = args
        .get("pattern")
        .or_else(|| args.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pattern/signature".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
    let context_bytes = args
        .get("context_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(16) as usize;
    let module_name = args.get("module_name").and_then(|v| v.as_str());
    let start_addr = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);

    tracing::info!(
        "[SCAN] IDA pattern scan pid={} pattern='{}'",
        pid,
        pattern_str
    );

    // Parse IDA pattern: supports ?? for wildcard byte, ?X and X? for nibble wildcards
    let parsed = parse_ida_pattern(pattern_str)?;
    if parsed.is_empty() {
        return Err(MemoricError::MemoryAccess("Empty pattern".to_string()));
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let module_regions = module_name.map(|name| get_module_regions(*handle, name));
        let readable = PAGE_READONLY.0
            | PAGE_READWRITE.0
            | PAGE_EXECUTE_READ.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_WRITECOPY.0
            | PAGE_EXECUTE_WRITECOPY.0;

        let mut matches: Vec<serde_json::Value> = Vec::new();
        let mut addr = start_addr;
        let mut timed_out = false;
        let mut scanned_bytes = 0u64;

        loop {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            if matches.len() >= limit {
                break;
            }

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

            let is_target = mbi.Protect.0 & readable != 0 && mbi.State.0 == MEM_COMMIT;
            let passes_module = if let Some(ref regions) = module_regions {
                !regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, regions)
            } else {
                true
            };

            if is_target && passes_module {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);
                    scanned_bytes += bytes_read as u64;

                    for i in 0..buffer.len().saturating_sub(parsed.len()) {
                        if ida_match(&buffer[i..], &parsed) {
                            let found_addr = addr + i;
                            // Extract context
                            let ctx_start = i.saturating_sub(context_bytes);
                            let ctx_end = (i + parsed.len() + context_bytes).min(buffer.len());
                            let context = &buffer[ctx_start..ctx_end];
                            let matched = &buffer[i..i + parsed.len()];

                            matches.push(serde_json::json!({
                                "address": format!("0x{:016X}", found_addr),
                                "matched_hex": matched.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                                "context_hex": context.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                                "context_offset": i - ctx_start,
                            }));

                            if matches.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "ida_pattern_scan",
            "pattern": pattern_str,
            "matches": matches,
            "count": matches.len(),
            "scanned_bytes": scanned_bytes,
            "timed_out": timed_out,
            "message": format!("Found {} matches for pattern '{}'", matches.len(), pattern_str)
        }))
    }
}

/// BYOVD stealth pattern scan — scans process memory via kernel driver, bypassing all usermode hooks
pub fn stealth_pattern_scan(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_READONLY, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};
    use windows::Win32::System::IO::DeviceIoControl;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let pattern_str = args
        .get("pattern")
        .or_else(|| args.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pattern/signature".to_string()))?;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .unwrap_or("\\\\.\\RTCore64");
    let read_ioctl = args
        .get("read_ioctl")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x80002048) as u32;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;

    tracing::warn!(
        "[STEALTH] BYOVD pattern scan pid={} pattern='{}' via {}",
        pid,
        pattern_str,
        device_path
    );

    let parsed = parse_ida_pattern(pattern_str)?;
    if parsed.is_empty() {
        return Err(MemoricError::MemoryAccess("Empty pattern".to_string()));
    }

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Open process just for VirtualQueryEx (region enumeration)
        let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess for query: {}", e)))?;
        let proc_handle = SafeHandle::new(proc_handle);

        // Open driver for reading
        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let driver_handle = CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Cannot open driver: {}", e)))?;

        let readable =
            PAGE_READONLY.0 | PAGE_READWRITE.0 | PAGE_EXECUTE_READ.0 | PAGE_EXECUTE_READWRITE.0;
        let mut matches: Vec<serde_json::Value> = Vec::new();
        let mut addr = 0usize;
        let mut scanned_bytes = 0u64;

        loop {
            if matches.len() >= limit {
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQueryEx(
                *proc_handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.Protect.0 & readable != 0
                && mbi.State.0 == MEM_COMMIT
                && mbi.RegionSize <= 16 * 1024 * 1024
            {
                // Read via driver in chunks
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut read_ok = true;

                for offset in (0..mbi.RegionSize).step_by(8) {
                    let remaining = (mbi.RegionSize - offset).min(8);
                    let target = (addr + offset) as u64;

                    #[repr(C, packed)]
                    struct Req {
                        address: u64,
                        _r: u32,
                        size: u32,
                    }
                    let req = Req {
                        address: target,
                        _r: 0,
                        size: remaining as u32,
                    };
                    let mut out = [0u8; 64];
                    let mut br = 0u32;

                    if DeviceIoControl(
                        driver_handle,
                        read_ioctl,
                        Some(&req as *const _ as *const _),
                        std::mem::size_of::<Req>() as u32,
                        Some(out.as_mut_ptr() as *mut _),
                        out.len() as u32,
                        Some(&mut br),
                        None,
                    )
                    .is_ok()
                        && br > 0
                    {
                        let n = remaining.min(br as usize);
                        buffer[offset..offset + n].copy_from_slice(&out[..n]);
                    } else {
                        read_ok = false;
                        break;
                    }
                }

                if read_ok {
                    scanned_bytes += mbi.RegionSize as u64;
                    for i in 0..buffer.len().saturating_sub(parsed.len()) {
                        if ida_match(&buffer[i..], &parsed) {
                            matches.push(serde_json::json!({
                                "address": format!("0x{:016X}", addr + i),
                                "matched_hex": buffer[i..i+parsed.len()].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                            }));
                            if matches.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
            if addr == 0 {
                break;
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(driver_handle);

        Ok(serde_json::json!({
            "success": true,
            "technique": "stealth_pattern_scan",
            "driver": device_path,
            "pattern": pattern_str,
            "matches": matches,
            "count": matches.len(),
            "scanned_bytes": scanned_bytes,
            "message": format!("BYOVD stealth scan found {} matches", matches.len())
        }))
    }
}

/// Parse IDA-style pattern string into pattern elements
/// Supports: "45 8B ?? 48" (full byte wildcard), "4? 8B ?0 48" (nibble wildcard)
#[derive(Clone, Debug)]
enum PatternByte {
    Exact(u8),
    Wildcard,
    NibbleMask { value: u8, mask: u8 }, // match = (byte & mask) == value
}

fn parse_ida_pattern(pattern_str: &str) -> Result<Vec<PatternByte>, MemoricError> {
    let mut result = Vec::new();
    for token in pattern_str.split_whitespace() {
        if token == "??" || token == "?" {
            result.push(PatternByte::Wildcard);
        } else if token.len() == 2 {
            let chars: Vec<char> = token.chars().collect();
            let hi_wild = chars[0] == '?';
            let lo_wild = chars[1] == '?';

            if hi_wild && lo_wild {
                result.push(PatternByte::Wildcard);
            } else if hi_wild {
                // ?X — match low nibble only
                let lo = u8::from_str_radix(&chars[1].to_string(), 16).map_err(|_| {
                    MemoricError::MemoryAccess(format!("Invalid pattern byte: {}", token))
                })?;
                result.push(PatternByte::NibbleMask {
                    value: lo,
                    mask: 0x0F,
                });
            } else if lo_wild {
                // X? — match high nibble only
                let hi = u8::from_str_radix(&chars[0].to_string(), 16).map_err(|_| {
                    MemoricError::MemoryAccess(format!("Invalid pattern byte: {}", token))
                })?;
                result.push(PatternByte::NibbleMask {
                    value: hi << 4,
                    mask: 0xF0,
                });
            } else {
                let byte = u8::from_str_radix(token, 16).map_err(|_| {
                    MemoricError::MemoryAccess(format!("Invalid hex byte: {}", token))
                })?;
                result.push(PatternByte::Exact(byte));
            }
        } else {
            return Err(MemoricError::MemoryAccess(format!(
                "Invalid pattern token: {}",
                token
            )));
        }
    }
    Ok(result)
}

fn ida_match(data: &[u8], pattern: &[PatternByte]) -> bool {
    if data.len() < pattern.len() {
        return false;
    }
    for (i, p) in pattern.iter().enumerate() {
        match p {
            PatternByte::Exact(expected) => {
                if data[i] != *expected {
                    return false;
                }
            }
            PatternByte::Wildcard => {}
            PatternByte::NibbleMask { value, mask } => {
                if data[i] & mask != *value {
                    return false;
                }
            }
        }
    }
    true
}

/// Scan for values within a range [min, max]
pub fn scan_range(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("int");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    let min_val = args
        .get("min")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing min".to_string()))?;
    let max_val = args
        .get("max")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing max".to_string()))?;

    tracing::info!(
        "[MEMORY] scan_range pid={} type={} min={} max={}",
        pid,
        scan_type,
        min_val,
        max_val
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let module_regions = module_name.map(|name| get_module_regions(*handle, name));

        let mut addresses = Vec::new();
        let mut session_data: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut addr = start_address;
        let mut timed_out = false;
        let mut last_address = 0usize;

        loop {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                last_address = addr;
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            let is_target = mbi.Protect.0 & (PAGE_READWRITE.0 | PAGE_EXECUTE_READWRITE.0) != 0
                && mbi.State.0 == MEM_COMMIT;
            let passes_type =
                is_target && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);
            let passes_mod = if let Some(ref regions) = module_regions {
                !regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, regions)
            } else {
                true
            };

            if passes_type && passes_mod {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    for i in 0..buffer.len().saturating_sub(4) {
                        let in_range = match scan_type {
                            "int" => {
                                let v = i32::from_ne_bytes([
                                    buffer[i],
                                    buffer[i + 1],
                                    buffer[i + 2],
                                    buffer[i + 3],
                                ]) as f64;
                                v >= min_val && v <= max_val
                            }
                            "float" => {
                                let v = f32::from_ne_bytes([
                                    buffer[i],
                                    buffer[i + 1],
                                    buffer[i + 2],
                                    buffer[i + 3],
                                ]) as f64;
                                v.is_finite() && v >= min_val && v <= max_val
                            }
                            _ => false,
                        };

                        if in_range {
                            let found_addr = addr + i;
                            addresses.push(format!("0x{:016X}", found_addr));
                            session_data.push((found_addr, buffer[i..i + 4].to_vec()));
                        }
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size: 4,
                    addresses: session_data,
                },
            );
        }

        let total_count = addresses.len();
        let paginated: Vec<_> = addresses.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "addresses": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": offset + paginated.len() < total_count,
            "timed_out": timed_out,
            "last_address": format!("0x{:016X}", last_address),
            "scan_type": scan_type,
            "range": { "min": min_val, "max": max_val }
        }))
    }
}

/// Scan for values that changed by a specific delta from previous scan
pub fn scan_delta(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let delta = args
        .get("delta")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing delta".to_string()))?;
    let direction = args
        .get("direction")
        .and_then(|v| v.as_str())
        .unwrap_or("increased_by");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::info!(
        "[MEMORY] scan_delta pid={} delta={} direction={}",
        pid,
        delta,
        direction
    );

    let session = {
        let state = SCAN_STATE
            .lock()
            .map_err(|e| MemoricError::MemoryAccess(format!("Lock failed: {}", e)))?;
        state.get(&pid).cloned().ok_or_else(|| {
            MemoricError::MemoryAccess(
                "No previous scan for this PID. Run scan_exact or scan_range first.".to_string(),
            )
        })?
    };

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut matches = Vec::new();
        let mut new_session_data: Vec<(usize, Vec<u8>)> = Vec::new();

        for (addr, old_bytes) in &session.addresses {
            let mut new_buf = vec![0u8; session.value_size];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                *handle,
                *addr as *const _,
                new_buf.as_mut_ptr() as *mut _,
                session.value_size,
                Some(&mut bytes_read as *mut _),
            )
            .is_ok()
                && bytes_read == session.value_size
            {
                let old_val = if session.value_size == 4 {
                    i32::from_ne_bytes([old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3]])
                        as f64
                } else {
                    0.0
                };
                let new_val = if session.value_size == 4 {
                    i32::from_ne_bytes([new_buf[0], new_buf[1], new_buf[2], new_buf[3]]) as f64
                } else {
                    0.0
                };
                let actual_delta = new_val - old_val;

                let matched = match direction {
                    "increased_by" => (actual_delta - delta).abs() < 0.001,
                    "decreased_by" => (actual_delta + delta).abs() < 0.001,
                    _ => false,
                };

                if matched {
                    matches.push(serde_json::json!({
                        "address": format!("0x{:016X}", addr),
                        "old_value": old_val as i64,
                        "new_value": new_val as i64,
                        "delta": actual_delta as i64
                    }));
                    new_session_data.push((*addr, new_buf));
                }
            }
        }

        // Update scan state with narrowed results
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size: session.value_size,
                    addresses: new_session_data,
                },
            );
        }

        let total_count = matches.len();
        let paginated: Vec<_> = matches.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "matches": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "direction": direction,
            "delta": delta
        }))
    }
}

/// Dedicated string scanner with ANSI/Unicode support and wildcard matching
pub fn scan_string(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let pattern = args
        .get("pattern")
        .or_else(|| args.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pattern/signature".to_string()))?;
    let encoding = args
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("both");
    let case_insensitive = args
        .get("case_insensitive")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::info!(
        "[MEMORY] scan_string pid={} pattern='{}' encoding={} case_insensitive={}",
        pid,
        pattern,
        encoding,
        case_insensitive
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    let search_pattern = if case_insensitive {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };

    // Build search patterns for different encodings
    let ansi_pattern: Vec<u8> = search_pattern.as_bytes().to_vec();
    let unicode_pattern: Vec<u8> = search_pattern
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let readable = PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_WRITECOPY.0;

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let mut results = Vec::new();
        let mut addr = 0usize;
        let mut timed_out = false;

        loop {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            let is_target = mbi.Protect.0 & readable != 0 && mbi.State.0 == MEM_COMMIT;
            let passes_type =
                is_target && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);

            if passes_type {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    // ANSI search
                    if encoding == "ansi" || encoding == "both" {
                        let search_buf = if case_insensitive {
                            buffer.to_ascii_lowercase()
                        } else {
                            buffer.clone()
                        };
                        for i in 0..search_buf.len().saturating_sub(ansi_pattern.len()) {
                            if search_buf[i..i + ansi_pattern.len()] == ansi_pattern[..] {
                                let found_addr = addr + i;
                                // Read a bit more context
                                let end = (i + 256).min(buffer.len());
                                let null_pos = buffer[i..end]
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(end - i);
                                let s = String::from_utf8_lossy(&buffer[i..i + null_pos]);
                                results.push(serde_json::json!({
                                    "address": format!("0x{:016X}", found_addr),
                                    "encoding": "ansi",
                                    "value": s,
                                    "length": null_pos
                                }));
                            }
                        }
                    }

                    // Unicode (UTF-16LE) search
                    if encoding == "unicode" || encoding == "both" {
                        for i in (0..buffer.len().saturating_sub(unicode_pattern.len())).step_by(2)
                        {
                            let mut matched = true;
                            for j in 0..unicode_pattern.len() {
                                let buf_byte = if case_insensitive {
                                    buffer.get(i + j).copied().unwrap_or(0).to_ascii_lowercase()
                                } else {
                                    buffer.get(i + j).copied().unwrap_or(0)
                                };
                                if buf_byte != unicode_pattern[j] {
                                    matched = false;
                                    break;
                                }
                            }
                            if matched {
                                let found_addr = addr + i;
                                // Read unicode string
                                let end = (i + 512).min(buffer.len());
                                let mut str_end = i;
                                while str_end + 1 < end {
                                    if buffer[str_end] == 0 && buffer[str_end + 1] == 0 {
                                        break;
                                    }
                                    str_end += 2;
                                }
                                let wide: Vec<u16> = buffer[i..str_end]
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                let s = String::from_utf16_lossy(&wide);
                                results.push(serde_json::json!({
                                    "address": format!("0x{:016X}", found_addr),
                                    "encoding": "unicode",
                                    "value": s,
                                    "length": wide.len()
                                }));
                            }
                        }
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        let total_count = results.len();
        let paginated: Vec<_> = results.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "results": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "pattern": pattern,
            "encoding": encoding,
            "case_insensitive": case_insensitive,
            "timed_out": timed_out
        }))
    }
}

/// Alignment-aware memory scan: scan for values at aligned addresses only (faster, reduces noise)
pub fn scan_aligned(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("int");
    let alignment = args.get("alignment").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    // Alignment must be power of 2 and >= 1
    let alignment = if alignment == 0 || (alignment & (alignment - 1)) != 0 {
        4
    } else {
        alignment
    };

    let value_str = args
        .get("value")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("value").and_then(|v| v.as_f64()).map(|_| ""))
        .ok_or_else(|| MemoricError::MemoryAccess("Missing value".to_string()))?;

    tracing::info!(
        "[MEMORY] scan_aligned pid={} type={} alignment={}",
        pid,
        scan_type,
        alignment
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let module_regions = module_name.map(|name| get_module_regions(*handle, name));

        let mut addresses = Vec::new();
        let mut session_data: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut addr = start_address;
        let mut timed_out = false;
        let mut last_address = 0usize;

        // Parse target value based on scan type
        let value_size: usize;
        let target_bytes: Vec<u8> = match scan_type {
            "int" => {
                let v: i32 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32
                } else {
                    value_str
                        .parse()
                        .map_err(|_| MemoricError::MemoryAccess("Invalid int value".to_string()))?
                };
                value_size = 4;
                v.to_ne_bytes().to_vec()
            }
            "long" => {
                let v: i64 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_i64()).unwrap_or(0)
                } else {
                    value_str
                        .parse()
                        .map_err(|_| MemoricError::MemoryAccess("Invalid long value".to_string()))?
                };
                value_size = 8;
                v.to_ne_bytes().to_vec()
            }
            "float" => {
                let v: f32 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32
                } else {
                    value_str.parse().map_err(|_| {
                        MemoricError::MemoryAccess("Invalid float value".to_string())
                    })?
                };
                value_size = 4;
                v.to_ne_bytes().to_vec()
            }
            "double" => {
                let v: f64 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0)
                } else {
                    value_str.parse().map_err(|_| {
                        MemoricError::MemoryAccess("Invalid double value".to_string())
                    })?
                };
                value_size = 8;
                v.to_ne_bytes().to_vec()
            }
            "short" => {
                let v: i16 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i16
                } else {
                    value_str.parse().map_err(|_| {
                        MemoricError::MemoryAccess("Invalid short value".to_string())
                    })?
                };
                value_size = 2;
                v.to_ne_bytes().to_vec()
            }
            "byte" => {
                let v: u8 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_u64()).unwrap_or(0) as u8
                } else {
                    value_str
                        .parse()
                        .map_err(|_| MemoricError::MemoryAccess("Invalid byte value".to_string()))?
                };
                value_size = 1;
                vec![v]
            }
            _ => {
                let v: i32 = if value_str.is_empty() {
                    args.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32
                } else {
                    value_str
                        .parse()
                        .map_err(|_| MemoricError::MemoryAccess("Invalid int value".to_string()))?
                };
                value_size = 4;
                v.to_ne_bytes().to_vec()
            }
        };

        loop {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                last_address = addr;
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            let is_target = mbi.Protect.0 & (PAGE_READWRITE.0 | PAGE_EXECUTE_READWRITE.0) != 0
                && mbi.State.0 == MEM_COMMIT;
            let passes_type =
                is_target && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);
            let passes_mod = if let Some(ref regions) = module_regions {
                !regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, regions)
            } else {
                true
            };

            if passes_type && passes_mod {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    // Align start offset within buffer
                    let base = addr;
                    let first_aligned = if base % alignment == 0 {
                        0
                    } else {
                        alignment - (base % alignment)
                    };

                    let mut i = first_aligned;
                    while i + value_size <= buffer.len() {
                        if buffer[i..i + value_size] == target_bytes[..] {
                            let found_addr = addr + i;
                            addresses.push(serde_json::json!({
                                "address": format!("0x{:016X}", found_addr),
                                "hex": hex::encode(&buffer[i..i + value_size])
                            }));
                            session_data.push((found_addr, buffer[i..i + value_size].to_vec()));
                        }
                        i += alignment;
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        // Store in session
        let session_id = pid;
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                session_id,
                ScanSession {
                    pid,
                    value_size,
                    addresses: session_data,
                },
            );
        }

        let total_count = addresses.len();
        let paginated: Vec<_> = addresses.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "results": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "scan_type": scan_type,
            "alignment": alignment,
            "value_size": value_size,
            "timed_out": timed_out,
            "resume_address": if timed_out { format!("0x{:016X}", last_address) } else { "".to_string() }
        }))
    }
}

/// Multi-value scan: scan for any of multiple values simultaneously (e.g. find all health values 80,90,100)
pub fn scan_multi_value(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("int");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    let values_arr = args
        .get("values")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing values array".to_string()))?;

    if values_arr.is_empty() {
        return Err(MemoricError::MemoryAccess(
            "values array is empty".to_string(),
        ));
    }

    tracing::info!(
        "[MEMORY] scan_multi_value pid={} type={} values_count={}",
        pid,
        scan_type,
        values_arr.len()
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // Parse all target values into byte patterns
    let mut targets: Vec<(Vec<u8>, String)> = Vec::new();
    let value_size: usize;

    match scan_type {
        "int" => {
            value_size = 4;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for int scan".to_string())
                })? as i32;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "long" => {
            value_size = 8;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for long scan".to_string())
                })?;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "float" => {
            value_size = 4;
            for v in values_arr {
                let num = v.as_f64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for float scan".to_string())
                })? as f32;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "double" => {
            value_size = 8;
            for v in values_arr {
                let num = v.as_f64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for double scan".to_string())
                })?;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "short" => {
            value_size = 2;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for short scan".to_string())
                })? as i16;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "byte" => {
            value_size = 1;
            for v in values_arr {
                let num = v.as_u64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for byte scan".to_string())
                })? as u8;
                targets.push((vec![num], num.to_string()));
            }
        }
        _ => {
            value_size = 4;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers".to_string())
                })? as i32;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let module_regions = module_name.map(|name| get_module_regions(*handle, name));

        let mut results = Vec::new();
        let mut session_data: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut addr = start_address;
        let mut timed_out = false;
        let mut last_address = 0usize;

        loop {
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                last_address = addr;
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQueryEx(
                *handle,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            let is_target = mbi.Protect.0 & (PAGE_READWRITE.0 | PAGE_EXECUTE_READWRITE.0) != 0
                && mbi.State.0 == MEM_COMMIT;
            let passes_type =
                is_target && should_scan_region(mbi.Type.0, exclude_mapped, exclude_image);
            let passes_mod = if let Some(ref regions) = module_regions {
                !regions.is_empty()
                    && in_module_regions(mbi.BaseAddress as usize, mbi.RegionSize, regions)
            } else {
                true
            };

            if passes_type && passes_mod {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0usize;

                if ReadProcessMemory(
                    *handle,
                    addr as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    Some(&mut bytes_read as *mut _),
                )
                .is_ok()
                {
                    buffer.truncate(bytes_read);

                    for i in 0..buffer.len().saturating_sub(value_size) {
                        let slice = &buffer[i..i + value_size];
                        for (target_bytes, target_label) in &targets {
                            if slice == target_bytes.as_slice() {
                                let found_addr = addr + i;
                                results.push(serde_json::json!({
                                    "address": format!("0x{:016X}", found_addr),
                                    "matched_value": target_label,
                                    "hex": hex::encode(slice)
                                }));
                                session_data.push((found_addr, slice.to_vec()));
                                break; // Don't match same address against remaining targets
                            }
                        }
                    }
                }
            }

            addr = (mbi.BaseAddress as usize) + mbi.RegionSize;
        }

        // Store in session
        let session_id = pid;
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                session_id,
                ScanSession {
                    pid,
                    value_size,
                    addresses: session_data,
                },
            );
        }

        let total_count = results.len();
        let paginated: Vec<_> = results.into_iter().skip(offset).take(limit).collect();

        Ok(serde_json::json!({
            "results": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "scan_type": scan_type,
            "values_searched": values_arr.len(),
            "timed_out": timed_out,
            "resume_address": if timed_out { format!("0x{:016X}", last_address) } else { "".to_string() }
        }))
    }
}

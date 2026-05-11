//! Module information implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// List loaded modules
pub fn list_modules(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::debug!("Listing modules for process {}", pid);

    let mut modules = Vec::new();

    unsafe {
        let snapshot =
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid as u32).map_err(
                |e| MemoricError::WindowsApi(format!("Failed to create snapshot: {}", e)),
            )?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szModule)
                    .trim_end_matches('\0')
                    .to_string();
                let path = String::from_utf16_lossy(&entry.szExePath)
                    .trim_end_matches('\0')
                    .to_string();

                modules.push(serde_json::json!({
                    "name": name,
                    "path": path,
                    "base_address": format!("0x{:016X}", entry.modBaseAddr as usize),
                    "size": entry.modBaseSize
                }));

                if Module32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!("Found {} modules", modules.len());

    let total_count = modules.len();
    let paginated: Vec<_> = modules.into_iter().skip(offset).take(limit).collect();
    let count = paginated.len();

    Ok(serde_json::json!({
        "modules": paginated,
        "count": count,
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + count < total_count
    }))
}

/// Get module base address (task 5.2: fully implemented)
pub fn get_module_base(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let module_name = args
        .get("module_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing module_name".to_string()))?;

    tracing::debug!(
        "Getting base address for module {} in PID {}",
        module_name,
        pid
    );

    unsafe {
        let snapshot =
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid as u32).map_err(
                |e| MemoricError::WindowsApi(format!("Failed to create module snapshot: {}", e)),
            )?;
        let _snapshot = SafeHandle::new(snapshot);

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        if Module32FirstW(*_snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szModule)
                    .trim_end_matches('\0')
                    .to_lowercase();

                if name == module_name.to_lowercase() {
                    return Ok(serde_json::json!({
                        "base_address": entry.modBaseAddr as u64,
                        "base_address_hex": format!("0x{:016X}", entry.modBaseAddr as usize),
                        "size": entry.modBaseSize,
                        "module_name": module_name,
                        "pid": pid
                    }));
                }

                if Module32NextW(*_snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    Err(MemoricError::MemoryAccess(format!(
        "Module '{}' not found in PID {}",
        module_name, pid
    )))
}

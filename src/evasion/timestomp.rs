//! Timestomping - copy file timestamps from a reference file

use crate::error::MemoricError;
use serde_json::Value;

/// Copy timestamps (creation, access, write) from reference file to target file
pub fn timestomp(args: &Value) -> Result<Value, MemoricError> {
    use crate::safe_handle::SafeHandle;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetFileTime, SetFileTime, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
    };

    let target = args
        .get("target")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing target file path".to_string()))?;
    let reference = args
        .get("reference")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\kernel32.dll");

    tracing::warn!(
        "[EVASION] Timestomping {} with timestamps from {}",
        target,
        reference
    );

    unsafe {
        // Open reference file
        let ref_w: Vec<u16> = reference.encode_utf16().chain(std::iter::once(0)).collect();
        let ref_file = CreateFileW(
            windows::core::PCWSTR(ref_w.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open reference file: {}", e)))?;
        let ref_file = SafeHandle::new(ref_file);

        let mut creation = FILETIME::default();
        let mut access = FILETIME::default();
        let mut write = FILETIME::default();
        GetFileTime(
            *ref_file,
            Some(&mut creation),
            Some(&mut access),
            Some(&mut write),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("GetFileTime failed: {}", e)))?;

        // Open target file for writing attributes
        let tgt_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let tgt_file = CreateFileW(
            windows::core::PCWSTR(tgt_w.as_ptr()),
            FILE_WRITE_ATTRIBUTES.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open target file: {}", e)))?;
        let tgt_file = SafeHandle::new(tgt_file);

        SetFileTime(*tgt_file, Some(&creation), Some(&access), Some(&write))
            .map_err(|e| MemoricError::WindowsApi(format!("SetFileTime failed: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "timestomp",
            "target": target,
            "reference": reference,
            "creation_time": format!("0x{:08X}{:08X}", creation.dwHighDateTime, creation.dwLowDateTime),
            "access_time": format!("0x{:08X}{:08X}", access.dwHighDateTime, access.dwLowDateTime),
            "write_time": format!("0x{:08X}{:08X}", write.dwHighDateTime, write.dwLowDateTime),
            "message": "Timestamps copied from reference to target"
        }))
    }
}

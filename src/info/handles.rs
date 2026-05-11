//! Handle enumeration via NtQuerySystemInformation

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;

/// Enumerate open handles for a process (files, registry keys, mutexes, etc.)
pub fn enum_handles(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_DUP_HANDLE};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let type_filter = args.get("type_filter").and_then(|v| v.as_str());
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::info!(
        "[INFO] enum_handles pid={} type_filter={:?}",
        pid,
        type_filter
    );

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Resolve NtQuerySystemInformation and NtQueryObject
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("ntdll: {}", e)))?;

        let nt_query_sys = GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        )
        .ok_or_else(|| {
            MemoricError::WindowsApi("NtQuerySystemInformation not found".to_string())
        })?;

        let nt_query_obj = GetProcAddress(ntdll, windows::core::PCSTR(b"NtQueryObject\0".as_ptr()))
            .ok_or_else(|| MemoricError::WindowsApi("NtQueryObject not found".to_string()))?;

        type NtQuerySysFn = unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;
        type NtQueryObjFn = unsafe extern "system" fn(HANDLE, u32, *mut u8, u32, *mut u32) -> i32;

        let query_sys: NtQuerySysFn = std::mem::transmute(nt_query_sys);
        let query_obj: NtQueryObjFn = std::mem::transmute(nt_query_obj);

        // Query all system handles (SystemHandleInformation = 16)
        let mut buf_size = 1024 * 1024u32; // Start at 1MB
        let mut buffer = vec![0u8; buf_size as usize];
        let mut ret_len = 0u32;

        loop {
            let status = query_sys(16, buffer.as_mut_ptr(), buf_size, &mut ret_len);
            if status == 0 {
                break;
            }
            // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
            if status as u32 == 0xC0000004 {
                buf_size *= 2;
                if buf_size > 256 * 1024 * 1024 {
                    return Err(MemoricError::WindowsApi(
                        "Handle info too large".to_string(),
                    ));
                }
                buffer.resize(buf_size as usize, 0);
            } else {
                return Err(MemoricError::WindowsApi(format!(
                    "NtQuerySystemInformation failed: 0x{:X}",
                    status
                )));
            }
        }

        // Parse SYSTEM_HANDLE_INFORMATION structure
        // First 4/8 bytes = NumberOfHandles, then array of handle entries
        let num_handles = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        // Each SYSTEM_HANDLE_TABLE_ENTRY_INFO: UniqueProcessId (u16), CreatorBackTraceIndex (u16),
        // ObjectTypeIndex (u8), HandleAttributes (u8), HandleValue (u16), Object (ptr), GrantedAccess (u32)
        // On x64 with alignment, entry size is typically 24-28 bytes. We'll use the raw struct.
        #[repr(C, packed)]
        #[derive(Copy, Clone)]
        struct HandleEntry {
            unique_process_id: u16,
            creator_back_trace_index: u16,
            object_type_index: u8,
            handle_attributes: u8,
            handle_value: u16,
            object: u64,
            granted_access: u32,
        }

        let entry_size = std::mem::size_of::<HandleEntry>();
        let entries_start = if cfg!(target_pointer_width = "64") {
            8
        } else {
            4
        };

        // Open target process for handle duplication
        let proc_handle = OpenProcess(PROCESS_DUP_HANDLE, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess(DUP_HANDLE): {}", e)))?;
        let proc_handle = SafeHandle::new(proc_handle);

        let cur_process = HANDLE(-1isize as *mut _); // pseudo-handle for current process

        let mut handles = Vec::new();
        let mut total_for_pid = 0usize;

        for i in 0..num_handles {
            let entry_offset = entries_start + i * entry_size;
            if entry_offset + entry_size > buffer.len() {
                break;
            }

            let entry: HandleEntry =
                std::ptr::read_unaligned(buffer.as_ptr().add(entry_offset) as *const _);

            if entry.unique_process_id as u64 != pid {
                continue;
            }
            total_for_pid += 1;

            if total_for_pid <= offset {
                continue;
            }
            if handles.len() >= limit {
                continue;
            }

            // Try to get type and name by duplicating handle
            let mut dup = HANDLE::default();
            let dup_ok = DuplicateHandle(
                *proc_handle,
                HANDLE(entry.handle_value as isize as *mut _),
                cur_process,
                &mut dup,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
            .is_ok();

            let mut type_name = String::new();
            let mut obj_name = String::new();

            if dup_ok && !dup.is_invalid() {
                // Query type info (ObjectTypeInformation = 2)
                let mut type_buf = vec![0u8; 1024];
                let mut type_ret = 0u32;
                if query_obj(
                    dup,
                    2,
                    type_buf.as_mut_ptr(),
                    type_buf.len() as u32,
                    &mut type_ret,
                ) == 0
                {
                    // UNICODE_STRING at offset 0: Length (u16), MaxLength (u16), pad, Buffer (ptr)
                    if type_ret >= 8 {
                        let len = u16::from_ne_bytes([type_buf[0], type_buf[1]]) as usize / 2;
                        let buf_ptr = u64::from_ne_bytes([
                            type_buf[8],
                            type_buf[9],
                            type_buf[10],
                            type_buf[11],
                            type_buf[12],
                            type_buf[13],
                            type_buf[14],
                            type_buf[15],
                        ]);
                        if buf_ptr != 0 && len > 0 && len < 256 {
                            // The buffer is inline for short strings, but for safety use the returned buffer directly
                            let wide: Vec<u16> = type_buf[16..16 + len * 2]
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            type_name = String::from_utf16_lossy(&wide);
                        }
                    }
                }

                // Query name info (ObjectNameInformation = 1) — skip for types that can hang
                let skip_name = type_name == "File" || type_name == "EtwRegistration";
                if !skip_name {
                    let mut name_buf = vec![0u8; 2048];
                    let mut name_ret = 0u32;
                    if query_obj(
                        dup,
                        1,
                        name_buf.as_mut_ptr(),
                        name_buf.len() as u32,
                        &mut name_ret,
                    ) == 0
                    {
                        if name_ret >= 8 {
                            let len = u16::from_ne_bytes([name_buf[0], name_buf[1]]) as usize / 2;
                            if len > 0 && len < 512 && 16 + len * 2 <= name_buf.len() {
                                let wide: Vec<u16> = name_buf[16..16 + len * 2]
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                obj_name = String::from_utf16_lossy(&wide);
                            }
                        }
                    }
                }

                let _ = windows::Win32::Foundation::CloseHandle(dup);
            }

            // Apply type filter
            if let Some(filter) = type_filter {
                if filter != "all" && !type_name.eq_ignore_ascii_case(filter) {
                    continue;
                }
            }

            let hv = entry.handle_value;
            let ga = entry.granted_access;
            let ti = entry.object_type_index;
            handles.push(serde_json::json!({
                "handle_value": format!("0x{:X}", hv),
                "type_name": type_name,
                "name": obj_name,
                "access_mask": format!("0x{:08X}", ga),
                "type_index": ti
            }));
        }

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "handles": handles,
            "count": handles.len(),
            "total_count": total_for_pid,
            "offset": offset,
            "limit": limit
        }))
    }
}

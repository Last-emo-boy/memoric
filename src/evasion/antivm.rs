//! Anti-VM/Sandbox detection - detect virtual machine environments

use crate::error::MemoricError;
use serde_json::Value;

/// Detect if running inside a VM or sandbox
pub fn detect_vm(args: &Value) -> Result<Value, MemoricError> {
    let mut indicators: Vec<String> = Vec::new();

    // 1. CPUID hypervisor bit check
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid_result = unsafe { std::arch::x86_64::__cpuid(1) };
        if cpuid_result.ecx & (1 << 31) != 0 {
            indicators.push("CPUID hypervisor bit set".to_string());

            // Get hypervisor brand
            let brand = unsafe { std::arch::x86_64::__cpuid(0x40000000) };
            let brand_str = String::from_utf8_lossy(
                &[
                    brand.ebx.to_le_bytes(),
                    brand.ecx.to_le_bytes(),
                    brand.edx.to_le_bytes(),
                ]
                .concat(),
            )
            .trim_end_matches('\0')
            .to_string();
            if !brand_str.is_empty() {
                indicators.push(format!("Hypervisor brand: {}", brand_str));
            }
        }
    }

    // 2. Registry checks for VM artifacts
    check_registry_key(r"SOFTWARE\VMware, Inc.\VMware Tools", &mut indicators);
    check_registry_key(
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        &mut indicators,
    );
    check_registry_key(
        r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        &mut indicators,
    );
    check_registry_key(r"SYSTEM\CurrentControlSet\Services\vmci", &mut indicators);

    // 3. Process checks
    let vm_processes = [
        "vmtoolsd.exe",
        "VBoxService.exe",
        "VBoxTray.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vmsrvc.exe",
        "vmusrvc.exe",
        "xenservice.exe",
        "qemu-ga.exe",
    ];
    check_vm_processes(&vm_processes, &mut indicators);

    // 4. RDTSC timing check
    #[cfg(target_arch = "x86_64")]
    {
        let start = unsafe { std::arch::x86_64::_rdtsc() };
        unsafe { std::arch::x86_64::__cpuid(0) }; // serializing instruction
        let end = unsafe { std::arch::x86_64::_rdtsc() };
        let delta = end - start;
        if delta > 10000 {
            indicators.push(format!(
                "RDTSC timing anomaly: {} cycles (threshold: 10000)",
                delta
            ));
        }
    }

    // 5. MAC OUI check for known VM vendors
    check_mac_oui(&mut indicators);

    let is_vm = !indicators.is_empty();

    Ok(serde_json::json!({
        "success": true,
        "technique": "detect_vm",
        "is_vm": is_vm,
        "indicator_count": indicators.len(),
        "indicators": indicators,
        "message": if is_vm { "VM/Sandbox environment detected" } else { "No VM indicators found" }
    }))
}

fn check_registry_key(subkey: &str, indicators: &mut Vec<String>) {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExA, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    unsafe {
        let mut hkey = Default::default();
        let mut key_str = subkey.as_bytes().to_vec();
        key_str.push(0);
        let result = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            windows::core::PCSTR(key_str.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        if result.is_ok() {
            indicators.push(format!("Registry key found: HKLM\\{}", subkey));
            let _ = RegCloseKey(hkey);
        }
    }
}

fn check_vm_processes(names: &[&str], indicators: &mut Vec<String>) {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(snap) = snap {
            let mut pe = PROCESSENTRY32W::default();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snap, &mut pe).is_ok() {
                loop {
                    let exe_name = String::from_utf16_lossy(
                        &pe.szExeFile[..pe
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(pe.szExeFile.len())],
                    )
                    .to_lowercase();

                    for &vm_proc in names {
                        if exe_name == vm_proc.to_lowercase() {
                            indicators.push(format!("VM process running: {}", exe_name));
                        }
                    }

                    if Process32NextW(snap, &mut pe).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
    }
}

fn check_mac_oui(indicators: &mut Vec<String>) {
    // Known VM MAC OUIs
    let vm_ouis: &[(&str, &str)] = &[
        ("00:0C:29", "VMware"),
        ("00:50:56", "VMware"),
        ("08:00:27", "VirtualBox"),
        ("00:15:5D", "Hyper-V"),
        ("00:16:3E", "Xen"),
        ("52:54:00", "QEMU/KVM"),
    ];

    // Use GetAdaptersInfo via iphlpapi
    use windows::Win32::NetworkManagement::IpHelper::GetAdaptersInfo;
    use windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_INFO;

    unsafe {
        let mut buf_len = 0u32;
        let _ = GetAdaptersInfo(None, &mut buf_len);
        if buf_len == 0 {
            return;
        }

        let mut buf = vec![0u8; buf_len as usize];
        let adapter = buf.as_mut_ptr() as *mut IP_ADAPTER_INFO;
        if GetAdaptersInfo(Some(adapter), &mut buf_len) != 0 {
            return;
        }

        let mut current = adapter;
        while !current.is_null() {
            let a = &*current;
            if a.AddressLength >= 3 {
                let mac_prefix = format!(
                    "{:02X}:{:02X}:{:02X}",
                    a.Address[0], a.Address[1], a.Address[2]
                );
                for &(oui, vendor) in vm_ouis {
                    if mac_prefix.eq_ignore_ascii_case(oui) {
                        indicators
                            .push(format!("VM MAC OUI detected: {} ({})", mac_prefix, vendor));
                    }
                }
            }
            current = a.Next;
        }
    }
}

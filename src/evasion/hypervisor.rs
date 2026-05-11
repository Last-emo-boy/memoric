//! Advanced hypervisor detection — CPUID leaf analysis, timing attacks,
//! SIDT/SGDT red pill, firmware SMBIOS fingerprinting, and interrupt
//! descriptor table analysis.

use crate::error::MemoricError;
use serde_json::{json, Value};

/// Comprehensive hypervisor detection with multiple techniques
pub fn detect_hypervisor(args: &Value) -> Result<Value, MemoricError> {
    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut results: Vec<Value> = Vec::new();
    let mut detected_hypervisor: Option<String> = None;
    let mut confidence: u32 = 0;

    // ── 1. CPUID Leaf 0x1 — Hypervisor Present Bit ──────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        let cpuid1 = unsafe { std::arch::x86_64::__cpuid(1) };
        let hv_present = (cpuid1.ecx >> 31) & 1 == 1;

        results.push(json!({
            "technique": "cpuid_leaf_1",
            "description": "CPUID.1:ECX[31] hypervisor present bit",
            "hv_present": hv_present,
        }));

        if hv_present {
            confidence += 30;
        }
    }

    // ── 2. CPUID Leaf 0x40000000 — Hypervisor Brand ─────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        let hv = unsafe { std::arch::x86_64::__cpuid(0x40000000) };
        let max_leaf = hv.eax;

        let brand_bytes = [
            hv.ebx.to_le_bytes(),
            hv.ecx.to_le_bytes(),
            hv.edx.to_le_bytes(),
        ]
        .concat();
        let brand = String::from_utf8_lossy(&brand_bytes)
            .trim_end_matches('\0')
            .to_string();

        let vendor = identify_hypervisor_vendor(&brand);
        if !vendor.is_empty() {
            detected_hypervisor = Some(vendor.clone());
            confidence += 40;
        }

        results.push(json!({
            "technique": "cpuid_leaf_40000000",
            "description": "Hypervisor vendor identification string",
            "max_leaf": format!("0x{:08X}", max_leaf),
            "brand_raw": brand,
            "identified_vendor": if vendor.is_empty() { "unknown".to_string() } else { vendor },
        }));
    }

    // ── 3. CPUID Leaf 0x40000001-6 — Hypervisor Interface Details ───────
    #[cfg(target_arch = "x86_64")]
    {
        let hv0 = unsafe { std::arch::x86_64::__cpuid(0x40000000) };
        let max_leaf = hv0.eax;
        let mut hv_details = Vec::new();

        // Read up to leaf 0x40000006 (Hyper-V exposes the most)
        for leaf in 0x40000001..=std::cmp::min(max_leaf, 0x40000006) {
            let result = unsafe { std::arch::x86_64::__cpuid(leaf) };
            hv_details.push(json!({
                "leaf": format!("0x{:08X}", leaf),
                "eax": format!("0x{:08X}", result.eax),
                "ebx": format!("0x{:08X}", result.ebx),
                "ecx": format!("0x{:08X}", result.ecx),
                "edx": format!("0x{:08X}", result.edx),
            }));
        }

        if !hv_details.is_empty() {
            results.push(json!({
                "technique": "cpuid_hv_leaves",
                "description": "Extended hypervisor CPUID leaves",
                "leaves": hv_details,
            }));
        }
    }

    // ── 4. RDTSC / CPUID Timing — VM Exit Overhead Detection ────────────
    #[cfg(target_arch = "x86_64")]
    {
        const ITERATIONS: u32 = 10;
        let mut deltas = Vec::with_capacity(ITERATIONS as usize);

        for _ in 0..ITERATIONS {
            let t1 = unsafe { std::arch::x86_64::_rdtsc() };
            unsafe { std::arch::x86_64::__cpuid(0) }; // serializing
            let t2 = unsafe { std::arch::x86_64::_rdtsc() };
            deltas.push(t2.wrapping_sub(t1));
        }

        deltas.sort_unstable();
        let median = deltas[deltas.len() / 2];
        let min_delta = deltas[0];
        let max_delta = deltas[deltas.len() - 1];

        // Bare metal CPUID typically < 500 cycles; VM typically > 1000-5000+
        let timing_suspicious = median > 1500;
        if timing_suspicious {
            confidence += 15;
        }

        results.push(json!({
            "technique": "rdtsc_timing",
            "description": "RDTSC timing around CPUID (VM exit overhead)",
            "iterations": ITERATIONS,
            "median_cycles": median,
            "min_cycles": min_delta,
            "max_cycles": max_delta,
            "threshold": 1500,
            "suspicious": timing_suspicious,
        }));
    }

    // ── 5. SIDT Red Pill ────────────────────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        let mut idtr: [u8; 10] = [0u8; 10];
        unsafe {
            std::arch::asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack));
        }

        let idt_base = u64::from_le_bytes([
            idtr[2], idtr[3], idtr[4], idtr[5], idtr[6], idtr[7], idtr[8], idtr[9],
        ]);
        let idt_limit = u16::from_le_bytes([idtr[0], idtr[1]]);

        // In VMs, IDT base is sometimes relocated to unusual addresses
        // On bare metal Windows x64, IDT base is typically in the higher kernel range
        let idt_suspicious = idt_base < 0xFFFFF000_00000000;
        if idt_suspicious {
            confidence += 10;
        }

        results.push(json!({
            "technique": "sidt_red_pill",
            "description": "Store IDT Register — detect relocated IDT base",
            "idt_base": format!("0x{:016X}", idt_base),
            "idt_limit": idt_limit,
            "suspicious": idt_suspicious,
        }));
    }

    // ── 6. SGDT Check ───────────────────────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        let mut gdtr: [u8; 10] = [0u8; 10];
        unsafe {
            std::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
        }

        let gdt_base = u64::from_le_bytes([
            gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9],
        ]);
        let gdt_limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);

        results.push(json!({
            "technique": "sgdt_check",
            "description": "Store GDT Register — cross-reference with IDT",
            "gdt_base": format!("0x{:016X}", gdt_base),
            "gdt_limit": gdt_limit,
        }));
    }

    // ── 7. SMBIOS / Firmware Fingerprinting ─────────────────────────────
    {
        let firmware = detect_firmware_artifacts();
        if !firmware.is_empty() {
            confidence += 15;
        }
        results.push(json!({
            "technique": "firmware_smbios",
            "description": "SMBIOS/firmware string fingerprinting",
            "artifacts": firmware,
        }));
    }

    // ── 8. Hardware Enumeration — Known VM Devices ──────────────────────
    {
        let devices = detect_vm_devices();
        if !devices.is_empty() {
            confidence += 15;
        }
        results.push(json!({
            "technique": "hardware_devices",
            "description": "PCI/ACPI device enumeration for VM artifacts",
            "vm_devices": devices,
        }));
    }

    // ── 9. Debug Registers / DR7 ────────────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        // Some hypervisors intercept MOV DR and return zeroed or stale values
        // We can't read DR7 from ring 3 on Windows, but we can use GetThreadContext
        let dr_analysis = check_debug_registers();
        results.push(json!({
            "technique": "debug_registers",
            "description": "Debug register analysis for hypervisor interference",
            "analysis": dr_analysis,
        }));
    }

    // Clamp confidence
    if confidence > 100 {
        confidence = 100;
    }

    let is_virtual = confidence >= 50;
    let hv_name = detected_hypervisor.unwrap_or_else(|| {
        if is_virtual {
            "Unknown".to_string()
        } else {
            "None".to_string()
        }
    });

    Ok(json!({
        "success": true,
        "technique": "hypervisor_detection",
        "is_virtual": is_virtual,
        "confidence": confidence,
        "hypervisor": hv_name,
        "technique_count": results.len(),
        "results": if verbose { Value::Array(results.clone()) } else { Value::Null },
        "summary": if verbose { Value::Null } else {
            Value::Array(results.iter().filter_map(|r| {
                let tech = r.get("technique")?.as_str()?;
                let suspicious = r.get("suspicious").and_then(|v| v.as_bool()).unwrap_or(false);
                let artifacts = r.get("artifacts").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                let devices = r.get("vm_devices").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                if suspicious || artifacts || devices {
                    Some(json!({"technique": tech, "indicator": true}))
                } else {
                    None
                }
            }).collect())
        },
        "message": format!("Hypervisor detection: {} (confidence {}%) — {} techniques applied",
                           hv_name, confidence, results.len()),
    }))
}

/// Identify hypervisor vendor from CPUID brand string
fn identify_hypervisor_vendor(brand: &str) -> String {
    match brand {
        "Microsoft Hv" => "Microsoft Hyper-V".to_string(),
        "VMwareVMware" => "VMware".to_string(),
        "VBoxVBoxVBox" => "Oracle VirtualBox".to_string(),
        "KVMKVMKVM\0\0\0" | "KVMKVMKVM" => "KVM".to_string(),
        "XenVMMXenVMM" => "Xen".to_string(),
        "prl hyperv  " | "prl hyperv" => "Parallels".to_string(),
        "TCGTCGTCGTCG" | "TCGTCGTCG" => "QEMU/TCG".to_string(),
        "bhyve bhyve " | "bhyve bhyve" => "bhyve".to_string(),
        "ACRNACRNACRN" | "ACRNACRN" => "ACRN".to_string(),
        _ => {
            // Fuzzy match
            let lower = brand.to_lowercase();
            if lower.contains("vmware") {
                "VMware".to_string()
            } else if lower.contains("vbox") || lower.contains("virtualbox") {
                "Oracle VirtualBox".to_string()
            } else if lower.contains("kvm") {
                "KVM".to_string()
            } else if lower.contains("xen") {
                "Xen".to_string()
            } else if lower.contains("microsoft") || lower.contains("hv") {
                "Microsoft Hyper-V".to_string()
            } else if lower.contains("qemu") {
                "QEMU".to_string()
            } else {
                String::new()
            }
        }
    }
}

/// Detect firmware/SMBIOS artifacts indicating virtualization
fn detect_firmware_artifacts() -> Vec<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
    };

    let mut artifacts = Vec::new();

    let checks: &[(&str, &str, &[&str])] = &[
        (
            r"HARDWARE\Description\System\BIOS",
            "SystemManufacturer",
            &[
                "VMware",
                "QEMU",
                "Xen",
                "innotek",
                "VirtualBox",
                "Microsoft Corporation",
                "Parallels",
            ],
        ),
        (
            r"HARDWARE\Description\System\BIOS",
            "SystemProductName",
            &[
                "VMware",
                "Virtual Machine",
                "VirtualBox",
                "KVM",
                "HVM domU",
                "Parallels",
            ],
        ),
        (
            r"HARDWARE\Description\System\BIOS",
            "BIOSVendor",
            &["Phoenix", "SeaBIOS", "OVMF", "Xen", "innotek"],
        ),
        (
            r"HARDWARE\Description\System",
            "SystemBiosVersion",
            &["VBOX", "VMWARE", "QEMU", "XEN", "VIRTUAL"],
        ),
        (
            r"HARDWARE\Description\System",
            "VideoBiosVersion",
            &["VirtualBox", "VMware"],
        ),
    ];

    unsafe {
        for &(subkey, value_name, markers) in checks {
            let mut hkey = Default::default();
            let mut key_bytes = subkey.as_bytes().to_vec();
            key_bytes.push(0);

            if RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                windows::core::PCSTR(key_bytes.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
            .is_ok()
            {
                let mut data = vec![0u8; 512];
                let mut data_len = data.len() as u32;
                let mut kind = REG_SZ;

                let mut val_bytes = value_name.as_bytes().to_vec();
                val_bytes.push(0);

                if RegQueryValueExA(
                    hkey,
                    windows::core::PCSTR(val_bytes.as_ptr()),
                    None,
                    Some(&mut kind),
                    Some(data.as_mut_ptr()),
                    Some(&mut data_len),
                )
                .is_ok()
                {
                    let text = String::from_utf8_lossy(&data[..data_len as usize])
                        .trim_end_matches('\0')
                        .to_string();

                    for &marker in markers {
                        if text.to_lowercase().contains(&marker.to_lowercase()) {
                            artifacts.push(format!(
                                "{}\\{} = \"{}\" (matches '{}')",
                                subkey, value_name, text, marker
                            ));
                            break;
                        }
                    }
                }
                let _ = RegCloseKey(hkey);
            }
        }
    }

    artifacts
}

/// Detect known VM PCI/ACPI device identifiers via registry
fn detect_vm_devices() -> Vec<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExA, RegOpenKeyExA, HKEY_LOCAL_MACHINE, KEY_READ,
    };

    let mut devices = Vec::new();

    let vm_device_ids: &[(&str, &str)] = &[
        ("VEN_15AD", "VMware"),
        ("VEN_80EE", "VirtualBox"),
        ("VEN_1AF4", "VirtIO/KVM"),
        ("VEN_1414", "Microsoft Hyper-V"),
        ("VMWARE", "VMware"),
        ("VBOX", "VirtualBox"),
        ("XEN", "Xen"),
        ("QEMU", "QEMU"),
        ("Red Hat", "KVM/RHEV"),
    ];

    unsafe {
        let subkey = b"SYSTEM\\CurrentControlSet\\Enum\\PCI\0";
        let mut hkey = Default::default();
        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            windows::core::PCSTR(subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
        .is_ok()
        {
            let mut idx: u32 = 0;
            loop {
                let mut name_buf = vec![0u8; 256];
                let mut name_len = name_buf.len() as u32;
                if RegEnumKeyExA(
                    hkey,
                    idx,
                    windows::core::PSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    windows::core::PSTR::null(),
                    None,
                    None,
                )
                .is_err()
                {
                    break;
                }
                let name = String::from_utf8_lossy(&name_buf[..name_len as usize]).to_string();
                let upper = name.to_uppercase();
                for &(pattern, vendor) in vm_device_ids {
                    if upper.contains(&pattern.to_uppercase()) {
                        devices.push(format!("PCI\\{} ({})", name, vendor));
                        break;
                    }
                }
                idx += 1;
            }
            let _ = RegCloseKey(hkey);
        }
    }

    devices
}

/// Check debug registers via thread context — hypervisors may intercept
fn check_debug_registers() -> Value {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT, CONTEXT_FLAGS};
    use windows::Win32::System::Threading::GetCurrentThread;

    unsafe {
        let thread = GetCurrentThread();
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FLAGS(0x00100010); // CONTEXT_DEBUG_REGISTERS

        if GetThreadContext(thread, &mut ctx).is_ok() {
            json!({
                "dr0": format!("0x{:016X}", ctx.Dr0),
                "dr1": format!("0x{:016X}", ctx.Dr1),
                "dr2": format!("0x{:016X}", ctx.Dr2),
                "dr3": format!("0x{:016X}", ctx.Dr3),
                "dr6": format!("0x{:016X}", ctx.Dr6),
                "dr7": format!("0x{:016X}", ctx.Dr7),
                "note": "Hypervisors may intercept MOV DR and return stale/zeroed values"
            })
        } else {
            json!({
                "error": "GetThreadContext failed for debug registers",
                "note": "Some hypervisors block debug register access"
            })
        }
    }
}

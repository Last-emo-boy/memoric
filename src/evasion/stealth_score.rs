//! Stealth posture scoring engine
//!
//! Live assessment across 8 dimensions (each 0-20, total 0-100):
//!   1. EDR process detection  — fewer EDR processes = higher score
//!   2. ETW provider status    — fewer active ETW providers = higher score
//!   3. AMSI patch status      — patched = 20, unpatched = 0
//!   4. Kernel callbacks       — fewer callbacks = higher score
//!   5. Minifilter presence    — fewer EDR minifilters = higher score
//!   6. Injection method       — thread=low, pool_party=high
//!   7. Module visibility      — hidden=20, visible=0
//!   8. Driver signing status  — test signing hidden = higher score
//!
//! Called via `detect` tool `action="stealth_score"` or from `self` tool state scoring.

use crate::error::MemoricError;
use serde_json::{json, Value};
use std::sync::Mutex;

lazy_static::lazy_static! {
    /// Tracks the last injection method used (for dimension 6 scoring)
    static ref LAST_INJECTION_METHOD: Mutex<Option<String>> = Mutex::new(None);
    /// Tracks module visibility state (for dimension 7 scoring)
    static ref MODULE_VISIBLE: Mutex<bool> = Mutex::new(true);
}

/// Stealth score dimensions
#[derive(Debug, Clone, serde::Serialize)]
pub struct StealthScore {
    pub total_score: u32,
    pub rating: String,
    pub dimensions: Vec<ScoreDimension>,
    pub summary: String,
    pub assessed_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScoreDimension {
    pub name: String,
    pub score: u32, // 0-20
    pub max: u32,
    pub status: String,
    pub details: Vec<String>,
}

/// Comprehensive stealth posture assessment
pub fn assess_stealth_posture(_args: &Value) -> Result<Value, MemoricError> {
    let now = crate::state::chrono_now_public();

    let mut dimensions = Vec::new();
    let mut total: u32 = 0;

    // ═══ Dimension 1: EDR process detection (0-20) ═══
    let edr_dim = assess_edr_presence();
    total += edr_dim.score;
    dimensions.push(edr_dim);

    // ═══ Dimension 2: ETW provider status (0-20) ═══
    let etw_dim = assess_etw_providers();
    total += etw_dim.score;
    dimensions.push(etw_dim);

    // ═══ Dimension 3: AMSI patch status (0-20) ═══
    let amsi_dim = assess_amsi_status();
    total += amsi_dim.score;
    dimensions.push(amsi_dim);

    // ═══ Dimension 4: Kernel callbacks (0-20) ═══
    let cb_dim = assess_kernel_callbacks();
    total += cb_dim.score;
    dimensions.push(cb_dim);

    // ═══ Dimension 5: Minifilter presence (0-20) ═══
    let mf_dim = assess_minifilters();
    total += mf_dim.score;
    dimensions.push(mf_dim);

    // ═══ Dimension 6: Injection method (0-20) ═══
    let inj_dim = assess_injection_method();
    total += inj_dim.score;
    dimensions.push(inj_dim);

    // ═══ Dimension 7: Module visibility (0-20) ═══
    let mod_dim = assess_module_visibility();
    total += mod_dim.score;
    dimensions.push(mod_dim);

    // ═══ Dimension 8: Driver signing (0-20) ═══
    let sig_dim = assess_driver_signing();
    total += sig_dim.score;
    dimensions.push(sig_dim);

    let rating = match total {
        0..=20 => "CRITICAL — heavily exposed to EDR monitoring",
        21..=40 => "POOR — significant detection surface",
        41..=60 => "FAIR — moderate exposure, several gaps remain",
        61..=75 => "GOOD — minimal exposure, few gaps",
        76..=100 => "EXCELLENT — deeply hidden, low detection risk",
        _ => "UNKNOWN",
    };

    let weaknesses: Vec<&str> = dimensions
        .iter()
        .filter(|d| d.score <= 10)
        .map(|d| d.name.as_str())
        .collect();

    let summary = if weaknesses.is_empty() {
        "All dimensions strong. EDR visibility is minimal.".to_string()
    } else {
        format!(
            "Weak areas: {}. Prioritize these for improved stealth.",
            weaknesses.join(", ")
        )
    };

    Ok(json!({
        "success": true,
        "total_score": total,
        "rating": rating,
        "dimensions": dimensions,
        "summary": summary,
        "assessed_at": now,
        "message": format!("Stealth Score: {}/100 — {}", total, rating)
    }))
}

// ─── Dimension assessors ──────────────────────────────────────────────────────

fn assess_edr_presence() -> ScoreDimension {
    let edr_names = crate::evasion::edr::EDR_PROCESSES;
    let edr_drivers = crate::evasion::edr::EDR_DRIVERS;

    let mut found_processes = Vec::new();
    let mut found_drivers = Vec::new();

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

                    for &(proc_name, product) in edr_names {
                        if name.eq_ignore_ascii_case(proc_name) {
                            found_processes.push(format!("{} ({})", product, name));
                        }
                    }

                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }

        // Also check loaded drivers
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
                        for &(drv_name, product) in edr_drivers {
                            if fname_lower.contains(&drv_name.to_lowercase()) {
                                found_drivers.push(format!("{} (driver: {})", product, fname));
                            }
                        }
                    }
                }
            }
        }
    }

    let total_found = found_processes.len() + found_drivers.len();
    let deduped: std::collections::HashSet<&str> = found_processes
        .iter()
        .map(|s| s.split(" (").next().unwrap_or(s))
        .chain(
            found_drivers
                .iter()
                .map(|s| s.split(" (").next().unwrap_or(s)),
        )
        .collect();

    // Score: 0 EDR = 20, each EDR costs 4 points, min 0
    let edr_count = deduped.len() as u32;
    let score = 20u32.saturating_sub(edr_count * 4);

    let mut details = Vec::new();
    details.extend(found_processes);
    details.extend(found_drivers);
    if details.is_empty() {
        details.push("No known EDR processes or drivers detected".into());
    }

    ScoreDimension {
        name: "EDR Presence".into(),
        score,
        max: 20,
        status: if edr_count == 0 {
            "clean".into()
        } else {
            format!("{} EDR product(s) active", edr_count)
        },
        details,
    }
}

fn assess_etw_providers() -> ScoreDimension {
    let mut active_count: u32;
    let mut details = Vec::new();

    // Use logman to enumerate ETW sessions (consistent with existing codebase pattern)
    if let Ok(output) = std::process::Command::new("logman")
        .args(["query", "-ets"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut session_count = 0u32;
        let mut high_threat = Vec::new();

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("Data Collector")
                || trimmed.starts_with("-")
            {
                continue;
            }
            if !trimmed.contains("Type") && !trimmed.contains("Status") {
                session_count += 1;

                let lowered = trimmed.to_lowercase();
                if lowered.contains("defender")
                    || lowered.contains("msmp")
                    || lowered.contains("sysmon")
                    || lowered.contains("senseir")
                {
                    high_threat.push(trimmed.to_string());
                }
            }
        }

        active_count = session_count;
        if session_count == 0 {
            details.push("No ETW trace sessions detected".into());
        } else {
            details.push(format!("{} active ETW trace sessions", session_count));
            for ht in &high_threat {
                details.push(format!("HIGH threat session: {}", ht));
            }
        }
    } else {
        details.push("Could not query ETW sessions (logman unavailable)".into());
        active_count = 2; // assume some active if we can't check
    }

    // Check session state for ETW evasion records
    if let Ok(state) = crate::state::get_state() {
        let etw_evasions: Vec<_> = state
            .evasion_applied
            .iter()
            .filter(|e| e.technique.contains("etw") && e.status == "applied")
            .collect();

        if !etw_evasions.is_empty() {
            details.push(format!(
                "ETW bypass applied ({} records)",
                etw_evasions.len()
            ));
            details.push("EtwEventWrite is patched in this process".into());
            active_count = active_count.saturating_sub(1);
        }

        if !state.kernel_callbacks_status.etw_ti_enabled {
            details.push("ETW-TI provider disabled via kernel".into());
            active_count = active_count.saturating_sub(1);
        }
    }

    // Score: 0 sessions = 20, each session costs 3, min 0
    let score = 20u32.saturating_sub(active_count * 3);

    ScoreDimension {
        name: "ETW Providers".into(),
        score,
        max: 20,
        status: if active_count == 0 {
            "quiet".into()
        } else {
            format!("{} trace sessions", active_count)
        },
        details,
    }
}

fn assess_amsi_status() -> ScoreDimension {
    let mut details = Vec::new();
    let patched;

    // Check session state for AMSI evasion records
    if let Ok(state) = crate::state::get_state() {
        let amsi_evasions: Vec<_> = state
            .evasion_applied
            .iter()
            .filter(|e| e.technique.contains("amsi"))
            .collect();

        if amsi_evasions.iter().any(|e| e.status == "applied") {
            patched = true;
            details.push("AMSI bypass recorded in session — patch applied".into());
        } else {
            patched = false;
            details.push("No AMSI bypass recorded — AMSI may still be active".into());
            details.push("Run stealth(action='patch_amsi') to bypass".into());
        }
    } else {
        patched = false;
        details.push("Unable to read session state".into());
    }

    // Also try live check: scan AmsiInitialize in amsi.dll for patch
    unsafe {
        if let Ok(amsi) = windows::Win32::System::LibraryLoader::GetModuleHandleA(
            windows::core::PCSTR(b"amsi.dll\0".as_ptr()),
        ) {
            if let Some(amsi_init) = windows::Win32::System::LibraryLoader::GetProcAddress(
                amsi,
                windows::core::PCSTR(b"AmsiInitialize\0".as_ptr()),
            ) {
                let first_byte = *(amsi_init as *const u8);
                let is_hooked = first_byte == 0xE9 || first_byte == 0xEB; // JMP or short JMP
                if is_hooked {
                    details
                        .push("Live check: AmsiInitialize appears patched (JMP detected)".into());
                } else if first_byte == 0xB8 {
                    details.push(
                        "Live check: AmsiInitialize appears patched (MOV EAX detected)".into(),
                    );
                } else {
                    let hex_byte = format!("0x{:02X}", first_byte);
                    details.push(format!(
                        "Live check: AmsiInitialize first byte = {} (may still be active)",
                        hex_byte
                    ));
                }
            } else {
                details.push("Live check: Could not resolve AmsiInitialize address".into());
            }
        } else {
            details.push("Live check: amsi.dll not loaded in this process".into());
        }
    }

    ScoreDimension {
        name: "AMSI Status".into(),
        score: if patched { 20 } else { 5 },
        max: 20,
        status: if patched {
            "patched".into()
        } else {
            "active".into()
        },
        details,
    }
}

fn assess_kernel_callbacks() -> ScoreDimension {
    let mut details = Vec::new();
    let score;

    if let Ok(state) = crate::state::get_state() {
        let cb = &state.kernel_callbacks_status;
        let total = cb.process_callbacks
            + cb.thread_callbacks
            + cb.image_callbacks
            + cb.object_callbacks
            + cb.registry_callbacks;

        if total == 0 && cb.last_enum_at.is_some() {
            details.push("Kernel callbacks: all clear — no callbacks enumerated".into());
            score = 20;
        } else if cb.last_enum_at.is_some() {
            details.push(format!("Process callbacks: {}", cb.process_callbacks));
            details.push(format!("Thread callbacks: {}", cb.thread_callbacks));
            details.push(format!("Image callbacks: {}", cb.image_callbacks));
            details.push(format!("Registry callbacks: {}", cb.registry_callbacks));
            // Score: each callback costs 2 points
            score = 20u32.saturating_sub(total * 2);
        } else {
            details.push("Kernel callbacks not yet enumerated — driver may not be loaded".into());
            details.push("Load a BYOVD driver for kernel-level callback enumeration".into());
            score = 10; // neutral — can't assess
        }
    } else {
        details.push("Cannot read session state".into());
        score = 10;
    }

    ScoreDimension {
        name: "Kernel Callbacks".into(),
        score,
        max: 20,
        status: if score >= 16 {
            "clean".into()
        } else if score >= 10 {
            "partial".into()
        } else {
            "exposed".into()
        },
        details,
    }
}

fn assess_minifilters() -> ScoreDimension {
    let mut details = Vec::new();

    // Check session state for minifilter evasion records
    let score = if let Ok(state) = crate::state::get_state() {
        let mf_evasions: Vec<_> = state
            .evasion_applied
            .iter()
            .filter(|e| e.technique.contains("minifilter"))
            .collect();

        let detached = mf_evasions.iter().filter(|e| e.status == "applied").count() as u32;

        if detached > 0 {
            details.push(format!("{} minifilter(s) detached", detached));
            details.push("Minifilter detach reduces file system monitoring".into());
            // 2 detached = full score, 1 = 15
            if detached >= 2 {
                20
            } else {
                15
            }
        } else {
            details.push("No minifilter detachments recorded".into());
            details.push("EDR file-system minifilters may still monitor I/O".into());
            details.push("Load a BYOVD driver for minifilter enumeration and detach".into());
            5
        }
    } else {
        details.push("Cannot read session state".into());
        10
    };

    ScoreDimension {
        name: "Minifilter Status".into(),
        score,
        max: 20,
        status: if score >= 16 {
            "clean".into()
        } else {
            "unknown".into()
        },
        details,
    }
}

fn assess_injection_method() -> ScoreDimension {
    let mut details = Vec::new();
    let method = LAST_INJECTION_METHOD.lock().unwrap().clone();

    // Score by method stealthiness
    let score = match method.as_deref() {
        Some("pool_party") => {
            details.push("Last injection: Pool Party (variant) — highest stealth".into());
            details.push("Uses thread pool worker factories, bypasses callback-based EDR".into());
            20
        }
        Some("threadless") => {
            details.push("Last injection: Threadless (export forwarding) — high stealth".into());
            details.push("No remote thread creation, uses export-forwarding trampoline".into());
            18
        }
        Some("mapping") => {
            details.push("Last injection: Manual mapping — high stealth".into());
            details.push("No LoadLibrary call, manual import resolution".into());
            16
        }
        Some("apc") | Some("special_apc") => {
            details.push("Last injection: APC-based — medium stealth".into());
            details.push("Uses alertable thread state, may trigger some EDR callbacks".into());
            12
        }
        Some("thread") | Some("create_remote_thread") => {
            details.push("Last injection: Remote thread — low stealth".into());
            details.push("Remote thread creation triggers kernel callbacks and ETW events".into());
            4
        }
        Some(ref m) => {
            details.push(format!("Last injection: {} — unknown stealth profile", m));
            10
        }
        None => {
            details.push("No injection method recorded yet".into());
            details.push("Score neutral — can't assess without injection context".into());
            10
        }
    };

    ScoreDimension {
        name: "Injection Method".into(),
        score,
        max: 20,
        status: method.unwrap_or_else(|| "none".into()),
        details,
    }
}

fn assess_module_visibility() -> ScoreDimension {
    let mut details = Vec::new();
    let visible = *MODULE_VISIBLE.lock().unwrap();

    let score = if !visible {
        details.push("Module is unlinked from PEB — not visible to process enumeration".into());
        details.push("PEB unlinking bypasses Task Manager and basic process enumeration".into());
        20
    } else {
        details.push("Module is visible in PEB — detectable by process enumeration".into());
        details.push("Run stealth(action='hide_module') to unlink from PEB loader lists".into());
        // Check session state for hide_module records
        if let Ok(state) = crate::state::get_state() {
            let hidden = state
                .evasion_applied
                .iter()
                .any(|e| e.technique.contains("hide_module") && e.status == "applied");
            if hidden {
                details
                    .push("Note: hide_module evasion recorded but live check shows visible".into());
                details.push("Module may have been re-linked by a system operation".into());
                10
            } else {
                4
            }
        } else {
            4
        }
    };

    ScoreDimension {
        name: "Module Visibility".into(),
        score,
        max: 20,
        status: if !visible {
            "hidden".into()
        } else {
            "visible".into()
        },
        details,
    }
}

fn assess_driver_signing() -> ScoreDimension {
    let mut details = Vec::new();
    let mut score = 20u32; // start optimistic

    // Check test signing status
    // Use the testsign query function
    match crate::evasion::testsign::testsign_query(&json!({})) {
        Ok(result) => {
            if let Some(active) = result.get("test_signing_active").and_then(|v| v.as_bool()) {
                if active {
                    details.push("Test signing IS active — detectable by EDR".into());
                    details.push("Run stealth(action='testsign_hide_ntquery') to hide from NtQuerySystemInformation".into());
                    score = score.saturating_sub(10);
                } else {
                    details.push(
                        "Test signing NOT detected — either disabled or bypass is working".into(),
                    );
                }
            }
        }
        Err(e) => {
            details.push(format!("Could not query test signing status: {}", e));
            score = 10;
        }
    }

    // Check if a signed driver is loaded
    if let Ok(state) = crate::state::get_state() {
        if let Some(ref drv) = state.loaded_driver {
            details.push(format!(
                "BYOVD driver loaded: {} at {}",
                drv.name, drv.device_path
            ));
            details.push(
                "Loaded driver may be detectable by its device path and service entry".into(),
            );
            score = score.saturating_sub(5);
        }
    }

    ScoreDimension {
        name: "Driver Signing".into(),
        score,
        max: 20,
        status: if score >= 16 {
            "clean".into()
        } else {
            "exposed".into()
        },
        details,
    }
}

// ─── Mutation helpers (called by other modules) ───────────────────────────────

/// Record the injection method used (call after successful injection)
pub fn record_injection_method(method: &str) {
    if let Ok(mut m) = LAST_INJECTION_METHOD.lock() {
        *m = Some(method.to_string());
    }
}

/// Record module visibility state (call after hide/unhide)
pub fn record_module_visibility(visible: bool) {
    if let Ok(mut v) = MODULE_VISIBLE.lock() {
        *v = visible;
    }
}

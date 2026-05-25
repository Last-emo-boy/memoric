//! Read-only memory diagnostics for defensive/lab analysis.

use crate::error::MemoricError;
use crate::safe_handle::SafeHandle;
use serde_json::{json, Value};

const DEFAULT_REGION_LIMIT: usize = 64;
const DEFAULT_MODULE_LIMIT: usize = 64;
const DEFAULT_HANDLE_LIMIT: usize = 32;
const DEFAULT_SUSPICIOUS_LIMIT: usize = 32;
const DEFAULT_ENTROPY_REGION_LIMIT: usize = 32;
const DEFAULT_ENTROPY_SAMPLE_BYTES: usize = 4096;
const MAX_REGION_LIMIT: usize = 1024;
const MAX_ENTROPY_REGION_LIMIT: usize = 128;
const MAX_ENTROPY_SAMPLE_BYTES: usize = 64 * 1024;

#[derive(Debug, Default)]
struct MemorySummary {
    total_regions: usize,
    committed_regions: usize,
    readable_regions: usize,
    guard_or_noaccess_regions: usize,
    executable_regions: usize,
    writable_regions: usize,
    rwx_regions: usize,
    private_regions: usize,
    image_regions: usize,
    mapped_regions: usize,
    other_regions: usize,
    total_region_bytes: u64,
    committed_bytes: u64,
    readable_bytes: u64,
    executable_bytes: u64,
    writable_bytes: u64,
}

impl MemorySummary {
    fn as_json(&self) -> Value {
        json!({
            "total_regions": self.total_regions,
            "committed_regions": self.committed_regions,
            "readable_regions": self.readable_regions,
            "guard_or_noaccess_regions": self.guard_or_noaccess_regions,
            "executable_regions": self.executable_regions,
            "writable_regions": self.writable_regions,
            "rwx_regions": self.rwx_regions,
            "private_regions": self.private_regions,
            "image_regions": self.image_regions,
            "mapped_regions": self.mapped_regions,
            "other_regions": self.other_regions,
            "total_region_bytes": self.total_region_bytes,
            "committed_bytes": self.committed_bytes,
            "readable_bytes": self.readable_bytes,
            "executable_bytes": self.executable_bytes,
            "writable_bytes": self.writable_bytes,
        })
    }
}

#[derive(Debug, Default)]
struct EntropySummary {
    sampled_regions: usize,
    sampled_bytes: u64,
    failed_samples: usize,
    max_entropy: f64,
    high_entropy_regions: usize,
}

impl EntropySummary {
    fn record(&mut self, bytes: usize, entropy: f64) {
        self.sampled_regions += 1;
        self.sampled_bytes += bytes as u64;
        self.max_entropy = self.max_entropy.max(entropy);
        if entropy >= 7.20 && bytes >= 512 {
            self.high_entropy_regions += 1;
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "sampled_regions": self.sampled_regions,
            "sampled_bytes": self.sampled_bytes,
            "failed_samples": self.failed_samples,
            "max_entropy": round2(self.max_entropy),
            "high_entropy_regions": self.high_entropy_regions,
            "high_entropy_threshold": 7.20,
            "note": "Entropy is computed from bounded samples only; raw bytes are not returned."
        })
    }
}

/// Build a defensive, read-only memory diagnostics profile for a process.
pub fn memory_diagnostics(args: &Value) -> Result<Value, MemoricError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
        PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let pid = parse_optional_pid(args)?;
    let region_limit =
        parse_bounded_usize(args, "region_limit", DEFAULT_REGION_LIMIT, MAX_REGION_LIMIT)?;
    let suspicious_limit = parse_bounded_usize(
        args,
        "suspicious_limit",
        DEFAULT_SUSPICIOUS_LIMIT,
        MAX_REGION_LIMIT,
    )?;
    let module_limit =
        parse_bounded_usize(args, "module_limit", DEFAULT_MODULE_LIMIT, MAX_REGION_LIMIT)?;
    let handle_limit =
        parse_bounded_usize(args, "handle_limit", DEFAULT_HANDLE_LIMIT, MAX_REGION_LIMIT)?;
    let entropy_region_limit = parse_bounded_usize(
        args,
        "entropy_region_limit",
        DEFAULT_ENTROPY_REGION_LIMIT,
        MAX_ENTROPY_REGION_LIMIT,
    )?;
    let entropy_sample_bytes = parse_bounded_usize(
        args,
        "entropy_sample_bytes",
        DEFAULT_ENTROPY_SAMPLE_BYTES,
        MAX_ENTROPY_SAMPLE_BYTES,
    )?;
    let include_modules = args
        .get("include_modules")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let include_handles = args
        .get("include_handles")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let include_entropy = args
        .get("include_entropy")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenProcess({}): {}", pid, e)))?;
        let handle = SafeHandle::new(handle);

        let mut summary = MemorySummary::default();
        let mut entropy_summary = EntropySummary::default();
        let mut regions = Vec::new();
        let mut suspicious = Vec::new();
        let mut suspicious_total = 0usize;
        let mut address = 0usize;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let result = VirtualQueryEx(
                *handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if result == 0 {
                break;
            }
            if mbi.RegionSize == 0 {
                break;
            }

            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            let state = mbi.State.0;
            let protect = mbi.Protect.0;
            let region_type = mbi.Type.0;
            let committed = mbi.State == MEM_COMMIT;
            let noaccess = (protect & PAGE_NOACCESS.0) != 0;
            let guard = (protect & PAGE_GUARD.0) != 0;
            let readable = committed && !noaccess && !guard;
            let executable = is_executable_protect(protect);
            let writable = is_writable_protect(protect);
            let rwx = (protect & PAGE_EXECUTE_READWRITE.0) != 0;

            summary.total_regions += 1;
            summary.total_region_bytes = summary.total_region_bytes.saturating_add(size as u64);
            if committed {
                summary.committed_regions += 1;
                summary.committed_bytes = summary.committed_bytes.saturating_add(size as u64);
            }
            if readable {
                summary.readable_regions += 1;
                summary.readable_bytes = summary.readable_bytes.saturating_add(size as u64);
            }
            if noaccess || guard {
                summary.guard_or_noaccess_regions += 1;
            }
            if executable {
                summary.executable_regions += 1;
                summary.executable_bytes = summary.executable_bytes.saturating_add(size as u64);
            }
            if writable {
                summary.writable_regions += 1;
                summary.writable_bytes = summary.writable_bytes.saturating_add(size as u64);
            }
            if rwx {
                summary.rwx_regions += 1;
            }
            match region_type {
                value if value == MEM_PRIVATE.0 => summary.private_regions += 1,
                value if value == MEM_IMAGE.0 => summary.image_regions += 1,
                value if value == MEM_MAPPED.0 => summary.mapped_regions += 1,
                _ => summary.other_regions += 1,
            }

            let mut entropy = None;
            if include_entropy
                && readable
                && entropy_summary.sampled_regions < entropy_region_limit
                && entropy_sample_bytes > 0
            {
                let sample_len = size.min(entropy_sample_bytes);
                let mut sample = vec![0u8; sample_len];
                let mut bytes_read = 0usize;
                if ReadProcessMemory(
                    *handle,
                    base as *const _,
                    sample.as_mut_ptr() as *mut _,
                    sample_len,
                    Some(&mut bytes_read),
                )
                .is_ok()
                    && bytes_read > 0
                {
                    sample.truncate(bytes_read);
                    let value = shannon_entropy(&sample);
                    entropy_summary.record(bytes_read, value);
                    entropy = Some(value);
                } else {
                    entropy_summary.failed_samples += 1;
                }
            }

            let labels = diagnostic_labels(
                region_type,
                protect,
                committed,
                readable,
                executable,
                writable,
            );
            if rwx
                || (region_type == MEM_PRIVATE.0 && executable)
                || entropy.is_some_and(|v| v >= 7.20)
            {
                suspicious_total += 1;
                if suspicious.len() < suspicious_limit {
                    suspicious.push(json!({
                        "base_address": format!("0x{:016X}", base),
                        "region_size": size,
                        "type": region_type_label(region_type),
                        "protect": protection_label(protect),
                        "signals": labels,
                        "entropy": entropy.map(round2),
                    }));
                }
            }

            if regions.len() < region_limit {
                regions.push(json!({
                    "base_address": format!("0x{:016X}", base),
                    "allocation_base": format!("0x{:016X}", mbi.AllocationBase as usize),
                    "region_size": size,
                    "state": state,
                    "type": region_type_label(region_type),
                    "protect": protection_label(protect),
                    "readable": readable,
                    "executable": executable,
                    "writable": writable,
                    "entropy": entropy.map(round2),
                }));
            }

            let next = base.saturating_add(size);
            if next <= address {
                break;
            }
            address = next;
        }

        let modules = if include_modules {
            degraded_call(crate::info::module::list_modules(&json!({
                "pid": pid,
                "limit": module_limit,
                "offset": 0
            })))
        } else {
            json!({"skipped": true})
        };

        let handles = if include_handles {
            handle_summary(pid, handle_limit)
        } else {
            json!({"skipped": true})
        };

        Ok(json!({
            "success": true,
            "profile": "defensive_memory_diagnostics",
            "read_only": true,
            "pid": pid,
            "scope": if pid == std::process::id() { "self" } else { "process" },
            "summary": summary.as_json(),
            "entropy": if include_entropy { entropy_summary.as_json() } else { json!({"skipped": true}) },
            "regions": regions,
            "regions_truncated": summary.total_regions.saturating_sub(regions.len()),
            "suspicious_regions": suspicious,
            "suspicious_regions_total": suspicious_total,
            "suspicious_regions_truncated": suspicious_total.saturating_sub(suspicious.len()),
            "modules": modules,
            "handles": handles,
            "safety": {
                "mutates_memory": false,
                "returns_raw_bytes": false,
                "uses_driver": false,
                "enables_privileges": false
            },
            "message": "Read-only defensive memory diagnostics completed without returning raw memory bytes."
        }))
    }
}

fn parse_optional_pid(args: &Value) -> Result<u32, MemoricError> {
    match args.get("pid").and_then(crate::args::parse_u64) {
        Some(pid) if pid <= u32::MAX as u64 => Ok(pid as u32),
        Some(_) => Err(MemoricError::MemoryAccess(
            "'pid' is outside the supported u32 PID range".to_string(),
        )),
        None => Ok(std::process::id()),
    }
}

fn parse_bounded_usize(
    args: &Value,
    key: &str,
    default: usize,
    max: usize,
) -> Result<usize, MemoricError> {
    crate::args::parse_limit(args, key, default, max).map_err(MemoricError::MemoryAccess)
}

fn degraded_call(result: Result<Value, MemoricError>) -> Value {
    match result {
        Ok(value) => value,
        Err(err) => json!({
            "degraded": true,
            "error": err.to_string()
        }),
    }
}

fn handle_summary(pid: u32, limit: usize) -> Value {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    unsafe {
        let ntdll = match GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr())) {
            Ok(module) => module,
            Err(err) => {
                return json!({
                    "degraded": true,
                    "error": format!("ntdll lookup failed: {}", err)
                });
            }
        };

        let nt_query_sys = match GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        ) {
            Some(function) => function,
            None => {
                return json!({
                    "degraded": true,
                    "error": "NtQuerySystemInformation not found"
                });
            }
        };

        type NtQuerySysFn = unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;
        let query_sys: NtQuerySysFn = std::mem::transmute(nt_query_sys);

        let mut buf_size = 1024 * 1024u32;
        let mut buffer = vec![0u8; buf_size as usize];
        let mut ret_len = 0u32;

        loop {
            let status = query_sys(16, buffer.as_mut_ptr(), buf_size, &mut ret_len);
            if status == 0 {
                break;
            }
            if status as u32 == 0xC0000004 {
                buf_size = buf_size.saturating_mul(2);
                if buf_size > 256 * 1024 * 1024 {
                    return json!({
                        "degraded": true,
                        "error": "Handle info too large"
                    });
                }
                buffer.resize(buf_size as usize, 0);
            } else {
                return json!({
                    "degraded": true,
                    "error": format!("NtQuerySystemInformation failed: 0x{:X}", status)
                });
            }
        }

        #[repr(C, packed)]
        #[derive(Copy, Clone)]
        struct HandleEntry {
            unique_process_id: u16,
            creator_back_trace_index: u16,
            object_type_index: u8,
            handle_attributes: u8,
            handle_value: u16,
            object: u64,
            granted_access: u32,
        }

        let num_handles = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        let entry_size = std::mem::size_of::<HandleEntry>();
        let entries_start = if cfg!(target_pointer_width = "64") {
            8
        } else {
            4
        };
        let mut total_for_pid = 0usize;
        let mut samples = Vec::new();

        for i in 0..num_handles {
            let entry_offset = entries_start + i * entry_size;
            if entry_offset + entry_size > buffer.len() {
                break;
            }

            let entry: HandleEntry =
                std::ptr::read_unaligned(buffer.as_ptr().add(entry_offset) as *const _);
            if entry.unique_process_id as u32 != pid {
                continue;
            }

            total_for_pid += 1;
            if samples.len() < limit {
                let hv = entry.handle_value;
                let ga = entry.granted_access;
                let ti = entry.object_type_index;
                let attrs = entry.handle_attributes;
                samples.push(json!({
                    "handle_value": format!("0x{:X}", hv),
                    "type_index": ti,
                    "attributes": format!("0x{:02X}", attrs),
                    "access_mask": format!("0x{:08X}", ga)
                }));
            }
        }

        json!({
            "pid": pid,
            "count": samples.len(),
            "total_count": total_for_pid,
            "limit": limit,
            "samples": samples,
            "names_resolved": false,
            "note": "Handle summary avoids DuplicateHandle/ObjectName queries and does not enable debug privilege."
        })
    }
}

fn is_executable_protect(protect: u32) -> bool {
    use windows::Win32::System::Memory::{
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };

    (protect
        & (PAGE_EXECUTE.0
            | PAGE_EXECUTE_READ.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_EXECUTE_WRITECOPY.0))
        != 0
}

fn is_writable_protect(protect: u32) -> bool {
    use windows::Win32::System::Memory::{
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE, PAGE_WRITECOPY,
    };

    (protect
        & (PAGE_READWRITE.0
            | PAGE_WRITECOPY.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_EXECUTE_WRITECOPY.0))
        != 0
}

fn diagnostic_labels(
    region_type: u32,
    protect: u32,
    committed: bool,
    readable: bool,
    executable: bool,
    writable: bool,
) -> Vec<&'static str> {
    use windows::Win32::System::Memory::{MEM_PRIVATE, PAGE_EXECUTE_READWRITE};

    let mut labels = Vec::new();
    if !committed {
        labels.push("not_committed");
    }
    if !readable {
        labels.push("not_readable");
    }
    if (protect & PAGE_EXECUTE_READWRITE.0) != 0 {
        labels.push("rwx");
    }
    if region_type == MEM_PRIVATE.0 && executable {
        labels.push("private_executable");
    }
    if executable && writable {
        labels.push("executable_writable");
    }
    labels
}

fn protection_label(protect: u32) -> &'static str {
    use windows::Win32::System::Memory::{
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };

    let base = protect & !PAGE_GUARD.0;
    match base {
        value if value == PAGE_NOACCESS.0 => "NOACCESS",
        value if value == PAGE_READONLY.0 => "R",
        value if value == PAGE_READWRITE.0 => "RW",
        value if value == PAGE_WRITECOPY.0 => "WC",
        value if value == PAGE_EXECUTE.0 => "X",
        value if value == PAGE_EXECUTE_READ.0 => "RX",
        value if value == PAGE_EXECUTE_READWRITE.0 => "RWX",
        value if value == PAGE_EXECUTE_WRITECOPY.0 => "XWC",
        _ => "UNKNOWN",
    }
}

fn region_type_label(region_type: u32) -> &'static str {
    use windows::Win32::System::Memory::{MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE};

    match region_type {
        value if value == MEM_PRIVATE.0 => "private",
        value if value == MEM_IMAGE.0 => "image",
        value if value == MEM_MAPPED.0 => "mapped",
        _ => "other",
    }
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_handles_empty_and_uniform_data() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 16]), 0.0);
    }

    #[test]
    fn entropy_reports_high_diversity_data() {
        let bytes = (0u8..=255).collect::<Vec<_>>();
        assert_eq!(round2(shannon_entropy(&bytes)), 8.0);
    }
}

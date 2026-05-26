//! Memory scanner implementations

use crate::error::MemoricError;
use crate::memory::region_cache::{self, MemoryRegion};
use crate::runtime::RuntimeContext;
use crate::util::parse_address;
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

// Global scan state storage using Lazy for safe initialization
static SCAN_STATE: Lazy<Mutex<HashMap<u64, ScanSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
struct ScanSession {
    pid: u64,
    value_size: usize,
    addresses: Vec<(usize, Vec<u8>)>, // address -> value bytes
}

#[derive(Clone, Debug)]
struct StringScanMatch {
    address: usize,
    encoding: &'static str,
    value: String,
    length: usize,
}

// Constants for memory region types
const MEM_COMMIT: u32 = 0x1000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_IMAGE: u32 = 0x1000000;
const MEM_PRIVATE: u32 = 0x20000;
const PAGE_EXECUTE_BITS: u32 = 0x10;
const PAGE_READONLY_BITS: u32 = 0x02;
const PAGE_READWRITE_BITS: u32 = 0x04;
const PAGE_WRITECOPY_BITS: u32 = 0x08;
const PAGE_EXECUTE_READ_BITS: u32 = 0x20;
const PAGE_EXECUTE_READWRITE_BITS: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY_BITS: u32 = 0x80;
const PROTECT_WRITABLE: u32 =
    PAGE_READWRITE_BITS | PAGE_WRITECOPY_BITS | PAGE_EXECUTE_READWRITE_BITS | PAGE_EXECUTE_WRITECOPY_BITS;
const PROTECT_READABLE: u32 = PAGE_EXECUTE_BITS
    | PAGE_READONLY_BITS
    | PAGE_READWRITE_BITS
    | PAGE_WRITECOPY_BITS
    | PAGE_EXECUTE_READ_BITS
    | PAGE_EXECUTE_READWRITE_BITS
    | PAGE_EXECUTE_WRITECOPY_BITS;
const MAX_SCAN_READ_CHUNK: usize = 512 * 1024;

fn scanner_runtime(args: &Value) -> Result<RuntimeContext, MemoricError> {
    RuntimeContext::from_args(args).map_err(MemoricError::Other)
}

fn check_runtime(runtime: &RuntimeContext) -> Result<(), MemoricError> {
    runtime.check().map_err(MemoricError::Other)
}

struct ScannerProcessHandle {
    _guard: crate::handle_cache::RequestCacheGuard,
    handle: windows::Win32::Foundation::HANDLE,
}

impl ScannerProcessHandle {
    fn open_read(pid: u32, context: &str) -> Result<Self, MemoricError> {
        use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

        let guard = crate::handle_cache::ensure_request();
        let handle = crate::handle_cache::get_or_open(
            pid,
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("{}: {}", context, e)))?;

        Ok(Self {
            _guard: guard,
            handle,
        })
    }

    fn raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.handle
    }
}

#[derive(Clone, Debug)]
struct ScanRegionView {
    base: usize,
    size: usize,
    read_size: usize,
    protect: u32,
    region_type: u32,
}

fn clipped_region_view(region: &MemoryRegion, start_address: usize) -> Option<ScanRegionView> {
    let start = start_address as u64;
    let region_end = region.end_address();
    if region_end <= start {
        return None;
    }

    let base = region.base_address.max(start);
    let size = region_end.saturating_sub(base);
    if base > usize::MAX as u64 || size == 0 || size > usize::MAX as u64 {
        return None;
    }

    Some(ScanRegionView {
        base: base as usize,
        size: size as usize,
        read_size: size as usize,
        protect: region.protect,
        region_type: region.region_type,
    })
}

fn get_cached_scan_regions(
    pid: u64,
    args: &Value,
    start_address: usize,
    protect_mask: u32,
    exclude_mapped: bool,
    exclude_image: bool,
    module_regions: Option<&[(usize, usize)]>,
) -> Result<(Vec<ScanRegionView>, Value, u64), MemoricError> {
    region_cache::with_scannable_region_source(pid as u32, args, |cached_regions, report| {
        let mut regions = Vec::new();
        let mut skipped_regions = 0u64;

        for region in cached_regions {
            if !region.is_scannable() {
                continue;
            }

            let Some(view) = clipped_region_view(region, start_address) else {
                continue;
            };

            let is_target = region.state == MEM_COMMIT && (view.protect & protect_mask) != 0;
            let passes_type =
                is_target && should_scan_region(view.region_type, exclude_mapped, exclude_image);
            let passes_module = if let Some(module_regions) = module_regions {
                !module_regions.is_empty() && in_module_regions(view.base, view.size, module_regions)
            } else {
                true
            };

            if passes_type && passes_module {
                regions.push(view);
            } else if is_target {
                skipped_regions = skipped_regions.saturating_add(1);
            }
        }

        (regions, report.to_json(), skipped_regions)
    })
    .map_err(MemoricError::MemoryAccess)
}

/// Get module base address and size ranges for a named module in a process.
/// Returns Vec<(base, size)> for matching modules.
fn get_module_regions(
    handle: windows::Win32::Foundation::HANDLE,
    pid: u32,
    module_name: &str,
) -> Vec<(usize, usize)> {
    let target = module_name.to_lowercase();
    crate::module_cache::with_modules(handle, pid, |modules| {
        modules
            .iter()
            .filter_map(|module| {
                let name = module.name.to_lowercase();
                (name == target || name.contains(&target))
                    .then_some((module.base as usize, module.size as usize))
            })
            .collect()
    })
        .unwrap_or_default()
}

fn resolve_module_regions_with_handle(
    handle: windows::Win32::Foundation::HANDLE,
    pid: u32,
    module_name: Option<&str>,
) -> Option<Vec<(usize, usize)>> {
    module_name
        .map(|name| get_module_regions(handle, pid, name))
}

fn resolve_module_regions_for_scan(
    pid: u32,
    module_name: Option<&str>,
    context: &str,
) -> Result<Option<Vec<(usize, usize)>>, MemoricError> {
    let Some(name) = module_name else {
        return Ok(None);
    };

    let handle = ScannerProcessHandle::open_read(pid, context)?;
    Ok(Some(get_module_regions(handle.raw(), pid, name)))
}

/// Check if address falls within any of the module regions
fn in_module_regions(addr: usize, size: usize, regions: &[(usize, usize)]) -> bool {
    for &(base, mod_size) in regions {
        let mod_end = base + mod_size;
        let region_end = addr + size;
        // Region overlaps module if: addr < mod_end && region_end > base
        if addr < mod_end && region_end > base {
            return true;
        }
    }
    false
}

/// Check if a memory region should be scanned based on type filters
fn should_scan_region(region_type: u32, exclude_mapped: bool, exclude_image: bool) -> bool {
    if exclude_mapped && region_type == MEM_MAPPED {
        return false;
    }
    if exclude_image && region_type == MEM_IMAGE {
        return false;
    }
    true
}

// ── Parallel scan infrastructure ──────────────────────────────────────────

/// Default scan thread count when CPU detection is unavailable.
const DEFAULT_SCAN_THREADS: usize = 4;

/// Resolve the scan thread count from env or CPU count.
///
/// Priority: `MEMORIC_SCAN_THREADS` env var > `available_parallelism / 2` > `DEFAULT_SCAN_THREADS`.
/// Return value is always `>= 1`.
fn scan_thread_count() -> usize {
    std::env::var("MEMORIC_SCAN_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get() / 2)
                .unwrap_or(DEFAULT_SCAN_THREADS)
                .max(1)
        })
}

fn split_regions_by_size(regions: &[ScanRegionView], thread_count: usize) -> Vec<Vec<ScanRegionView>> {
    if regions.is_empty() || thread_count == 0 {
        return Vec::new();
    }

    let total_bytes = regions
        .iter()
        .map(|region| region.size as u64)
        .fold(0u64, u64::saturating_add);
    let worker_count = thread_count
        .min(total_bytes.min(usize::MAX as u64).max(1) as usize)
        .max(1);
    let target_bytes = total_bytes
        .saturating_add(worker_count as u64 - 1)
        .checked_div(worker_count as u64)
        .unwrap_or(1)
        .max(1);

    let mut chunks: Vec<Vec<ScanRegionView>> = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 0u64;

    for region in regions {
        let mut offset = 0usize;
        while offset < region.size {
            if current_bytes >= target_bytes
                && !current.is_empty()
                && chunks.len() + 1 < worker_count
            {
                chunks.push(current);
                current = Vec::new();
                current_bytes = 0;
            }

            let remaining = region.size - offset;
            let chunk_budget = if chunks.len() + 1 < worker_count {
                (target_bytes.saturating_sub(current_bytes).max(1)).min(usize::MAX as u64) as usize
            } else {
                remaining
            };
            let segment_size = remaining.min(chunk_budget).max(1);
            let base = region.base.saturating_add(offset);
            let read_size = region.read_size.saturating_sub(offset);

            current.push(ScanRegionView {
                base,
                size: segment_size,
                read_size,
                protect: region.protect,
                region_type: region.region_type,
            });
            current_bytes = current_bytes.saturating_add(segment_size as u64);
            offset = offset.saturating_add(segment_size);
        }
    }

    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

/// Process memory regions in parallel using `std::thread::scope`.
///
/// Each worker thread opens its own `OpenProcess` handle so there is zero
/// contention on a single kernel handle.  When `thread_count == 1` or when
/// only a single region needs scanning the function falls back to sequential
/// execution inside the calling thread.
///
/// The `per_thread` closure receives its chunk of regions, a fresh process
/// handle, and a shared `RuntimeContext` for cooperative cancellation.
/// Results from all threads are merged via the `reduce` function.
fn process_regions_parallel<F, R>(
    pid: u32,
    regions: &[ScanRegionView],
    runtime: &RuntimeContext,
    per_thread: F,
    reduce: fn(Vec<R>, Vec<R>) -> Vec<R>,
) -> Vec<R>
where
    F: Fn(&[ScanRegionView], windows::Win32::Foundation::HANDLE, &RuntimeContext) -> Vec<R> + Send + Sync + Copy,
    R: Send,
{
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let thread_count = scan_thread_count();

    // Fast path — no scope overhead when parallelism is pointless.
    if thread_count <= 1 || regions.is_empty() {
        let handle =
            unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid) };
        return match handle {
            Ok(h) => {
                let result = per_thread(regions, h, runtime);
                unsafe {
                    let _ = CloseHandle(h);
                }
                result
            }
            Err(_) => Vec::new(),
        };
    }

    let region_chunks = split_regions_by_size(regions, thread_count);

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for chunk_regions in region_chunks {
            handles.push(s.spawn(move || {
                let h = unsafe {
                    OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
                };
                match h {
                    Ok(handle) => {
                        let result = per_thread(&chunk_regions, handle, runtime);
                        unsafe {
                            let _ = CloseHandle(handle);
                        }
                        result
                    }
                    Err(_) => {
                        tracing::warn!(
                            "process_regions_parallel: OpenProcess failed pid={} in worker",
                            pid
                        );
                        Vec::new()
                    }
                }
            }));
        }

        let mut all_results: Vec<R> = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(thread_results) => {
                    all_results = reduce(all_results, thread_results);
                }
                Err(_) => {
                    tracing::warn!("process_regions_parallel: worker thread panicked");
                }
            }
        }
        all_results
    })
}

fn scan_region_chunks<F>(
    handle: windows::Win32::Foundation::HANDLE,
    region: &ScanRegionView,
    overlap: usize,
    mut scan_chunk: F,
) where
    F: FnMut(usize, &[u8], usize),
{
    let overlap = overlap.min(MAX_SCAN_READ_CHUNK.saturating_sub(1));
    let mut offset = 0usize;

    while offset < region.size {
        let requested = (region.size - offset).min(MAX_SCAN_READ_CHUNK);
        let readable_remaining = region.read_size.saturating_sub(offset);
        if readable_remaining == 0 {
            break;
        }
        let read_size = requested
            .saturating_add(if requested < readable_remaining {
                overlap
            } else {
                0
            })
            .min(readable_remaining);
        let read_base = region.base.saturating_add(offset);
        let mut buffer = vec![0u8; read_size];
        let mut bytes_read = 0usize;
        let read_ok = unsafe {
            ReadProcessMemory(
                handle,
                read_base as *const _,
                buffer.as_mut_ptr() as *mut _,
                read_size,
                Some(&mut bytes_read as *mut _),
            )
        };

        if read_ok.is_ok() && bytes_read > 0 {
            let unique_len = requested.min(bytes_read);
            buffer.truncate(bytes_read);
            scan_chunk(read_base, &buffer, unique_len);
        }

        offset = offset.saturating_add(requested);
    }
}

fn scan_search_end(buffer_len: usize, needle_len: usize) -> usize {
    if needle_len == 0 || buffer_len < needle_len {
        0
    } else {
        buffer_len - needle_len + 1
    }
}

fn scan_chunk_search_end(buffer_len: usize, needle_len: usize, unique_len: usize) -> usize {
    scan_search_end(buffer_len, needle_len).min(unique_len)
}

/// Concatenate two address lists (used by `find_pattern`).
fn reduce_addresses(mut a: Vec<usize>, b: Vec<usize>) -> Vec<usize> {
    a.extend(b);
    a
}

/// Concatenate two string scan match lists (used by `scan_string`).
fn reduce_string_matches(
    mut a: Vec<StringScanMatch>,
    b: Vec<StringScanMatch>,
) -> Vec<StringScanMatch> {
    a.extend(b);
    a
}

/// Concatenate two scan match lists (used by `scan_exact`, `scan_range`).
fn reduce_pairs(
    mut a: Vec<(usize, Vec<u8>)>,
    b: Vec<(usize, Vec<u8>)>,
) -> Vec<(usize, Vec<u8>)> {
    a.extend(b);
    a
}

fn address_page_from_scan_data(
    scan_data: &[(usize, Vec<u8>)],
    offset: usize,
    limit: usize,
) -> Vec<String> {
    scan_data
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(addr, _)| format!("0x{:016X}", addr))
        .collect()
}

fn address_page_from_addresses(addresses: &[usize], offset: usize, limit: usize) -> Vec<String> {
    addresses
        .iter()
        .skip(offset)
        .take(limit)
        .map(|addr| format!("0x{:016X}", *addr))
        .collect()
}

fn scan_data_result_page(scan_data: &[(usize, Vec<u8>)], offset: usize, limit: usize) -> Vec<Value> {
    scan_data
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(addr, bytes)| {
            serde_json::json!({
                "address": format!("0x{:016X}", addr),
                "hex": hex::encode(bytes)
            })
        })
        .collect()
}

fn string_scan_result_page(
    results: &[StringScanMatch],
    offset: usize,
    limit: usize,
) -> Vec<Value> {
    results
        .iter()
        .skip(offset)
        .take(limit)
        .map(|result| {
            serde_json::json!({
                "address": format!("0x{:016X}", result.address),
                "encoding": result.encoding,
                "value": result.value,
                "length": result.length
            })
        })
        .collect()
}

fn bytes_to_spaced_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    if bytes.is_empty() {
        return String::new();
    }

    let mut output = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}


/// Scan for exact values
pub fn scan_exact(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let value = args
        .get("value")
        .ok_or_else(|| MemoricError::MemoryAccess("Missing value".to_string()))?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing scan_type".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    // Region type filters (default: skip mapped + image, only scan private)
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    tracing::info!("Scanning process {} for {:?} ({}) timeout={}s start=0x{:X} exclude_mapped={} exclude_image={}", pid, value, scan_type, timeout_secs, start_address, exclude_mapped, exclude_image);
    check_runtime(&runtime)?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // Determine value size for state storage
    let value_size = match scan_type {
        "int" => 4,
        "float" => 4,
        "string" => value.as_str().map(|s| s.len()).unwrap_or(0),
        "bytes" => value.as_array().map(|a| a.len()).unwrap_or(0),
        _ => 4,
    };

    let module_regions =
        resolve_module_regions_for_scan(pid as u32, module_name, "Failed to open process")?;
    let (scan_regions, region_cache_report, skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        start_address,
        PROTECT_READABLE,
        exclude_mapped,
        exclude_image,
        module_regions.as_deref(),
    )?;

    // ── Parallel region scan ──
    let scanned_bytes_sc = std::sync::atomic::AtomicU64::new(0u64);
    let timed_out_sc = std::sync::atomic::AtomicBool::new(false);

        let batch_results: Vec<(usize, Vec<u8>)> = process_regions_parallel(
            pid as u32,
            &scan_regions,
            &runtime,
            |chunk, handle, rt| {
                let mut results = Vec::new();
                for region in chunk {
                    if check_runtime(rt).is_err() {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        timed_out_sc.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    scan_region_chunks(handle, region, value_size.saturating_sub(1), |addr, buffer, unique_len| {
                        scanned_bytes_sc.fetch_add(unique_len as u64, std::sync::atomic::Ordering::Relaxed);

                        match scan_type {
                            "int" => {
                                if let Some(val) = value.as_i64() {
                                    let bytes = (val as i32).to_ne_bytes();
                                    for i in 0..scan_chunk_search_end(buffer.len(), 4, unique_len) {
                                        if i % 4096 == 0 && check_runtime(rt).is_err() {
                                            break;
                                        }
                                        if buffer[i..i + 4] == bytes[..] {
                                            let found_addr = addr + i;
                                            results.push((
                                                found_addr,
                                                buffer[i..i + 4].to_vec(),
                                            ));
                                        }
                                    }
                                }
                            }
                            "float" => {
                                if let Some(val) = value.as_f64() {
                                    let bytes = (val as f32).to_ne_bytes();
                                    for i in 0..scan_chunk_search_end(buffer.len(), 4, unique_len) {
                                        if i % 4096 == 0 && check_runtime(rt).is_err() {
                                            break;
                                        }
                                        if buffer[i..i + 4] == bytes[..] {
                                            let found_addr = addr + i;
                                            results.push((
                                                found_addr,
                                                buffer[i..i + 4].to_vec(),
                                            ));
                                        }
                                    }
                                }
                            }
                            "string" => {
                                if let Some(val) = value.as_str() {
                                    let bytes = val.as_bytes();
                                    for i in 0..scan_chunk_search_end(buffer.len(), bytes.len(), unique_len) {
                                        if i % 4096 == 0 && check_runtime(rt).is_err() {
                                            break;
                                        }
                                        if buffer[i..i + bytes.len()] == bytes[..] {
                                            let found_addr = addr + i;
                                            results.push((
                                                found_addr,
                                                buffer[i..i + bytes.len()].to_vec(),
                                            ));
                                        }
                                    }
                                }
                            }
                            "bytes" => {
                                if let Some(byte_array) = value.as_array() {
                                    let pattern: Vec<u8> = byte_array
                                        .iter()
                                        .filter_map(|v| v.as_u64().map(|b| b as u8))
                                        .collect();
                                    for i in 0..scan_chunk_search_end(buffer.len(), pattern.len(), unique_len) {
                                        if i % 4096 == 0 && check_runtime(rt).is_err() {
                                            break;
                                        }
                                        if buffer[i..i + pattern.len()] == pattern[..] {
                                            let found_addr = addr + i;
                                            results.push((
                                                found_addr,
                                                buffer[i..i + pattern.len()].to_vec(),
                                            ));
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    });
                }
                results
            },
            reduce_pairs,
        );

        let session_data: Vec<(usize, Vec<u8>)> = batch_results;

        let timed_out =
            timed_out_sc.load(std::sync::atomic::Ordering::Relaxed) || runtime.check().is_err();
        let last_address = 0usize;
        let scanned_bytes = scanned_bytes_sc.load(std::sync::atomic::Ordering::Relaxed);
        let total_count = session_data.len();
        let paginated = address_page_from_scan_data(&session_data, offset, limit);

        // Store scan state for scan_changed
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size,
                    addresses: session_data,
                },
            );
        }

        tracing::info!(
            "Found {} addresses, stored in scan state (timed_out={}, skipped={})",
            total_count,
            timed_out,
            skipped_regions
        );

    Ok(serde_json::json!({
        "addresses": paginated,
        "count": paginated.len(),
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + paginated.len() < total_count,
        "timed_out": timed_out,
        "last_address": format!("0x{:016X}", last_address),
        "scanned_bytes": scanned_bytes,
        "skipped_regions": skipped_regions,
        "region_cache": region_cache_report,
        "filters": {
            "exclude_mapped": exclude_mapped,
            "exclude_image": exclude_image,
            "module_name": module_name
        }
    }))
}

/// Scan for changed values
pub fn scan_changed(args: &Value) -> Result<Value, MemoricError> {
        use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let _handle_cache_guard = crate::handle_cache::ensure_request();
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let change = args
        .get("change")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing change".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::info!("Scanning process {} for {} values", pid, change);
    check_runtime(&runtime)?;

    // Get previous scan results
    let prev_session = {
        let state = SCAN_STATE
            .lock()
            .map_err(|_| MemoricError::MemoryAccess("Failed to lock state".to_string()))?;
        state
            .get(&pid)
            .ok_or_else(|| {
                MemoricError::MemoryAccess(
                    "No previous scan found. Run scan_exact first.".to_string(),
                )
            })?
            .clone()
    };

    // Group addresses by page for batch reads (reduces kernel calls from N to ~N/64)
    const PAGE: usize = 0x1000;
    let mut page_groups: HashMap<usize, Vec<(usize, &[u8])>> = HashMap::new();
    for (addr, old_value) in &prev_session.addresses {
        let page_base = *addr & !(PAGE - 1);
        page_groups
            .entry(page_base)
            .or_default()
            .push((*addr, old_value.as_slice()));
    }
    let mut page_keys: Vec<usize> = page_groups.keys().copied().collect();
    page_keys.sort_unstable();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid as u32,
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0,
        )
        .map_err(|e| MemoricError::MemoryAccess(e))?;

        let mut new_session_data = Vec::new();

        for page_base in &page_keys {
            check_runtime(&runtime)?;
            let entries = &page_groups[page_base];
            let mut page_buf = vec![0u8; PAGE];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                handle,
                *page_base as *const _,
                page_buf.as_mut_ptr() as *mut _,
                PAGE,
                Some(&mut bytes_read as *mut _),
            )
            .is_ok()
            {
                for (addr, old_value) in entries {
                    let offset = addr & (PAGE - 1);
                    if offset + old_value.len() <= bytes_read {
                        let new_value = &page_buf[offset..offset + old_value.len()];
                        let changed = match change {
                            "increased" => new_value > *old_value,
                            "decreased" => new_value < *old_value,
                            "changed" => new_value != *old_value,
                            "unchanged" => new_value == *old_value,
                            _ => false,
                        };
                        if changed {
                            new_session_data.push((*addr, new_value.to_vec()));
                        }
                    }
                }
            }
        }

        let total_count = new_session_data.len();
        let paginated = address_page_from_scan_data(&new_session_data, offset, limit);

        // Update scan state with filtered results
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size: prev_session.value_size,
                    addresses: new_session_data,
                },
            );
        }

        tracing::info!("Found {} {} addresses", total_count, change);

        Ok(serde_json::json!({
            "addresses": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "change_type": change,
            "offset": offset,
            "limit": limit,
            "has_more": offset + paginated.len() < total_count
        }))
    }
}

/// Scan for unknown values (first scan) - scans all readable memory
pub fn scan_unknown(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;

    // Region type filters
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    tracing::info!(
        "Unknown scan for process {} exclude_mapped={} exclude_image={}",
        pid,
        exclude_mapped,
        exclude_image
    );
    check_runtime(&runtime)?;

    let module_regions =
        resolve_module_regions_for_scan(pid as u32, module_name, "Failed to open process")?;
    let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        0,
        PROTECT_READABLE,
        exclude_mapped,
        exclude_image,
        module_regions.as_deref(),
    )?;

    let mut regions = Vec::new();
    let mut total_readable = 0u64;

    for region in scan_regions {
        check_runtime(&runtime)?;
        regions.push(json!({
            "base_address": format!("0x{:016X}", region.base),
            "size": region.size,
            "protect": region.protect,
            "type": region.region_type
        }));
        total_readable += region.size as u64;
    }

    tracing::info!(
        "Unknown scan found {} readable regions, {} bytes total",
        regions.len(),
        total_readable
    );

    Ok(serde_json::json!({
        "regions": regions,
        "count": regions.len(),
        "total_readable_bytes": total_readable,
        "region_cache": region_cache_report,
        "message": "Use scan_changed after modifying values to find what changed",
        "filters": {
            "exclude_mapped": exclude_mapped,
            "exclude_image": exclude_image,
            "module_name": module_name
        }
    }))
}

/// Pattern scan (AOB) - scans ALL readable memory including code and headers
pub fn find_pattern(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let signature = args
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing signature".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset_param = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    // Region type filters (find_pattern defaults to false since AOB commonly targets code)
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    tracing::info!("Scanning process {} for pattern '{}'", pid, signature);
    check_runtime(&runtime)?;

    let pattern = parse_find_pattern_signature(signature)?;

    if pattern.is_empty() {
        return Err(MemoricError::MemoryAccess("Invalid pattern".to_string()));
    }

    let module_regions =
        resolve_module_regions_for_scan(pid as u32, module_name, "Failed to open process")?;
    let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        0,
        PROTECT_READABLE,
        exclude_mapped,
        exclude_image,
        module_regions.as_deref(),
    )?;

    // ── Parallel region scan ──
    let addresses: Vec<usize> = process_regions_parallel(
            pid as u32,
            &scan_regions,
            &runtime,
            |chunk, handle, rt| {
                let mut addrs = Vec::new();
                for region in chunk {
                    if check_runtime(rt).is_err() {
                        break;
                    }
                    scan_region_chunks(handle, region, pattern.len().saturating_sub(1), |addr, buffer, unique_len| {
                        for i in 0..scan_chunk_search_end(buffer.len(), pattern.len(), unique_len) {
                            if i % 4096 == 0 && check_runtime(rt).is_err() {
                                break;
                            }
                            let matched = pattern.iter().enumerate().all(|(j, &expected)| {
                                expected.is_none() || buffer[i + j] == expected.unwrap()
                            });
                            if matched {
                                addrs.push(addr + i);
                            }
                        }
                    });
                }
                addrs
            },
            reduce_addresses,
        );

                tracing::info!("Found {} addresses", addresses.len());

        let total_count = addresses.len();
        let paginated = address_page_from_addresses(&addresses, offset_param, limit);

    Ok(serde_json::json!({
        "addresses": paginated,
        "count": paginated.len(),
        "total_count": total_count,
        "offset": offset_param,
        "limit": limit,
        "has_more": offset_param + paginated.len() < total_count,
        "region_cache": region_cache_report
    }))
}

fn parse_find_pattern_signature(signature: &str) -> Result<Vec<Option<u8>>, MemoricError> {
    let mut pattern = Vec::new();
    for token in signature.split_whitespace() {
        if token == "??" || token == "?" {
            pattern.push(None);
        } else {
            pattern.push(Some(parse_signature_hex_byte(token)?));
        }
    }
    Ok(pattern)
}

fn parse_signature_hex_byte(token: &str) -> Result<u8, MemoricError> {
    let mut value = 0u16;
    let mut saw_digit = false;
    for byte in token.bytes() {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => {
                return Err(MemoricError::MemoryAccess(format!(
                    "Invalid hex byte: {}",
                    token
                )));
            }
        };
        saw_digit = true;
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(nibble as u16))
            .ok_or_else(|| {
                MemoricError::MemoryAccess(format!("Invalid hex byte: {}", token))
            })?;
        if value > u8::MAX as u16 {
            return Err(MemoricError::MemoryAccess(format!(
                "Invalid hex byte: {}",
                token
            )));
        }
    }

    if !saw_digit {
        return Err(MemoricError::MemoryAccess("Invalid hex byte: ".to_string()));
    }
    Ok(value as u8)
}

/// Pointer scan - find pointers that point to a target address
pub fn pointer_scan(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let target_address = args
        .get("target_address")
        .and_then(parse_address)
        .ok_or_else(|| MemoricError::MemoryAccess("Missing target_address".to_string()))?;
    let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(3) as usize;
    let uses_pagination = args.get("limit").is_some() || args.get("offset").is_some();
    let limit = if uses_pagination {
        args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize
    } else {
        usize::MAX
    };
    let offset = if uses_pagination {
        args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize
    } else {
        0
    };

    tracing::info!(
        "Pointer scan for target 0x{:016X}, max depth {}",
        target_address,
        max_depth
    );
    check_runtime(&runtime)?;

    let handle = ScannerProcessHandle::open_read(pid as u32, "Failed to open process")?;

    let mut pointers = Vec::new();
    let mut total_count = 0usize;
    let pointer_size: usize = 8; // x64
    let (scan_regions, region_cache_report, _skipped_regions) =
        get_cached_scan_regions(pid, args, 0, PROTECT_WRITABLE, false, false, None)?;

    for region in scan_regions {
        check_runtime(&runtime)?;
        scan_region_chunks(handle.raw(), &region, pointer_size.saturating_sub(1), |addr, buffer, unique_len| {
                for i in (0..scan_chunk_search_end(buffer.len(), pointer_size, unique_len)).step_by(pointer_size) {
                    if i % 4096 == 0 && check_runtime(&runtime).is_err() {
                        break;
                    }
                    let ptr_value =
                        u64::from_ne_bytes(buffer[i..i + 8].try_into().unwrap_or([0; 8]));

                    if ptr_value == target_address {
                        if !uses_pagination || (total_count >= offset && pointers.len() < limit) {
                            pointers.push(addr + i);
                        }
                        total_count += 1;
                    }
                }
            });
    }

    let paginated = address_page_from_addresses(&pointers, 0, pointers.len());
    let mut response = serde_json::json!({
        "target_address": format!("0x{:016X}", target_address),
        "pointers": paginated,
        "count": paginated.len(),
        "max_depth": max_depth,
        "region_cache": region_cache_report
    });
    if uses_pagination {
        response["total_count"] = serde_json::json!(total_count);
        response["offset"] = serde_json::json!(offset);
        response["limit"] = serde_json::json!(limit);
        response["has_more"] = serde_json::json!(offset.saturating_add(paginated.len()) < total_count);
    }
    Ok(response)
}

/// IDA-style pattern scan with advanced wildcard support
/// Supports: "45 8B ?? ?? 48 89" — ?? is wildcard byte
/// Supports: "45 8B ?0 4? 48 89" — nibble wildcards using ?
/// Returns addresses + context bytes around each match
pub fn ida_pattern_scan(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let pattern_str = args
        .get("pattern")
        .or_else(|| args.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pattern/signature".to_string()))?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
    let context_bytes = args
        .get("context_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(16) as usize;
    let module_name = args.get("module_name").and_then(|v| v.as_str());
    let start_addr = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);

    tracing::info!(
        "[SCAN] IDA pattern scan pid={} pattern='{}'",
        pid,
        pattern_str
    );
    check_runtime(&runtime)?;

    // Parse IDA pattern: supports ?? for wildcard byte, ?X and X? for nibble wildcards
    let parsed = parse_ida_pattern(pattern_str)?;
    if parsed.is_empty() {
        return Err(MemoricError::MemoryAccess("Empty pattern".to_string()));
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    let handle = ScannerProcessHandle::open_read(pid as u32, "OpenProcess")?;

    let module_regions = resolve_module_regions_with_handle(handle.raw(), pid as u32, module_name);
    let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        start_addr,
        PROTECT_READABLE,
        false,
        false,
        module_regions.as_deref(),
    )?;

    let mut matches: Vec<serde_json::Value> = Vec::new();
    let mut timed_out = false;
    let mut scanned_bytes = 0u64;

    for region in scan_regions {
        check_runtime(&runtime)?;
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        if matches.len() >= limit {
            break;
        }

        scan_region_chunks(handle.raw(), &region, parsed.len().saturating_sub(1), |addr, buffer, unique_len| {
                    scanned_bytes += unique_len as u64;

                    for i in 0..scan_chunk_search_end(buffer.len(), parsed.len(), unique_len) {
                        if i % 4096 == 0 {
                            if check_runtime(&runtime).is_err() {
                                break;
                            }
                        }
                        if ida_match(&buffer[i..], &parsed) {
                            let found_addr = addr + i;
                            // Extract context
                            let ctx_start = i.saturating_sub(context_bytes);
                            let ctx_end = (i + parsed.len() + context_bytes).min(buffer.len());
                            let context = &buffer[ctx_start..ctx_end];
                            let matched = &buffer[i..i + parsed.len()];

                            matches.push(serde_json::json!({
                                "address": format!("0x{:016X}", found_addr),
                                "matched_hex": bytes_to_spaced_hex(matched),
                                "context_hex": bytes_to_spaced_hex(context),
                                "context_offset": i - ctx_start,
                            }));

                            if matches.len() >= limit {
                                break;
                            }
                        }
                    }
        });
    }

    Ok(serde_json::json!({
        "success": true,
        "technique": "ida_pattern_scan",
        "pattern": pattern_str,
        "matches": matches,
        "count": matches.len(),
        "scanned_bytes": scanned_bytes,
        "timed_out": timed_out,
        "region_cache": region_cache_report,
        "message": format!("Found {} matches for pattern '{}'", matches.len(), pattern_str)
    }))
}

/// BYOVD stealth pattern scan — scans process memory via kernel driver, bypassing all usermode hooks
pub fn stealth_pattern_scan(args: &Value) -> Result<Value, MemoricError> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let pattern_str = args
        .get("pattern")
        .or_else(|| args.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pattern/signature".to_string()))?;
    let device_path = args
        .get("device_path")
        .and_then(|v| v.as_str())
        .unwrap_or("\\\\.\\RTCore64");
    let read_ioctl = args
        .get("read_ioctl")
        .and_then(|v| v.as_u64())
        .unwrap_or(0x80002048) as u32;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;

    tracing::warn!(
        "[STEALTH] BYOVD pattern scan pid={} pattern='{}' via {}",
        pid,
        pattern_str,
        device_path
    );
    check_runtime(&runtime)?;

    let parsed = parse_ida_pattern(pattern_str)?;
    if parsed.is_empty() {
        return Err(MemoricError::MemoryAccess("Empty pattern".to_string()));
    }

    let _ = crate::privilege::enable_debug_privilege(&serde_json::json!({}));

    unsafe {
        // Open driver for reading
        let dev_w: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let driver_handle = CreateFileW(
            PCWSTR(dev_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .map_err(|e| MemoricError::WindowsApi(format!("Cannot open driver: {}", e)))?;

        let (scan_regions, region_cache_report, _skipped_regions) =
            get_cached_scan_regions(pid, args, 0, PROTECT_READABLE, false, false, None)?;
        let mut matches: Vec<serde_json::Value> = Vec::new();
        let mut scanned_bytes = 0u64;

        for region in scan_regions {
            check_runtime(&runtime)?;
            if matches.len() >= limit {
                break;
            }
            if region.size > 16 * 1024 * 1024 {
                continue;
            }

            {
                let addr = region.base;
                // Read via driver in chunks
                let mut buffer = vec![0u8; region.size];
                let mut read_ok = true;

                for offset in (0..region.size).step_by(8) {
                    if offset % 4096 == 0 {
                        check_runtime(&runtime)?;
                    }
                    let remaining = (region.size - offset).min(8);
                    let target = (addr + offset) as u64;

                    #[repr(C, packed)]
                    struct Req {
                        address: u64,
                        _r: u32,
                        size: u32,
                    }
                    let req = Req {
                        address: target,
                        _r: 0,
                        size: remaining as u32,
                    };
                    let mut out = [0u8; 64];
                    let mut br = 0u32;

                    if DeviceIoControl(
                        driver_handle,
                        read_ioctl,
                        Some(&req as *const _ as *const _),
                        std::mem::size_of::<Req>() as u32,
                        Some(out.as_mut_ptr() as *mut _),
                        out.len() as u32,
                        Some(&mut br),
                        None,
                    )
                    .is_ok()
                        && br > 0
                    {
                        let n = remaining.min(br as usize);
                        buffer[offset..offset + n].copy_from_slice(&out[..n]);
                    } else {
                        read_ok = false;
                        break;
                    }
                }

                if read_ok {
                    scanned_bytes += region.size as u64;
                    for i in 0..scan_search_end(buffer.len(), parsed.len()) {
                        if i % 4096 == 0 {
                            check_runtime(&runtime)?;
                        }
                        if ida_match(&buffer[i..], &parsed) {
                            matches.push(serde_json::json!({
                                "address": format!("0x{:016X}", addr + i),
                                "matched_hex": bytes_to_spaced_hex(&buffer[i..i+parsed.len()]),
                            }));
                            if matches.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(driver_handle);

        Ok(serde_json::json!({
            "success": true,
            "technique": "stealth_pattern_scan",
            "driver": device_path,
            "pattern": pattern_str,
            "matches": matches,
            "count": matches.len(),
            "scanned_bytes": scanned_bytes,
            "region_cache": region_cache_report,
            "message": format!("BYOVD stealth scan found {} matches", matches.len())
        }))
    }
}

/// Parse IDA-style pattern string into pattern elements
/// Supports: "45 8B ?? 48" (full byte wildcard), "4? 8B ?0 48" (nibble wildcard)
#[derive(Clone, Debug)]
enum PatternByte {
    Exact(u8),
    Wildcard,
    NibbleMask { value: u8, mask: u8 }, // match = (byte & mask) == value
}

fn parse_ida_pattern(pattern_str: &str) -> Result<Vec<PatternByte>, MemoricError> {
    let mut result = Vec::new();
    for token in pattern_str.split_whitespace() {
        if token == "??" || token == "?" {
            result.push(PatternByte::Wildcard);
        } else if token.len() == 2 {
            let bytes = token.as_bytes();
            let hi_wild = bytes[0] == b'?';
            let lo_wild = bytes[1] == b'?';

            if hi_wild && lo_wild {
                result.push(PatternByte::Wildcard);
            } else if hi_wild {
                // ?X — match low nibble only
                let lo = parse_pattern_nibble(bytes[1], token)?;
                result.push(PatternByte::NibbleMask {
                    value: lo,
                    mask: 0x0F,
                });
            } else if lo_wild {
                // X? — match high nibble only
                let hi = parse_pattern_nibble(bytes[0], token)?;
                result.push(PatternByte::NibbleMask {
                    value: hi << 4,
                    mask: 0xF0,
                });
            } else {
                let byte = u8::from_str_radix(token, 16).map_err(|_| {
                    MemoricError::MemoryAccess(format!("Invalid hex byte: {}", token))
                })?;
                result.push(PatternByte::Exact(byte));
            }
        } else {
            return Err(MemoricError::MemoryAccess(format!(
                "Invalid pattern token: {}",
                token
            )));
        }
    }
    Ok(result)
}

fn parse_pattern_nibble(byte: u8, token: &str) -> Result<u8, MemoricError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(MemoricError::MemoryAccess(format!(
            "Invalid pattern byte: {}",
            token
        ))),
    }
}

fn ida_match(data: &[u8], pattern: &[PatternByte]) -> bool {
    if data.len() < pattern.len() {
        return false;
    }
    for (i, p) in pattern.iter().enumerate() {
        match p {
            PatternByte::Exact(expected) => {
                if data[i] != *expected {
                    return false;
                }
            }
            PatternByte::Wildcard => {}
            PatternByte::NibbleMask { value, mask } => {
                if data[i] & mask != *value {
                    return false;
                }
            }
        }
    }
    true
}

/// Scan for values within a range [min, max]
pub fn scan_range(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("int");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    let min_val = args
        .get("min")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing min".to_string()))?;
    let max_val = args
        .get("max")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing max".to_string()))?;

    tracing::info!(
        "[MEMORY] scan_range pid={} type={} min={} max={}",
        pid,
        scan_type,
        min_val,
        max_val
    );
    check_runtime(&runtime)?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    let module_regions =
        resolve_module_regions_for_scan(pid as u32, module_name, "OpenProcess failed")?;
    let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        start_address,
        PROTECT_READABLE,
        exclude_mapped,
        exclude_image,
        module_regions.as_deref(),
    )?;

    // ── Parallel region scan ──
    let timed_out_sc = std::sync::atomic::AtomicBool::new(false);

        let batch_results: Vec<(usize, Vec<u8>)> = process_regions_parallel(
            pid as u32,
            &scan_regions,
            &runtime,
            |chunk, handle, rt| {
                let mut results = Vec::new();
                for region in chunk {
                    if check_runtime(rt).is_err() {
                        break;
                    }
                    if std::time::Instant::now() >= deadline {
                        timed_out_sc.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    scan_region_chunks(handle, region, 3, |addr, buffer, unique_len| {
                        for i in 0..scan_chunk_search_end(buffer.len(), 4, unique_len) {
                            if i % 4096 == 0 && check_runtime(rt).is_err() {
                                break;
                            }
                            let in_range = match scan_type {
                                "int" => {
                                    let v = i32::from_ne_bytes([
                                        buffer[i],
                                        buffer[i + 1],
                                        buffer[i + 2],
                                        buffer[i + 3],
                                    ]) as f64;
                                    v >= min_val && v <= max_val
                                }
                                "float" => {
                                    let v = f32::from_ne_bytes([
                                        buffer[i],
                                        buffer[i + 1],
                                        buffer[i + 2],
                                        buffer[i + 3],
                                    ]) as f64;
                                    v.is_finite() && v >= min_val && v <= max_val
                                }
                                _ => false,
                            };
                            if in_range {
                                let found_addr = addr + i;
                                results.push((
                                    found_addr,
                                    buffer[i..i + 4].to_vec(),
                                ));
                            }
                        }
                    });
                }
                results
            },
            reduce_pairs,
        );

        let session_data: Vec<(usize, Vec<u8>)> = batch_results;

        let timed_out =
            timed_out_sc.load(std::sync::atomic::Ordering::Relaxed) || runtime.check().is_err();
        let last_address = 0usize;
        let total_count = session_data.len();
        let paginated = address_page_from_scan_data(&session_data, offset, limit);

                if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size: 4,
                    addresses: session_data,
                },
            );
        }

    Ok(serde_json::json!({
        "addresses": paginated,
        "count": paginated.len(),
        "total_count": total_count,
        "offset": offset,
        "limit": limit,
        "has_more": offset + paginated.len() < total_count,
        "timed_out": timed_out,
        "last_address": format!("0x{:016X}", last_address),
        "scan_type": scan_type,
        "region_cache": region_cache_report,
        "range": { "min": min_val, "max": max_val }
    }))
}

/// Scan for values that changed by a specific delta from previous scan
pub fn scan_delta(args: &Value) -> Result<Value, MemoricError> {
        use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let _handle_cache_guard = crate::handle_cache::ensure_request();
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let delta = args
        .get("delta")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing delta".to_string()))?;
    let direction = args
        .get("direction")
        .and_then(|v| v.as_str())
        .unwrap_or("increased_by");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    tracing::info!(
        "[MEMORY] scan_delta pid={} delta={} direction={}",
        pid,
        delta,
        direction
    );
    check_runtime(&runtime)?;

    let session = {
        let state = SCAN_STATE
            .lock()
            .map_err(|e| MemoricError::MemoryAccess(format!("Lock failed: {}", e)))?;
        state.get(&pid).cloned().ok_or_else(|| {
            MemoricError::MemoryAccess(
                "No previous scan for this PID. Run scan_exact or scan_range first.".to_string(),
            )
        })?
    };

    // Group addresses by page for batch reads (reduces kernel calls from N to ~N/64)
    const PAGE: usize = 0x1000;
    let mut page_groups: HashMap<usize, Vec<(usize, &[u8])>> = HashMap::new();
    for (addr, old_bytes) in &session.addresses {
        let page_base = *addr & !(PAGE - 1);
        page_groups
            .entry(page_base)
            .or_default()
            .push((*addr, old_bytes.as_slice()));
    }
    let mut page_keys: Vec<usize> = page_groups.keys().copied().collect();
    page_keys.sort_unstable();

    unsafe {
        let handle = crate::handle_cache::get_or_open(
            pid as u32,
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0,
        )
        .map_err(|e| MemoricError::MemoryAccess(e))?;

        let mut paginated = Vec::new();
        let mut total_count = 0usize;
        let mut new_session_data: Vec<(usize, Vec<u8>)> = Vec::new();

        for page_base in &page_keys {
            check_runtime(&runtime)?;
            let entries = &page_groups[page_base];
            let mut page_buf = vec![0u8; PAGE];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                handle,
                *page_base as *const _,
                page_buf.as_mut_ptr() as *mut _,
                PAGE,
                Some(&mut bytes_read as *mut _),
            )
            .is_ok()
            {
                let vs = session.value_size;
                for (addr, old_bytes) in entries {
                    let offset = addr & (PAGE - 1);
                    if offset + vs <= bytes_read {
                        let new_buf = page_buf[offset..offset + vs].to_vec();
                        let old_val = if vs == 4 {
                            i32::from_ne_bytes([
                                old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3],
                            ]) as f64
                        } else {
                            0.0
                        };
                        let new_val = if vs == 4 {
                            i32::from_ne_bytes([
                                new_buf[0], new_buf[1], new_buf[2], new_buf[3],
                            ]) as f64
                        } else {
                            0.0
                        };
                        let actual_delta = new_val - old_val;

                        let matched = match direction {
                            "increased_by" => (actual_delta - delta).abs() < 0.001,
                            "decreased_by" => (actual_delta + delta).abs() < 0.001,
                            _ => false,
                        };

                        if matched {
                            if total_count >= offset && paginated.len() < limit {
                                paginated.push(serde_json::json!({
                                    "address": format!("0x{:016X}", addr),
                                    "old_value": old_val as i64,
                                    "new_value": new_val as i64,
                                    "delta": actual_delta as i64
                                }));
                            }
                            total_count += 1;
                            new_session_data.push((*addr, new_buf));
                        }
                    }
                }
            }
        }

        // Update scan state with narrowed results
        if let Ok(mut state) = SCAN_STATE.lock() {
            state.insert(
                pid,
                ScanSession {
                    pid,
                    value_size: session.value_size,
                    addresses: new_session_data,
                },
            );
        }

        Ok(serde_json::json!({
            "matches": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "direction": direction,
            "delta": delta
        }))
    }
}

/// Dedicated string scanner with ANSI/Unicode support and wildcard matching
pub fn scan_string(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let pattern = args
        .get("pattern")
        .or_else(|| args.get("signature"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pattern/signature".to_string()))?;
    let encoding = args
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("both");
    let case_insensitive = args
        .get("case_insensitive")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::info!(
        "[MEMORY] scan_string pid={} pattern='{}' encoding={} case_insensitive={}",
        pid,
        pattern,
        encoding,
        case_insensitive
    );
    check_runtime(&runtime)?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    let search_pattern = if case_insensitive {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };

    // Build search patterns for different encodings
    let ansi_pattern: Vec<u8> = search_pattern.as_bytes().to_vec();
    let unicode_pattern: Vec<u8> = search_pattern
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

        // ── Parallel region scan ──
        let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
            pid,
            args,
            0,
            PROTECT_READABLE,
            exclude_mapped,
            exclude_image,
            None,
        )?;

        let string_overlap = ansi_pattern
            .len()
            .max(unicode_pattern.len())
            .saturating_sub(1)
            .saturating_add(512);

        let results: Vec<StringScanMatch> = process_regions_parallel(
            pid as u32,
            &scan_regions,
            &runtime,
            |chunk, handle, rt| {
                let mut results: Vec<StringScanMatch> = Vec::new();
                for region in chunk {
                    if check_runtime(rt).is_err() {
                        break;
                    }
                    scan_region_chunks(handle, region, string_overlap, |addr, buffer, unique_len| {
                        // ANSI search
                        if encoding == "ansi" || encoding == "both" {
                            let search_buf = if case_insensitive {
                                buffer.to_ascii_lowercase()
                            } else {
                                buffer.to_vec()
                            };
                            for i in 0..scan_chunk_search_end(
                                search_buf.len(),
                                ansi_pattern.len(),
                                unique_len,
                            ) {
                                if i % 4096 == 0 && check_runtime(rt).is_err() {
                                    break;
                                }
                                if search_buf[i..i + ansi_pattern.len()] == ansi_pattern[..] {
                                    let found_addr = addr + i;
                                    let end = (i + 256).min(buffer.len());
                                    let null_pos = buffer[i..end]
                                        .iter()
                                        .position(|&b| b == 0)
                                        .unwrap_or(end - i);
                                    let s = String::from_utf8_lossy(&buffer[i..i + null_pos]);
                                    results.push(StringScanMatch {
                                        address: found_addr,
                                        encoding: "ansi",
                                        value: s.into_owned(),
                                        length: null_pos,
                                    });
                                }
                            }
                        }

                        // Unicode (UTF-16LE) search
                        if encoding == "unicode" || encoding == "both" {
                            for i in (0..scan_chunk_search_end(
                                buffer.len(),
                                unicode_pattern.len(),
                                unique_len,
                            ))
                                .step_by(2)
                            {
                                if i % 4096 == 0 && check_runtime(rt).is_err() {
                                    break;
                                }
                                let mut matched = true;
                                for j in 0..unicode_pattern.len() {
                                    let buf_byte = if case_insensitive {
                                        buffer.get(i + j).copied().unwrap_or(0).to_ascii_lowercase()
                                    } else {
                                        buffer.get(i + j).copied().unwrap_or(0)
                                    };
                                    if buf_byte != unicode_pattern[j] {
                                        matched = false;
                                        break;
                                    }
                                }
                                if matched {
                                    let found_addr = addr + i;
                                    let end = (i + 512).min(buffer.len());
                                    let mut str_end = i;
                                    while str_end + 1 < end {
                                        if buffer[str_end] == 0 && buffer[str_end + 1] == 0 {
                                            break;
                                        }
                                        str_end += 2;
                                    }
                                    let wide: Vec<u16> = buffer[i..str_end]
                                        .chunks_exact(2)
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect();
                                    let s = String::from_utf16_lossy(&wide);
                                    results.push(StringScanMatch {
                                        address: found_addr,
                                        encoding: "unicode",
                                        value: s,
                                        length: wide.len(),
                                    });
                                }
                            }
                        }
                    });
                }
                results
            },
            reduce_string_matches,
        );

        let timed_out = runtime.check().is_err();

                let total_count = results.len();
        let paginated = string_scan_result_page(&results, offset, limit);

        Ok(serde_json::json!({
            "results": paginated,
            "count": paginated.len(),
            "total_count": total_count,
            "pattern": pattern,
            "encoding": encoding,
            "case_insensitive": case_insensitive,
            "region_cache": region_cache_report,
            "timed_out": timed_out
        }))
}

/// Alignment-aware memory scan: scan for values at aligned addresses only (faster, reduces noise)
pub fn scan_aligned(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("int");
    let alignment = args.get("alignment").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    // Alignment must be power of 2 and >= 1
    let alignment = if alignment == 0 || (alignment & (alignment - 1)) != 0 {
        4
    } else {
        alignment
    };

    let value_str = args
        .get("value")
        .and_then(|v| v.as_str())
        .or_else(|| args.get("value").and_then(|v| v.as_f64()).map(|_| ""))
        .ok_or_else(|| MemoricError::MemoryAccess("Missing value".to_string()))?;

    tracing::info!(
        "[MEMORY] scan_aligned pid={} type={} alignment={}",
        pid,
        scan_type,
        alignment
    );
    check_runtime(&runtime)?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    let handle = ScannerProcessHandle::open_read(pid as u32, "OpenProcess failed")?;

    let module_regions = resolve_module_regions_with_handle(handle.raw(), pid as u32, module_name);
    let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        start_address,
        PROTECT_READABLE,
        exclude_mapped,
        exclude_image,
        module_regions.as_deref(),
    )?;

    let mut session_data: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut timed_out = false;
    let mut last_address = 0usize;

    // Parse target value based on scan type
    let value_size: usize;
    let target_bytes: Vec<u8> = match scan_type {
        "int" => {
            let v: i32 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32
            } else {
                value_str
                    .parse()
                    .map_err(|_| MemoricError::MemoryAccess("Invalid int value".to_string()))?
            };
            value_size = 4;
            v.to_ne_bytes().to_vec()
        }
        "long" => {
            let v: i64 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_i64()).unwrap_or(0)
            } else {
                value_str
                    .parse()
                    .map_err(|_| MemoricError::MemoryAccess("Invalid long value".to_string()))?
            };
            value_size = 8;
            v.to_ne_bytes().to_vec()
        }
        "float" => {
            let v: f32 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32
            } else {
                value_str.parse().map_err(|_| {
                    MemoricError::MemoryAccess("Invalid float value".to_string())
                })?
            };
            value_size = 4;
            v.to_ne_bytes().to_vec()
        }
        "double" => {
            let v: f64 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0)
            } else {
                value_str.parse().map_err(|_| {
                    MemoricError::MemoryAccess("Invalid double value".to_string())
                })?
            };
            value_size = 8;
            v.to_ne_bytes().to_vec()
        }
        "short" => {
            let v: i16 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i16
            } else {
                value_str.parse().map_err(|_| {
                    MemoricError::MemoryAccess("Invalid short value".to_string())
                })?
            };
            value_size = 2;
            v.to_ne_bytes().to_vec()
        }
        "byte" => {
            let v: u8 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_u64()).unwrap_or(0) as u8
            } else {
                value_str
                    .parse()
                    .map_err(|_| MemoricError::MemoryAccess("Invalid byte value".to_string()))?
            };
            value_size = 1;
            vec![v]
        }
        _ => {
            let v: i32 = if value_str.is_empty() {
                args.get("value").and_then(|v| v.as_i64()).unwrap_or(0) as i32
            } else {
                value_str
                    .parse()
                    .map_err(|_| MemoricError::MemoryAccess("Invalid int value".to_string()))?
            };
            value_size = 4;
            v.to_ne_bytes().to_vec()
        }
    };

    for region in scan_regions {
        check_runtime(&runtime)?;
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            last_address = region.base;
            break;
        }

        scan_region_chunks(handle.raw(), &region, value_size.saturating_sub(1), |addr, buffer, unique_len| {
            let first_aligned = if addr % alignment == 0 {
                0
            } else {
                alignment - (addr % alignment)
            };

            let mut i = first_aligned;
            let search_end = scan_chunk_search_end(buffer.len(), value_size, unique_len);
            while i < search_end {
                if i % 4096 == 0 && check_runtime(&runtime).is_err() {
                    break;
                }
                if buffer[i..i + value_size] == target_bytes[..] {
                    let found_addr = addr + i;
                    session_data.push((found_addr, buffer[i..i + value_size].to_vec()));
                }
                i += alignment;
            }
        });
    }

    let total_count = session_data.len();
    let paginated = scan_data_result_page(&session_data, offset, limit);

    // Store in session
    let session_id = pid;
    if let Ok(mut state) = SCAN_STATE.lock() {
        state.insert(
            session_id,
            ScanSession {
                pid,
                value_size,
                addresses: session_data,
            },
        );
    }

    Ok(serde_json::json!({
        "results": paginated,
        "count": paginated.len(),
        "total_count": total_count,
        "scan_type": scan_type,
        "alignment": alignment,
        "value_size": value_size,
        "timed_out": timed_out,
        "region_cache": region_cache_report,
        "resume_address": if timed_out { format!("0x{:016X}", last_address) } else { "".to_string() }
    }))
}

/// Multi-value scan: scan for any of multiple values simultaneously (e.g. find all health values 80,90,100)
pub fn scan_multi_value(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing pid".to_string()))?;
    let runtime = scanner_runtime(args)?;
    let scan_type = args
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("int");
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(200) as usize;
    let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let timeout_secs = args
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30);
    let start_address = args
        .get("start_address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exclude_mapped = args
        .get("exclude_mapped")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude_image = args
        .get("exclude_image")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let module_name = args.get("module_name").and_then(|v| v.as_str());

    let values_arr = args
        .get("values")
        .and_then(|v| v.as_array())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing values array".to_string()))?;

    if values_arr.is_empty() {
        return Err(MemoricError::MemoryAccess(
            "values array is empty".to_string(),
        ));
    }

    tracing::info!(
        "[MEMORY] scan_multi_value pid={} type={} values_count={}",
        pid,
        scan_type,
        values_arr.len()
    );
    check_runtime(&runtime)?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    // Parse all target values into byte patterns
    let mut targets: Vec<(Vec<u8>, String)> = Vec::new();
    let value_size: usize;

    match scan_type {
        "int" => {
            value_size = 4;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for int scan".to_string())
                })? as i32;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "long" => {
            value_size = 8;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for long scan".to_string())
                })?;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "float" => {
            value_size = 4;
            for v in values_arr {
                let num = v.as_f64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for float scan".to_string())
                })? as f32;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "double" => {
            value_size = 8;
            for v in values_arr {
                let num = v.as_f64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for double scan".to_string())
                })?;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "short" => {
            value_size = 2;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for short scan".to_string())
                })? as i16;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
        "byte" => {
            value_size = 1;
            for v in values_arr {
                let num = v.as_u64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers for byte scan".to_string())
                })? as u8;
                targets.push((vec![num], num.to_string()));
            }
        }
        _ => {
            value_size = 4;
            for v in values_arr {
                let num = v.as_i64().ok_or_else(|| {
                    MemoricError::MemoryAccess("values must be numbers".to_string())
                })? as i32;
                targets.push((num.to_ne_bytes().to_vec(), num.to_string()));
            }
        }
    }

    let handle = ScannerProcessHandle::open_read(pid as u32, "OpenProcess failed")?;

    let module_regions = resolve_module_regions_with_handle(handle.raw(), pid as u32, module_name);
    let (scan_regions, region_cache_report, _skipped_regions) = get_cached_scan_regions(
        pid,
        args,
        start_address,
        PROTECT_READABLE,
        exclude_mapped,
        exclude_image,
        module_regions.as_deref(),
    )?;

    let mut paginated = Vec::new();
    let mut total_count = 0usize;
    let mut session_data: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut timed_out = false;
    let mut last_address = 0usize;

    for region in scan_regions {
        check_runtime(&runtime)?;
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            last_address = region.base;
            break;
        }

        scan_region_chunks(handle.raw(), &region, value_size.saturating_sub(1), |addr, buffer, unique_len| {
            for i in 0..scan_chunk_search_end(buffer.len(), value_size, unique_len) {
                if i % 4096 == 0 && check_runtime(&runtime).is_err() {
                    break;
                }
                let slice = &buffer[i..i + value_size];
                for (target_bytes, target_label) in &targets {
                    if slice == target_bytes.as_slice() {
                        let found_addr = addr + i;
                        if total_count >= offset && paginated.len() < limit {
                            paginated.push(serde_json::json!({
                                "address": format!("0x{:016X}", found_addr),
                                "matched_value": target_label,
                                "hex": hex::encode(slice)
                            }));
                        }
                        total_count += 1;
                        session_data.push((found_addr, slice.to_vec()));
                        break; // Don't match same address against remaining targets
                    }
                }
            }
        });
    }

    // Store in session
    let session_id = pid;
    if let Ok(mut state) = SCAN_STATE.lock() {
        state.insert(
            session_id,
            ScanSession {
                pid,
                value_size,
                addresses: session_data,
            },
        );
    }

    Ok(serde_json::json!({
        "results": paginated,
        "count": paginated.len(),
        "total_count": total_count,
        "scan_type": scan_type,
        "values_searched": values_arr.len(),
        "timed_out": timed_out,
        "region_cache": region_cache_report,
        "resume_address": if timed_out { format!("0x{:016X}", last_address) } else { "".to_string() }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct HandleCacheTestGuard;

    impl HandleCacheTestGuard {
        fn new() -> Self {
            crate::handle_cache::begin_request();
            Self
        }
    }

    impl Drop for HandleCacheTestGuard {
        fn drop(&mut self) {
            crate::handle_cache::end_request();
        }
    }

    #[test]
    fn protection_masks_match_readable_and_writable_scan_intent() {
        assert_ne!(PROTECT_WRITABLE & PAGE_READWRITE_BITS, 0);
        assert_ne!(PROTECT_WRITABLE & PAGE_WRITECOPY_BITS, 0);
        assert_ne!(PROTECT_WRITABLE & PAGE_EXECUTE_READWRITE_BITS, 0);
        assert_ne!(PROTECT_WRITABLE & PAGE_EXECUTE_WRITECOPY_BITS, 0);

        assert_ne!(PROTECT_READABLE & PAGE_EXECUTE_BITS, 0);
        assert_ne!(PROTECT_READABLE & PAGE_READONLY_BITS, 0);
        assert_ne!(PROTECT_READABLE & PAGE_EXECUTE_READ_BITS, 0);
    }

    #[test]
    fn scan_search_end_includes_last_start_without_short_buffer_overflow() {
        assert_eq!(scan_search_end(8, 4), 5);
        assert_eq!(scan_search_end(4, 4), 1);
        assert_eq!(scan_search_end(3, 4), 0);
        assert_eq!(scan_search_end(8, 0), 0);

        assert_eq!(scan_chunk_search_end(10, 4, 6), 6);
        assert_eq!(scan_chunk_search_end(10, 4, 8), 7);
    }

    #[test]
    fn spaced_hex_preview_preserves_pattern_scan_output_format() {
        assert_eq!(
            bytes_to_spaced_hex(&[0x00, 0x0A, 0x41, 0xFE, 0xFF]),
            "00 0A 41 FE FF"
        );
        assert_eq!(bytes_to_spaced_hex(&[]), "");
    }

    #[test]
    fn find_pattern_signature_parser_rejects_invalid_hex_without_scan() {
        let pattern = parse_find_pattern_signature("A 0f ?? FF").expect("signature pattern");
        assert_eq!(pattern, vec![Some(0x0A), Some(0x0F), None, Some(0xFF)]);

        let err = parse_find_pattern_signature("90 GG").expect_err("invalid byte should fail");
        assert!(err.to_string().contains("Invalid hex byte: GG"));

        let err = parse_find_pattern_signature("100").expect_err("overflow should fail");
        assert!(err.to_string().contains("Invalid hex byte: 100"));
    }

    #[test]
    fn ida_pattern_nibble_wildcards_parse_without_allocating_token_strings() {
        let pattern = parse_ida_pattern("4? ?F ?? 90").expect("ida pattern");
        assert_eq!(pattern.len(), 4);
        assert!(ida_match(&[0x4A, 0x0F, 0xAB, 0x90], &pattern));
        assert!(!ida_match(&[0x5A, 0x0F, 0xAB, 0x90], &pattern));
        assert!(!ida_match(&[0x4A, 0x10, 0xAB, 0x90], &pattern));

        let err = parse_ida_pattern("?G").expect_err("invalid nibble should fail");
        assert!(err.to_string().contains("Invalid pattern byte"));
    }

    #[test]
    fn scanner_pages_format_only_requested_window() {
        let scan_data = vec![
            (0x1000usize, vec![0xAA, 0xBB]),
            (0x2000usize, vec![0xCC, 0xDD]),
            (0x3000usize, vec![0xEE, 0xFF]),
        ];

        let addresses = address_page_from_scan_data(&scan_data, 1, 1);
        assert_eq!(addresses, vec!["0x0000000000002000"]);

        let raw_addresses = vec![0x1111usize, 0x2222, 0x3333];
        let formatted = address_page_from_addresses(&raw_addresses, 2, 8);
        assert_eq!(formatted, vec!["0x0000000000003333"]);

        let values = scan_data_result_page(&scan_data, 1, 2);
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["address"], "0x0000000000002000");
        assert_eq!(values[0]["hex"], "ccdd");
        assert_eq!(values[1]["address"], "0x0000000000003000");
    }

    #[test]
    fn split_regions_by_size_balances_by_bytes() {
        let regions = vec![
            ScanRegionView {
                base: 0x1000,
                size: 512,
                read_size: 512,
                protect: PROTECT_READABLE,
                region_type: MEM_PRIVATE,
            },
            ScanRegionView {
                base: 0x2000,
                size: 512,
                read_size: 512,
                protect: PROTECT_READABLE,
                region_type: MEM_PRIVATE,
            },
            ScanRegionView {
                base: 0x3000,
                size: 4096,
                read_size: 4096,
                protect: PROTECT_READABLE,
                region_type: MEM_PRIVATE,
            },
        ];

        let chunks = split_regions_by_size(&regions, 2);
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks
                .iter()
                .flatten()
                .map(|region| region.size)
                .sum::<usize>(),
            5120
        );
        assert!(chunks
            .iter()
            .map(|chunk| chunk.iter().map(|region| region.size).sum::<usize>())
            .all(|bytes| bytes <= 2560));
    }

    #[test]
    fn split_regions_by_size_splits_single_large_region() {
        let regions = vec![ScanRegionView {
            base: 0x1000,
            size: 4096,
            read_size: 4096,
            protect: PROTECT_READABLE,
            region_type: MEM_PRIVATE,
        }];

        let chunks = split_regions_by_size(&regions, 4);
        assert_eq!(chunks.len(), 4);

        let flattened: Vec<_> = chunks.into_iter().flatten().collect();
        assert_eq!(flattened.len(), 4);
        assert_eq!(flattened[0].base, 0x1000);
        assert_eq!(flattened[0].size, 1024);
        assert_eq!(flattened[0].read_size, 4096);
        assert_eq!(flattened[1].base, 0x1400);
        assert_eq!(flattened[1].size, 1024);
        assert_eq!(flattened[1].read_size, 3072);
        assert_eq!(flattened.iter().map(|region| region.size).sum::<usize>(), 4096);
    }

    #[test]
    fn module_region_resolution_skips_process_handle_without_module_filter() {
        use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

        let _guard = TEST_LOCK.lock().unwrap();
        let _handle_cache_guard = HandleCacheTestGuard::new();
        let pid = std::process::id();
        let access = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).0;

        let module_regions =
            resolve_module_regions_for_scan(pid, None, "test open").expect("no module filter");

        assert!(module_regions.is_none());
        assert!(
            crate::handle_cache::take(pid, access).is_none(),
            "module filtering should be the only scanner path that opens a cached QUERY|VM_READ handle"
        );
    }

    #[test]
    fn scan_exact_reports_region_cache_reuse_for_current_process() {
        let _guard = TEST_LOCK.lock().unwrap();
        let _handle_cache_guard = HandleCacheTestGuard::new();
        let mut data = vec![0x71u8, 0x72, 0x73, 0x74];
        let pid = std::process::id() as u64;

        let base_args = json!({
            "pid": pid,
            "value": 0x74737271i64,
            "scan_type": "int",
            "start_address": data.as_mut_ptr() as u64,
            "limit": 4,
            "region_cache": "clear"
        });
        let first = scan_exact(&base_args).expect("first scan should query regions");
        assert_eq!(first["region_cache"]["enabled"], true);
        assert_eq!(first["region_cache"]["source"], "refresh");

        let second = scan_exact(&json!({
            "pid": pid,
            "value": 0x74737271i64,
            "scan_type": "int",
            "start_address": data.as_mut_ptr() as u64,
            "limit": 4
        }))
        .expect("second scan should reuse fresh region cache");
        assert_eq!(second["region_cache"]["source"], "cache");
        assert_eq!(second["region_cache"]["reused"], true);
    }
}

//! Scan Session Management — Cheat Engine-style persistent scan workflow
//!
//! Workflow:
//! 1. `scan_new` — First scan: searches entire process memory, creates session
//! 2. `scan_next` — Narrow: filter previous results (changed/unchanged/exact/increased/decreased)  
//! 3. `scan_undo` — Pop last narrowing step
//! 4. `scan_list` — List active sessions
//! 5. `scan_reset` — Clear a session
//!
//! Each session stores its result set and history stack for undo support.

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_SCAN_RESULT_PAGE_LIMIT: usize = 50;
pub const MAX_SCAN_RESULT_PAGE_LIMIT: usize = 500;
pub const MAX_SCAN_RESULT_OFFSET: usize = crate::args::DEFAULT_MAX_LIMIT;
const AUTO_SCAN_RESULT_ARTIFACT_THRESHOLD: usize = 1_000;
const SCAN_RESULT_CURSOR_PREFIX: &str = "scan-result-cursor:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanResultSort {
    IndexAsc,
    IndexDesc,
    AddressAsc,
    AddressDesc,
    ValueAsc,
    ValueDesc,
}

impl ScanResultSort {
    fn as_str(self) -> &'static str {
        match self {
            Self::IndexAsc => "index_asc",
            Self::IndexDesc => "index_desc",
            Self::AddressAsc => "address_asc",
            Self::AddressDesc => "address_desc",
            Self::ValueAsc => "value_asc",
            Self::ValueDesc => "value_desc",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "index" | "index_asc" => Some(Self::IndexAsc),
            "index_desc" => Some(Self::IndexDesc),
            "address" | "address_asc" => Some(Self::AddressAsc),
            "address_desc" => Some(Self::AddressDesc),
            "value" | "value_asc" => Some(Self::ValueAsc),
            "value_desc" => Some(Self::ValueDesc),
            _ => None,
        }
    }
}

/// Global scan session store
static SESSIONS: Lazy<Mutex<ScanSessionStore>> = Lazy::new(|| Mutex::new(ScanSessionStore::new()));

/// Scan value types
#[derive(Debug, Clone)]
pub enum ScanValueType {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
    F32,
    F64,
    /// Array of bytes (AOB/signature)
    Bytes,
}

impl ScanValueType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bytes => "bytes",
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
            Self::Bytes => 0, // variable
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "u8" | "byte" => Some(Self::U8),
            "u16" | "short" => Some(Self::U16),
            "u32" | "int" | "dword" => Some(Self::U32),
            "u64" | "long" | "qword" => Some(Self::U64),
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "f32" | "float" => Some(Self::F32),
            "f64" | "double" => Some(Self::F64),
            "bytes" | "aob" => Some(Self::Bytes),
            _ => None,
        }
    }
}

/// A single scan match (address + value snapshot)
#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub address: u64,
    pub value: Vec<u8>,
}

/// Filter mode for narrowing scans
#[derive(Debug, Clone)]
pub enum NarrowFilter {
    /// Value equals a specific target
    Exact(Vec<u8>),
    /// Value changed since last scan
    Changed,
    /// Value unchanged since last scan
    Unchanged,
    /// Value increased
    Increased,
    /// Value decreased
    Decreased,
    /// Value increased by a specific amount
    IncreasedBy(Vec<u8>),
    /// Value decreased by a specific amount
    DecreasedBy(Vec<u8>),
}

/// A scan session
struct ScanSession {
    id: String,
    pid: u32,
    value_type: ScanValueType,
    value_size: usize,
    /// Current result set
    results: Vec<ScanEntry>,
    /// History stack for undo
    history: Vec<Vec<ScanEntry>>,
    created_at: u64,
    last_scan_at: u64,
    scan_count: u32,
}

struct ScanSessionStore {
    sessions: HashMap<String, ScanSession>,
    next_id: u32,
}

impl ScanSessionStore {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    fn generate_id(&mut self) -> String {
        let id = format!("scan_{}", self.next_id);
        self.next_id += 1;
        id
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read process memory at address for scan operations
fn read_process_memory_bytes(pid: u32, address: u64, size: usize) -> Result<Vec<u8>, String> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    unsafe {
        let handle =
            OpenProcess(PROCESS_VM_READ, false, pid).map_err(|e| format!("OpenProcess: {}", e))?;
        let _guard = crate::safe_handle::SafeHandle::new(handle);

        let mut buf = vec![0u8; size];
        let mut bytes_read = 0usize;
        ReadProcessMemory(
            handle,
            address as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
        .map_err(|e| format!("ReadProcessMemory at 0x{:X}: {}", address, e))?;
        buf.truncate(bytes_read);
        Ok(buf)
    }
}

/// Compare two byte slices as numeric values
fn compare_numeric(old: &[u8], new: &[u8], filter: &NarrowFilter) -> bool {
    if old.len() != new.len() {
        return false;
    }

    match filter {
        NarrowFilter::Changed => old != new,
        NarrowFilter::Unchanged => old == new,
        NarrowFilter::Exact(target) => new == target.as_slice(),
        NarrowFilter::Increased => match old.len() {
            4 => {
                let o = u32::from_le_bytes(old.try_into().unwrap_or_default());
                let n = u32::from_le_bytes(new.try_into().unwrap_or_default());
                n > o
            }
            8 => {
                let o = u64::from_le_bytes(old.try_into().unwrap_or_default());
                let n = u64::from_le_bytes(new.try_into().unwrap_or_default());
                n > o
            }
            _ => false,
        },
        NarrowFilter::Decreased => match old.len() {
            4 => {
                let o = u32::from_le_bytes(old.try_into().unwrap_or_default());
                let n = u32::from_le_bytes(new.try_into().unwrap_or_default());
                n < o
            }
            8 => {
                let o = u64::from_le_bytes(old.try_into().unwrap_or_default());
                let n = u64::from_le_bytes(new.try_into().unwrap_or_default());
                n < o
            }
            _ => false,
        },
        NarrowFilter::IncreasedBy(delta) => match old.len() {
            4 => {
                let o = u32::from_le_bytes(old.try_into().unwrap_or_default());
                let n = u32::from_le_bytes(new.try_into().unwrap_or_default());
                let d = u32::from_le_bytes(delta.as_slice().try_into().unwrap_or_default());
                n.wrapping_sub(o) == d
            }
            _ => false,
        },
        NarrowFilter::DecreasedBy(delta) => match old.len() {
            4 => {
                let o = u32::from_le_bytes(old.try_into().unwrap_or_default());
                let n = u32::from_le_bytes(new.try_into().unwrap_or_default());
                let d = u32::from_le_bytes(delta.as_slice().try_into().unwrap_or_default());
                o.wrapping_sub(n) == d
            }
            _ => false,
        },
    }
}

// ═════════════════════════════════════════════════════════════════
// Public API — called from MCP tool dispatch
// ═════════════════════════════════════════════════════════════════

/// Create a new scan session and perform initial scan
pub fn scan_new(args: &Value) -> Result<Value, String> {
    let runtime = crate::runtime::RuntimeContext::from_args(args)?;
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or("scan_new requires 'pid'")? as u32;
    let value_type_str = args
        .get("value_type")
        .and_then(|v| v.as_str())
        .unwrap_or("u32");
    let value_type = ScanValueType::from_str(value_type_str).ok_or_else(|| {
        format!(
            "Unknown value_type: {}. Use: u8/u16/u32/u64/i32/i64/f32/f64/bytes",
            value_type_str
        )
    })?;

    // Parse target value. For byte/AOB scans, accept the session-friendly
    // signature/pattern form used by non-session scanners.
    let byte_pattern = if matches!(value_type, ScanValueType::Bytes) {
        let value = args
            .get("signature")
            .or_else(|| args.get("pattern"))
            .or_else(|| args.get("value"))
            .ok_or("scan_new with value_type='bytes' requires 'signature', 'pattern', or byte-array 'value'")?;
        Some(value_to_byte_pattern(value)?)
    } else {
        None
    };
    let target_bytes = if let Some(pattern) = &byte_pattern {
        if pattern.is_empty() {
            return Err("scan_new byte signature must contain at least one byte".to_string());
        }
        pattern
            .iter()
            .map(|byte| byte.unwrap_or(0))
            .collect::<Vec<u8>>()
    } else if let Some(v) = args.get("value") {
        value_to_bytes(v, &value_type)?
    } else {
        return Err("scan_new requires 'value' (the value to search for)".to_string());
    };
    let value_size = target_bytes.len();

    if value_size == 0 {
        return Err("scan_new target value must not be empty".to_string());
    }

    tracing::info!(
        "[SCAN] New scan: PID={}, type={}, value={} bytes",
        pid,
        value_type_str,
        target_bytes.len()
    );
    runtime.mark_running(
        None,
        format!("scan_new: locating scannable regions for pid {}", pid),
    );

    // Get all scannable regions. This uses a metadata-only cache; raw memory
    // bytes are still read live for every scan.
    let region_query = crate::memory::region_cache::get_scannable_regions(pid, args)?;
    let region_cache_report = region_query.report.clone();
    let regions = region_query
        .regions
        .iter()
        .map(|region| region.as_scan_range())
        .collect::<Vec<_>>();
    tracing::info!("[SCAN] {} scannable regions found", regions.len());
    let total_regions = regions.len() as u64;
    runtime.mark_running(
        Some(total_regions),
        format!("scan_new: scanning {} regions", total_regions),
    );

    let mut results: Vec<ScanEntry> = Vec::new();
    let mut regions_scanned = 0u32;
    let mut bytes_scanned = 0u64;

    for (idx, (base, size)) in regions.iter().enumerate() {
        runtime.check()?;
        let current_region = idx as u64 + 1;
        match read_process_memory_bytes(pid, *base, *size) {
            Ok(data) => {
                regions_scanned += 1;
                bytes_scanned += data.len() as u64;
                if data.len() < value_size {
                    if current_region == total_regions || current_region % 16 == 0 {
                        runtime.update_progress(
                            current_region,
                            Some(total_regions),
                            format!(
                                "scan_new: scanned {}/{} regions, {} matches",
                                current_region,
                                total_regions,
                                results.len()
                            ),
                        );
                    }
                    continue;
                }

                // Scan for exact match
                for offset in 0..=(data.len() - value_size) {
                    if offset % 4096 == 0 {
                        runtime.check()?;
                    }
                    let window = &data[offset..offset + value_size];
                    let matched = if let Some(pattern) = &byte_pattern {
                        pattern_matches(window, pattern)
                    } else {
                        window == target_bytes.as_slice()
                    };

                    if matched {
                        results.push(ScanEntry {
                            address: base + offset as u64,
                            value: window.to_vec(),
                        });
                    }
                }
            }
            Err(_) => {
                if current_region == total_regions || current_region % 16 == 0 {
                    runtime.update_progress(
                        current_region,
                        Some(total_regions),
                        format!(
                            "scan_new: scanned {}/{} regions, {} matches",
                            current_region,
                            total_regions,
                            results.len()
                        ),
                    );
                }
                continue; // skip unreadable regions
            }
        }
        if current_region == total_regions || current_region % 16 == 0 {
            runtime.update_progress(
                current_region,
                Some(total_regions),
                format!(
                    "scan_new: scanned {}/{} regions, {} matches",
                    current_region,
                    total_regions,
                    results.len()
                ),
            );
        }
    }
    runtime.update_progress(
        total_regions,
        Some(total_regions),
        format!(
            "scan_new: complete, {} readable regions, {} matches",
            regions_scanned,
            results.len()
        ),
    );

    // Create session
    let mut store = SESSIONS.lock().map_err(|e| e.to_string())?;
    let session_id = store.generate_id();
    let result_count = results.len();

    store.sessions.insert(
        session_id.clone(),
        ScanSession {
            id: session_id.clone(),
            pid,
            value_type,
            value_size,
            results,
            history: Vec::new(),
            created_at: now_epoch(),
            last_scan_at: now_epoch(),
            scan_count: 1,
        },
    );

    Ok(json!({
        "session_id": session_id,
        "pid": pid,
        "value_type": value_type_str,
        "results_found": result_count,
        "regions_scanned": regions_scanned,
        "region_cache": region_cache_report.to_json(),
        "bytes_scanned": bytes_scanned,
        "message": format!("Session '{}' created. {} matches found. Use scan_next to narrow.", session_id, result_count),
        "hint": if result_count > 1000 {
            "Too many results — change the value in-game and use scan_next(filter='changed') to narrow"
        } else if result_count == 0 {
            "No matches. Try a different value_type or check if the value is correct"
        } else {
            "Use scan_next with filter 'changed'/'unchanged'/'increased'/'decreased' to narrow"
        }
    }))
}

/// Narrow an existing scan session
pub fn scan_next(args: &Value) -> Result<Value, String> {
    let runtime = crate::runtime::RuntimeContext::from_args(args)?;
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or("scan_next requires 'session_id'")?;
    let filter_str = args
        .get("filter")
        .and_then(|v| v.as_str())
        .ok_or("scan_next requires 'filter' (changed/unchanged/exact/increased/decreased)")?;

    let filter = match filter_str {
        "changed" => NarrowFilter::Changed,
        "unchanged" => NarrowFilter::Unchanged,
        "increased" => NarrowFilter::Increased,
        "decreased" => NarrowFilter::Decreased,
        "exact" => {
            let vt = {
                let store = SESSIONS.lock().map_err(|e| e.to_string())?;
                let session = store
                    .sessions
                    .get(session_id)
                    .ok_or_else(|| format!("Session '{}' not found", session_id))?;
                session.value_type.clone()
            };
            let value = args.get("value").ok_or("exact filter requires 'value'")?;
            let bytes = value_to_bytes(value, &vt)?;
            NarrowFilter::Exact(bytes)
        }
        _ => {
            return Err(format!(
                "Unknown filter: {}. Use: changed/unchanged/exact/increased/decreased",
                filter_str
            ))
        }
    };

    let mut store = SESSIONS.lock().map_err(|e| e.to_string())?;
    let session = store
        .sessions
        .get_mut(session_id)
        .ok_or_else(|| format!("Session '{}' not found", session_id))?;

    let value_size = session.value_size;
    if value_size == 0 {
        return Err(format!("Session '{}' has invalid value size", session_id));
    }
    if matches!(session.value_type, ScanValueType::Bytes)
        && matches!(
            filter,
            NarrowFilter::Increased
                | NarrowFilter::Decreased
                | NarrowFilter::IncreasedBy(_)
                | NarrowFilter::DecreasedBy(_)
        )
    {
        return Err("Byte scan sessions support filters changed/unchanged/exact only".to_string());
    }
    let before_count = session.results.len();
    let mut changed_count = 0usize;
    let mut unchanged_count = 0usize;
    let mut unreadable_count = 0usize;
    runtime.mark_running(
        Some(before_count as u64),
        format!(
            "scan_next: applying '{}' filter to {} candidates",
            filter_str, before_count
        ),
    );

    // Save current state for undo
    session.history.push(session.results.clone());

    // Re-read current values and filter
    let mut new_results: Vec<ScanEntry> = Vec::new();
    for (idx, entry) in session.results.iter().enumerate() {
        runtime.check()?;
        match read_process_memory_bytes(session.pid, entry.address, value_size) {
            Ok(current) if current.len() == value_size => {
                if current == entry.value {
                    unchanged_count += 1;
                } else {
                    changed_count += 1;
                }
                if compare_numeric(&entry.value, &current, &filter) {
                    new_results.push(ScanEntry {
                        address: entry.address,
                        value: current,
                    });
                }
            }
            _ => {
                unreadable_count += 1;
                continue; // address became unreadable — discard
            }
        }
        let current_candidate = idx as u64 + 1;
        if current_candidate == before_count as u64 || current_candidate % 128 == 0 {
            runtime.update_progress(
                current_candidate,
                Some(before_count as u64),
                format!(
                    "scan_next: filtered {}/{} candidates, {} remain",
                    current_candidate,
                    before_count,
                    new_results.len()
                ),
            );
        }
    }

    let after_count = new_results.len();
    let delta = build_scan_delta_summary(
        before_count,
        after_count,
        changed_count,
        unchanged_count,
        unreadable_count,
    );
    let removed_count = delta["removed"].as_u64().unwrap_or_default() as usize;
    runtime.update_progress(
        before_count as u64,
        Some(before_count as u64),
        format!(
            "scan_next: complete, {} -> {} candidates ({} removed, {} changed, {} unchanged, {} unreadable)",
            before_count,
            after_count,
            removed_count,
            changed_count,
            unchanged_count,
            unreadable_count
        ),
    );
    session.results = new_results;
    session.last_scan_at = now_epoch();
    session.scan_count += 1;

    // Show first few results
    let preview: Vec<Value> = session
        .results
        .iter()
        .take(20)
        .map(|e| {
            json!({
                "address": format!("0x{:016X}", e.address),
                "value": format_value_bytes(&e.value, &session.value_type),
                "hex": hex::encode(&e.value),
            })
        })
        .collect();

    Ok(json!({
        "session_id": session_id,
        "filter": filter_str,
        "before": before_count,
        "after": after_count,
        "eliminated": before_count - after_count,
        "delta": delta,
        "scan_count": session.scan_count,
        "preview": preview,
        "message": format!(
            "{} → {} results ({} eliminated, {} changed, {} unchanged, {} unreadable). {}",
            before_count,
            after_count,
            before_count - after_count,
            changed_count,
            unchanged_count,
            unreadable_count,
            if after_count <= 5 { "Likely found the target!" }
            else if after_count == 0 { "All eliminated — try scan_undo" }
            else { "Continue narrowing with scan_next" }
        )
    }))
}

fn build_scan_delta_summary(
    before_count: usize,
    after_count: usize,
    changed_count: usize,
    unchanged_count: usize,
    unreadable_count: usize,
) -> Value {
    let readable_count = changed_count.saturating_add(unchanged_count);
    let removed_count = before_count.saturating_sub(after_count);
    json!({
        "before": before_count,
        "after": after_count,
        "added": after_count.saturating_sub(before_count),
        "removed": removed_count,
        "changed": changed_count,
        "unchanged": unchanged_count,
        "unreadable": unreadable_count,
        "readable": readable_count,
        "retained": after_count,
    })
}

/// Undo the last narrowing step
pub fn scan_undo(args: &Value) -> Result<Value, String> {
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or("scan_undo requires 'session_id'")?;

    let mut store = SESSIONS.lock().map_err(|e| e.to_string())?;
    let session = store
        .sessions
        .get_mut(session_id)
        .ok_or_else(|| format!("Session '{}' not found", session_id))?;

    if let Some(previous) = session.history.pop() {
        let restored_count = previous.len();
        session.results = previous;
        session.scan_count = session.scan_count.saturating_sub(1);
        Ok(json!({
            "session_id": session_id,
            "restored_count": restored_count,
            "remaining_undos": session.history.len(),
            "message": format!("Restored to {} results. {} more undos available.", restored_count, session.history.len())
        }))
    } else {
        Err("No undo history available".to_string())
    }
}

/// List active scan sessions, or page candidates for one session when session_id is supplied.
pub fn scan_list(args: &Value) -> Result<Value, String> {
    let store = SESSIONS.lock().map_err(|e| e.to_string())?;
    if args.get("session_id").is_some() {
        let session_id = args
            .get("session_id")
            .and_then(|v| v.as_str())
            .ok_or("scan_list session_id must be a string")?;
        let session = store
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("Session '{}' not found", session_id))?;
        return scan_result_page(session, args);
    }

    let sessions: Vec<Value> = store
        .sessions
        .values()
        .map(|s| {
            json!({
                "session_id": s.id,
                "pid": s.pid,
                "results": s.results.len(),
                "value_size": s.value_size,
                "scan_count": s.scan_count,
                "undo_depth": s.history.len(),
                "created_at": s.created_at,
                "last_scan_at": s.last_scan_at,
            })
        })
        .collect();

    Ok(json!({
        "sessions": sessions,
        "total": sessions.len(),
    }))
}

fn scan_result_page(session: &ScanSession, args: &Value) -> Result<Value, String> {
    let limit = parse_scan_result_limit(args)?;
    let sort = parse_scan_result_sort(args)?;
    let summary_only = parse_bool_arg(args, "summary_only")?;
    let (start, cursor_mode) = if let Some(cursor) = args.get("cursor") {
        let cursor = cursor
            .as_str()
            .ok_or_else(|| "Invalid cursor: expected opaque string token".to_string())?;
        (
            decode_scan_result_cursor(cursor, &session.id, session.scan_count, sort)?,
            true,
        )
    } else {
        let offset = crate::args::parse_limit(args, "offset", 0, MAX_SCAN_RESULT_OFFSET)?;
        (offset, false)
    };

    if start > session.results.len() {
        return Err("Invalid cursor: pagination position is outside scan result list".to_string());
    }

    let total = session.results.len();
    let candidates = if summary_only {
        Vec::new()
    } else {
        sorted_scan_entries(session, sort)
            .into_iter()
            .skip(start)
            .take(limit)
            .map(|(idx, entry)| scan_entry_to_json(idx, entry, &session.value_type))
            .collect::<Vec<_>>()
    };
    let next_offset = start.saturating_add(limit);
    let mut response = json!({
        "session_id": session.id,
        "pid": session.pid,
        "value_type": session.value_type.as_str(),
        "value_size": session.value_size,
        "scan_count": session.scan_count,
        "total": total,
        "offset": start,
        "limit": limit,
        "sort": sort.as_str(),
        "summary_only": summary_only,
        "count": candidates.len(),
        "candidates": candidates,
        "snapshot": {
            "cursorKind": "scan-results",
            "sessionId": session.id,
            "scanCount": session.scan_count,
            "sort": sort.as_str(),
            "total": total
        }
    });
    if !summary_only && next_offset < total {
        response["nextCursor"] = json!(encode_scan_result_cursor(
            &session.id,
            session.scan_count,
            sort,
            next_offset
        ));
    }
    if cursor_mode {
        response["cursor"] = args.get("cursor").cloned().unwrap_or(Value::Null);
    }
    if let Some(artifact) = export_scan_results_artifact(session, args, sort, summary_only)? {
        response["artifact"] = artifact.clone();
        response["output_path"] = json!(artifact["path"].as_str().unwrap_or_default());
        response["exported_count"] = json!(total);
        response["redaction_status"] = json!("artifact");
        response["export_reason"] = json!(if output_path_from_args(args).is_some() {
            "explicit_output_path"
        } else {
            "large_session_auto"
        });
    }
    Ok(response)
}

fn export_scan_results_artifact(
    session: &ScanSession,
    args: &Value,
    sort: ScanResultSort,
    summary_only: bool,
) -> Result<Option<Value>, String> {
    let explicit_path = output_path_from_args(args);
    let should_export = explicit_path.is_some()
        || (!summary_only && session.results.len() > AUTO_SCAN_RESULT_ARTIFACT_THRESHOLD);
    if !should_export {
        return Ok(None);
    };
    let candidates = sorted_scan_entries(session, sort)
        .into_iter()
        .map(|(idx, entry)| scan_entry_to_json(idx, entry, &session.value_type))
        .collect::<Vec<_>>();
    let payload = json!({
        "kind": "scan-results",
        "session_id": session.id,
        "pid": session.pid,
        "value_type": session.value_type.as_str(),
        "value_size": session.value_size,
        "scan_count": session.scan_count,
        "sort": sort.as_str(),
        "total": candidates.len(),
        "candidates": candidates,
        "snapshot": {
            "cursorKind": "scan-results",
            "sessionId": session.id,
            "scanCount": session.scan_count,
            "sort": sort.as_str(),
            "total": candidates.len()
        },
        "redaction_status": "artifact"
    });
    let bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|err| format!("serialize scan result artifact: {}", err))?;
    let path = explicit_path.unwrap_or_else(|| auto_scan_results_output_path(session, &bytes));
    let correlation_id = crate::observability::correlation_id_from_args(args);
    crate::artifact::write_artifact_bytes(
        &path,
        &bytes,
        crate::artifact::retention_secs_from_args(args),
        correlation_id.as_deref(),
    )
    .map(Some)
}

fn auto_scan_results_output_path(session: &ScanSession, bytes: &[u8]) -> PathBuf {
    let safe_session_id = session
        .id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let hash = crate::artifact::sha256_bytes(bytes);
    std::env::temp_dir().join(format!(
        "memoric-scan-results-{}-{}-{}.json",
        safe_session_id, session.scan_count, hash
    ))
}

fn output_path_from_args(args: &Value) -> Option<PathBuf> {
    args.get("output_path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn parse_scan_result_limit(args: &Value) -> Result<usize, String> {
    let limit = crate::args::parse_limit(
        args,
        "limit",
        DEFAULT_SCAN_RESULT_PAGE_LIMIT,
        MAX_SCAN_RESULT_PAGE_LIMIT,
    )?;
    if limit == 0 {
        return Err("'limit' must be greater than 0".to_string());
    }
    Ok(limit)
}

fn parse_scan_result_sort(args: &Value) -> Result<ScanResultSort, String> {
    match args.get("sort") {
        Some(Value::String(value)) => ScanResultSort::from_str(value).ok_or_else(|| {
            "Invalid 'sort'; expected index_asc, index_desc, address_asc, address_desc, value_asc, or value_desc".to_string()
        }),
        Some(_) => Err("Invalid 'sort'; expected a string".to_string()),
        None => Ok(ScanResultSort::IndexAsc),
    }
}

fn parse_bool_arg(args: &Value, key: &str) -> Result<bool, String> {
    match args.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(Value::String(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(format!("Invalid '{}'; expected boolean", key)),
        },
        Some(_) => Err(format!("Invalid '{}'; expected boolean", key)),
        None => Ok(false),
    }
}

fn sorted_scan_entries(session: &ScanSession, sort: ScanResultSort) -> Vec<(usize, &ScanEntry)> {
    let mut entries = session.results.iter().enumerate().collect::<Vec<_>>();
    match sort {
        ScanResultSort::IndexAsc => {}
        ScanResultSort::IndexDesc => entries.reverse(),
        ScanResultSort::AddressAsc => entries.sort_by(|(left_idx, left), (right_idx, right)| {
            left.address
                .cmp(&right.address)
                .then_with(|| left_idx.cmp(right_idx))
        }),
        ScanResultSort::AddressDesc => entries.sort_by(|(left_idx, left), (right_idx, right)| {
            right
                .address
                .cmp(&left.address)
                .then_with(|| left_idx.cmp(right_idx))
        }),
        ScanResultSort::ValueAsc => entries.sort_by(|(left_idx, left), (right_idx, right)| {
            left.value
                .cmp(&right.value)
                .then_with(|| left_idx.cmp(right_idx))
        }),
        ScanResultSort::ValueDesc => entries.sort_by(|(left_idx, left), (right_idx, right)| {
            right
                .value
                .cmp(&left.value)
                .then_with(|| left_idx.cmp(right_idx))
        }),
    }
    entries
}

fn scan_entry_to_json(index: usize, entry: &ScanEntry, value_type: &ScanValueType) -> Value {
    json!({
        "index": index,
        "address": format!("0x{:016X}", entry.address),
        "value": format_value_bytes(&entry.value, value_type),
        "hex": hex::encode(&entry.value),
    })
}

fn encode_scan_result_cursor(
    session_id: &str,
    scan_count: u32,
    sort: ScanResultSort,
    offset: usize,
) -> String {
    format!(
        "{}{}:{}:{}:{}",
        SCAN_RESULT_CURSOR_PREFIX,
        session_id,
        scan_count,
        sort.as_str(),
        offset
    )
}

fn decode_scan_result_cursor(
    cursor: &str,
    expected_session_id: &str,
    expected_scan_count: u32,
    expected_sort: ScanResultSort,
) -> Result<usize, String> {
    let raw = cursor
        .strip_prefix(SCAN_RESULT_CURSOR_PREFIX)
        .ok_or_else(|| "Invalid cursor: unrecognized opaque token".to_string())?;
    let mut parts = raw.split(':');
    let session_id = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Invalid cursor: missing session snapshot".to_string())?;
    let scan_count = parts
        .next()
        .ok_or_else(|| "Invalid cursor: missing scan count".to_string())?
        .parse::<u32>()
        .map_err(|_| "Invalid cursor: malformed scan count".to_string())?;
    let third = parts
        .next()
        .ok_or_else(|| "Invalid cursor: missing pagination position".to_string())?;
    let (sort, offset) = match parts.next() {
        Some(offset) => {
            let sort = ScanResultSort::from_str(third)
                .ok_or_else(|| "Invalid cursor: malformed sort mode".to_string())?;
            let offset = offset
                .parse::<usize>()
                .map_err(|_| "Invalid cursor: malformed pagination position".to_string())?;
            (sort, offset)
        }
        None => {
            let offset = third
                .parse::<usize>()
                .map_err(|_| "Invalid cursor: malformed pagination position".to_string())?;
            (ScanResultSort::IndexAsc, offset)
        }
    };
    if parts.next().is_some() {
        return Err("Invalid cursor: malformed opaque token".to_string());
    }
    if session_id != expected_session_id {
        return Err("Invalid cursor: session mismatch".to_string());
    }
    if scan_count != expected_scan_count {
        return Err("Invalid cursor: scan snapshot changed".to_string());
    }
    if sort != expected_sort {
        return Err("Invalid cursor: sort mode mismatch".to_string());
    }
    Ok(offset)
}

/// Reset/delete a scan session
pub fn scan_reset(args: &Value) -> Result<Value, String> {
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or("scan_reset requires 'session_id'")?;

    let mut store = SESSIONS.lock().map_err(|e| e.to_string())?;
    if store.sessions.remove(session_id).is_some() {
        Ok(json!({ "deleted": session_id, "success": true }))
    } else {
        Err(format!("Session '{}' not found", session_id))
    }
}

/// Freeze/write a value to all results in a session (write-lock)
pub fn scan_freeze(args: &Value) -> Result<Value, String> {
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or("scan_freeze requires 'session_id'")?;

    let store = SESSIONS.lock().map_err(|e| e.to_string())?;
    let session = store
        .sessions
        .get(session_id)
        .ok_or_else(|| format!("Session '{}' not found", session_id))?;

    let value = args.get("value").ok_or("scan_freeze requires 'value'")?;
    let write_bytes = value_to_bytes(value, &session.value_type)?;
    if write_bytes.len() != session.value_size {
        return Err(format!(
            "scan_freeze value has {} bytes, but session '{}' expects {} bytes",
            write_bytes.len(),
            session_id,
            session.value_size
        ));
    }

    let mut success_count = 0u32;
    let mut fail_count = 0u32;

    for entry in &session.results {
        let write_args = json!({
            "pid": session.pid,
            "address": entry.address,
            "bytes": write_bytes.iter().map(|b| *b as u64).collect::<Vec<_>>(),
        });
        match crate::inject::force_write(&write_args) {
            Ok(_) => success_count += 1,
            Err(_) => fail_count += 1,
        }
    }

    Ok(json!({
        "session_id": session_id,
        "addresses_written": success_count,
        "failed": fail_count,
        "value_hex": hex::encode(&write_bytes),
    }))
}

// ── Helpers ──

fn value_to_byte_pattern(value: &Value) -> Result<Vec<Option<u8>>, String> {
    if let Some(arr) = value.as_array() {
        let mut pattern = Vec::with_capacity(arr.len());
        for item in arr {
            if item.is_null() {
                pattern.push(None);
            } else if let Some(byte) = item.as_u64() {
                if byte > u8::MAX as u64 {
                    return Err(format!("Byte value out of range: {}", byte));
                }
                pattern.push(Some(byte as u8));
            } else if let Some(s) = item.as_str() {
                let token = s.trim();
                if token == "?" || token == "??" {
                    pattern.push(None);
                } else {
                    pattern
                        .push(Some(u8::from_str_radix(token, 16).map_err(|e| {
                            format!("Invalid byte token '{}': {}", token, e)
                        })?));
                }
            } else {
                return Err(
                    "Byte pattern arrays must contain integers, null wildcards, or hex tokens"
                        .to_string(),
                );
            }
        }
        return Ok(pattern);
    }

    if let Some(signature) = value.as_str() {
        return parse_byte_signature(signature);
    }

    Err("bytes type requires array, signature string, or pattern string".to_string())
}

fn parse_byte_signature(signature: &str) -> Result<Vec<Option<u8>>, String> {
    let trimmed = signature.trim();
    if trimmed.is_empty() {
        return Err("signature is empty".to_string());
    }

    let tokens: Vec<String> = if trimmed.contains(char::is_whitespace) {
        trimmed.split_whitespace().map(|s| s.to_string()).collect()
    } else {
        let compact = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if compact.contains('?') {
            return Err(
                "compact signatures with wildcards must be space-separated, e.g. '48 8B ?? ??'"
                    .to_string(),
            );
        }
        if compact.len() % 2 != 0 {
            return Err("compact hex signature must have an even number of digits".to_string());
        }
        compact
            .as_bytes()
            .chunks(2)
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect()
    };

    let mut pattern = Vec::with_capacity(tokens.len());
    for token in tokens {
        let token = token.trim();
        if token == "?" || token == "??" {
            pattern.push(None);
        } else if token.len() == 2 && token.chars().all(|c| c.is_ascii_hexdigit()) {
            pattern
                .push(Some(u8::from_str_radix(token, 16).map_err(|e| {
                    format!("Invalid byte token '{}': {}", token, e)
                })?));
        } else {
            return Err(format!(
                "Invalid byte token '{}'. Use hex bytes or ?? wildcards.",
                token
            ));
        }
    }

    Ok(pattern)
}

fn pattern_matches(window: &[u8], pattern: &[Option<u8>]) -> bool {
    window.len() == pattern.len()
        && window
            .iter()
            .zip(pattern)
            .all(|(byte, expected)| expected.map_or(true, |expected| *byte == expected))
}

fn value_to_bytes(value: &Value, vt: &ScanValueType) -> Result<Vec<u8>, String> {
    match vt {
        ScanValueType::U8 => {
            let v = value.as_u64().ok_or("Expected integer")? as u8;
            Ok(vec![v])
        }
        ScanValueType::U16 => {
            let v = value.as_u64().ok_or("Expected integer")? as u16;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::U32 => {
            let v = value.as_u64().ok_or("Expected integer")? as u32;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::U64 => {
            let v = value.as_u64().ok_or("Expected integer")?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::I32 => {
            let v = value.as_i64().ok_or("Expected integer")? as i32;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::I64 => {
            let v = value.as_i64().ok_or("Expected integer")?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::F32 => {
            let v = value.as_f64().ok_or("Expected number")? as f32;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::F64 => {
            let v = value.as_f64().ok_or("Expected number")?;
            Ok(v.to_le_bytes().to_vec())
        }
        ScanValueType::Bytes => {
            if let Some(arr) = value.as_array() {
                Ok(arr
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect())
            } else if let Some(s) = value.as_str() {
                hex::decode(s.replace(' ', "")).map_err(|e| format!("Invalid hex: {}", e))
            } else {
                Err("bytes type requires array or hex string".to_string())
            }
        }
    }
}

fn format_value_bytes(bytes: &[u8], vt: &ScanValueType) -> Value {
    match vt {
        ScanValueType::U8 => json!(bytes[0] as u64),
        ScanValueType::U16 => {
            json!(u16::from_le_bytes(bytes.try_into().unwrap_or_default()) as u64)
        }
        ScanValueType::U32 => {
            json!(u32::from_le_bytes(bytes.try_into().unwrap_or_default()) as u64)
        }
        ScanValueType::U64 => json!(u64::from_le_bytes(bytes.try_into().unwrap_or_default())),
        ScanValueType::I32 => json!(i32::from_le_bytes(bytes.try_into().unwrap_or_default())),
        ScanValueType::I64 => json!(i64::from_le_bytes(bytes.try_into().unwrap_or_default())),
        ScanValueType::F32 => json!(f32::from_le_bytes(bytes.try_into().unwrap_or_default())),
        ScanValueType::F64 => json!(f64::from_le_bytes(bytes.try_into().unwrap_or_default())),
        ScanValueType::Bytes => json!(hex::encode(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_scan_delta_summary, scan_list, ScanEntry, ScanSession, ScanValueType,
        SCAN_RESULT_CURSOR_PREFIX, SESSIONS,
    };
    use serde_json::json;

    fn insert_scan_session(session_id: &str, scan_count: u32) {
        insert_scan_session_with_results(
            session_id,
            scan_count,
            vec![
                ScanEntry {
                    address: 0x1000,
                    value: 1u32.to_le_bytes().to_vec(),
                },
                ScanEntry {
                    address: 0x2000,
                    value: 2u32.to_le_bytes().to_vec(),
                },
                ScanEntry {
                    address: 0x3000,
                    value: 3u32.to_le_bytes().to_vec(),
                },
            ],
        );
    }

    fn insert_scan_session_with_results(
        session_id: &str,
        scan_count: u32,
        results: Vec<ScanEntry>,
    ) {
        let mut store = SESSIONS.lock().expect("scan session store");
        store.sessions.insert(
            session_id.to_string(),
            ScanSession {
                id: session_id.to_string(),
                pid: 1234,
                value_type: ScanValueType::U32,
                value_size: 4,
                results,
                history: Vec::new(),
                created_at: 1,
                last_scan_at: 2,
                scan_count,
            },
        );
    }

    fn remove_scan_session(session_id: &str) {
        let mut store = SESSIONS.lock().expect("scan session store");
        store.sessions.remove(session_id);
    }

    #[test]
    fn scan_list_pages_session_candidates_with_opaque_cursor() {
        let session_id = "scan_test_pagination";
        insert_scan_session(session_id, 1);

        let first = scan_list(&json!({
            "session_id": session_id,
            "limit": 2
        }))
        .expect("first page");
        assert_eq!(first["session_id"], session_id);
        assert_eq!(first["count"], 2);
        assert_eq!(first["total"], 3);
        assert_eq!(first["candidates"].as_array().unwrap().len(), 2);
        let cursor = first["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_string();
        assert!(cursor.starts_with(SCAN_RESULT_CURSOR_PREFIX));

        let second = scan_list(&json!({
            "session_id": session_id,
            "cursor": cursor
        }))
        .expect("second page");
        assert_eq!(second["count"], 1);
        assert_eq!(second["offset"], 2);
        assert_eq!(second["candidates"][0]["index"], 2);
        assert_eq!(second["candidates"][0]["value"], 3);
        assert!(second.get("nextCursor").is_none());

        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_rejects_invalid_or_stale_result_cursors() {
        let session_id = "scan_test_invalid_cursor";
        insert_scan_session(session_id, 1);

        let err = scan_list(&json!({
            "session_id": session_id,
            "cursor": "not-a-scan-cursor"
        }))
        .expect_err("invalid prefix should fail");
        assert!(err.contains("Invalid cursor"));

        let first = scan_list(&json!({
            "session_id": session_id,
            "limit": 2
        }))
        .expect("first page");
        let cursor = first["nextCursor"].as_str().unwrap().to_string();
        {
            let mut store = SESSIONS.lock().expect("scan session store");
            let session = store.sessions.get_mut(session_id).expect("session");
            session.scan_count += 1;
        }

        let err = scan_list(&json!({
            "session_id": session_id,
            "cursor": cursor
        }))
        .expect_err("stale cursor should fail");
        assert!(err.contains("scan snapshot changed"));

        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_rejects_zero_result_page_limit() {
        let session_id = "scan_test_zero_limit";
        insert_scan_session(session_id, 1);

        let err = scan_list(&json!({
            "session_id": session_id,
            "limit": 0
        }))
        .expect_err("zero limit should fail");
        assert!(err.contains("greater than 0"));

        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_summary_only_returns_metadata_without_candidates_or_cursor() {
        let session_id = "scan_test_summary_only";
        insert_scan_session(session_id, 1);

        let result = scan_list(&json!({
            "session_id": session_id,
            "limit": 1,
            "summary_only": true
        }))
        .expect("summary-only scan list");

        assert_eq!(result["session_id"], session_id);
        assert_eq!(result["summary_only"], true);
        assert_eq!(result["total"], 3);
        assert_eq!(result["count"], 0);
        assert_eq!(result["candidates"].as_array().unwrap().len(), 0);
        assert!(result.get("nextCursor").is_none());
        assert_eq!(result["snapshot"]["total"], 3);

        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_sorts_candidates_and_binds_cursor_to_sort_mode() {
        let session_id = "scan_test_sort";
        insert_scan_session_with_results(
            session_id,
            1,
            vec![
                ScanEntry {
                    address: 0x3000,
                    value: 3u32.to_le_bytes().to_vec(),
                },
                ScanEntry {
                    address: 0x1000,
                    value: 1u32.to_le_bytes().to_vec(),
                },
                ScanEntry {
                    address: 0x2000,
                    value: 2u32.to_le_bytes().to_vec(),
                },
            ],
        );

        let first = scan_list(&json!({
            "session_id": session_id,
            "limit": 2,
            "sort": "address_asc"
        }))
        .expect("sorted first page");
        assert_eq!(first["sort"], "address_asc");
        assert_eq!(first["candidates"][0]["address"], "0x0000000000001000");
        assert_eq!(first["candidates"][0]["index"], 1);
        assert_eq!(first["candidates"][1]["address"], "0x0000000000002000");
        assert_eq!(first["candidates"][1]["index"], 2);
        let cursor = first["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_string();

        let mismatch = scan_list(&json!({
            "session_id": session_id,
            "cursor": cursor,
            "sort": "address_desc"
        }))
        .expect_err("cursor should be bound to sort");
        assert!(mismatch.contains("sort mode mismatch"));

        let second = scan_list(&json!({
            "session_id": session_id,
            "cursor": first["nextCursor"].as_str().unwrap(),
            "sort": "address_asc"
        }))
        .expect("sorted second page");
        assert_eq!(second["count"], 1);
        assert_eq!(second["candidates"][0]["address"], "0x0000000000003000");
        assert_eq!(second["candidates"][0]["index"], 0);

        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_rejects_invalid_sort_value() {
        let session_id = "scan_test_invalid_sort";
        insert_scan_session(session_id, 1);

        let err = scan_list(&json!({
            "session_id": session_id,
            "sort": "bad"
        }))
        .expect_err("invalid sort should fail");
        assert!(err.contains("Invalid 'sort'"));

        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_exports_full_session_candidates_to_artifact() {
        let session_id = "scan_test_export";
        insert_scan_session(session_id, 1);
        let output_path = std::env::temp_dir().join(format!(
            "memoric-scan-export-{}-{}.json",
            std::process::id(),
            session_id
        ));
        let _ = std::fs::remove_file(&output_path);

        let result = scan_list(&json!({
            "session_id": session_id,
            "limit": 1,
            "sort": "address_desc",
            "output_path": output_path.display().to_string(),
            "artifact_retention_secs": 60,
            "request_id": "scan-export-test"
        }))
        .expect("scan export");

        assert_eq!(result["count"], 1);
        assert_eq!(result["total"], 3);
        assert_eq!(result["exported_count"], 3);
        assert_eq!(result["redaction_status"], "artifact");
        assert_eq!(result["output_path"], output_path.display().to_string());
        let uri = result["artifact"]["uri"].as_str().expect("artifact uri");
        assert!(crate::artifact::is_artifact_uri(uri));

        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output_path).expect("scan artifact file"))
                .expect("scan artifact json");
        assert_eq!(exported["kind"], "scan-results");
        assert_eq!(exported["session_id"], session_id);
        assert_eq!(exported["sort"], "address_desc");
        assert_eq!(exported["total"], 3);
        assert_eq!(exported["candidates"].as_array().unwrap().len(), 3);
        assert_eq!(exported["candidates"][0]["address"], "0x0000000000003000");

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(output_path);
        remove_scan_session(session_id);
    }

    #[test]
    fn scan_list_auto_exports_large_session_candidates_to_artifact() {
        let session_id = "scan_test_auto_export";
        let results = (0..1001)
            .map(|idx| ScanEntry {
                address: 0x1000 + (idx as u64 * 4),
                value: (idx as u32).to_le_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        insert_scan_session_with_results(session_id, 1, results);

        let result = scan_list(&json!({
            "session_id": session_id,
            "limit": 1,
            "artifact_retention_secs": 60,
            "request_id": "scan-auto-export-test"
        }))
        .expect("scan auto export");

        assert_eq!(result["count"], 1);
        assert_eq!(result["total"], 1001);
        assert_eq!(result["exported_count"], 1001);
        assert_eq!(result["redaction_status"], "artifact");
        assert_eq!(result["export_reason"], "large_session_auto");
        let uri = result["artifact"]["uri"].as_str().expect("artifact uri");
        assert!(crate::artifact::is_artifact_uri(uri));
        let output_path = result["output_path"].as_str().expect("output path");
        assert!(std::path::Path::new(output_path).exists());

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(output_path);
        remove_scan_session(session_id);
    }

    #[test]
    fn scan_delta_summary_reports_safe_counts_without_raw_bytes() {
        let summary = build_scan_delta_summary(10, 4, 3, 5, 2);

        assert_eq!(summary["before"], 10);
        assert_eq!(summary["after"], 4);
        assert_eq!(summary["added"], 0);
        assert_eq!(summary["removed"], 6);
        assert_eq!(summary["changed"], 3);
        assert_eq!(summary["unchanged"], 5);
        assert_eq!(summary["unreadable"], 2);
        assert_eq!(summary["readable"], 8);
        assert_eq!(summary["retained"], 4);
        assert!(summary.get("value").is_none());
        assert!(summary.get("hex").is_none());
        assert!(summary.get("bytes").is_none());
    }
}

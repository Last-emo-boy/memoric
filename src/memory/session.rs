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
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Get all readable memory regions of a process
fn get_scannable_regions(pid: u32) -> Result<Vec<(u64, usize)>, String> {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| format!("OpenProcess: {}", e))?;
        let _guard = crate::safe_handle::SafeHandle::new(handle);

        let mut regions = Vec::new();
        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        loop {
            let ret = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if ret == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT
                && mbi.Protect.0 & PAGE_GUARD.0 == 0
                && mbi.Protect.0 & PAGE_NOACCESS.0 == 0
                && mbi.RegionSize > 0
            {
                regions.push((mbi.BaseAddress as u64, mbi.RegionSize));
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break; // overflow — reached end of address space
            }
        }

        Ok(regions)
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

    // Get all scannable regions
    let regions = get_scannable_regions(pid)?;
    tracing::info!("[SCAN] {} scannable regions found", regions.len());

    let mut results: Vec<ScanEntry> = Vec::new();
    let mut regions_scanned = 0u32;
    let mut bytes_scanned = 0u64;

    for (base, size) in &regions {
        match read_process_memory_bytes(pid, *base, *size) {
            Ok(data) => {
                regions_scanned += 1;
                bytes_scanned += data.len() as u64;
                if data.len() < value_size {
                    continue;
                }

                // Scan for exact match
                for offset in 0..=(data.len() - value_size) {
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
            Err(_) => continue, // skip unreadable regions
        }
    }

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

    // Save current state for undo
    session.history.push(session.results.clone());

    // Re-read current values and filter
    let mut new_results: Vec<ScanEntry> = Vec::new();
    for entry in &session.results {
        match read_process_memory_bytes(session.pid, entry.address, value_size) {
            Ok(current) if current.len() == value_size => {
                if compare_numeric(&entry.value, &current, &filter) {
                    new_results.push(ScanEntry {
                        address: entry.address,
                        value: current,
                    });
                }
            }
            _ => continue, // address became unreadable — discard
        }
    }

    let after_count = new_results.len();
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
        "scan_count": session.scan_count,
        "preview": preview,
        "message": format!("{} → {} results ({} eliminated). {}",
            before_count, after_count, before_count - after_count,
            if after_count <= 5 { "Likely found the target!" }
            else if after_count == 0 { "All eliminated — try scan_undo" }
            else { "Continue narrowing with scan_next" }
        )
    }))
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

/// List active scan sessions
pub fn scan_list(_args: &Value) -> Result<Value, String> {
    let store = SESSIONS.lock().map_err(|e| e.to_string())?;
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

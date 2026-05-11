//! MCP Session State Management
//!
//! Global session state tracking for the MCP server lifecycle. Instruments
//! stealth, detection, injection, and kernel tools to maintain a coherent
//! view of the operator's current position on the target.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

lazy_static! {
    static ref SESSION: Mutex<SessionState> = Mutex::new(SessionState::new());
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub started_at: String,
    pub target_pid: Option<u32>,
    pub detected_edrs: Vec<EdrRecord>,
    pub loaded_driver: Option<DriverRecord>,
    pub evasion_applied: Vec<EvasionRecord>,
    pub active_injections: Vec<InjectionRecord>,
    pub stealth_score: Option<StealthAssessment>,
    pub kernel_callbacks_status: KernelCallbackStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrRecord {
    pub product: String,
    pub process_name: String,
    pub pid: u32,
    pub detected_at: String,
    pub confidence: String, // "high", "medium", "low"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverRecord {
    pub name: String,
    pub device_path: String,
    pub loaded_at: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionRecord {
    pub technique: String,
    pub target: String,
    pub applied_at: String,
    pub status: String, // "applied", "failed", "reverted"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionRecord {
    pub pid: u32,
    pub technique: String,
    pub shellcode_size: usize,
    pub injected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAssessment {
    pub total_score: u32, // 0-100
    pub etw_patched: bool,
    pub amsi_patched: bool,
    pub ntdll_unhooked: bool,
    pub modules_hidden: bool,
    pub callbacks_removed: u32,
    pub minifilters_detached: u32,
    pub edr_processes_detected: u32,
    pub assessed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCallbackStatus {
    pub process_callbacks: u32,
    pub thread_callbacks: u32,
    pub image_callbacks: u32,
    pub object_callbacks: u32,
    pub registry_callbacks: u32,
    pub etw_ti_enabled: bool,
    pub last_enum_at: Option<String>,
}

impl Default for KernelCallbackStatus {
    fn default() -> Self {
        Self {
            process_callbacks: 0,
            thread_callbacks: 0,
            image_callbacks: 0,
            object_callbacks: 0,
            registry_callbacks: 0,
            etw_ti_enabled: true,
            last_enum_at: None,
        }
    }
}

impl SessionState {
    fn new() -> Self {
        let now = chrono_now();
        Self {
            session_id: uuid_v4(),
            started_at: now.clone(),
            target_pid: None,
            detected_edrs: Vec::new(),
            loaded_driver: None,
            evasion_applied: Vec::new(),
            active_injections: Vec::new(),
            stealth_score: None,
            kernel_callbacks_status: KernelCallbackStatus::default(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

fn chrono_now() -> String {
    chrono_now_public()
}

/// Public re-export for other modules that need ISO timestamps
pub fn chrono_now_public() -> String {
    use std::time::SystemTime;
    // ISO-8601 UTC timestamp via SystemTime (no chrono dependency)
    let dur = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Rough ISO-8601: seconds since epoch as UTC date
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let secs_part = time_of_day % 60;
    // Days since 1970-01-01 to year/month/day (simplified but correct)
    let (y, m, d) = days_to_ymd(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, mins, secs_part
    )
}

fn days_to_ymd(mut days: i64) -> (i64, u32, u32) {
    // Algorithm from Howard Hinnant, works for 1970-2100
    days += 719468; // shift epoch to 0000-03-01
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("memoric-{:016x}", ts.as_secs())
}

// ─── Public getter ───────────────────────────────────────────────────────────

pub fn get_state() -> Result<SessionState, String> {
    SESSION
        .lock()
        .map(|s| s.clone())
        .map_err(|e| format!("Session lock error: {}", e))
}

pub fn get_state_json() -> Result<serde_json::Value, String> {
    let state = get_state()?;
    serde_json::to_value(&state).map_err(|e| format!("Serialize error: {}", e))
}

// ─── Mutation helpers ────────────────────────────────────────────────────────

fn with_state<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut SessionState) -> R,
{
    SESSION
        .lock()
        .map(|mut s| f(&mut s))
        .map_err(|e| format!("Session lock error: {}", e))
}

pub fn set_target(pid: u32) {
    let _ = with_state(|s| {
        s.target_pid = Some(pid);
    });
}

pub fn record_edr_detection(products: &[EdrRecord]) {
    let _ = with_state(|s| {
        for p in products {
            if !s.detected_edrs.iter().any(|e| e.product == p.product) {
                s.detected_edrs.push(p.clone());
            }
        }
    });
}

pub fn record_driver(name: &str, device_path: &str, capabilities: &[&str]) {
    let _ = with_state(|s| {
        s.loaded_driver = Some(DriverRecord {
            name: name.to_string(),
            device_path: device_path.to_string(),
            loaded_at: chrono_now(),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        });
    });
}

pub fn record_evasion(technique: &str, target: &str, status: &str) {
    let _ = with_state(|s| {
        s.evasion_applied.push(EvasionRecord {
            technique: technique.to_string(),
            target: target.to_string(),
            applied_at: chrono_now(),
            status: status.to_string(),
        });
    });
}

pub fn record_injection(pid: u32, technique: &str, shellcode_size: usize) {
    let _ = with_state(|s| {
        s.active_injections.push(InjectionRecord {
            pid,
            technique: technique.to_string(),
            shellcode_size,
            injected_at: chrono_now(),
        });
    });
}

pub fn update_stealth_score(assessment: StealthAssessment) {
    let _ = with_state(|s| {
        s.stealth_score = Some(assessment);
    });
}

pub fn update_kernel_callbacks(status: KernelCallbackStatus) {
    let _ = with_state(|s| {
        s.kernel_callbacks_status = status;
    });
}

/// Reset the session to defaults (for fresh start)
pub fn reset_session() {
    let _ = with_state(|s| s.reset());
}

/// Compute a fresh stealth score from current state
pub fn compute_stealth_score() -> StealthAssessment {
    let state = get_state().unwrap_or_default();
    let mut score: u32 = 0;

    // ETW patched: +20
    let etw_patched = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("etw") && e.status == "applied");
    if etw_patched {
        score += 20;
    }

    // AMSI patched: +20
    let amsi_patched = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("amsi") && e.status == "applied");
    if amsi_patched {
        score += 20;
    }

    // ntdll unhooked: +15
    let ntdll_unhooked = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("unhook") && e.status == "applied");
    if ntdll_unhooked {
        score += 15;
    }

    // Modules hidden: +10
    let modules_hidden = state
        .evasion_applied
        .iter()
        .any(|e| e.technique.contains("hide_module") && e.status == "applied");
    if modules_hidden {
        score += 10;
    }

    // Kernel callbacks removed (each ~5 points, max 20)
    let cb = &state.kernel_callbacks_status;
    let callbacks_removed = cb.process_callbacks + cb.thread_callbacks + cb.image_callbacks;
    score += std::cmp::min(callbacks_removed * 5, 20);

    // Minifilters detached (each ~3 points, max 10)
    let minifilter_bonus = state
        .evasion_applied
        .iter()
        .filter(|e| e.technique.contains("minifilter"))
        .count() as u32
        * 3;
    score += std::cmp::min(minifilter_bonus, 10);

    // EDR penalty: -5 per EDR still detected
    let edr_penalty = std::cmp::min(state.detected_edrs.len() as u32 * 5, 25);
    score = score.saturating_sub(edr_penalty);

    // Cap at 100
    score = std::cmp::min(score, 100);

    StealthAssessment {
        total_score: score,
        etw_patched,
        amsi_patched,
        ntdll_unhooked,
        modules_hidden,
        callbacks_removed,
        minifilters_detached: minifilter_bonus / 3,
        edr_processes_detected: state.detected_edrs.len() as u32,
        assessed_at: chrono_now(),
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

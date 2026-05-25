//! Per-process memory region metadata cache.
//!
//! The cache stores only VirtualQueryEx-style region metadata. It never stores
//! memory bytes.

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_REGION_CACHE_TTL_MS: u64 = 5_000;
pub const MAX_REGION_CACHE_TTL_MS: u64 = 5 * 60 * 1_000;
const MEM_COMMIT_BITS: u32 = 0x1000;
const PAGE_NOACCESS_BITS: u32 = 0x01;
const PAGE_GUARD_BITS: u32 = 0x100;

static REGION_CACHE: Lazy<Mutex<RegionCacheStore>> =
    Lazy::new(|| Mutex::new(RegionCacheStore::new()));

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub region_type: u32,
}

impl MemoryRegion {
    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.size as u64)
    }

    pub fn as_scan_range(&self) -> (u64, usize) {
        (self.base_address, self.size)
    }

    pub fn is_scannable(&self) -> bool {
        self.state == MEM_COMMIT_BITS
            && self.size > 0
            && (self.protect & PAGE_GUARD_BITS) == 0
            && (self.protect & PAGE_NOACCESS_BITS) == 0
    }
}

#[derive(Clone, Debug)]
pub struct RegionCacheOptions {
    enabled: bool,
    force_refresh: bool,
    clear_first: bool,
    ttl_ms: u64,
}

impl RegionCacheOptions {
    pub fn from_args(args: &Value) -> Result<Self, String> {
        let mut options = Self {
            enabled: true,
            force_refresh: false,
            clear_first: false,
            ttl_ms: DEFAULT_REGION_CACHE_TTL_MS,
        };

        if let Some(mode) = args.get("region_cache").and_then(|value| value.as_str()) {
            match mode.trim().to_ascii_lowercase().as_str() {
                "" | "auto" | "use" | "enabled" | "on" => {}
                "refresh" | "force_refresh" => options.force_refresh = true,
                "clear" | "invalidate" => {
                    options.clear_first = true;
                    options.force_refresh = true;
                }
                "off" | "disabled" | "disable" | "none" | "bypass" => options.enabled = false,
                other => {
                    return Err(format!(
                        "Invalid region_cache '{}'; expected auto, refresh, clear, or off",
                        other
                    ));
                }
            }
        }

        if args
            .get("region_cache_refresh")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            options.force_refresh = true;
        }
        if args
            .get("region_cache_clear")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
        {
            options.clear_first = true;
            options.force_refresh = true;
        }

        if let Some(ttl) = crate::args::parse_u64_value(args.get("region_cache_ttl_ms")) {
            options.ttl_ms = ttl;
        } else if let Some(ttl_secs) =
            crate::args::parse_u64_value(args.get("region_cache_ttl_secs"))
        {
            options.ttl_ms = ttl_secs.saturating_mul(1_000);
        }

        if options.ttl_ms > MAX_REGION_CACHE_TTL_MS {
            return Err(format!(
                "'region_cache_ttl_ms' exceeds maximum {}",
                MAX_REGION_CACHE_TTL_MS
            ));
        }

        Ok(options)
    }
}

#[derive(Clone, Debug)]
struct CachedRegionList {
    regions: Vec<MemoryRegion>,
    captured_at: Instant,
    generation: u64,
}

#[derive(Debug)]
struct RegionCacheStore {
    entries: HashMap<u32, CachedRegionList>,
    next_generation: u64,
}

impl RegionCacheStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            next_generation: 1,
        }
    }

    fn clear_pid(&mut self, pid: u32) -> bool {
        self.entries.remove(&pid).is_some()
    }

    fn get_or_refresh_with<F>(
        &mut self,
        pid: u32,
        options: &RegionCacheOptions,
        now: Instant,
        loader: F,
    ) -> Result<RegionCacheQuery, String>
    where
        F: FnOnce() -> Result<Vec<MemoryRegion>, String>,
    {
        if options.clear_first {
            self.clear_pid(pid);
        }

        if options.enabled && !options.force_refresh {
            if let Some(entry) = self.entries.get(&pid) {
                let age = now.saturating_duration_since(entry.captured_at);
                if age <= Duration::from_millis(options.ttl_ms) {
                    return Ok(RegionCacheQuery::from_cache_entry(
                        pid, options, entry, age, true,
                    ));
                }
            }
        }

        let regions = loader()?;
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1);
        let entry = CachedRegionList {
            regions: regions.clone(),
            captured_at: now,
            generation,
        };

        if options.enabled {
            self.entries.insert(pid, entry.clone());
        }

        Ok(RegionCacheQuery::from_cache_entry(
            pid,
            options,
            &entry,
            Duration::ZERO,
            false,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct RegionCacheQuery {
    pub regions: Vec<MemoryRegion>,
    pub report: RegionCacheReport,
}

impl RegionCacheQuery {
    fn from_cache_entry(
        pid: u32,
        options: &RegionCacheOptions,
        entry: &CachedRegionList,
        age: Duration,
        reused: bool,
    ) -> Self {
        Self {
            regions: entry.regions.clone(),
            report: RegionCacheReport::new(
                pid,
                options.enabled,
                reused,
                age,
                options.ttl_ms,
                entry.generation,
                &entry.regions,
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RegionCacheReport {
    pid: u32,
    enabled: bool,
    reused: bool,
    age_ms: u64,
    ttl_ms: u64,
    generation: u64,
    region_count: usize,
    total_bytes: u64,
    min_address: Option<u64>,
    max_address: Option<u64>,
}

impl RegionCacheReport {
    fn new(
        pid: u32,
        enabled: bool,
        reused: bool,
        age: Duration,
        ttl_ms: u64,
        generation: u64,
        regions: &[MemoryRegion],
    ) -> Self {
        let min_address = regions.iter().map(|region| region.base_address).min();
        let max_address = regions.iter().map(MemoryRegion::end_address).max();
        let total_bytes = regions
            .iter()
            .map(|region| region.size as u64)
            .fold(0u64, u64::saturating_add);

        Self {
            pid,
            enabled,
            reused,
            age_ms: age.as_millis().min(u128::from(u64::MAX)) as u64,
            ttl_ms,
            generation,
            region_count: regions.len(),
            total_bytes,
            min_address,
            max_address,
        }
    }

    pub fn reused(&self) -> bool {
        self.reused
    }

    pub fn age_ms(&self) -> u64 {
        self.age_ms
    }

    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "pid": self.pid,
            "source": if self.reused { "cache" } else { "refresh" },
            "reused": self.reused,
            "age_ms": self.age_ms,
            "ttl_ms": self.ttl_ms,
            "generation": self.generation,
            "coverage": {
                "regions": self.region_count,
                "total_bytes": self.total_bytes,
                "min_address": self.min_address.map(|address| format!("0x{:016X}", address)),
                "max_address": self.max_address.map(|address| format!("0x{:016X}", address)),
            }
        })
    }
}

pub fn get_memory_regions(pid: u32, args: &Value) -> Result<RegionCacheQuery, String> {
    let options = RegionCacheOptions::from_args(args)?;
    if options.enabled && !process_is_likely_active(pid) {
        let _ = clear_region_cache_for_pid(pid)?;
    }

    let mut store = REGION_CACHE.lock().map_err(|err| err.to_string())?;
    store.get_or_refresh_with(pid, &options, Instant::now(), || {
        enumerate_memory_regions(pid)
    })
}

pub fn get_scannable_regions(pid: u32, args: &Value) -> Result<RegionCacheQuery, String> {
    let query = get_memory_regions(pid, args)?;
    let regions = query
        .regions
        .into_iter()
        .filter(MemoryRegion::is_scannable)
        .collect::<Vec<_>>();
    let entry = CachedRegionList {
        regions,
        captured_at: Instant::now()
            .checked_sub(Duration::from_millis(query.report.age_ms))
            .unwrap_or_else(Instant::now),
        generation: query.report.generation,
    };

    Ok(RegionCacheQuery::from_cache_entry(
        pid,
        &RegionCacheOptions {
            enabled: query.report.enabled,
            force_refresh: false,
            clear_first: false,
            ttl_ms: query.report.ttl_ms,
        },
        &entry,
        Duration::from_millis(query.report.age_ms),
        query.report.reused,
    ))
}

pub fn clear_region_cache_for_pid(pid: u32) -> Result<bool, String> {
    let mut store = REGION_CACHE.lock().map_err(|err| err.to_string())?;
    Ok(store.clear_pid(pid))
}

#[cfg(test)]
pub fn cached_region_count_for_pid(pid: u32) -> Result<usize, String> {
    let store = REGION_CACHE.lock().map_err(|err| err.to_string())?;
    Ok(store
        .entries
        .get(&pid)
        .map(|entry| entry.regions.len())
        .unwrap_or(0))
}

fn enumerate_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>, String> {
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|err| format!("OpenProcess: {}", err))?;
        let _guard = crate::safe_handle::SafeHandle::new(handle);

        let mut regions = Vec::new();
        let mut address: usize = 0;

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ret = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if ret == 0 {
                break;
            }

            if mbi.RegionSize > 0 {
                regions.push(MemoryRegion {
                    base_address: mbi.BaseAddress as u64,
                    size: mbi.RegionSize,
                    state: mbi.State.0,
                    protect: mbi.Protect.0,
                    region_type: mbi.Type.0,
                });
            }

            let next = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            if next == 0 || next <= address {
                break;
            }
            address = next;
        }

        Ok(regions)
    }
}

fn process_is_likely_active(pid: u32) -> bool {
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE_EXIT_CODE: u32 = 259;

    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let _guard = crate::safe_handle::SafeHandle::new(handle);
                let mut exit_code = 0u32;
                GetExitCodeProcess(handle, &mut exit_code).is_ok()
                    && exit_code == STILL_ACTIVE_EXIT_CODE
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cached_region_count_for_pid, clear_region_cache_for_pid, get_scannable_regions,
        CachedRegionList, MemoryRegion, RegionCacheOptions, RegionCacheStore, REGION_CACHE,
    };
    use serde_json::json;
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    fn region(base_address: u64, size: usize) -> MemoryRegion {
        MemoryRegion {
            base_address,
            size,
            state: 0x1000,
            protect: 0x04,
            region_type: 0x20000,
        }
    }

    #[test]
    fn fresh_cache_entry_is_reused_until_ttl_expires() {
        let mut store = RegionCacheStore::new();
        let options =
            RegionCacheOptions::from_args(&json!({"region_cache_ttl_ms": 1000})).expect("options");
        let now = Instant::now();
        let loads = Cell::new(0);

        let first = store
            .get_or_refresh_with(42, &options, now, || {
                loads.set(loads.get() + 1);
                Ok(vec![region(0x1000, 0x100)])
            })
            .expect("first query");
        assert!(!first.report.reused());
        assert_eq!(first.report.age_ms(), 0);

        let second = store
            .get_or_refresh_with(42, &options, now + Duration::from_millis(250), || {
                loads.set(loads.get() + 1);
                Ok(vec![region(0x2000, 0x100)])
            })
            .expect("second query");
        assert!(second.report.reused());
        assert_eq!(second.report.age_ms(), 250);
        assert_eq!(second.regions[0].base_address, 0x1000);
        assert_eq!(loads.get(), 1);
    }

    #[test]
    fn stale_cache_entry_refreshes_with_new_generation() {
        let mut store = RegionCacheStore::new();
        let options =
            RegionCacheOptions::from_args(&json!({"region_cache_ttl_ms": 10})).expect("options");
        let now = Instant::now();

        let first = store
            .get_or_refresh_with(7, &options, now, || Ok(vec![region(0x1000, 0x100)]))
            .expect("first query");
        let second = store
            .get_or_refresh_with(7, &options, now + Duration::from_millis(11), || {
                Ok(vec![region(0x2000, 0x200)])
            })
            .expect("second query");

        assert!(!second.report.reused());
        assert!(
            second.report.to_json()["generation"].as_u64().unwrap()
                > first.report.to_json()["generation"].as_u64().unwrap()
        );
        assert_eq!(second.regions[0].base_address, 0x2000);
    }

    #[test]
    fn clear_request_invalidates_before_loading() {
        let mut store = RegionCacheStore::new();
        let now = Instant::now();
        let auto = RegionCacheOptions::from_args(&json!({})).expect("auto options");
        store
            .get_or_refresh_with(9, &auto, now, || Ok(vec![region(0x1000, 0x100)]))
            .expect("seed cache");

        let clear =
            RegionCacheOptions::from_args(&json!({"region_cache": "clear"})).expect("clear");
        let query = store
            .get_or_refresh_with(9, &clear, now + Duration::from_millis(1), || {
                Ok(vec![region(0x3000, 0x300)])
            })
            .expect("clear query");

        assert!(!query.report.reused());
        assert_eq!(query.regions[0].base_address, 0x3000);
    }

    #[test]
    fn disabled_cache_does_not_populate_store() {
        let mut store = RegionCacheStore::new();
        let off = RegionCacheOptions::from_args(&json!({"region_cache": "off"})).expect("off");
        let now = Instant::now();

        store
            .get_or_refresh_with(11, &off, now, || Ok(vec![region(0x1000, 0x100)]))
            .expect("disabled first query");
        let second = store
            .get_or_refresh_with(11, &off, now + Duration::from_millis(1), || {
                Ok(vec![region(0x2000, 0x100)])
            })
            .expect("disabled second query");

        assert!(!second.report.reused());
        assert_eq!(second.regions[0].base_address, 0x2000);
    }

    #[test]
    fn global_cache_clears_entry_for_inactive_pid_before_refresh() {
        let unlikely_pid = u32::MAX;
        let _ = clear_region_cache_for_pid(unlikely_pid);

        {
            let mut store = REGION_CACHE.lock().expect("cache lock");
            store.entries.insert(
                unlikely_pid,
                CachedRegionList {
                    regions: vec![region(0x1000, 0x100)],
                    captured_at: Instant::now(),
                    generation: 99,
                },
            );
        }
        assert_eq!(
            cached_region_count_for_pid(unlikely_pid).expect("cache count"),
            1
        );

        let result = get_scannable_regions(unlikely_pid, &json!({}));
        assert!(result.is_err(), "inactive PID should not refresh");
        assert_eq!(
            cached_region_count_for_pid(unlikely_pid).expect("cache count after failed refresh"),
            0
        );
    }
}

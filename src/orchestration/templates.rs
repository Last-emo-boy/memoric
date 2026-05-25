//! Orchestration template registry.
//!
//! Templates are metadata and plan seeds only. They do not execute actions.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateCategory {
    Reconnaissance,
    MemoryDiagnostics,
    DriverReadiness,
    AuthorizedLabValidation,
    Cleanup,
    PrivilegeReview,
}

impl TemplateCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reconnaissance => "reconnaissance",
            Self::MemoryDiagnostics => "memory_diagnostics",
            Self::DriverReadiness => "driver_readiness",
            Self::AuthorizedLabValidation => "authorized_lab_validation",
            Self::Cleanup => "cleanup",
            Self::PrivilegeReview => "privilege_review",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Template {
    pub id: &'static str,
    pub category: TemplateCategory,
    pub description: &'static str,
    pub safe_by_default: bool,
    pub requires_explicit_target: bool,
    pub steps: &'static [&'static str],
}

const TEMPLATES: &[Template] = &[
    Template {
        id: "reconnaissance",
        category: TemplateCategory::Reconnaissance,
        description: "Read-only target reconnaissance and environment summary",
        safe_by_default: true,
        requires_explicit_target: false,
        steps: &[
            "target(action='ps_list') -> enumerate processes",
            "detect(action='edr_products') -> identify security products",
            "detect(action='vm_sandbox') -> inspect virtualization/sandbox signals",
            "memory(action='diagnostics', pid=<pid>) -> optional read-only target memory profile",
        ],
    },
    Template {
        id: "memory_diagnostics",
        category: TemplateCategory::MemoryDiagnostics,
        description: "Read-only memory layout, module, handle, suspicious-region, and entropy profile",
        safe_by_default: true,
        requires_explicit_target: false,
        steps: &[
            "self(action='memory_diagnostics', include_handles=false, include_entropy=true) -> local baseline",
            "memory(action='diagnostics', pid=<pid>, include_handles=true, include_entropy=true) -> target profile when explicitly selected",
            "memory(action='query', pid=<pid>) -> committed region inventory",
        ],
    },
    Template {
        id: "driver_readiness",
        category: TemplateCategory::DriverReadiness,
        description: "Probe-only driver and platform readiness checks",
        safe_by_default: true,
        requires_explicit_target: false,
        steps: &[
            "self(action='doctor') -> policy, privilege, and driver payload readiness",
            "resources/read(uri='memoric://capabilities') -> capability matrix",
            "kernel(action='driver_discover') -> enumerate known driver candidates without loading them",
        ],
    },
    Template {
        id: "lab_validation",
        category: TemplateCategory::AuthorizedLabValidation,
        description: "Controlled install validation against the current process or an explicitly launched benign test target",
        safe_by_default: true,
        requires_explicit_target: false,
        steps: &[
            "self(action='test', include_scan=false) -> validate local read path",
            "self(action='memory_diagnostics', include_handles=false, include_entropy=false) -> local read-only diagnostics",
            "memory(action='diagnostics', pid=<benign_pid>, include_handles=false, include_entropy=false) -> optional benign target profile",
            "memory(action='read', pid=<benign_pid>, address=<marker_address>, size=<marker_len>) -> optional benign marker read",
            "memory(action='write', pid=<benign_pid>, address=<counter_address>, bytes=[...], dry_run=true) -> preview mutation only",
        ],
    },
    Template {
        id: "cleanup",
        category: TemplateCategory::Cleanup,
        description: "Review session state and cleanup candidates without destructive defaults",
        safe_by_default: true,
        requires_explicit_target: false,
        steps: &[
            "self(action='state') -> inspect session state",
            "self(action='state', sub_action='history', limit=25) -> inspect recent operations",
            "payload(action='cleanup', pid=<pid>, dry_run=true) -> preview cleanup when a target is explicit",
        ],
    },
    Template {
        id: "privilege_review",
        category: TemplateCategory::PrivilegeReview,
        description: "Read-only privilege posture review",
        safe_by_default: true,
        requires_explicit_target: false,
        steps: &[
            "privilege(action='check') -> current token and elevation state",
            "privilege(action='token_scan') -> token inventory",
            "privilege(action='service_unquoted') -> service path audit",
            "privilege(action='service_weak_perms') -> service permission audit",
        ],
    },
];

pub fn templates_json() -> Value {
    let templates = TEMPLATES
        .iter()
        .map(|template| {
            json!({
                "id": template.id,
                "category": template.category.as_str(),
                "description": template.description,
                "safe_by_default": template.safe_by_default,
                "requires_explicit_target": template.requires_explicit_target,
                "steps": template.steps,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "success": true,
        "templates": templates,
        "categories": [
            "reconnaissance",
            "memory_diagnostics",
            "driver_readiness",
            "authorized_lab_validation",
            "cleanup",
            "privilege_review"
        ],
        "message": "Templates are plan seeds only; use orchestrate(action='plan', template='<id>') to validate a concrete plan."
    })
}

pub fn plan_steps(template_id: &str, args: &Value) -> Result<Vec<Value>, String> {
    match template_id {
        "lab_validation" => Ok(lab_validation_steps(args)),
        "memory_diagnostics" => Ok(memory_diagnostics_steps(args)),
        "driver_readiness" => Ok(driver_readiness_steps()),
        "reconnaissance" => Ok(reconnaissance_steps(args)),
        "cleanup" => Ok(cleanup_steps(args)),
        "privilege_review" => Ok(privilege_review_steps()),
        _ => Err(format!("Unknown orchestration template '{}'", template_id)),
    }
}

fn lab_validation_steps(args: &Value) -> Vec<Value> {
    let benign_pid = args.get("benign_pid").and_then(crate::args::parse_u64);
    let marker_address = crate::args::parse_address_value(args.get("marker_address"));
    let marker_len = args
        .get("marker_len")
        .and_then(crate::args::parse_u64)
        .unwrap_or(28)
        .min(256);
    let counter_address = crate::args::parse_address_value(args.get("counter_address"));

    let mut steps = vec![
        json!({
            "tool": "self",
            "action": "test",
            "args": { "include_scan": false },
            "description": "Validate local memory read path against the current process",
            "required": true
        }),
        json!({
            "tool": "self",
            "action": "memory_diagnostics",
            "args": {
                "include_modules": true,
                "include_handles": false,
                "include_entropy": false,
                "region_limit": 32
            },
            "description": "Collect read-only diagnostics for the current process",
            "required": true
        }),
    ];

    if let Some(pid) = benign_pid {
        steps.push(json!({
            "tool": "memory",
            "action": "diagnostics",
            "args": {
                "pid": pid,
                "include_modules": true,
                "include_handles": false,
                "include_entropy": false,
                "region_limit": 64
            },
            "description": "Collect read-only diagnostics for the explicitly launched benign test target",
            "required": true
        }));

        if let Some(address) = marker_address {
            steps.push(json!({
                "tool": "memory",
                "action": "read",
                "args": {
                    "pid": pid,
                    "address": format!("0x{:X}", address),
                    "size": marker_len
                },
                "description": "Read the benign target marker bytes printed by examples/benign_test_target.rs",
                "required": true
            }));
        }

        if let Some(address) = counter_address {
            steps.push(json!({
                "tool": "memory",
                "action": "write",
                "args": {
                    "pid": pid,
                    "address": format!("0x{:X}", address),
                    "bytes": [1, 67, 73, 82, 79, 77, 69, 77],
                    "dry_run": true
                },
                "description": "Preview a counter write against the benign target without mutating it",
                "required": false
            }));
        }
    }

    steps
}

fn memory_diagnostics_steps(args: &Value) -> Vec<Value> {
    let pid = args.get("pid").and_then(crate::args::parse_u64);
    let mut steps = vec![json!({
        "tool": "self",
        "action": "memory_diagnostics",
        "args": { "include_handles": false, "include_entropy": true, "region_limit": 64 },
        "description": "Collect local read-only memory diagnostics",
        "required": true
    })];

    if let Some(pid) = pid {
        steps.push(json!({
            "tool": "memory",
            "action": "diagnostics",
            "args": { "pid": pid, "include_handles": true, "include_entropy": true, "region_limit": 128 },
            "description": "Collect read-only memory diagnostics for the explicit target PID",
            "required": true
        }));
    }

    steps
}

fn driver_readiness_steps() -> Vec<Value> {
    vec![
        json!({
            "tool": "self",
            "action": "doctor",
            "args": {},
            "description": "Probe policy, privilege, platform, and driver readiness",
            "required": true
        }),
        json!({
            "tool": "kernel",
            "action": "driver_discover",
            "args": {},
            "description": "Enumerate known vulnerable-driver candidates without loading a driver",
            "required": false
        }),
    ]
}

fn reconnaissance_steps(args: &Value) -> Vec<Value> {
    let pid = args.get("pid").and_then(crate::args::parse_u64);
    let mut steps = vec![
        json!({
            "tool": "target",
            "action": "ps_list",
            "args": { "limit": 200 },
            "description": "Enumerate running processes",
            "required": true
        }),
        json!({
            "tool": "detect",
            "action": "edr_products",
            "args": {},
            "description": "Detect security products",
            "required": false
        }),
        json!({
            "tool": "detect",
            "action": "vm_sandbox",
            "args": {},
            "description": "Inspect virtualization and sandbox signals",
            "required": false
        }),
    ];

    if let Some(pid) = pid {
        steps.push(json!({
            "tool": "memory",
            "action": "diagnostics",
            "args": { "pid": pid, "include_handles": true, "include_entropy": false },
            "description": "Collect read-only diagnostics for the explicit target PID",
            "required": false
        }));
    }

    steps
}

fn cleanup_steps(args: &Value) -> Vec<Value> {
    let pid = args.get("pid").and_then(crate::args::parse_u64);
    let mut steps = vec![
        json!({
            "tool": "self",
            "action": "state",
            "args": {},
            "description": "Inspect current session state",
            "required": true
        }),
        json!({
            "tool": "self",
            "action": "state",
            "args": { "sub_action": "history", "limit": 25 },
            "description": "Inspect recent audited operations",
            "required": false
        }),
    ];

    if let Some(pid) = pid {
        steps.push(json!({
            "tool": "payload",
            "action": "cleanup",
            "args": { "pid": pid, "dry_run": true },
            "description": "Preview cleanup for the explicit target PID",
            "required": false
        }));
    }

    steps
}

fn privilege_review_steps() -> Vec<Value> {
    vec![
        json!({
            "tool": "privilege",
            "action": "check",
            "args": {},
            "description": "Inspect current token and elevation state",
            "required": true
        }),
        json!({
            "tool": "privilege",
            "action": "service_unquoted",
            "args": {},
            "description": "Audit unquoted service paths",
            "required": false
        }),
        json!({
            "tool": "privilege",
            "action": "service_weak_perms",
            "args": {},
            "description": "Audit weak service permissions",
            "required": false
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn template_catalog_contains_lab_validation() {
        let value = templates_json();
        let templates = value["templates"].as_array().unwrap();
        assert!(templates
            .iter()
            .any(|template| template["id"] == "lab_validation"));
        assert!(templates
            .iter()
            .all(|template| template["safe_by_default"] == true));
    }

    #[test]
    fn lab_validation_defaults_to_self_only_and_dry_run_for_write_preview() {
        let self_only = plan_steps("lab_validation", &json!({})).unwrap();
        assert!(self_only.iter().all(|step| step["tool"] == "self"));

        let target = plan_steps(
            "lab_validation",
            &json!({
                "benign_pid": 1234,
                "marker_address": "0x1000",
                "counter_address": "0x2000"
            }),
        )
        .unwrap();
        assert!(target.iter().any(|step| step["action"] == "diagnostics"));
        let write = target
            .iter()
            .find(|step| step["tool"] == "memory" && step["action"] == "write")
            .expect("write preview");
        assert_eq!(write["args"]["dry_run"], true);
    }
}

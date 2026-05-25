//! MCP orchestrate tool handler.

use serde_json::{json, Value};

use crate::mcp::action_registry::OrchestrateAction;
use crate::mcp::readiness::runtime_readiness_json;
use crate::mcp::tool_args::{require_typed_action, unknown_registered_action_error};

pub(crate) fn handle_orchestrate(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "orchestrate")?;
    let typed_action = OrchestrateAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("orchestrate", action.as_str()))?;

    match typed_action {
        OrchestrateAction::Assess => {
            crate::orchestration::engine::assess_environment(args).map_err(|e| e.to_string())
        }
        OrchestrateAction::Execute => {
            crate::orchestration::engine::execute_chain(args).map_err(|e| e.to_string())
        }
        OrchestrateAction::Plan => {
            crate::orchestration::engine::plan_chain(args).map_err(|e| e.to_string())
        }

        OrchestrateAction::Templates => Ok(crate::orchestration::templates::templates_json()),

        OrchestrateAction::Resume => {
            crate::orchestration::engine::resume_chain(args).map_err(|e| e.to_string())
        }

        OrchestrateAction::Cancel => {
            crate::orchestration::engine::cancel_chain(args).map_err(|e| e.to_string())
        }

        OrchestrateAction::Cleanup => {
            crate::orchestration::engine::cleanup_chain(args).map_err(|e| e.to_string())
        }

        OrchestrateAction::Status => {
            let admin = crate::privilege::uac::is_admin().unwrap_or(json!(false));
            let uac = crate::privilege::check_uac_status(&json!({})).map_err(|e| e.to_string())?;
            let edr = crate::evasion::edr::detect_edr_products(&json!({})).ok();
            let readiness = runtime_readiness_json(args);
            let chain_status = crate::orchestration::engine::chain_status(args)
                .unwrap_or_else(|error| json!({"success": false, "error": error.to_string()}));

            Ok(json!({
                "is_admin": admin,
                "uac": uac,
                "edr_detected": edr,
                "driver": readiness.get("driver").cloned().unwrap_or_else(|| json!(null)),
                "readiness": readiness,
                "chain": chain_status,
                "pid": std::process::id(),
                "arch": std::env::consts::ARCH,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_action_exposes_registered_templates() {
        let templates = handle_orchestrate(&json!({"action": "templates"})).expect("templates");

        assert!(templates["templates"]
            .as_array()
            .expect("templates array")
            .iter()
            .any(|template| template["id"] == "lab_validation"));
    }

    #[test]
    fn unknown_action_uses_registered_action_error() {
        let error = handle_orchestrate(&json!({"action": "missing"})).expect_err("unknown action");

        assert!(error.contains("Unknown orchestrate action: missing"));
        assert!(error.contains("Available:"));
        assert!(error.contains("templates"));
    }
}

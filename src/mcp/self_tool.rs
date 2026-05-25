//! MCP self tool handler.

use serde_json::{json, Value};

use crate::mcp::action_registry::SelfAction;
use crate::mcp::readiness::{explain_error_next_steps, runtime_readiness_json, self_doctor_json};
use crate::mcp::tool_args::{
    require_nonzero_usize_param, require_typed_action, require_u64_param,
    unknown_registered_action_error,
};

pub(crate) fn handle_self(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "self")?;
    let typed_action = SelfAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("self", action.as_str()))?;

    match typed_action {
        SelfAction::Peb => crate::info::read_peb(args).map_err(|e| e.to_string()),
        SelfAction::Heap => crate::info::heap_query(args).map_err(|e| e.to_string()),
        SelfAction::Test => {
            if crate::mcp::platform_gate::unsupported_platform_simulated() {
                Ok(json!({
                    "success": false,
                    "code": "unsupported_platform",
                    "skipped": true,
                    "tests": {
                        "current_process_memory": {
                            "enabled": false,
                            "pass": false,
                            "reason": "Windows memory self-test requires Windows process memory APIs"
                        }
                    },
                    "message": "self(action='test') is available as a fallback diagnostic, but Windows memory checks are skipped on unsupported platforms"
                }))
            } else {
                crate::memory::memory_self_test(args).map_err(|e| e.to_string())
            }
        }
        SelfAction::MemoryDiagnostics => {
            crate::memory::memory_diagnostics(args).map_err(|e| e.to_string())
        }

        SelfAction::ProtectInit => {
            let config = crate::bruteforce::self_protect::ProtectionConfig::default();
            crate::bruteforce::self_protect::init_self_protection(config).map_err(|e| e.to_string())
        }
        SelfAction::ProtectEncrypt => {
            let address = require_u64_param(args, "address", "self", "protect_encrypt")? as usize;
            let size = require_nonzero_usize_param(args, "size", "self", "protect_encrypt")?;
            crate::bruteforce::self_protect::encrypt_region(address, size)
                .map_err(|e| e.to_string())
        }
        SelfAction::ProtectDecrypt => {
            let address = require_u64_param(args, "address", "self", "protect_decrypt")? as usize;
            crate::bruteforce::self_protect::decrypt_region(address).map_err(|e| e.to_string())
        }
        SelfAction::ProtectWipe => {
            let address = require_u64_param(args, "address", "self", "protect_wipe")? as usize;
            let size = require_nonzero_usize_param(args, "size", "self", "protect_wipe")?;
            crate::bruteforce::self_protect::secure_wipe(address, size).map_err(|e| e.to_string())
        }

        SelfAction::Info | SelfAction::Version | SelfAction::Status => {
            let pid = std::process::id();
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let admin = crate::privilege::uac::is_admin().unwrap_or(json!(false));
            let readiness = runtime_readiness_json(args);

            Ok(json!({
                "name": "memoric",
                "version": env!("CARGO_PKG_VERSION"),
                "pid": pid,
                "executable": exe,
                "is_admin": admin,
                "arch": std::env::consts::ARCH,
                "os": std::env::consts::OS,
                "driver": readiness.get("driver").cloned().unwrap_or_else(|| json!(null)),
                "readiness": readiness,
                "tools": 12,
                "scan_modes": 12,
                "kernel_ioctls": 37
            }))
        }

        SelfAction::Doctor => Ok(self_doctor_json(args)),
        SelfAction::Diagnostics => Ok(crate::capability::diagnostics_bundle_json(args)),
        SelfAction::CapabilityDiff => Ok(crate::capability::capability_diff_json(args)),
        SelfAction::NextSteps => Ok(crate::capability::next_steps_json(args)),

        SelfAction::ExplainError => {
            let error_text = args
                .get("error")
                .and_then(|v| v.as_str())
                .or_else(|| args.get("message").and_then(|v| v.as_str()))
                .unwrap_or("");
            let classification = crate::error::classify_tool_error(error_text);
            Ok(json!({
                "success": true,
                "code": classification.code,
                "input": error_text,
                "hint": classification.hint,
                "next_diagnostics": explain_error_next_steps(classification.code),
            }))
        }

        SelfAction::AntiDebug => {
            let is_debugged = unsafe {
                windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool()
            };
            Ok(json!({
                "is_debugged": is_debugged,
                "warning": if is_debugged { "Debugger detected!" } else { "No debugger detected" }
            }))
        }

        SelfAction::State => {
            let sub_action = args
                .get("sub_action")
                .and_then(|v| v.as_str())
                .unwrap_or("get");
            match sub_action {
                "reset" => {
                    crate::state::reset_session();
                    Ok(json!({"state": "reset"}))
                }
                "score" => {
                    let score = crate::state::compute_stealth_score();
                    crate::state::update_stealth_score(score.clone());
                    serde_json::to_value(&score).map_err(|e| e.to_string())
                }
                "history" | "operations" => Ok(crate::state::operation_history_json(args)),
                "mutations" | "rollback" => Ok(crate::state::mutation_history_json(args)),
                "replay" | "replay_dry_run" => Ok(crate::state::workflow_replay_dry_run_json(args)),
                "timeline" | "observability" => Ok(crate::observability::timeline_json(args)),
                "artifact_cleanup" => {
                    let task_id = args.get("task_id").and_then(|v| v.as_str());
                    let chain_id = args.get("chain_id").and_then(|v| v.as_str());
                    let mut result = if let Some(task_id) = task_id {
                        crate::artifact::cleanup_for_task(task_id, true)
                    } else {
                        crate::artifact::cleanup_expired_filtered(
                            true,
                            chain_id
                                .or_else(|| args.get("correlation_id").and_then(|v| v.as_str())),
                        )
                    };
                    result["message"] = json!(
                        "Artifact cleanup dry-run completed; expired process-local resource links are removed opportunistically on artifact reads and registry reads."
                    );
                    Ok(result)
                }
                _ => crate::state::get_state_json().map_err(|e| e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_server_identity_and_readiness() {
        let status = handle_self(&json!({"action": "status"})).expect("status");

        assert_eq!(status["name"], json!("memoric"));
        assert_eq!(status["version"], json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(status["tools"], json!(12));
        assert!(status.get("readiness").is_some());
    }

    #[test]
    fn explain_error_uses_shared_taxonomy() {
        let result =
            handle_self(&json!({"action": "explain_error", "error": "driver unavailable"}))
                .expect("explain_error");

        assert_eq!(result["success"], json!(true));
        assert!(result["next_diagnostics"].as_array().is_some());
    }

    #[test]
    fn self_test_reports_clean_unsupported_platform_fallback() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        struct EnvRestore(Option<String>);
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                if let Some(previous) = &self.0 {
                    std::env::set_var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM", previous);
                } else {
                    std::env::remove_var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM");
                }
            }
        }
        let _env = EnvRestore(std::env::var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM").ok());
        std::env::set_var("MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM", "1");

        let result = handle_self(&json!({"action": "test"})).expect("self test fallback");

        assert_eq!(result["success"], json!(false));
        assert_eq!(result["code"], json!("unsupported_platform"));
        assert_eq!(result["skipped"], json!(true));
    }
}

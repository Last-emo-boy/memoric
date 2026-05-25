//! MCP detect tool handler.

use serde_json::Value;

use crate::mcp::action_registry::DetectAction;
use crate::mcp::tool_args::{
    normalize_alias, require_str_param, require_typed_action, unknown_registered_action_error,
};

pub(crate) fn handle_detect(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "detect")?;
    let typed_action = DetectAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("detect", action.as_str()))?;

    match typed_action {
        DetectAction::EdrProducts => {
            crate::evasion::edr::detect_edr_products(args).map_err(|e| e.to_string())
        }
        DetectAction::EdrHooks => {
            crate::evasion::edr::scan_inline_hooks(args).map_err(|e| e.to_string())
        }
        DetectAction::EdrQuickCheck => {
            crate::evasion::edr::quick_hook_check(args).map_err(|e| e.to_string())
        }
        DetectAction::EdrSuspend => {
            crate::evasion::edr::suspend_edr_processes(args).map_err(|e| e.to_string())
        }

        DetectAction::EtwSessions => {
            crate::evasion::edr::enumerate_etw_sessions(args).map_err(|e| e.to_string())
        }
        DetectAction::VehChain => {
            crate::evasion::edr::detect_veh_chain(args).map_err(|e| e.to_string())
        }
        DetectAction::VmSandbox => {
            crate::evasion::antivm::detect_vm(args).map_err(|e| e.to_string())
        }
        DetectAction::Hypervisor => {
            crate::evasion::hypervisor::detect_hypervisor(args).map_err(|e| e.to_string())
        }

        DetectAction::Hooks => {
            if args.get("function_name").is_some() {
                tracing::warn!("detect(action='hooks', function_name=...) is deprecated, use action='hook_function'");
                crate::evasion::edr::detect_hook_on_function(args).map_err(|e| e.to_string())
            } else {
                crate::evasion::edr::scan_inline_hooks(args).map_err(|e| e.to_string())
            }
        }
        DetectAction::HookFunction => {
            require_str_param(
                args,
                "function_name",
                "detect",
                "hook_function",
                Some("Provide the exported or symbol name to inspect, e.g. function_name='NtOpenProcess'."),
            )?;
            crate::evasion::edr::detect_hook_on_function(args).map_err(|e| e.to_string())
        }

        DetectAction::Forensics => {
            crate::bruteforce::anti_forensics::detect_forensic_tools().map_err(|e| e.to_string())
        }
        DetectAction::Integrity => {
            crate::bruteforce::anti_forensics::check_system_integrity().map_err(|e| e.to_string())
        }

        DetectAction::SyscallResolve => {
            let normalized = normalize_alias(
                args,
                "function_name",
                "function",
                "detect",
                "syscall_resolve",
            );
            require_str_param(
                &normalized,
                "function_name",
                "detect",
                "syscall_resolve",
                Some(
                    "Provide the Nt/Zw export name to resolve, e.g. function_name='NtOpenProcess'.",
                ),
            )?;
            crate::evasion::syscall::resolve_syscall_number(&normalized).map_err(|e| e.to_string())
        }

        DetectAction::StealthScore => {
            crate::evasion::stealth_score::assess_stealth_posture(args).map_err(|e| e.to_string())
        }

        DetectAction::BypassRecommendations => {
            crate::bypass_db::bypass_recommendations(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hook_function_requires_function_name() {
        let error = handle_detect(&json!({"action": "hook_function"}))
            .expect_err("missing function_name should fail before hook inspection");

        assert!(error.contains("detect(action='hook_function')"));
        assert!(error.contains("function_name"));
    }

    #[test]
    fn syscall_resolve_accepts_function_alias_for_validation() {
        let error = handle_detect(&json!({"action": "syscall_resolve", "function": ""}))
            .expect_err("empty alias value should fail validation");

        assert!(error.contains("function_name"));
    }
}

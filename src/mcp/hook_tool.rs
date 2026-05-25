//! MCP hook tool handler.

use serde_json::Value;

use crate::mcp::action_registry::HookAction;
use crate::mcp::tool_args::{
    invalid_registered_choice_error, missing_param_error, normalize_alias,
    require_module_name_param, require_str_param, require_typed_action, require_u64_param,
    unknown_registered_action_error,
};

pub(crate) fn handle_hook(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "hook")?;
    let typed_action = HookAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("hook", action.as_str()))?;
    let action_name = typed_action.as_str();

    match typed_action {
        // Install hooks
        HookAction::HookFunction | HookAction::Install | HookAction::InstallIat => {
            let normalized =
                normalize_alias(args, "function", "target_function", "hook", action_name);
            let method = if typed_action == HookAction::InstallIat {
                "iat"
            } else {
                normalized
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("iat")
            };

            match method {
                "iat" => {
                    require_u64_param(&normalized, "pid", "hook", action_name)?;
                    require_module_name_param(
                        &normalized,
                        "module",
                        "hook",
                        action_name,
                        Some("Provide the imported module name, e.g. module='kernel32.dll'."),
                    )?;
                    require_str_param(
                        &normalized,
                        "function",
                        "hook",
                        action_name,
                        Some(
                            "Provide the imported function to patch, e.g. function='CreateFileW'.",
                        ),
                    )?;
                    require_u64_param(&normalized, "hook_address", "hook", action_name)?;
                    crate::inject::hook::hook_function_iat(&normalized).map_err(|e| e.to_string())
                }
                "inline" => {
                    require_u64_param(&normalized, "pid", "hook", action_name)?;
                    require_u64_param(&normalized, "target_address", "hook", action_name)?;
                    require_u64_param(&normalized, "hook_address", "hook", action_name)?;
                    crate::inject::hook::inline_hook(&normalized).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "hook",
                    action_name,
                    "method",
                    method,
                )),
            }
        }
        HookAction::InstallHwbp => {
            require_u64_param(args, "tid", "hook", "install_hwbp")?;
            require_u64_param(args, "target_address", "hook", "install_hwbp")?;
            crate::evasion::hwbp::hwbp_hook(args).map_err(|e| e.to_string())
        }

        // Remove hooks
        HookAction::Remove | HookAction::RemoveIat => {
            require_u64_param(args, "pid", "hook", action_name)?;
            require_u64_param(args, "iat_address", "hook", action_name)?;
            require_u64_param(args, "original_address", "hook", action_name)?;
            crate::inject::iat_unhook(args).map_err(|e| e.to_string())
        }
        HookAction::RemoveHwbp => {
            require_u64_param(args, "tid", "hook", "remove_hwbp")?;
            crate::evasion::hwbp::hwbp_unhook(args).map_err(|e| e.to_string())
        }

        // Advanced hooking
        HookAction::Trampoline => {
            require_u64_param(args, "pid", "hook", "trampoline")?;
            require_u64_param(args, "target_address", "hook", "trampoline")?;
            crate::inject::hook::generate_trampoline(args).map_err(|e| e.to_string())
        }
        HookAction::Detour => {
            require_u64_param(args, "pid", "hook", "detour")?;
            args.get("hooks")
                .and_then(|v| v.as_array())
                .ok_or_else(|| missing_param_error("hook", "detour", "hooks", None))?;
            crate::inject::hook::detour_transaction(args).map_err(|e| e.to_string())
        }
        HookAction::Restore => {
            require_u64_param(args, "pid", "hook", "restore")?;
            require_u64_param(args, "address", "hook", "restore")?;
            args.get("original_bytes")
                .and_then(|v| v.as_array())
                .ok_or_else(|| missing_param_error("hook", "restore", "original_bytes", None))?;
            crate::inject::hook::restore_hook(args).map_err(|e| e.to_string())
        }
        HookAction::Winhook => {
            require_u64_param(args, "pid", "hook", "winhook")?;
            require_str_param(
                args,
                "dll_path",
                "hook",
                "winhook",
                Some("Provide the DLL containing the hook procedure."),
            )?;
            crate::inject::hook::set_windows_hook_inject(args).map_err(|e| e.to_string())
        }
        HookAction::HwbpSyscall => {
            require_str_param(
                args,
                "function",
                "hook",
                "hwbp_syscall",
                Some("Provide the ntdll syscall wrapper name, e.g. function='NtOpenProcess'."),
            )?;
            crate::evasion::hwbp::hwbp_syscall_hook(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn install_rejects_unknown_method() {
        let error = handle_hook(&json!({"action": "install", "method": "unknown"}))
            .expect_err("unknown hook method should fail before execution");

        assert!(error.contains("hook(action='install')"));
        assert!(error.contains("method"));
        assert!(error.contains("iat"));
        assert!(error.contains("inline"));
    }

    #[test]
    fn install_iat_requires_module_before_function() {
        let error = handle_hook(&json!({"action": "install_iat", "pid": 1234}))
            .expect_err("missing module should fail before execution");

        assert!(error.contains("hook(action='install_iat')"));
        assert!(error.contains("module"));
    }

    #[test]
    fn install_iat_rejects_path_like_module_names() {
        let error = handle_hook(&json!({
            "action": "install_iat",
            "pid": 1234,
            "module": "C:\\Windows\\System32\\kernel32.dll"
        }))
        .expect_err("module paths should fail before IAT patching");

        assert!(error.contains("hook(action='install_iat')"));
        assert!(error.contains("module"));
        assert!(error.contains("path separators"));
    }

    #[test]
    fn detour_requires_hooks_array() {
        let error = handle_hook(&json!({"action": "detour", "pid": 1234}))
            .expect_err("detour should require hooks array");

        assert!(error.contains("hook(action='detour')"));
        assert!(error.contains("hooks"));
    }

    #[test]
    fn restore_requires_original_bytes() {
        let error = handle_hook(&json!({"action": "restore", "pid": 1234, "address": 4096}))
            .expect_err("restore should require original bytes");

        assert!(error.contains("hook(action='restore')"));
        assert!(error.contains("original_bytes"));
    }

    #[test]
    fn hwbp_syscall_requires_function() {
        let error = handle_hook(&json!({"action": "hwbp_syscall"}))
            .expect_err("hwbp syscall hook should require a function");

        assert!(error.contains("hook(action='hwbp_syscall')"));
        assert!(error.contains("function"));
    }
}

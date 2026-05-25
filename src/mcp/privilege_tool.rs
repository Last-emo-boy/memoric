//! MCP privilege tool handler.

use serde_json::{json, Value};

use crate::mcp::action_registry::PrivilegeAction;
use crate::mcp::tool_args::{
    invalid_registered_choice_error, normalize_alias, require_str_param, require_typed_action,
    unknown_registered_action_error,
};

pub(crate) fn handle_privilege(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "privilege")?;
    let typed_action = PrivilegeAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("privilege", action.as_str()))?;

    match typed_action {
        // Elevation
        PrivilegeAction::Elevate => {
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("auto");
            match method {
                "auto" => crate::privilege::auto::auto_elevate(args).map_err(|e| e.to_string()),
                "fodhelper" => {
                    crate::privilege::uac::fodhelper_bypass(args).map_err(|e| e.to_string())
                }
                "eventvwr" => {
                    crate::privilege::uac::eventvwr_bypass(args).map_err(|e| e.to_string())
                }
                "computerdefaults" => {
                    crate::privilege::uac::computerdefaults_bypass(args).map_err(|e| e.to_string())
                }
                "sdclt" => crate::privilege::uac::sdclt_bypass(args).map_err(|e| e.to_string()),
                "disk_cleanup" => {
                    crate::privilege::uac::disk_cleanup_bypass(args).map_err(|e| e.to_string())
                }
                "mock_trusted_dir" => {
                    crate::privilege::uac::mock_trusted_dir_bypass(args).map_err(|e| e.to_string())
                }
                "request_uac" => {
                    crate::privilege::uac::request_elevation(args).map_err(|e| e.to_string())
                }
                "system" => {
                    crate::privilege::system::elevate_to_system(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "privilege",
                    "elevate",
                    "method",
                    method,
                )),
            }
        }

        // Token operations
        PrivilegeAction::TokenSteal => {
            let normalized = normalize_alias(args, "target_pid", "pid", "privilege", "token_steal");
            crate::privilege::token::steal_token(&normalized).map_err(|e| e.to_string())
        }
        PrivilegeAction::TokenImpersonate => {
            let normalized =
                normalize_alias(args, "target_pid", "pid", "privilege", "token_impersonate");
            crate::privilege::token::impersonate_process(&normalized).map_err(|e| e.to_string())
        }
        PrivilegeAction::TokenRevert => {
            crate::privilege::token::revert_to_self(args).map_err(|e| e.to_string())
        }
        PrivilegeAction::TokenScan => {
            let normalized = normalize_alias(args, "target_pid", "pid", "privilege", "token_scan");
            crate::privilege::token::scan_token_targets(&normalized).map_err(|e| e.to_string())
        }

        // Debug privilege
        PrivilegeAction::DebugPriv => {
            crate::privilege::enable_debug_privilege(args).map_err(|e| e.to_string())
        }

        // Check status
        PrivilegeAction::Check => {
            let detail = args
                .get("detail")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let admin = crate::privilege::uac::is_admin().map_err(|e| e.to_string())?;
            let uac = crate::privilege::check_uac_status(&json!({})).map_err(|e| e.to_string())?;

            if detail {
                let privs = crate::redteam::get_system_privileges(&json!({}))
                    .unwrap_or(json!({"error": "failed"}));
                Ok(json!({"is_admin": admin, "uac": uac, "privileges": privs}))
            } else {
                Ok(json!({"is_admin": admin, "uac": uac}))
            }
        }

        // Potato attacks (named pipe impersonation)
        PrivilegeAction::Potato => {
            let method = args
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("print_spoofer");
            require_str_param(
                args,
                "command",
                "privilege",
                "potato",
                Some("Provide the command to run after privilege escalation."),
            )?;
            match method {
                "print_spoofer" => {
                    crate::privilege::potato::print_spoofer(args).map_err(|e| e.to_string())
                }
                "god_potato" => {
                    crate::privilege::potato::god_potato(args).map_err(|e| e.to_string())
                }
                "efs_potato" => {
                    crate::privilege::potato::efs_potato(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "privilege",
                    "potato",
                    "method",
                    method,
                )),
            }
        }

        // Service abuse
        PrivilegeAction::ServiceUnquoted => {
            crate::privilege::service::unquoted_service_path(args).map_err(|e| e.to_string())
        }
        PrivilegeAction::ServiceWeakPerms => {
            crate::privilege::service::weak_service_permissions(args).map_err(|e| e.to_string())
        }
        PrivilegeAction::ServiceAlwaysElevated => {
            crate::privilege::service::always_install_elevated(args).map_err(|e| e.to_string())
        }

        // Symlink attack
        PrivilegeAction::Symlink => {
            require_str_param(
                args,
                "link_path",
                "privilege",
                "symlink",
                Some("Provide the link path to create, e.g. link_path='C:\\temp\\bait'."),
            )?;
            require_str_param(
                args,
                "target_path",
                "privilege",
                "symlink",
                Some("Provide the target path the link should point to."),
            )?;
            crate::privilege::symlink::symlink_attack(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn elevate_rejects_unknown_method() {
        let error = handle_privilege(&json!({"action": "elevate", "method": "unknown"}))
            .expect_err("unknown elevation method should fail before execution");

        assert!(error.contains("privilege(action='elevate')"));
        assert!(error.contains("method"));
        assert!(error.contains("fodhelper"));
    }

    #[test]
    fn potato_requires_command() {
        let error = handle_privilege(&json!({"action": "potato"}))
            .expect_err("potato action should require a command");

        assert!(error.contains("privilege(action='potato')"));
        assert!(error.contains("command"));
    }

    #[test]
    fn symlink_requires_link_and_target_paths() {
        let error = handle_privilege(&json!({"action": "symlink", "link_path": "C:\\temp\\bait"}))
            .expect_err("symlink action should require a target path");

        assert!(error.contains("privilege(action='symlink')"));
        assert!(error.contains("target_path"));
    }
}

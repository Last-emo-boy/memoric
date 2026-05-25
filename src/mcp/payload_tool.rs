//! MCP payload tool handler.

use serde_json::Value;

use crate::mcp::action_registry::PayloadAction;
use crate::mcp::tool_args::{
    invalid_registered_choice_error, require_str_param, require_typed_action,
    unknown_registered_action_error,
};

pub(crate) fn handle_payload(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "payload")?;
    let typed_action = PayloadAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("payload", action.as_str()))?;

    match typed_action {
        PayloadAction::PeParse => {
            let show = args
                .get("show")
                .and_then(|v| v.as_str())
                .unwrap_or("headers");
            match show {
                "headers" | "imports" | "exports" | "sections" => {
                    crate::inject::parse_pe_headers(args).map_err(|e| e.to_string())
                }
                "iat_entry" => crate::inject::find_iat_entry(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "payload", "pe_parse", "show", show,
                )),
            }
        }

        PayloadAction::Obfuscate => {
            let obf_method = require_str_param(
                args,
                "obf_method",
                "payload",
                "obfuscate",
                Some("Choose one of: xor, rc4, aes_ctr, polymorphic, uuid, ipv4, mac, transform, strings."),
            )?;
            match obf_method {
                "xor" => crate::inject::obfuscate::xor_encrypt(args).map_err(|e| e.to_string()),
                "rc4" => crate::inject::obfuscate::rc4_encrypt(args).map_err(|e| e.to_string()),
                "aes_ctr" => {
                    crate::inject::obfuscate::aes_ctr_encrypt(args).map_err(|e| e.to_string())
                }
                "polymorphic" => {
                    crate::inject::obfuscate::polymorphic_encode(args).map_err(|e| e.to_string())
                }
                "uuid" => crate::inject::obfuscate::uuid_encode(args).map_err(|e| e.to_string()),
                "ipv4" => crate::inject::obfuscate::ipv4_encode(args).map_err(|e| e.to_string()),
                "mac" => crate::inject::obfuscate::mac_encode(args).map_err(|e| e.to_string()),
                "transform" => {
                    crate::inject::obfuscate::transform_shellcode(args).map_err(|e| e.to_string())
                }
                "strings" => {
                    crate::inject::obfuscate::obfuscate_strings(args).map_err(|e| e.to_string())
                }
                _ => Err(invalid_registered_choice_error(
                    "payload",
                    "obfuscate",
                    "obf_method",
                    obf_method,
                )),
            }
        }

        PayloadAction::Wait => crate::inject::wait_for_execution(args).map_err(|e| e.to_string()),
        PayloadAction::ExitCode => crate::inject::get_exit_code(args).map_err(|e| e.to_string()),
        PayloadAction::Cleanup => crate::inject::cleanup_injection(args).map_err(|e| e.to_string()),
        PayloadAction::Serialize => {
            crate::inject::serialize_params(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invalid_show_value_reports_allowed_choices() {
        let error = handle_payload(&json!({"action": "pe_parse", "show": "bogus"}))
            .expect_err("invalid show should fail before PE parsing");

        assert!(error.contains("Invalid show for payload(action='pe_parse')"));
        assert!(error.contains("Allowed: headers, imports, exports, sections, iat_entry."));
    }

    #[test]
    fn unknown_action_uses_registered_action_error() {
        let error = handle_payload(&json!({"action": "not_real"})).expect_err("unknown action");

        assert!(error.contains("Unknown payload action: not_real"));
        assert!(error.contains("Available:"));
    }
}

//! MCP target tool handler.

use serde_json::Value;

use crate::mcp::action_registry::TargetAction;
use crate::mcp::tool_args::{
    normalize_alias, require_module_name_param, require_str_param, require_typed_action,
    require_u64_param, unknown_registered_action_error,
};

pub(crate) fn handle_target(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "target")?;
    let typed_action = TargetAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("target", action.as_str()))?;

    match typed_action {
        // Process operations
        TargetAction::PsList => crate::info::list_processes(args).map_err(|e| e.to_string()),
        TargetAction::PsFind => crate::info::find_process(args).map_err(|e| e.to_string()),
        TargetAction::PsInfo => {
            if let Some(pid) = args.get("pid").and_then(|v| v.as_u64()) {
                crate::state::set_target(pid as u32);
            }
            crate::info::get_process_info(args).map_err(|e| e.to_string())
        }
        TargetAction::Modules => crate::info::list_modules(args).map_err(|e| e.to_string()),

        // Thread operations
        TargetAction::Threads => {
            if args.get("tid").is_some() {
                tracing::warn!(
                    "target(action='threads', tid=...) is deprecated, use action='thread_context'"
                );
                crate::info::get_thread_context(args).map_err(|e| e.to_string())
            } else {
                crate::info::list_threads(args).map_err(|e| e.to_string())
            }
        }
        TargetAction::ThreadsList => crate::info::list_threads(args).map_err(|e| e.to_string()),
        TargetAction::ThreadSuspend => crate::info::suspend_thread(args).map_err(|e| e.to_string()),
        TargetAction::ThreadResume => crate::info::resume_thread(args).map_err(|e| e.to_string()),
        TargetAction::ThreadContext => {
            crate::info::get_thread_context(args).map_err(|e| e.to_string())
        }

        // Handle enumeration
        TargetAction::Handles => {
            crate::info::handles::enum_handles(args).map_err(|e| e.to_string())
        }

        // Environment
        TargetAction::Env => {
            crate::info::environment::get_environment(args).map_err(|e| e.to_string())
        }
        TargetAction::Cmdline => {
            crate::info::environment::get_command_line(args).map_err(|e| e.to_string())
        }

        // Window enumeration
        TargetAction::Windows => crate::info::window::enum_windows(args).map_err(|e| e.to_string()),

        // Advanced memory introspection
        TargetAction::Peb => crate::info::memory::read_peb(args).map_err(|e| e.to_string()),
        TargetAction::ModuleBase => {
            let normalized =
                normalize_alias(args, "module_name", "module", "target", "module_base");
            require_u64_param(&normalized, "pid", "target", "module_base")?;
            require_module_name_param(
                &normalized,
                "module_name",
                "target",
                "module_base",
                Some("Provide a loaded module name, e.g. module_name='kernel32.dll'."),
            )?;
            crate::info::module::get_module_base(&normalized).map_err(|e| e.to_string())
        }
        TargetAction::MemFind => {
            crate::info::memory::find_memory_region(args).map_err(|e| e.to_string())
        }
        TargetAction::StringRead => {
            require_u64_param(args, "pid", "target", "string_read")?;
            require_u64_param(args, "address", "target", "string_read")?;
            crate::info::memory::read_string(args).map_err(|e| e.to_string())
        }
        TargetAction::StringWrite => {
            require_u64_param(args, "pid", "target", "string_write")?;
            require_u64_param(args, "address", "target", "string_write")?;
            require_str_param(
                args,
                "text",
                "target",
                "string_write",
                Some("Provide the string to write."),
            )?;
            crate::info::memory::write_string(args).map_err(|e| e.to_string())
        }

        // Thread advanced
        TargetAction::Callstack => {
            crate::info::thread::get_thread_callstack(args).map_err(|e| e.to_string())
        }
        TargetAction::Heap => crate::info::thread::heap_query(args).map_err(|e| e.to_string()),
        TargetAction::CredDump => {
            crate::info::thread::dump_credentials(args).map_err(|e| e.to_string())
        }
        TargetAction::SamDump => crate::info::sam::dump_sam_hive(args).map_err(|e| e.to_string()),
        TargetAction::KerberosTickets => {
            crate::info::kerberos::extract_kerberos_tickets(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn module_base_requires_pid_before_module_lookup() {
        let error = handle_target(&json!({"action": "module_base", "module": "kernel32.dll"}))
            .expect_err("missing pid should fail before module lookup");

        assert!(error.contains("target(action='module_base')"));
        assert!(error.contains("pid"));
    }

    #[test]
    fn module_base_accepts_module_alias_for_validation() {
        let error = handle_target(&json!({"action": "module_base", "pid": 1234, "module": ""}))
            .expect_err("empty module alias should fail as module_name");

        assert!(error.contains("target(action='module_base')"));
        assert!(error.contains("module_name"));
    }

    #[test]
    fn string_read_requires_address() {
        let error = handle_target(&json!({"action": "string_read", "pid": 1234}))
            .expect_err("string_read should require address");

        assert!(error.contains("target(action='string_read')"));
        assert!(error.contains("address"));
    }

    #[test]
    fn string_write_requires_text() {
        let error = handle_target(&json!({"action": "string_write", "pid": 1234, "address": 4096}))
            .expect_err("string_write should require text");

        assert!(error.contains("target(action='string_write')"));
        assert!(error.contains("text"));
    }
}

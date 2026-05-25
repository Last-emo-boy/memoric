//! MCP memory tool handler.

use serde_json::Value;

use crate::mcp::action_registry::MemoryAction;
use crate::mcp::tool_args::{
    invalid_registered_choice_error, require_nonzero_usize_param, require_typed_action,
    require_u64_param, unknown_registered_action_error,
};

pub(crate) fn handle_memory(args: &Value) -> Result<Value, String> {
    let action = require_typed_action(args, "memory")?;
    let typed_action = MemoryAction::try_from(&action)
        .map_err(|_| unknown_registered_action_error("memory", action.as_str()))?;

    match typed_action {
        // Read operations
        MemoryAction::Read => {
            let mode = args.get("mode").and_then(|v| v.as_str()).unwrap_or("raw");
            match mode {
                "raw" | "string" => crate::memory::read_memory(args).map_err(|e| e.to_string()),
                "stealth" => crate::memory::stealth_read_memory(args).map_err(|e| e.to_string()),
                "scattered" => crate::memory::scattered_read(args).map_err(|e| e.to_string()),
                "physical" => crate::memory::read_physical_memory(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "memory", "read", "mode", mode,
                )),
            }
        }
        MemoryAction::TypedRead => {
            crate::memory::struct_rw::typed_read(args).map_err(|e| e.to_string())
        }

        // Write operations
        MemoryAction::Write => {
            if args.get("text").is_some() {
                tracing::warn!(
                    "memory(action='write', text=...) is deprecated, use action='write_string'"
                );
                crate::info::write_string(args).map_err(|e| e.to_string())
            } else {
                let bypass = args
                    .get("bypass_protect")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if bypass {
                    crate::inject::force_write(args).map_err(|e| e.to_string())
                } else {
                    crate::memory::write_memory(args).map_err(|e| e.to_string())
                }
            }
        }
        MemoryAction::TypedWrite => {
            crate::memory::struct_rw::typed_write(args).map_err(|e| e.to_string())
        }
        MemoryAction::WriteString => crate::info::write_string(args).map_err(|e| e.to_string()),

        // Scan operations
        MemoryAction::Scan => {
            let scan_mode = args
                .get("scan_mode")
                .and_then(|v| v.as_str())
                .unwrap_or("exact");
            match scan_mode {
                "exact" => crate::memory::scan_exact(args).map_err(|e| e.to_string()),
                "changed" => crate::memory::scan_changed(args).map_err(|e| e.to_string()),
                "pattern" => crate::memory::ida_pattern_scan(args).map_err(|e| e.to_string()),
                "stealth_pattern" => {
                    crate::memory::stealth_pattern_scan(args).map_err(|e| e.to_string())
                }
                "range" => crate::memory::scan_range(args).map_err(|e| e.to_string()),
                "delta" => crate::memory::scan_delta(args).map_err(|e| e.to_string()),
                "string" => crate::memory::scan_string(args).map_err(|e| e.to_string()),
                "unknown" => crate::memory::scan_unknown(args).map_err(|e| e.to_string()),
                "pointer" => crate::memory::pointer_scan(args).map_err(|e| e.to_string()),
                "aob" => crate::memory::find_pattern(args).map_err(|e| e.to_string()),
                "aligned" => crate::memory::scan_aligned(args).map_err(|e| e.to_string()),
                "multi" => crate::memory::scan_multi_value(args).map_err(|e| e.to_string()),
                _ => Err(invalid_registered_choice_error(
                    "memory",
                    "scan",
                    "scan_mode",
                    scan_mode,
                )),
            }
        }

        // Memory management
        MemoryAction::Query => {
            if args.get("filter").is_some() {
                tracing::warn!(
                    "memory(action='query', filter=...) is deprecated, use action='query_find'"
                );
                let mut modified = args.clone();
                if let Some(filter) = args.get("filter") {
                    modified
                        .as_object_mut()
                        .map(|m| m.insert("type".to_string(), filter.clone()));
                }
                crate::info::find_memory_region(&modified).map_err(|e| e.to_string())
            } else {
                crate::memory::query_regions(args).map_err(|e| e.to_string())
            }
        }
        MemoryAction::QueryFind => {
            let mut modified = args.clone();
            if let Some(filter) = args.get("filter") {
                modified
                    .as_object_mut()
                    .map(|m| m.insert("type".to_string(), filter.clone()));
            }
            crate::info::find_memory_region(&modified).map_err(|e| e.to_string())
        }
        MemoryAction::Alloc => {
            require_u64_param(args, "pid", "memory", "alloc")?;
            require_nonzero_usize_param(args, "size", "memory", "alloc")?;
            crate::memory::virtual_alloc_ex(args).map_err(|e| e.to_string())
        }
        MemoryAction::Free => {
            require_u64_param(args, "pid", "memory", "free")?;
            require_u64_param(args, "address", "memory", "free")?;
            crate::memory::virtual_free_ex(args).map_err(|e| e.to_string())
        }
        MemoryAction::Protect => {
            require_u64_param(args, "pid", "memory", "protect")?;
            require_u64_param(args, "address", "memory", "protect")?;
            if args.get("size").is_some() {
                require_nonzero_usize_param(args, "size", "memory", "protect")?;
            }
            crate::memory::virtual_protect_ex(args).map_err(|e| e.to_string())
        }

        // Scan session (Cheat Engine-style persistent scan workflow)
        MemoryAction::ScanNew => crate::memory::session::scan_new(args),
        MemoryAction::ScanNext => crate::memory::session::scan_next(args),
        MemoryAction::ScanUndo => crate::memory::session::scan_undo(args),
        MemoryAction::ScanList => crate::memory::session::scan_list(args),
        MemoryAction::ScanReset => crate::memory::session::scan_reset(args),
        MemoryAction::ScanFreeze => crate::memory::session::scan_freeze(args),
        MemoryAction::Diagnostics => {
            crate::memory::memory_diagnostics(args).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_rejects_unknown_mode() {
        let error = handle_memory(&json!({"action": "read", "mode": "unknown"}))
            .expect_err("unknown read mode should fail before memory read");

        assert!(error.contains("memory(action='read')"));
        assert!(error.contains("mode"));
        assert!(error.contains("raw"));
    }

    #[test]
    fn scan_rejects_unknown_scan_mode() {
        let error = handle_memory(&json!({"action": "scan", "scan_mode": "not_a_mode"}))
            .expect_err("unknown scan mode should fail before scan execution");

        assert!(error.contains("memory(action='scan')"));
        assert!(error.contains("scan_mode"));
        assert!(error.contains("exact"));
    }

    #[test]
    fn alloc_requires_size_after_pid() {
        let error = handle_memory(&json!({"action": "alloc", "pid": 1234}))
            .expect_err("alloc should require size before execution");

        assert!(error.contains("memory(action='alloc')"));
        assert!(error.contains("size"));
    }

    #[test]
    fn free_requires_address_after_pid() {
        let error = handle_memory(&json!({"action": "free", "pid": 1234}))
            .expect_err("free should require address before execution");

        assert!(error.contains("memory(action='free')"));
        assert!(error.contains("address"));
    }
}

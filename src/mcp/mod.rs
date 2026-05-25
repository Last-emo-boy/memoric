//! MCP server module

pub mod action_registry;
#[cfg(test)]
pub(crate) mod conformance;
pub(crate) mod consent;
pub(crate) mod detect_tool;
pub(crate) mod dry_run;
pub(crate) mod guide;
pub(crate) mod hook_tool;
pub(crate) mod http_adapter;
pub(crate) mod inject_tool;
pub(crate) mod kernel_meta;
pub(crate) mod kernel_tool;
pub(crate) mod legacy_tools;
pub(crate) mod memory_tool;
pub mod meta;
pub(crate) mod orchestrate;
pub(crate) mod payload_tool;
pub(crate) mod platform_gate;
pub(crate) mod privilege_tool;
pub mod protocol;
pub(crate) mod readiness;
pub mod request_context;
pub mod resources;
pub(crate) mod self_tool;
pub mod server;
pub(crate) mod stealth_tool;
pub(crate) mod target_tool;
pub mod tasks;
pub(crate) mod tool_args;
pub(crate) mod tool_call;
pub(crate) mod tool_dispatch;
pub(crate) mod tool_list;
pub mod tool_result;
pub(crate) mod tool_schema;
pub(crate) mod tool_state;
pub mod tools;

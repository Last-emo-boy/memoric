//! MCP Tools - Consolidated memory weapon toolkit
//!
//! memoric is a specialized memory weapon MCP server.
//! All tools consolidated into 12 core commands for maximum efficiency.

use serde_json::Value;

pub use crate::mcp::tool_result::{tool_error_payload, tool_success_payload};

pub fn tool_error_text(tool: &str, args: &Value, message: &str) -> String {
    crate::mcp::tool_result::tool_error_text(tool, args, message)
}

/// Register all consolidated tools.
pub fn register_tools() -> Vec<Value> {
    crate::mcp::tool_schema::register_tools()
}

pub fn list_request(request: &Value) -> Result<Value, String> {
    crate::mcp::tool_list::list_request(request)
}

pub fn list_page(limit: usize, cursor: Option<&str>) -> Result<Value, String> {
    crate::mcp::tool_list::list_page(limit, cursor)
}

#[cfg(test)]
#[path = "tool_contract_tests.rs"]
mod tests;

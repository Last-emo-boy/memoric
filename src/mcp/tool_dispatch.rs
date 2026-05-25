//! Standard MCP tool dispatch boundary.

use serde_json::Value;

pub fn is_standard_tool(name: &str) -> bool {
    crate::mcp::action_registry::is_known_tool(name)
}

pub fn dispatch(name: &str, args: &Value) -> Result<Value, String> {
    match crate::mcp::action_registry::tool_handler(name) {
        Some(handler) => handler(args),
        None => Err(format!(
            "Unknown tool: {}. Call `memoric` to see available tools.",
            name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_tool_detection_comes_from_action_registry() {
        for descriptor in crate::mcp::action_registry::tool_descriptors() {
            assert!(
                is_standard_tool(descriptor.name),
                "{} should be standard",
                descriptor.name
            );
        }
        assert!(!is_standard_tool("ps"));
        assert!(!is_standard_tool("not-real"));
    }

    #[test]
    fn every_registered_tool_has_a_handler_binding() {
        for descriptor in crate::mcp::action_registry::tool_descriptors() {
            assert!(
                crate::mcp::action_registry::tool_handler(descriptor.name).is_some(),
                "{} should have a dispatch handler",
                descriptor.name
            );
        }
    }
}

//! Shared dry-run preview policy for state-changing tools.

use serde_json::{json, Value};

pub fn should_preview(tool: &str, args: &Value) -> bool {
    let dry_run = args
        .get("dry_run")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    if !dry_run {
        return false;
    }

    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let traits = crate::mcp::action_registry::classify_action(tool, action);
    traits.state_changing
}

pub fn preview(tool: &str, args: &Value) -> Value {
    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let traits = crate::mcp::action_registry::classify_action(tool, action);
    let provided_fields = args
        .as_object()
        .map(|obj| obj.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();

    json!({
        "success": true,
        "dry_run": true,
        "tool": tool,
        "action": action,
        "summary": format!("Dry run only: {}(action='{}') was not executed", tool, action),
        "would_execute": false,
        "required_policy": traits.required_policy.as_str(),
        "risk": traits.risk.as_str(),
        "state_changing": traits.state_changing,
        "privileged": traits.privileged,
        "kernel": traits.kernel,
        "destructive": traits.destructive,
        "requires_target": traits.requires_target,
        "provided_fields": provided_fields,
        "planned_handles": crate::mcp::action_registry::planned_handles(tool, action)
            .into_iter()
            .map(|handle| handle.to_json())
            .collect::<Vec<_>>(),
        "required_privileges": crate::mcp::action_registry::required_privileges(tool, action),
        "side_effects": crate::mcp::action_registry::side_effects(tool, action),
        "rollback": crate::mcp::action_registry::rollback_preview_metadata(tool, action).to_json(),
        "message": "dry_run=true returned a preview and skipped the live handler"
    })
}

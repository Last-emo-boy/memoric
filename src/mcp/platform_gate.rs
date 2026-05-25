//! Platform fallback gate for Windows-backed tool handlers.

use serde_json::Value;

const SIMULATE_UNSUPPORTED_PLATFORM_ENV: &str = "MEMORIC_SIMULATE_UNSUPPORTED_PLATFORM";

pub(crate) fn validate_tool_call(tool: &str, args: &Value) -> Result<(), String> {
    if platform_supported() {
        return Ok(());
    }

    let action = args
        .get("action")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if is_portable_tool_call(tool, action) {
        return Ok(());
    }

    Err(unsupported_platform_error(tool, action))
}

pub(crate) fn unsupported_platform_simulated() -> bool {
    !platform_supported()
}

fn platform_supported() -> bool {
    cfg!(target_os = "windows") && !simulate_unsupported_platform()
}

fn simulate_unsupported_platform() -> bool {
    std::env::var(SIMULATE_UNSUPPORTED_PLATFORM_ENV)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn is_portable_tool_call(tool: &str, action: &str) -> bool {
    match tool {
        "memoric" => true,
        "self" => matches!(
            action,
            "status"
                | "info"
                | "version"
                | "test"
                | "doctor"
                | "diagnostics"
                | "explain_error"
                | "capability_diff"
                | "next_steps"
        ),
        _ => false,
    }
}

fn unsupported_platform_error(tool: &str, action: &str) -> String {
    let action_hint = if action.is_empty() {
        String::new()
    } else {
        format!("(action='{}')", action)
    };
    format!(
        "unsupported_platform: {}{} is unavailable on this platform. Schema, resource, guide, and self diagnostic calls remain available; Windows process, memory, privilege, driver, kernel, and live orchestration handlers require Windows.",
        tool, action_hint
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    struct EnvRestore {
        previous: Option<String>,
    }

    impl EnvRestore {
        fn simulate_unsupported() -> Self {
            let previous = std::env::var(SIMULATE_UNSUPPORTED_PLATFORM_ENV).ok();
            std::env::set_var(SIMULATE_UNSUPPORTED_PLATFORM_ENV, "1");
            Self { previous }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(SIMULATE_UNSUPPORTED_PLATFORM_ENV, value);
            } else {
                std::env::remove_var(SIMULATE_UNSUPPORTED_PLATFORM_ENV);
            }
        }
    }

    #[test]
    fn simulated_unsupported_platform_allows_schema_safe_self_calls() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = EnvRestore::simulate_unsupported();

        validate_tool_call("memoric", &json!({"status": true})).expect("guide/status");
        validate_tool_call("self", &json!({"action": "status"})).expect("self status");
        validate_tool_call("self", &json!({"action": "doctor"})).expect("self doctor");
        validate_tool_call("self", &json!({"action": "explain_error"}))
            .expect("self explain_error");
    }

    #[test]
    fn simulated_unsupported_platform_blocks_windows_handlers() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        let _env = EnvRestore::simulate_unsupported();

        let error = validate_tool_call(
            "memory",
            &json!({
                "action": "read",
                "pid": std::process::id(),
                "address": "0x1000",
                "size": 4
            }),
        )
        .expect_err("memory read should be platform-gated");

        assert!(error.contains("unsupported_platform"));
        assert!(error.contains("memory(action='read')"));
    }
}

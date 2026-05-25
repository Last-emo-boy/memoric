//! Error types for memoric

use thiserror::Error;

/// Main error type for memoric
#[derive(Error, Debug)]
pub enum MemoricError {
    #[error("Windows API error: {0}")]
    WindowsApi(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Process not found: {0}")]
    ProcessNotFound(u32),

    #[error("Memory access error: {0}")]
    MemoryAccess(String),

    #[error("Injection failed: {0}")]
    InjectionFailed(String),

    #[error("Hook failed: {0}")]
    HookFailed(String),

    #[error("IPC error: {0}")]
    IpcError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, MemoricError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolErrorClassification {
    pub code: &'static str,
    pub hint: &'static str,
}

pub fn classify_tool_error(message: &str) -> ToolErrorClassification {
    let lower = message.to_lowercase();

    if lower.contains("cancelled:") || lower.contains(" was cancelled") {
        ToolErrorClassification {
            code: "cancelled",
            hint: "The task was cancelled cooperatively. Start a new task if the operation is still needed.",
        }
    } else if lower.contains("timeout:") || lower.contains("timed out") {
        ToolErrorClassification {
            code: "timeout",
            hint: "Retry with narrower scope or a larger timeout_ms when the operation is expected to run longer.",
        }
    } else if lower.contains("policy_denied")
        || lower.contains("blocked by policy")
        || lower.contains("policy denied")
    {
        ToolErrorClassification {
            code: "policy_denied",
            hint: "Inspect active policy, consent, and dry_run settings before retrying.",
        }
    } else if lower.contains("unsupported_platform") || lower.contains("unsupported platform") {
        ToolErrorClassification {
            code: "unsupported_platform",
            hint: "Run the action on a supported Windows host or use the read-only capability diagnostics path.",
        }
    } else if lower.contains("driver_unavailable")
        || lower.contains("driver unavailable")
        || lower.contains("driver is not reachable")
        || lower.contains("device is not reachable")
    {
        ToolErrorClassification {
            code: "driver_unavailable",
            hint: "Check driver readiness and signing status before using kernel-backed actions.",
        }
    } else if lower.contains("requires") || lower.contains("missing ") {
        ToolErrorClassification {
            code: "missing_param",
            hint: "Provide the required parameter shown in the error message.",
        }
    } else if lower.contains("invalid ") || lower.contains("invalid_") {
        ToolErrorClassification {
            code: "invalid_param",
            hint: "Check the parameter type, range, and accepted enum values.",
        }
    } else if lower.contains("0x8007012b")
        || lower.contains("partial copy")
        || lower.contains("partial read")
        || lower.contains("299")
    {
        ToolErrorClassification {
            code: "partial_read",
            hint: "The requested span crosses unreadable or incompatible memory. Query regions first, then read a committed readable range or use a smaller size.",
        }
    } else if lower.contains("0x80070005")
        || lower.contains("access is denied")
        || lower.contains("permission denied")
        || lower.contains("access denied")
    {
        ToolErrorClassification {
            code: "access_denied",
            hint: "Run elevated, confirm UAC approval, enable SeDebugPrivilege where applicable, and avoid protected/system processes unless authorized.",
        }
    } else if lower.contains("0x80070057") {
        ToolErrorClassification {
            code: "invalid_target",
            hint: "Verify the PID, thread ID, handle, or address still exists and belongs to the expected process.",
        }
    } else if lower.contains("0x8007006d") || lower.contains("pipe") || lower.contains("broken") {
        ToolErrorClassification {
            code: "ipc_closed",
            hint: "The worker or service pipe closed unexpectedly. Reconnect the MCP session after checking whether the previous action terminated the worker.",
        }
    } else if lower.contains("0xc000010a")
        || lower.contains("terminated")
        || lower.contains("process is terminating")
    {
        ToolErrorClassification {
            code: "process_terminating",
            hint: "The target process is exiting. Wait for a fresh target process and retry after it is initialized.",
        }
    } else if lower.contains("not found") {
        ToolErrorClassification {
            code: "not_found",
            hint: "Verify the target process/module/function/session exists and retry after readiness checks if needed.",
        }
    } else {
        ToolErrorClassification {
            code: "tool_error",
            hint: "Inspect the context fields and retry with narrower parameters.",
        }
    }
}

pub fn classification_for_code(code: &str) -> Option<ToolErrorClassification> {
    let probe = match code.trim().to_ascii_lowercase().as_str() {
        "cancelled" => "cancelled: task cancellation requested",
        "timeout" => "timeout: operation exceeded timeout_ms",
        "policy_denied" => "policy_denied: operation blocked by policy",
        "unsupported_platform" => "unsupported_platform: Windows operation unavailable",
        "driver_unavailable" => "driver_unavailable: memoric.sys device is not reachable",
        "missing_param" => "missing required parameter",
        "invalid_param" => "invalid parameter",
        "partial_read" | "partial_copy" => "partial read",
        "access_denied" => "access is denied",
        "invalid_target" => "0x80070057",
        "ipc_closed" => "worker pipe broken",
        "process_terminating" => "process is terminating",
        "not_found" => "target not found",
        "tool_error" => "unexpected tool failure",
        _ => return None,
    };
    Some(classify_tool_error(probe))
}

pub fn classify_tool_result(value: &serde_json::Value) -> ToolErrorClassification {
    if let Some(classification) = value
        .get("code")
        .and_then(|code| code.as_str())
        .and_then(classification_for_code)
    {
        return classification;
    }

    let mut text = String::new();
    for key in ["error", "message", "summary", "hint"] {
        if let Some(part) = value.get(key).and_then(|part| part.as_str()) {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(part);
        }
    }

    classify_tool_error(&text)
}

impl From<&str> for MemoricError {
    fn from(s: &str) -> Self {
        MemoricError::WindowsApi(s.to_string())
    }
}

impl From<String> for MemoricError {
    fn from(s: String) -> Self {
        MemoricError::WindowsApi(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_windows_and_runtime_errors() {
        let cases = [
            ("Missing params for tools/call", "missing_param"),
            ("invalid action: no_such_action", "invalid_param"),
            ("Windows API error: 0x8007012B partial copy", "partial_read"),
            ("ReadProcessMemory failed: partial read", "partial_read"),
            (
                "OpenProcess failed: Access is denied (0x80070005)",
                "access_denied",
            ),
            ("OpenThread failed: 0x80070057", "invalid_target"),
            ("worker pipe broken: 0x8007006D", "ipc_closed"),
            (
                "target process is terminating: 0xC000010A",
                "process_terminating",
            ),
            ("module not found: kernel32.dll", "not_found"),
            (
                "policy_denied: memory(action='write') blocked",
                "policy_denied",
            ),
            (
                "unsupported_platform: Windows operation unavailable",
                "unsupported_platform",
            ),
            (
                "driver_unavailable: memoric.sys device is not reachable",
                "driver_unavailable",
            ),
            ("timeout: operation exceeded timeout_ms=10", "timeout"),
            ("cancelled: task task-1 cancellation requested", "cancelled"),
        ];

        for (message, expected_code) in cases {
            assert_eq!(
                classify_tool_error(message).code,
                expected_code,
                "{}",
                message
            );
        }
    }

    #[test]
    fn classifies_unknown_errors_as_tool_error() {
        let classification = classify_tool_error("unexpected tool failure");

        assert_eq!(classification.code, "tool_error");
        assert!(classification.hint.contains("Inspect"));
    }

    #[test]
    fn classifies_structured_tool_result() {
        let classification = classify_tool_result(&serde_json::json!({
            "success": false,
            "code": "policy_denied",
            "message": "blocked"
        }));

        assert_eq!(classification.code, "policy_denied");

        let inferred = classify_tool_result(&serde_json::json!({
            "success": false,
            "message": "driver_unavailable: memoric.sys device is not reachable"
        }));
        assert_eq!(inferred.code, "driver_unavailable");
    }
}

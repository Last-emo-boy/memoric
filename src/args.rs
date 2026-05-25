//! Shared argument parsing and bounded validation helpers.
//!
//! MCP clients often send numeric fields as JSON numbers, decimal strings, or
//! hex strings. Keep that behavior consistent here instead of re-implementing
//! ad hoc parsing in every handler.

use serde_json::Value;

pub const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_LIMIT: usize = 10_000;
pub const DEFAULT_MAX_TIMEOUT_MS: u64 = 10 * 60 * 1000;
pub const DEFAULT_MAX_PATH_LEN: usize = 32_767;
pub const DEFAULT_MAX_MODULE_NAME_LEN: usize = 260;

pub fn parse_u64_value(value: Option<&Value>) -> Option<u64> {
    value.and_then(parse_u64)
}

pub fn parse_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().filter(|n| *n >= 0).map(|n| n as u64))
        .or_else(|| value.as_f64().and_then(parse_integral_f64))
        .or_else(|| value.as_str().and_then(parse_numeric_string))
}

pub fn require_u64(args: &Value, key: &str) -> Result<u64, String> {
    parse_u64_value(args.get(key)).ok_or_else(|| format!("Missing or invalid '{}'", key))
}

pub fn require_pid(args: &Value, key: &str) -> Result<u32, String> {
    let value = require_u64(args, key)?;
    if value > u32::MAX as u64 {
        return Err(format!("'{}' is outside the supported u32 PID range", key));
    }
    Ok(value as u32)
}

pub fn require_tid(args: &Value, key: &str) -> Result<u32, String> {
    let value = require_u64(args, key)?;
    if value > u32::MAX as u64 {
        return Err(format!("'{}' is outside the supported u32 TID range", key));
    }
    Ok(value as u32)
}

pub fn parse_address_value(value: Option<&Value>) -> Option<u64> {
    value.and_then(crate::util::parse_address)
}

pub fn require_address(args: &Value, key: &str) -> Result<u64, String> {
    parse_address_value(args.get(key)).ok_or_else(|| {
        format!(
            "Missing or invalid '{}'; expected integer, decimal string, or hex string",
            key
        )
    })
}

pub fn require_nonzero_usize(args: &Value, key: &str, max: usize) -> Result<usize, String> {
    let value = require_u64(args, key)?;
    if value == 0 {
        return Err(format!("'{}' must be greater than 0", key));
    }
    if value > max as u64 {
        return Err(format!("'{}' exceeds maximum {}", key, max));
    }
    usize::try_from(value).map_err(|_| format!("'{}' is too large for this platform", key))
}

pub fn parse_limit(args: &Value, key: &str, default: usize, max: usize) -> Result<usize, String> {
    let value = match args.get(key) {
        Some(value) => parse_u64(value).ok_or_else(|| format!("Invalid '{}'", key))?,
        None => default as u64,
    };
    if value > max as u64 {
        return Err(format!("'{}' exceeds maximum {}", key, max));
    }
    usize::try_from(value).map_err(|_| format!("'{}' is too large for this platform", key))
}

pub fn parse_timeout_ms(args: &Value, default: u64, max: u64) -> Result<u64, String> {
    let value = match args.get("timeout_ms") {
        Some(value) => parse_u64(value).ok_or_else(|| "Invalid 'timeout_ms'".to_string())?,
        None => default,
    };
    if value > max {
        return Err(format!("'timeout_ms' exceeds maximum {}", max));
    }
    Ok(value)
}

pub fn parse_bytes_value(value: &Value, max_len: usize) -> Result<Vec<u8>, String> {
    let bytes = if let Some(values) = value.as_array() {
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                let byte =
                    parse_u64(value).ok_or_else(|| format!("byte[{}] is not an integer", idx))?;
                if byte > u8::MAX as u64 {
                    return Err(format!("byte[{}] exceeds 255", idx));
                }
                Ok(byte as u8)
            })
            .collect::<Result<Vec<_>, String>>()?
    } else if let Some(text) = value.as_str() {
        parse_hex_bytes(text)?
    } else {
        return Err("expected byte array or hex string".to_string());
    };

    if bytes.is_empty() {
        return Err("byte payload must not be empty".to_string());
    }
    if bytes.len() > max_len {
        return Err(format!(
            "byte payload length {} exceeds maximum {}",
            bytes.len(),
            max_len
        ));
    }
    Ok(bytes)
}

pub fn parse_byte_pattern_value(value: &Value, max_len: usize) -> Result<Vec<Option<u8>>, String> {
    let pattern = if let Some(values) = value.as_array() {
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                if value.is_null() {
                    return Ok(None);
                }
                if let Some(text) = value.as_str() {
                    let token = text.trim();
                    if token == "?" || token == "??" {
                        return Ok(None);
                    }
                    if token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                        return u8::from_str_radix(token, 16)
                            .map(Some)
                            .map_err(|err| format!("pattern[{}] invalid hex byte: {}", idx, err));
                    }
                }
                let byte = parse_u64(value)
                    .ok_or_else(|| format!("pattern[{}] is not a byte or wildcard", idx))?;
                if byte > u8::MAX as u64 {
                    return Err(format!("pattern[{}] exceeds 255", idx));
                }
                Ok(Some(byte as u8))
            })
            .collect::<Result<Vec<_>, String>>()?
    } else if let Some(text) = value.as_str() {
        parse_byte_pattern_string(text)?
    } else {
        return Err("expected byte pattern array or string".to_string());
    };

    if pattern.is_empty() {
        return Err("byte pattern must not be empty".to_string());
    }
    if pattern.len() > max_len {
        return Err(format!(
            "byte pattern length {} exceeds maximum {}",
            pattern.len(),
            max_len
        ));
    }
    Ok(pattern)
}

pub fn parse_protection_str(value: &str) -> Option<u32> {
    match value.trim().to_ascii_uppercase().as_str() {
        "RWX" | "PAGE_EXECUTE_READWRITE" => Some(0x40),
        "RW" | "PAGE_READWRITE" => Some(0x04),
        "RX" | "PAGE_EXECUTE_READ" => Some(0x20),
        "R" | "PAGE_READONLY" => Some(0x02),
        "NOACCESS" | "PAGE_NOACCESS" => Some(0x01),
        _ => None,
    }
}

pub fn parse_protection_value(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| value.as_str().and_then(parse_protection_str))
}

pub fn parse_module_name_value(value: &Value, max_len: usize) -> Result<&str, String> {
    let name = value
        .as_str()
        .ok_or_else(|| "expected module name string".to_string())?;
    parse_module_name_str(name, max_len)
}

pub fn parse_module_name_str(value: &str, max_len: usize) -> Result<&str, String> {
    let name = value.trim();
    if name.is_empty() {
        return Err("module name must not be empty".to_string());
    }
    if name.len() > max_len {
        return Err(format!(
            "module name length {} exceeds maximum {}",
            name.len(),
            max_len
        ));
    }
    if name == "." || name == ".." {
        return Err("module name must be a file name, not a relative path segment".to_string());
    }
    if name.contains('\\') || name.contains('/') || name.contains(':') {
        return Err("module name must not contain path separators or drive prefixes".to_string());
    }
    if name.chars().any(|ch| ch == '\0' || ch.is_control()) {
        return Err("module name must not contain NUL or control characters".to_string());
    }
    Ok(name)
}

pub fn parse_path_value(value: &Value, max_len: usize) -> Result<&str, String> {
    let path = value
        .as_str()
        .ok_or_else(|| "expected path string".to_string())?;
    parse_path_str(path, max_len)
}

pub fn parse_path_str(value: &str, max_len: usize) -> Result<&str, String> {
    let path = value.trim();
    if path.is_empty() {
        return Err("path must not be empty".to_string());
    }
    if path.len() > max_len {
        return Err(format!(
            "path length {} exceeds maximum {}",
            path.len(),
            max_len
        ));
    }
    if path.chars().any(|ch| ch == '\0' || ch.is_control()) {
        return Err("path must not contain NUL or control characters".to_string());
    }
    Ok(path)
}

fn parse_numeric_string(value: &str) -> Option<u64> {
    let trimmed = value.trim().replace('_', "");
    if trimmed.is_empty() {
        return None;
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return trimmed.parse::<u64>().ok();
    }

    if trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(&trimmed, 16).ok();
    }

    None
}

fn parse_integral_f64(value: f64) -> Option<u64> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= u64::MAX as f64 {
        Some(value as u64)
    } else {
        None
    }
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    let mut compact = value.trim().to_string();
    if let Some(hex) = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
    {
        compact = hex.to_string();
    }
    compact.retain(|c| !c.is_ascii_whitespace() && c != ',' && c != ':' && c != '-');

    if compact.len() % 2 != 0 {
        return Err("hex byte string must contain an even number of digits".to_string());
    }
    if !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hex byte string contains non-hex characters".to_string());
    }

    (0..compact.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&compact[idx..idx + 2], 16)
                .map_err(|err| format!("invalid hex byte at {}: {}", idx, err))
        })
        .collect()
}

fn parse_byte_pattern_string(value: &str) -> Result<Vec<Option<u8>>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("byte pattern string must not be empty".to_string());
    }

    let tokens = if trimmed.contains(char::is_whitespace) {
        trimmed.split_whitespace().collect::<Vec<_>>()
    } else {
        let compact = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        if compact.contains('?') {
            return Err(
                "compact wildcard patterns must be space-separated, e.g. '48 8B ?? ??'".to_string(),
            );
        }
        if compact.len() % 2 != 0 {
            return Err("compact byte pattern must have an even number of digits".to_string());
        }
        return compact
            .as_bytes()
            .chunks(2)
            .map(|chunk| {
                let token = std::str::from_utf8(chunk).unwrap_or_default();
                if !token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    return Err(format!("invalid byte pattern token '{}'", token));
                }
                u8::from_str_radix(token, 16)
                    .map(Some)
                    .map_err(|err| format!("invalid byte pattern token '{}': {}", token, err))
            })
            .collect();
    };

    tokens
        .into_iter()
        .map(|token| {
            let token = token.trim();
            if token == "?" || token == "??" {
                Ok(None)
            } else if token.len() == 2 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
                u8::from_str_radix(token, 16)
                    .map(Some)
                    .map_err(|err| format!("invalid byte pattern token '{}': {}", token, err))
            } else {
                Err(format!(
                    "invalid byte pattern token '{}'; use hex bytes or ?? wildcards",
                    token
                ))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_numbers_without_treating_decimal_strings_as_hex() {
        assert_eq!(parse_u64(&json!(100)), Some(100));
        assert_eq!(parse_u64(&json!("100")), Some(100));
        assert_eq!(parse_u64(&json!("0x100")), Some(256));
        assert_eq!(parse_u64(&json!("7ffabc")), Some(0x7ffabc));
        assert_eq!(parse_u64(&json!(-1)), None);
    }

    #[test]
    fn validates_bounds() {
        assert_eq!(
            require_nonzero_usize(&json!({"size": 8}), "size", 16).unwrap(),
            8
        );
        assert!(require_nonzero_usize(&json!({"size": 0}), "size", 16).is_err());
        assert!(require_nonzero_usize(&json!({"size": 17}), "size", 16).is_err());
        assert!(parse_limit(&json!({"limit": 11}), "limit", 1, 10).is_err());
    }

    #[test]
    fn parses_bytes_from_array_or_hex() {
        assert_eq!(
            parse_bytes_value(&json!([0, "0x10", 255]), DEFAULT_MAX_BYTES).unwrap(),
            vec![0, 16, 255]
        );
        assert_eq!(
            parse_bytes_value(&json!("DE AD BE EF"), DEFAULT_MAX_BYTES).unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(parse_bytes_value(&json!([256]), DEFAULT_MAX_BYTES).is_err());
    }

    #[test]
    fn parses_byte_patterns_with_wildcards() {
        assert_eq!(
            parse_byte_pattern_value(&json!("48 8B ?? 00"), DEFAULT_MAX_BYTES).unwrap(),
            vec![Some(0x48), Some(0x8B), None, Some(0x00)]
        );
        assert_eq!(
            parse_byte_pattern_value(&json!("0xDEADBEEF"), DEFAULT_MAX_BYTES).unwrap(),
            vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]
        );
        assert_eq!(
            parse_byte_pattern_value(&json!([0x90, null, "??", "CC"]), DEFAULT_MAX_BYTES).unwrap(),
            vec![Some(0x90), None, None, Some(0xCC)]
        );
        assert!(parse_byte_pattern_value(&json!("488B??00"), DEFAULT_MAX_BYTES).is_err());
        assert!(parse_byte_pattern_value(&json!([256]), DEFAULT_MAX_BYTES).is_err());
    }

    #[test]
    fn parses_protection_flags() {
        assert_eq!(parse_protection_str("RWX"), Some(0x40));
        assert_eq!(parse_protection_str("page_readwrite"), Some(0x04));
        assert_eq!(parse_protection_value(&json!(0x20)), Some(0x20));
    }

    #[test]
    fn validates_module_names_without_accepting_paths() {
        assert_eq!(
            parse_module_name_value(&json!(" ntdll.dll "), DEFAULT_MAX_MODULE_NAME_LEN).unwrap(),
            "ntdll.dll"
        );
        assert!(parse_module_name_value(&json!(""), DEFAULT_MAX_MODULE_NAME_LEN).is_err());
        assert!(parse_module_name_value(
            &json!("C:\\Windows\\System32\\ntdll.dll"),
            DEFAULT_MAX_MODULE_NAME_LEN
        )
        .is_err());
        assert!(parse_module_name_value(&json!(".."), DEFAULT_MAX_MODULE_NAME_LEN).is_err());
        assert!(parse_module_name_value(&json!("bad\0.dll"), DEFAULT_MAX_MODULE_NAME_LEN).is_err());
    }

    #[test]
    fn validates_paths_with_length_and_control_character_limits() {
        assert_eq!(
            parse_path_value(&json!(" C:\\temp\\payload.dll "), DEFAULT_MAX_PATH_LEN).unwrap(),
            "C:\\temp\\payload.dll"
        );
        assert!(parse_path_value(&json!(""), DEFAULT_MAX_PATH_LEN).is_err());
        assert!(parse_path_value(&json!("bad\0path"), DEFAULT_MAX_PATH_LEN).is_err());
        assert!(parse_path_value(&json!("a".repeat(12)), 8).is_err());
    }
}

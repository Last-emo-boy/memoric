//! Common utility functions

use serde_json::Value;

/// Parse an address from a JSON Value.
/// Handles both JSON numbers (u64) and hex strings ("0x1234ABCD" or "1234ABCD").
/// This is critical because tools return addresses as hex strings (e.g. "0x00007FFE1234ABCD")
/// but callers may also pass raw integers.
pub fn parse_address(value: &Value) -> Option<u64> {
    // Try as JSON number first
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    // Also try as i64 in case it's negative in JSON (shouldn't happen for addresses, but defensive)
    if let Some(n) = value.as_i64() {
        return Some(n as u64);
    }
    // Try as string
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();

        // Has 0x prefix → parse as hex
        if let Some(hex_str) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex_str, 16).ok();
        }

        // Contains hex chars (a-f, A-F) → must be hex
        if trimmed.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
            return u64::from_str_radix(trimmed, 16).ok();
        }

        // All digits → parse as DECIMAL (this is the fix)
        if trimmed.chars().all(|c| c.is_ascii_digit()) {
            return trimmed.parse::<u64>().ok();
        }

        // Fallback: try hex anyway
        return u64::from_str_radix(trimmed, 16).ok();
    }
    // Try as f64 (JSON numbers > 2^53 may come as floats from some clients)
    if let Some(f) = value.as_f64() {
        if f >= 0.0 && f <= u64::MAX as f64 {
            return Some(f as u64);
        }
    }
    None
}

/// Parse an address with descriptive error messages
pub fn parse_address_strict(value: &Value) -> Result<u64, String> {
    parse_address(value).ok_or_else(|| {
        format!(
            "Invalid address format: {:?}. Expected u64, hex string (0x...), or decimal string.",
            value
        )
    })
}

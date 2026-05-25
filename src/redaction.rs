//! Result and audit redaction profiles.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionProfile {
    None,
    Standard,
    Strict,
}

impl RedactionProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DataClassification {
    Public,
    LocalSensitive,
    CredentialLike,
    RawMemory,
    Path,
    ArtifactReference,
}

impl DataClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::LocalSensitive => "local-sensitive",
            Self::CredentialLike => "credential-like",
            Self::RawMemory => "raw-memory",
            Self::Path => "path",
            Self::ArtifactReference => "artifact-reference",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataClassificationRule {
    pub path: &'static str,
    pub classification: DataClassification,
}

pub const fn classification_rule(
    path: &'static str,
    classification: DataClassification,
) -> DataClassificationRule {
    DataClassificationRule {
        path,
        classification,
    }
}

pub fn profile_from_args(args: &Value) -> RedactionProfile {
    args.get("redaction")
        .and_then(|value| value.as_str())
        .and_then(parse_profile)
        .or_else(|| {
            std::env::var("MEMORIC_REDACTION")
                .ok()
                .as_deref()
                .and_then(parse_profile)
        })
        .unwrap_or(RedactionProfile::Standard)
}

pub fn parse_profile(value: &str) -> Option<RedactionProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "none" | "off" | "false" => Some(RedactionProfile::None),
        "standard" | "default" => Some(RedactionProfile::Standard),
        "strict" | "safe" => Some(RedactionProfile::Strict),
        _ => None,
    }
}

pub fn redact_for_args(value: &Value, args: &Value) -> Value {
    redact_value(value, profile_from_args(args))
}

pub fn redact_value(value: &Value, profile: RedactionProfile) -> Value {
    redact_with_path(value, None, &mut Vec::new(), profile, &[])
}

pub fn redact_value_with_classifications(
    value: &Value,
    profile: RedactionProfile,
    rules: &[DataClassificationRule],
) -> Value {
    redact_with_path(value, None, &mut Vec::new(), profile, rules)
}

pub fn metadata(profile: RedactionProfile) -> Value {
    json!({
        "profile": profile.as_str(),
        "env": "MEMORIC_REDACTION",
        "argument": "redaction"
    })
}

fn redact_with_path(
    value: &Value,
    key: Option<&str>,
    path: &mut Vec<String>,
    profile: RedactionProfile,
    rules: &[DataClassificationRule],
) -> Value {
    if profile == RedactionProfile::None {
        return value.clone();
    }

    if let Some(classification) = classification_for_path(path, rules) {
        if should_redact_classification(classification, profile) {
            return classification_marker(classification, value);
        }
    }

    if key.is_some_and(|key| should_redact_key(key, value, profile)) {
        return redaction_marker(key.unwrap(), value, profile);
    }

    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (child_key, child_value) in map {
                path.push(child_key.clone());
                out.insert(
                    child_key.clone(),
                    redact_with_path(child_value, Some(child_key), path, profile, rules),
                );
                path.pop();
            }
            Value::Object(out)
        }
        Value::Array(values) => {
            if profile == RedactionProfile::Strict
                && key.is_some_and(is_raw_bytes_key)
                && looks_like_byte_array(values)
            {
                return json!({
                    "redacted": true,
                    "reason": "raw_bytes",
                    "count": values.len()
                });
            }
            Value::Array(
                values
                    .iter()
                    .map(|child| {
                        path.push("[]".to_string());
                        let redacted = redact_with_path(child, key, path, profile, rules);
                        path.pop();
                        redacted
                    })
                    .collect(),
            )
        }
        _ => value.clone(),
    }
}

fn classification_for_path(
    path: &[String],
    rules: &[DataClassificationRule],
) -> Option<DataClassification> {
    if path.is_empty() {
        return None;
    }

    let formatted = format_classification_path(path);
    rules
        .iter()
        .find(|rule| rule.path == formatted)
        .map(|rule| rule.classification)
}

fn format_classification_path(path: &[String]) -> String {
    let mut formatted = String::new();
    for segment in path {
        if segment == "[]" {
            formatted.push_str("[]");
        } else {
            if !formatted.is_empty() {
                formatted.push('.');
            }
            formatted.push_str(segment);
        }
    }
    formatted
}

fn should_redact_classification(
    classification: DataClassification,
    profile: RedactionProfile,
) -> bool {
    match classification {
        DataClassification::Public => false,
        DataClassification::CredentialLike => {
            matches!(
                profile,
                RedactionProfile::Standard | RedactionProfile::Strict
            )
        }
        DataClassification::LocalSensitive
        | DataClassification::RawMemory
        | DataClassification::Path
        | DataClassification::ArtifactReference => profile == RedactionProfile::Strict,
    }
}

fn classification_marker(classification: DataClassification, value: &Value) -> Value {
    let mut marker = serde_json::Map::new();
    marker.insert("redacted".to_string(), json!(true));
    marker.insert("classification".to_string(), json!(classification.as_str()));
    marker.insert("reason".to_string(), json!(classification.as_str()));

    match value {
        Value::Array(values) => {
            marker.insert("count".to_string(), json!(values.len()));
        }
        Value::String(text) => {
            marker.insert("chars".to_string(), json!(text.chars().count()));
        }
        _ => {}
    }

    Value::Object(marker)
}

fn should_redact_key(key: &str, value: &Value, profile: RedactionProfile) -> bool {
    let lower = key.to_ascii_lowercase();

    let standard = matches!(
        lower.as_str(),
        "shellcode"
            | "shellcode_bytes"
            | "payload"
            | "payload_hex"
            | "key"
            | "token"
            | "access_token"
            | "refresh_token"
            | "consent_token"
            | "password"
            | "secret"
            | "credential"
            | "credentials"
    );

    if standard {
        return true;
    }

    profile == RedactionProfile::Strict
        && ((is_raw_bytes_key(&lower)
            && value
                .as_array()
                .is_some_and(|values| looks_like_byte_array(values)))
            || lower == "hex"
            || lower.ends_with("_hex")
            || lower == "dump_file"
            || lower == "dump_path"
            || lower == "output_path"
            || lower == "output_dir"
            || lower == "file_path"
            || lower.ends_with("_path")
            || lower == "path"
            || lower.contains("credential"))
}

fn redaction_marker(key: &str, value: &Value, profile: RedactionProfile) -> Value {
    if profile == RedactionProfile::Strict && is_raw_bytes_key(key) {
        let count = value.as_array().map(|values| values.len());
        return json!({
            "redacted": true,
            "reason": "raw_bytes",
            "count": count
        });
    }
    json!("<redacted>")
}

fn is_raw_bytes_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "bytes" | "raw_bytes" | "data" | "buffer" | "dump" | "memory" | "contents"
    )
}

fn looks_like_byte_array(values: &[Value]) -> bool {
    !values.is_empty()
        && values.len() >= 4
        && values.iter().all(|value| {
            value
                .as_u64()
                .is_some_and(|number| number <= u8::MAX as u64)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn standard_redacts_tokens_and_payloads() {
        let value = redact_value(
            &json!({"token": "abc", "payload": [1, 2, 3], "pid": 7}),
            RedactionProfile::Standard,
        );
        assert_eq!(value["token"], "<redacted>");
        assert_eq!(value["payload"], "<redacted>");
        assert_eq!(value["pid"], 7);
    }

    #[test]
    fn strict_redacts_paths_hex_and_raw_bytes() {
        let value = redact_value(
            &json!({
                "path": "C:\\temp\\dump.bin",
                "hex": "DEADBEEF",
                "bytes": [1, 2, 3, 4],
                "nested": {"output_path": "C:\\temp\\out.bin"}
            }),
            RedactionProfile::Strict,
        );
        assert_eq!(value["path"], "<redacted>");
        assert_eq!(value["hex"], "<redacted>");
        assert_eq!(value["bytes"]["redacted"], true);
        assert_eq!(value["nested"]["output_path"], "<redacted>");
    }

    #[test]
    fn classification_rules_drive_strict_redaction() {
        let rules = [
            classification_rule("outer.innocent_name", DataClassification::RawMemory),
            classification_rule("outer.location_hint", DataClassification::Path),
            classification_rule("outer.items[].preview", DataClassification::LocalSensitive),
        ];
        let value = redact_value_with_classifications(
            &json!({
                "outer": {
                    "innocent_name": [1, 2, 3, 4],
                    "location_hint": "C:\\temp\\sample.bin",
                    "items": [{"preview": "operator-local detail"}]
                }
            }),
            RedactionProfile::Strict,
            &rules,
        );

        assert_eq!(
            value["outer"]["innocent_name"]["classification"],
            "raw-memory"
        );
        assert_eq!(value["outer"]["innocent_name"]["count"], 4);
        assert_eq!(value["outer"]["location_hint"]["classification"], "path");
        assert_eq!(
            value["outer"]["items"][0]["preview"]["classification"],
            "local-sensitive"
        );
    }

    #[test]
    fn classification_rules_drive_standard_credential_redaction() {
        let rules = [classification_rule(
            "metadata.auth_material",
            DataClassification::CredentialLike,
        )];
        let value = redact_value_with_classifications(
            &json!({"metadata": {"auth_material": "opaque"}}),
            RedactionProfile::Standard,
            &rules,
        );

        assert_eq!(
            value["metadata"]["auth_material"]["classification"],
            "credential-like"
        );
    }

    #[test]
    fn none_leaves_values_unchanged() {
        let original = json!({"token": "abc", "bytes": [1, 2, 3, 4]});
        assert_eq!(redact_value(&original, RedactionProfile::None), original);
    }
}

//! Artifact integrity metadata and MCP resource links.
//!
//! The registry only references files that handlers already produced and
//! reported. Artifact URIs are hash-scoped handles, so clients do not receive a
//! direct filesystem path unless their redaction profile allows it.

use once_cell::sync::Lazy;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const ARTIFACT_URI_PREFIX: &str = "memoric://artifact/sha256/";
pub const DEFAULT_ARTIFACT_RETENTION_SECS: u64 = 15 * 60;
pub const MAX_ARTIFACT_RETENTION_SECS: u64 = 24 * 60 * 60;

static ARTIFACTS: Lazy<Mutex<HashMap<String, ArtifactRecord>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
struct ArtifactRecord {
    uri: String,
    name: String,
    path: PathBuf,
    mime_type: String,
    size_bytes: u64,
    sha256: String,
    created_at: u64,
    last_modified: String,
    expires_at: u64,
    retention_secs: u64,
    classification: String,
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn json_integrity(value: &Value) -> Value {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    json!({
        "algorithm": "sha256",
        "result_sha256": sha256_bytes(&bytes),
        "result_bytes": bytes.len()
    })
}

pub fn collect_artifacts(result: &Value) -> Vec<Value> {
    collect_artifacts_with_retention(result, DEFAULT_ARTIFACT_RETENTION_SECS)
}

pub fn collect_artifacts_with_retention(result: &Value, retention_secs: u64) -> Vec<Value> {
    collect_artifacts_with_retention_and_correlation(result, retention_secs, None)
}

pub fn collect_artifacts_with_retention_and_correlation(
    result: &Value,
    retention_secs: u64,
    correlation_id: Option<&str>,
) -> Vec<Value> {
    let mut paths = Vec::new();
    collect_artifact_paths(result, &mut paths);
    paths.sort();
    paths.dedup();

    paths
        .into_iter()
        .filter_map(|path| {
            register_file_artifact_with_correlation(&path, retention_secs, correlation_id).ok()
        })
        .collect()
}

pub fn collect_artifact_references(result: &Value) -> Vec<Value> {
    let mut references = Vec::new();
    collect_artifact_reference_values(result, &mut references);
    references.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["uri"].as_str().unwrap_or_default())
    });
    references.dedup_by(|left, right| left["uri"] == right["uri"]);
    references
}

pub fn file_artifact_json(path: &Path) -> Result<Value, String> {
    register_file_artifact(path, DEFAULT_ARTIFACT_RETENTION_SECS)
}

pub fn retention_secs_from_args(args: &Value) -> u64 {
    args.get("artifact_retention_secs")
        .and_then(crate::args::parse_u64)
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_ARTIFACT_RETENTION_SECS))
        .unwrap_or(DEFAULT_ARTIFACT_RETENTION_SECS)
}

pub fn register_file_artifact(path: &Path, retention_secs: u64) -> Result<Value, String> {
    register_file_artifact_with_correlation(path, retention_secs, None)
}

pub fn register_file_artifact_with_correlation(
    path: &Path,
    retention_secs: u64,
    correlation_id: Option<&str>,
) -> Result<Value, String> {
    let metadata =
        std::fs::metadata(path).map_err(|err| format!("metadata {}: {}", path.display(), err))?;
    if metadata.is_dir() {
        return Ok(json!({
            "kind": "directory",
            "path": path.display().to_string(),
            "exists": true,
            "size_bytes": 0,
            "sha256": Value::Null,
            "hash_error": "directory hashing is not supported"
        }));
    }
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }

    let sha256 = sha256_file(path)?;
    let uri = format!("{}{}", ARTIFACT_URI_PREFIX, sha256);
    let now = now_epoch();
    let retention_secs = retention_secs.min(MAX_ARTIFACT_RETENTION_SECS);
    let expires_at = now.saturating_add(retention_secs);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact")
        .to_string();
    let mime_type = guess_mime_type(path);
    let last_modified = crate::state::chrono_now_public();
    let record = ArtifactRecord {
        uri: uri.clone(),
        name: name.clone(),
        path: path.to_path_buf(),
        mime_type: mime_type.clone(),
        size_bytes: metadata.len(),
        sha256: sha256.clone(),
        created_at: now,
        last_modified: last_modified.clone(),
        expires_at,
        retention_secs,
        classification: "artifact-reference".to_string(),
    };
    ARTIFACTS
        .lock()
        .map_err(|err| err.to_string())?
        .insert(uri.clone(), record);

    let artifact = json!({
        "kind": "file",
        "path": path.display().to_string(),
        "uri": uri,
        "name": name,
        "mimeType": mime_type,
        "exists": true,
        "size_bytes": metadata.len(),
        "sha256": sha256,
        "classification": "artifact-reference",
        "created_at": now,
        "last_modified": last_modified,
        "expires_at": expires_at,
        "retention_secs": retention_secs,
        "verified": true
    });
    crate::observability::record_artifact_registered(&artifact, correlation_id);
    Ok(artifact)
}

pub fn write_artifact_bytes<P: AsRef<Path>>(
    path: P,
    bytes: &[u8],
    retention_secs: u64,
    correlation_id: Option<&str>,
) -> Result<Value, String> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("create {}: {}", parent.display(), err))?;
        }
    }
    std::fs::write(path, bytes).map_err(|err| format!("write {}: {}", path.display(), err))?;
    register_file_artifact_with_correlation(path, retention_secs, correlation_id)
}

pub fn is_artifact_uri(uri: &str) -> bool {
    uri.starts_with(ARTIFACT_URI_PREFIX)
}

pub fn registry_json() -> Value {
    cleanup_expired(false);
    let records = ARTIFACTS
        .lock()
        .map(|records| {
            let mut artifacts = records
                .values()
                .map(ArtifactRecord::to_json)
                .collect::<Vec<_>>();
            artifacts.sort_by(|left, right| {
                left["uri"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["uri"].as_str().unwrap_or_default())
            });
            artifacts
        })
        .unwrap_or_default();

    json!({
        "success": true,
        "count": records.len(),
        "artifacts": records,
        "retention": {
            "default_secs": DEFAULT_ARTIFACT_RETENTION_SECS,
            "max_secs": MAX_ARTIFACT_RETENTION_SECS
        }
    })
}

pub fn read_resource_content(uri: &str) -> Result<Value, String> {
    let record = {
        let mut records = ARTIFACTS.lock().map_err(|err| err.to_string())?;
        let record = records
            .get(uri)
            .cloned()
            .ok_or_else(|| format!("Artifact resource not found: {}", uri))?;
        if record.is_expired(now_epoch()) {
            records.remove(uri);
            return Err(format!("Artifact resource expired: {}", uri));
        }
        record
    };

    let current_sha = sha256_file(&record.path)?;
    if current_sha != record.sha256 {
        return Err(format!(
            "Artifact hash mismatch for {}: expected {}, got {}",
            uri, record.sha256, current_sha
        ));
    }

    let bytes = std::fs::read(&record.path)
        .map_err(|err| format!("read {}: {}", record.path.display(), err))?;
    let mut content = json!({
        "uri": uri,
        "mimeType": record.mime_type,
        "annotations": {
            "audience": ["user"],
            "priority": 0.7,
            "lastModified": record.last_modified
        }
    });
    match String::from_utf8(bytes) {
        Ok(text) => content["text"] = json!(text),
        Err(err) => content["blob"] = json!(base64_encode(&err.into_bytes())),
    }
    Ok(content)
}

pub fn cleanup_expired(dry_run: bool) -> Value {
    cleanup_expired_filtered(dry_run, None)
}

pub fn cleanup_expired_filtered(dry_run: bool, correlation_id: Option<&str>) -> Value {
    let now = now_epoch();
    let Ok(mut records) = ARTIFACTS.lock() else {
        return json!({
            "success": false,
            "error": "artifact registry lock is poisoned"
        });
    };
    let expired = records
        .iter()
        .filter(|(uri, record)| {
            let is_expired = record.is_expired(now) || !record.path.exists();
            let matches_scope = correlation_id
                .map(|correlation_id| {
                    crate::observability::artifact_registered_with_correlation(uri, correlation_id)
                })
                .unwrap_or(true);
            is_expired && matches_scope
        })
        .map(|(uri, record)| {
            json!({
                "uri": uri,
                "path": record.path.display().to_string(),
                "expires_at": record.expires_at,
                "missing": !record.path.exists()
            })
        })
        .collect::<Vec<_>>();

    if !dry_run {
        for entry in &expired {
            if let Some(uri) = entry["uri"].as_str() {
                records.remove(uri);
            }
        }
    }

    json!({
        "success": true,
        "dry_run": dry_run,
        "correlation_id": correlation_id,
        "expired_count": expired.len(),
        "removed_count": if dry_run { 0 } else { expired.len() },
        "expired": expired
    })
}

pub fn cleanup_for_task(task_id: &str, dry_run: bool) -> Value {
    let correlation_id = crate::observability::task_correlation_id(task_id);
    let mut result = cleanup_expired_filtered(dry_run, correlation_id.as_deref());
    if let Some(obj) = result.as_object_mut() {
        obj.insert("task_id".to_string(), json!(task_id));
        obj.insert("matched_correlation_id".to_string(), json!(correlation_id));
    }
    result
}

pub fn forget(uri: &str) -> bool {
    ARTIFACTS
        .lock()
        .map(|mut records| records.remove(uri).is_some())
        .unwrap_or(false)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|err| format!("open {}: {}", path.display(), err))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("read {}: {}", path.display(), err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

impl ArtifactRecord {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    fn to_json(&self) -> Value {
        json!({
            "kind": "file",
            "uri": self.uri,
            "name": self.name,
            "path": self.path.display().to_string(),
            "mimeType": self.mime_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "classification": self.classification,
            "created_at": self.created_at,
            "last_modified": self.last_modified,
            "expires_at": self.expires_at,
            "retention_secs": self.retention_secs
        })
    }
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn guess_mime_type(path: &Path) -> String {
    match path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "json" => "application/json",
        "md" => "text/markdown",
        "txt" | "log" | "csv" => "text/plain",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(b0 >> 2) as usize] as char);
        output.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn collect_artifact_paths(value: &Value, paths: &mut Vec<PathBuf>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_artifact_path_key(key, map) {
                    if let Some(path) = child
                        .as_str()
                        .map(str::trim)
                        .filter(|path| !path.is_empty())
                    {
                        let candidate = PathBuf::from(path);
                        if candidate.is_file() {
                            paths.push(candidate);
                        }
                    }
                }
                collect_artifact_paths(child, paths);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_artifact_paths(child, paths);
            }
        }
        _ => {}
    }
}

fn collect_artifact_reference_values(value: &Value, references: &mut Vec<Value>) {
    match value {
        Value::Object(map) => {
            if let Some(reference) = artifact_reference_from_map(map) {
                references.push(reference);
            }
            for child in map.values() {
                collect_artifact_reference_values(child, references);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_artifact_reference_values(child, references);
            }
        }
        _ => {}
    }
}

fn artifact_reference_from_map(map: &serde_json::Map<String, Value>) -> Option<Value> {
    let uri = map.get("uri").and_then(|value| value.as_str())?;
    if !is_artifact_uri(uri) {
        return None;
    }

    Some(json!({
        "kind": map.get("kind").cloned().unwrap_or_else(|| json!("file")),
        "uri": uri,
        "name": map.get("name").cloned().unwrap_or_else(|| json!("artifact")),
        "mimeType": map
            .get("mimeType")
            .cloned()
            .unwrap_or_else(|| json!("application/octet-stream")),
        "size_bytes": map.get("size_bytes").cloned().unwrap_or(Value::Null),
        "sha256": map.get("sha256").cloned().unwrap_or(Value::Null),
        "classification": map
            .get("classification")
            .cloned()
            .unwrap_or_else(|| json!("artifact-reference")),
        "created_at": map.get("created_at").cloned().unwrap_or(Value::Null),
        "last_modified": map.get("last_modified").cloned().unwrap_or(Value::Null),
        "expires_at": map.get("expires_at").cloned().unwrap_or(Value::Null),
        "retention_secs": map.get("retention_secs").cloned().unwrap_or(Value::Null),
        "verified": map.get("verified").cloned().unwrap_or(Value::Null),
    }))
}

fn is_artifact_path_key(key: &str, map: &serde_json::Map<String, Value>) -> bool {
    match key {
        "dump_file" | "dump_path" | "artifact_path" | "output_file" | "output_path" => true,
        "path" => {
            map.contains_key("size_bytes")
                || map.contains_key("sha256")
                || map
                    .get("status")
                    .and_then(|value| value.as_str())
                    .is_some_and(|status| status.eq_ignore_ascii_case("success"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hashes_bytes_with_sha256() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn collects_existing_file_artifacts() {
        let path =
            std::env::temp_dir().join(format!("memoric-artifact-test-{}.bin", std::process::id()));
        std::fs::write(&path, b"artifact").unwrap();
        let result = json!({"dump_file": path.display().to_string()});

        let artifacts = collect_artifacts(&result);
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0]["size_bytes"], 8);
        assert!(artifacts[0]["sha256"].as_str().is_some());
        assert!(artifacts[0]["uri"]
            .as_str()
            .unwrap()
            .starts_with(ARTIFACT_URI_PREFIX));

        let _ = forget(artifacts[0]["uri"].as_str().unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn registered_artifact_resource_reads_text_after_hash_check() {
        let path =
            std::env::temp_dir().join(format!("memoric-artifact-read-{}.txt", std::process::id()));
        std::fs::write(&path, "artifact text").unwrap();
        let artifact = register_file_artifact(&path, 60).expect("register artifact");
        let uri = artifact["uri"].as_str().unwrap();

        let content = read_resource_content(uri).expect("artifact resource");
        assert_eq!(content["uri"], uri);
        assert_eq!(content["mimeType"], "text/plain");
        assert_eq!(content["text"], "artifact text");

        let _ = forget(uri);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn collects_registered_artifact_reference_without_path() {
        let reference = json!({
            "artifact": {
                "kind": "file",
                "uri": format!("{}abc", ARTIFACT_URI_PREFIX),
                "name": "bundle.json",
                "mimeType": "application/json",
                "size_bytes": 10,
                "sha256": "abc",
                "path": "C:\\temp\\bundle.json"
            }
        });

        let references = collect_artifact_references(&reference);
        assert_eq!(references.len(), 1);
        assert_eq!(references[0]["uri"], format!("{}abc", ARTIFACT_URI_PREFIX));
        assert!(references[0].get("path").is_none());
    }

    #[test]
    fn cleanup_expired_supports_dry_run_preview() {
        let path = std::env::temp_dir().join(format!(
            "memoric-artifact-expired-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "expired").unwrap();
        let artifact = register_file_artifact(&path, 0).expect("register artifact");
        let uri = artifact["uri"].as_str().unwrap().to_string();

        let preview = cleanup_expired(true);
        assert_eq!(preview["dry_run"], true);
        assert!(preview["expired_count"].as_u64().unwrap_or_default() >= 1);
        assert!(preview["expired"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["uri"] == uri));
        assert!(read_resource_content(&uri).is_err());

        let _ = forget(&uri);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cleanup_expired_can_filter_by_correlation_id() {
        let path =
            std::env::temp_dir().join(format!("memoric-artifact-scope-{}.txt", std::process::id()));
        std::fs::write(&path, "scoped").unwrap();
        let artifact = register_file_artifact_with_correlation(&path, 0, Some("task-1"))
            .expect("register artifact");
        let uri = artifact["uri"].as_str().unwrap().to_string();

        let scoped = cleanup_expired_filtered(true, Some("task-1"));
        assert!(scoped["expired"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["uri"] == uri));

        let unscoped = cleanup_expired_filtered(true, Some("other-task"));
        assert!(!unscoped["expired"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["uri"] == uri));

        let _ = forget(&uri);
        let _ = std::fs::remove_file(path);
    }
}

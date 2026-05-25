//! Runtime policy gates for MCP tool calls.
//!
//! Policy defaults to `observe`, which allows read-only operations and dry-run
//! previews. Broader policies can be enabled with `MEMORIC_POLICY`.

use crate::info::process::ProcessFingerprint;
use crate::mcp::action_registry::ActionTraits;
use crate::mcp::action_registry::{self, PolicyLevel};
use crate::mcp::request_context::{current_request_context, PolicyOrigin};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::RefCell;
use std::path::{Path, PathBuf};

#[cfg(test)]
thread_local! {
    static TEST_AUDIT_PATH: RefCell<Option<String>> = const { RefCell::new(None) };
}

const POLICY_PROFILE_PATH_ENV: &str = "MEMORIC_POLICY_PROFILE_PATH";
const POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE_ENV: &str = "MEMORIC_POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE";

#[derive(Debug, Clone)]
struct PolicyProfileResolution {
    configured: bool,
    path: Option<String>,
    profile: Option<String>,
    version: Option<u64>,
    base_policy: PolicyLevel,
    declared_policy: Option<PolicyLevel>,
    effective_policy: PolicyLevel,
    file_sha256: Option<String>,
    hash_expected: Option<String>,
    hash_verified: Option<bool>,
    signature_expected: Option<String>,
    signature_verified: Option<bool>,
    verification_issues: Vec<String>,
    status: &'static str,
    error: Option<String>,
    downgraded: bool,
    override_applied: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub configured_level: PolicyLevel,
    pub required_level: PolicyLevel,
    pub reason: String,
}

impl PolicyDecision {
    pub fn allowed(configured_level: PolicyLevel, required_level: PolicyLevel) -> Self {
        Self {
            allowed: true,
            configured_level,
            required_level,
            reason: "allowed".to_string(),
        }
    }

    pub fn denied(
        configured_level: PolicyLevel,
        required_level: PolicyLevel,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            allowed: false,
            configured_level,
            required_level,
            reason: reason.into(),
        }
    }

    pub fn as_json(&self) -> Value {
        json!({
            "allowed": self.allowed,
            "configured_policy": self.configured_level.as_str(),
            "required_policy": self.required_level.as_str(),
            "reason": self.reason,
            "policy_profile": crate::policy::policy_profile_audit_json(),
        })
    }
}

pub fn configured_level() -> PolicyLevel {
    policy_profile_resolution().effective_policy
}

pub fn policy_profile_status_json() -> Value {
    let profile = policy_profile_resolution();
    profile.to_status_json()
}

pub fn policy_profile_audit_json() -> Value {
    let profile = policy_profile_resolution();
    profile.to_audit_json()
}

fn base_policy_level() -> PolicyLevel {
    std::env::var("MEMORIC_POLICY")
        .ok()
        .as_deref()
        .and_then(parse_policy_level)
        .unwrap_or(PolicyLevel::Observe)
}

fn policy_profile_resolution() -> PolicyProfileResolution {
    let base_policy = base_policy_level();
    let Some(path) = policy_profile_path() else {
        return PolicyProfileResolution {
            configured: false,
            path: None,
            profile: None,
            version: None,
            base_policy,
            declared_policy: None,
            effective_policy: base_policy,
            file_sha256: None,
            hash_expected: None,
            hash_verified: None,
            signature_expected: None,
            signature_verified: None,
            verification_issues: Vec::new(),
            status: "absent",
            error: None,
            downgraded: false,
            override_applied: false,
        };
    };

    let parsed = match load_policy_profile(&path) {
        Ok(profile) => profile,
        Err(error) => {
            let override_applied = policy_profile_override_enabled();
            return PolicyProfileResolution {
                configured: true,
                path: Some(path),
                profile: None,
                version: None,
                base_policy,
                declared_policy: None,
                effective_policy: if override_applied {
                    base_policy
                } else {
                    PolicyLevel::Observe
                },
                file_sha256: None,
                hash_expected: None,
                hash_verified: None,
                signature_expected: None,
                signature_verified: None,
                verification_issues: vec![error.clone()],
                status: if override_applied {
                    "override_applied"
                } else {
                    "invalid"
                },
                error: Some(error),
                downgraded: false,
                override_applied,
            };
        }
    };

    let downgraded = parsed.declared_policy < base_policy || parsed.version < 1;
    let verification_failed = !parsed.verification_issues.is_empty();
    let override_applied = policy_profile_override_enabled() && (downgraded || verification_failed);
    let mut error_messages = parsed.verification_issues.clone();
    if downgraded {
        error_messages.push(format!(
            "policy profile '{}' declares '{}' with version {} but current policy floor is '{}' and downgrade is not allowed",
            parsed.profile,
            parsed.declared_policy.as_str(),
            parsed.version,
            base_policy.as_str()
        ));
    }

    let (effective_policy, status, error) = if override_applied {
        (parsed.declared_policy, "override_applied", None)
    } else if downgraded {
        (
            PolicyLevel::Observe,
            "downgraded",
            Some(error_messages.join("; ")),
        )
    } else if verification_failed {
        (
            PolicyLevel::Observe,
            "invalid",
            Some(error_messages.join("; ")),
        )
    } else {
        (parsed.declared_policy, "loaded", None)
    };

    PolicyProfileResolution {
        configured: true,
        path: Some(path),
        profile: Some(parsed.profile),
        version: Some(parsed.version),
        base_policy,
        declared_policy: Some(parsed.declared_policy),
        effective_policy,
        file_sha256: Some(parsed.file_sha256),
        hash_expected: parsed.hash_expected,
        hash_verified: parsed.hash_verified,
        signature_expected: parsed.signature_expected,
        signature_verified: parsed.signature_verified,
        verification_issues: parsed.verification_issues,
        status,
        error,
        downgraded,
        override_applied,
    }
}

fn protected_target_override_enabled(args: &Value) -> bool {
    args.get("allow_protected_target")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || env_flag("MEMORIC_ALLOW_PROTECTED_TARGETS")
}

fn policy_profile_path() -> Option<String> {
    std::env::var(POLICY_PROFILE_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn policy_profile_override_enabled() -> bool {
    cfg!(debug_assertions)
        && std::env::var(POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE_ENV)
            .ok()
            .is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "y" | "on"
                )
            })
}

impl PolicyProfileResolution {
    fn to_status_json(&self) -> Value {
        json!({
            "configured": self.configured,
            "status": self.status,
            "path": self.path,
            "profile": self.profile,
            "version": self.version,
            "base_policy": self.base_policy.as_str(),
            "declared_policy": self.declared_policy.map(|policy| policy.as_str()),
            "configured_policy": self.effective_policy.as_str(),
            "hash": {
                "algorithm": "sha256",
                "expected": self.hash_expected,
                "actual": self.file_sha256,
                "verified": self.hash_verified
            },
            "signature": {
                "algorithm": "hmac-sha256",
                "expected": self.signature_expected,
                "verified": self.signature_verified
            },
            "verification_issues": self.verification_issues,
            "downgraded": self.downgraded,
            "override_applied": self.override_applied,
            "error": self.error,
        })
    }

    fn to_audit_json(&self) -> Value {
        json!({
            "configured": self.configured,
            "status": self.status,
            "path": self.path,
            "profile": self.profile,
            "version": self.version,
            "base_policy": self.base_policy.as_str(),
            "declared_policy": self.declared_policy.map(|policy| policy.as_str()),
            "configured_policy": self.effective_policy.as_str(),
            "hash": {
                "algorithm": "sha256",
                "actual": self.file_sha256,
                "expected": self.hash_expected,
                "verified": self.hash_verified
            },
            "signature": {
                "algorithm": "hmac-sha256",
                "expected": self.signature_expected,
                "verified": self.signature_verified
            },
            "verification_issues": self.verification_issues,
            "downgraded": self.downgraded,
            "override_applied": self.override_applied,
            "error": self.error,
        })
    }
}

#[derive(Debug, Clone)]
struct LoadedPolicyProfile {
    profile: String,
    version: u64,
    declared_policy: PolicyLevel,
    file_sha256: String,
    hash_expected: Option<String>,
    hash_verified: Option<bool>,
    signature_expected: Option<String>,
    signature_verified: Option<bool>,
    verification_issues: Vec<String>,
}

fn load_policy_profile(path: &str) -> Result<LoadedPolicyProfile, String> {
    let raw_path = Path::new(path);
    let bytes =
        std::fs::read(raw_path).map_err(|err| format!("read policy profile {}: {}", path, err))?;
    let file_sha256 = crate::artifact::sha256_bytes(&bytes);
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|err| format!("parse policy profile JSON: {}", err))?;

    let profile = required_string(&value, &["profile", "name", "identity"])?;
    let version = required_u64(&value, &["version"])?;
    let declared_policy = required_policy_level(&value, &["policy", "configured_policy", "level"])?;

    let mut verification_issues = Vec::new();

    let hash_expected = match policy_profile_sidecar_value(path, "sha256") {
        Ok(value) => value,
        Err(err) => {
            verification_issues.push(err);
            None
        }
    };
    let hash_verified = match &hash_expected {
        Some(expected) => {
            let verified = expected.eq_ignore_ascii_case(&file_sha256);
            if !verified {
                verification_issues.push(format!(
                    "policy profile hash verification failed for {}",
                    path
                ));
            }
            Some(verified)
        }
        None => None,
    };

    let signature_expected = match policy_profile_sidecar_value(path, "sig") {
        Ok(value) => value,
        Err(err) => {
            verification_issues.push(err);
            None
        }
    };
    let signature_verified = match &signature_expected {
        Some(expected) => {
            let key = match std::env::var("MEMORIC_POLICY_PROFILE_SIGNATURE_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty())
            {
                Some(key) => key,
                None => {
                    verification_issues.push(
                        "policy profile signature sidecar present but MEMORIC_POLICY_PROFILE_SIGNATURE_KEY is not configured"
                            .to_string(),
                    );
                    String::new()
                }
            };
            if key.is_empty() {
                Some(false)
            } else {
                let computed = hmac_sha256_hex(key.as_bytes(), &bytes);
                let verified = expected.eq_ignore_ascii_case(&computed);
                if !verified {
                    verification_issues.push(format!(
                        "policy profile signature verification failed for {}",
                        path
                    ));
                }
                Some(verified)
            }
        }
        None => None,
    };

    Ok(LoadedPolicyProfile {
        profile,
        version,
        declared_policy,
        file_sha256,
        hash_expected,
        hash_verified,
        signature_expected,
        signature_verified,
        verification_issues,
    })
}

fn required_string(value: &Value, keys: &[&str]) -> Result<String, String> {
    for key in keys {
        if let Some(text) = value.get(key).and_then(|value| value.as_str()) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    Err(format!(
        "policy profile missing required string field {:?}",
        keys
    ))
}

fn required_u64(value: &Value, keys: &[&str]) -> Result<u64, String> {
    for key in keys {
        if let Some(raw) = value.get(key).and_then(crate::args::parse_u64) {
            return Ok(raw);
        }
    }
    Err(format!(
        "policy profile missing required numeric field {:?}",
        keys
    ))
}

fn required_policy_level(value: &Value, keys: &[&str]) -> Result<PolicyLevel, String> {
    let raw = required_string(value, keys)?;
    parse_policy_level(&raw)
        .ok_or_else(|| format!("policy profile declares unsupported policy level '{}'", raw))
}

fn policy_profile_sidecar_value(path: &str, suffix: &str) -> Result<Option<String>, String> {
    let sidecar = policy_profile_sidecar_path(path, suffix);
    match std::fs::read_to_string(&sidecar) {
        Ok(text) => {
            let normalized = normalize_hex_token(&text);
            if normalized.is_empty() {
                Err(format!(
                    "policy profile sidecar {} is empty",
                    sidecar.display()
                ))
            } else {
                Ok(Some(normalized))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!(
            "read policy profile sidecar {}: {}",
            sidecar.display(),
            err
        )),
    }
}

fn policy_profile_sidecar_path(path: &str, suffix: &str) -> PathBuf {
    let mut sidecar = PathBuf::from(path);
    let file_name = sidecar
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{}.{}", name, suffix))
        .unwrap_or_else(|| format!("policy-profile.{}", suffix));
    sidecar.set_file_name(file_name);
    sidecar
}

fn normalize_hex_token(text: &str) -> String {
    let trimmed = text.trim().trim_matches(|ch| ch == '"' || ch == '\'');
    trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("hmac-sha256:"))
        .unwrap_or(trimmed)
        .trim_matches(|ch| ch == '"' || ch == '\'')
        .to_ascii_lowercase()
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = if key.len() > BLOCK_SIZE {
        Sha256::digest(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(BLOCK_SIZE, 0);

    let mut inner_key = vec![0x36; BLOCK_SIZE];
    let mut outer_key = vec![0x5c; BLOCK_SIZE];
    for (index, byte) in normalized_key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_key);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_key);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

pub fn audit_path() -> Option<String> {
    #[cfg(test)]
    {
        if let Some(path) = test_audit_path_override() {
            return Some(path);
        }
    }

    std::env::var("MEMORIC_AUDIT_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
pub(crate) fn set_test_audit_path(path: Option<String>) -> TestAuditPathGuard {
    let previous = TEST_AUDIT_PATH.with(|slot| slot.replace(path));
    TestAuditPathGuard { previous }
}

#[cfg(test)]
fn test_audit_path_override() -> Option<String> {
    TEST_AUDIT_PATH.with(|slot| slot.borrow().clone())
}

#[cfg(test)]
pub(crate) struct TestAuditPathGuard {
    previous: Option<String>,
}

#[cfg(test)]
impl Drop for TestAuditPathGuard {
    fn drop(&mut self) {
        TEST_AUDIT_PATH.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

pub fn evaluate_tool_call(tool: &str, args: &Value) -> PolicyDecision {
    let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if !action.is_empty() && !action_registry::is_known_tool_action(tool, action) {
        return PolicyDecision::allowed(configured_level(), PolicyLevel::Observe);
    }

    let traits = action_registry::classify_action(tool, action);
    let configured = configured_level();
    let dry_run = args
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if dry_run {
        return PolicyDecision::allowed(configured, PolicyLevel::Observe);
    }

    if traits.read_only {
        return PolicyDecision::allowed(configured, traits.required_policy);
    }

    let ui_origin = current_request_context()
        .as_ref()
        .is_some_and(|context| context.policy_origin == PolicyOrigin::App);
    let consent_approved = consent_token_matches(args)
        || crate::mcp::consent::consume_matching_grant(tool, action, args);
    if ui_origin && !consent_approved {
        return PolicyDecision::denied(
            configured,
            traits.required_policy,
            format!(
                "{}(action='{}') from an app/widget origin requires matching consent_token before state-changing execution",
                tool, action
            ),
        );
    }

    if configured >= traits.required_policy {
        if let Some(denial) = evaluate_target_guards(tool, action, args, traits, configured) {
            return denial;
        }
        return PolicyDecision::allowed(configured, traits.required_policy);
    }

    if consent_approved && configured >= traits.required_policy {
        if let Some(denial) = evaluate_target_guards(tool, action, args, traits, configured) {
            return denial;
        }
        return PolicyDecision::allowed(configured, traits.required_policy);
    }

    PolicyDecision::denied(
        configured,
        traits.required_policy,
        format!(
            "{}(action='{}') requires policy '{}' but current MEMORIC_POLICY is '{}'",
            tool,
            action,
            traits.required_policy.as_str(),
            configured.as_str()
        ),
    )
}

fn consent_token_matches(args: &Value) -> bool {
    let supplied_consent = args
        .get("consent_token")
        .and_then(|v| v.as_str())
        .filter(|token| !token.trim().is_empty());
    let expected_consent = std::env::var("MEMORIC_CONSENT_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty());

    matches!((supplied_consent, expected_consent.as_deref()), (Some(supplied), Some(expected)) if supplied == expected)
}

pub fn denial_error(tool: &str, args: &Value, decision: &PolicyDecision) -> String {
    let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");
    format!(
        "policy_denied: {}(action='{}') blocked. {}. Set MEMORIC_POLICY={} in an authorized lab environment, or call with dry_run=true for a preview.",
        tool,
        action,
        decision.reason,
        decision.required_level.as_str()
    )
}

pub fn status_json() -> Value {
    let allowlist = TargetAllowlist::from_env();
    json!({
        "configured_policy": configured_level().as_str(),
        "policy_profile": policy_profile_status_json(),
        "audit_path": audit_path(),
        "consent_token_configured": std::env::var("MEMORIC_CONSENT_TOKEN")
            .ok()
            .is_some_and(|token| !token.trim().is_empty()),
        "target_allowlist": {
            "configured": allowlist.configured(),
            "entry_count": allowlist.entries.len(),
            "env": "MEMORIC_TARGET_ALLOWLIST"
        },
        "protected_target_guard": {
            "enabled": true,
            "override_enabled": env_flag("MEMORIC_ALLOW_PROTECTED_TARGETS"),
            "override_env": "MEMORIC_ALLOW_PROTECTED_TARGETS",
            "override_argument": "allow_protected_target"
        },
        "levels": ["observe", "research", "lab-write", "privileged", "kernel", "destructive"],
        "default_behavior": "read-only operations and dry-run previews are allowed by default",
    })
}

fn evaluate_target_guards(
    tool: &str,
    action: &str,
    args: &Value,
    traits: ActionTraits,
    configured: PolicyLevel,
) -> Option<PolicyDecision> {
    let targets = collect_targets(tool, action, args);
    let allowlist = TargetAllowlist::from_env();

    if allowlist.configured() {
        if targets.is_empty() && traits.requires_target {
            return Some(PolicyDecision::denied(
                configured,
                traits.required_policy,
                format!(
                    "{}(action='{}') requires a target that can be checked against MEMORIC_TARGET_ALLOWLIST",
                    tool, action
                ),
            ));
        }

        for target in &targets {
            if !allowlist.matches(target) {
                return Some(PolicyDecision::denied(
                    configured,
                    traits.required_policy,
                    format!(
                        "{}(action='{}') target {} is outside MEMORIC_TARGET_ALLOWLIST",
                        tool,
                        action,
                        target.summary()
                    ),
                ));
            }
        }
    }

    let protected_override = protected_target_override_enabled(args);
    for target in &targets {
        if target.is_high_risk() && !protected_override {
            return Some(PolicyDecision::denied(
                configured,
                traits.required_policy,
                format!(
                    "{}(action='{}') target {} is protected or critical; set allow_protected_target=true only for an authorized lab target",
                    tool,
                    action,
                    target.summary()
                ),
            ));
        }
        if target.is_high_risk() && configured < traits.required_policy {
            return Some(PolicyDecision::denied(
                configured,
                traits.required_policy,
                format!(
                    "{}(action='{}') target {} is protected or critical and requires policy '{}'",
                    tool,
                    action,
                    target.summary(),
                    traits.required_policy.as_str()
                ),
            ));
        }
    }

    None
}

#[derive(Debug, Clone, Default)]
struct TargetAllowlist {
    entries: Vec<AllowlistEntry>,
}

impl TargetAllowlist {
    fn from_env() -> Self {
        parse_target_allowlist(std::env::var("MEMORIC_TARGET_ALLOWLIST").ok().as_deref())
    }

    fn configured(&self) -> bool {
        !self.entries.is_empty()
    }

    fn matches(&self, target: &TargetIdentity) -> bool {
        self.entries.iter().any(|entry| entry.matches(target))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowlistEntry {
    Pid(u32),
    Name(String),
    Path(String),
    Signer(String),
}

impl AllowlistEntry {
    fn matches(&self, target: &TargetIdentity) -> bool {
        match self {
            Self::Pid(pid) => target.pid == Some(*pid),
            Self::Name(name) => target.name_candidates().iter().any(|candidate| {
                candidate == name || trim_exe_suffix(candidate) == trim_exe_suffix(name)
            }),
            Self::Path(path) => target
                .path_candidates()
                .iter()
                .any(|candidate| candidate == path),
            Self::Signer(signer) => target
                .signer_candidates()
                .iter()
                .any(|candidate| candidate == signer),
        }
    }
}

#[derive(Debug, Clone)]
struct TargetIdentity {
    pid: Option<u32>,
    source: String,
    fingerprint: Option<ProcessFingerprint>,
    name_hint: Option<String>,
    path_hint: Option<String>,
    errors: Vec<String>,
}

impl TargetIdentity {
    fn from_pid(pid: u32, source: impl Into<String>) -> Self {
        let fingerprint = crate::info::process::process_fingerprint(pid);
        Self {
            pid: Some(pid),
            source: source.into(),
            fingerprint: Some(fingerprint),
            name_hint: None,
            path_hint: None,
            errors: Vec::new(),
        }
    }

    fn from_name(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            pid: None,
            source: source.into(),
            fingerprint: None,
            name_hint: Some(name.into()),
            path_hint: None,
            errors: Vec::new(),
        }
    }

    fn from_path(path: impl Into<String>, source: impl Into<String>) -> Self {
        let path = path.into();
        Self {
            pid: None,
            source: source.into(),
            fingerprint: None,
            name_hint: basename(&path),
            path_hint: Some(path),
            errors: Vec::new(),
        }
    }

    fn unresolved(source: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            pid: None,
            source: source.into(),
            fingerprint: None,
            name_hint: None,
            path_hint: None,
            errors: vec![error.into()],
        }
    }

    fn is_high_risk(&self) -> bool {
        self.pid.is_some_and(|pid| pid <= 4)
            || self
                .fingerprint
                .as_ref()
                .is_some_and(ProcessFingerprint::is_high_risk_target)
            || self
                .name_hint
                .as_deref()
                .is_some_and(crate::info::process::is_critical_process_name)
    }

    fn summary(&self) -> String {
        if let Some(fingerprint) = &self.fingerprint {
            let protection = fingerprint.protection_name.as_deref().unwrap_or("unknown");
            let signer = fingerprint.signer.as_deref().unwrap_or("unknown");
            return format!(
                "pid={} name={} source={} protection={} signer={}",
                fingerprint.pid,
                fingerprint.display_name(),
                self.source,
                protection,
                signer
            );
        }

        if let Some(path) = &self.path_hint {
            return format!("path={} source={}", path, self.source);
        }
        if let Some(name) = &self.name_hint {
            return format!("name={} source={}", name, self.source);
        }
        if !self.errors.is_empty() {
            return format!(
                "source={} unresolved={}",
                self.source,
                self.errors.join("; ")
            );
        }
        format!("source={}", self.source)
    }

    fn name_candidates(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Some(name) = &self.name_hint {
            names.push(normalize_name(name));
        }
        if let Some(path) = &self.path_hint {
            if let Some(name) = basename(path) {
                names.push(normalize_name(&name));
            }
        }
        if let Some(fingerprint) = &self.fingerprint {
            if let Some(name) = &fingerprint.name {
                names.push(normalize_name(name));
            }
            if let Some(path) = &fingerprint.exe_path {
                if let Some(name) = basename(path) {
                    names.push(normalize_name(&name));
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }

    fn path_candidates(&self) -> Vec<String> {
        let mut paths = Vec::new();
        if let Some(path) = &self.path_hint {
            paths.push(normalize_path(path));
        }
        if let Some(fingerprint) = &self.fingerprint {
            if let Some(path) = &fingerprint.exe_path {
                paths.push(normalize_path(path));
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    fn signer_candidates(&self) -> Vec<String> {
        let mut signers = Vec::new();
        if let Some(fingerprint) = &self.fingerprint {
            if let Some(signer) = &fingerprint.signer {
                signers.push(normalize_signer(signer));
            }
        }
        signers.sort();
        signers.dedup();
        signers
    }
}

fn collect_targets(tool: &str, action: &str, args: &Value) -> Vec<TargetIdentity> {
    let mut targets = Vec::new();

    if let Some(pid) = target_pid_arg(args, "target_pid")
        .or_else(|| target_pid_arg(args, "protect_pid"))
        .or_else(|| target_pid_arg(args, "pid"))
    {
        targets.push(TargetIdentity::from_pid(pid, "pid"));
    }

    if targets.is_empty() {
        if let Some(tid) = target_pid_arg(args, "tid") {
            match crate::info::process::thread_owner_pid(tid) {
                Ok(owner_pid) => targets.push(TargetIdentity::from_pid(owner_pid, "tid")),
                Err(err) => targets.push(TargetIdentity::unresolved("tid", err.to_string())),
            }
        }
    }

    if matches!(tool, "inject" | "stealth" | "orchestrate") {
        for key in ["target_exe", "target_path"] {
            if let Some(path) = args
                .get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                targets.push(TargetIdentity::from_path(path, key));
            }
        }
    }

    if tool == "kernel" {
        for key in ["process_filter", "target_process"] {
            if let Some(name) = args
                .get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                targets.push(TargetIdentity::from_name(name, key));
            }
        }
    }

    if tool == "target" && action == "cred_dump" {
        targets.push(TargetIdentity::from_name("lsass.exe", "implicit"));
    }

    targets
}

fn target_pid_arg(args: &Value, key: &str) -> Option<u32> {
    let value = crate::args::parse_u64_value(args.get(key))?;
    if value == 0 || value > u32::MAX as u64 {
        return None;
    }
    Some(value as u32)
}

fn parse_target_allowlist(value: Option<&str>) -> TargetAllowlist {
    let entries = value
        .unwrap_or_default()
        .split(|ch| matches!(ch, ',' | ';' | '\n' | '\r' | '\t'))
        .filter_map(parse_allowlist_entry)
        .collect();

    TargetAllowlist { entries }
}

fn parse_allowlist_entry(raw: &str) -> Option<AllowlistEntry> {
    let token = raw.trim();
    if token.is_empty() {
        return None;
    }

    let (kind, value) = token
        .split_once(':')
        .map(|(kind, value)| (Some(kind.trim().to_ascii_lowercase()), value.trim()))
        .unwrap_or((None, token));

    match kind.as_deref() {
        Some("pid") => crate::args::parse_u64(&json!(value))
            .and_then(|pid| u32::try_from(pid).ok())
            .map(AllowlistEntry::Pid),
        Some("name") | Some("image") | Some("exe") => {
            Some(AllowlistEntry::Name(normalize_name(value)))
        }
        Some("path") => Some(AllowlistEntry::Path(normalize_path(value))),
        Some("signer") | Some("publisher") => Some(AllowlistEntry::Signer(normalize_signer(value))),
        Some(_) => Some(AllowlistEntry::Name(normalize_name(token))),
        None => {
            if let Some(pid) =
                crate::args::parse_u64(&json!(value)).and_then(|pid| u32::try_from(pid).ok())
            {
                Some(AllowlistEntry::Pid(pid))
            } else if value.contains('\\') || value.contains('/') {
                Some(AllowlistEntry::Path(normalize_path(value)))
            } else {
                Some(AllowlistEntry::Name(normalize_name(value)))
            }
        }
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "on"
        )
    })
}

fn normalize_name(value: &str) -> String {
    value.trim().trim_matches('"').to_ascii_lowercase()
}

fn normalize_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn normalize_signer(value: &str) -> String {
    value.trim().trim_matches('"').to_ascii_lowercase()
}

fn trim_exe_suffix(value: &str) -> &str {
    value.strip_suffix(".exe").unwrap_or(value)
}

fn basename(path: &str) -> Option<String> {
    path.rsplit(['\\', '/'])
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_policy_level(value: &str) -> Option<PolicyLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "observe" | "readonly" | "read-only" => Some(PolicyLevel::Observe),
        "research" | "read" => Some(PolicyLevel::Research),
        "lab-write" | "lab_write" | "write" => Some(PolicyLevel::LabWrite),
        "privileged" | "priv" => Some(PolicyLevel::Privileged),
        "kernel" => Some(PolicyLevel::Kernel),
        "destructive" | "danger" => Some(PolicyLevel::Destructive),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FIXTURE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn clear_policy_env() {
        std::env::remove_var("MEMORIC_POLICY");
        std::env::remove_var("MEMORIC_TARGET_ALLOWLIST");
        std::env::remove_var("MEMORIC_CONSENT_TOKEN");
        std::env::remove_var("MEMORIC_ALLOW_PROTECTED_TARGETS");
        std::env::remove_var(POLICY_PROFILE_PATH_ENV);
        std::env::remove_var(POLICY_PROFILE_ALLOW_LOCAL_OVERRIDE_ENV);
        std::env::remove_var("MEMORIC_POLICY_PROFILE_SIGNATURE_KEY");
    }

    #[test]
    fn read_only_action_is_allowed_by_default() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let decision = evaluate_tool_call("target", &json!({"action": "ps_list"}));
        assert!(decision.allowed);
    }

    #[test]
    fn write_action_is_denied_by_default() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let decision = evaluate_tool_call("memory", &json!({"action": "write"}));
        assert!(!decision.allowed);
        assert_eq!(decision.required_level, PolicyLevel::LabWrite);
    }

    #[test]
    fn dry_run_is_allowed_by_default() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let decision = evaluate_tool_call("memory", &json!({"action": "write", "dry_run": true}));
        assert!(decision.allowed);
    }

    #[test]
    fn allowlist_controls_state_changing_target_pid() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let pid = std::process::id();
        std::env::set_var("MEMORIC_POLICY", "lab-write");

        std::env::set_var("MEMORIC_TARGET_ALLOWLIST", "name:notepad.exe");
        let denied = evaluate_tool_call(
            "memory",
            &json!({"action": "write", "pid": pid, "address": "0x1000", "bytes": [1]}),
        );
        assert!(!denied.allowed);
        assert!(denied.reason.contains("outside MEMORIC_TARGET_ALLOWLIST"));

        std::env::set_var("MEMORIC_TARGET_ALLOWLIST", format!("pid:{}", pid));
        let allowed = evaluate_tool_call(
            "memory",
            &json!({"action": "write", "pid": pid, "address": "0x1000", "bytes": [1]}),
        );
        assert!(allowed.allowed);

        clear_policy_env();
    }

    #[test]
    fn target_allowlist_can_match_signer_identity() {
        let target = TargetIdentity {
            pid: Some(42),
            source: "test".to_string(),
            fingerprint: Some(ProcessFingerprint {
                pid: 42,
                name: Some("signed.exe".to_string()),
                signer: Some("Microsoft Windows".to_string()),
                ..Default::default()
            }),
            name_hint: None,
            path_hint: None,
            errors: Vec::new(),
        };
        let allowlist = parse_target_allowlist(Some("signer:microsoft windows"));
        let denied = parse_target_allowlist(Some("signer:contoso lab"));

        assert!(allowlist.configured());
        assert!(allowlist.matches(&target));
        assert!(!denied.matches(&target));
        assert!(target.summary().contains("signer=Microsoft Windows"));
    }

    #[test]
    fn parse_target_allowlist_accepts_publisher_alias_for_signer() {
        let parsed = parse_target_allowlist(Some("publisher:Example Publisher"));
        assert_eq!(
            parsed.entries,
            vec![AllowlistEntry::Signer("example publisher".to_string())]
        );
    }

    #[test]
    fn protected_target_requires_explicit_override() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        std::env::set_var("MEMORIC_POLICY", "lab-write");

        let denied = evaluate_tool_call(
            "memory",
            &json!({"action": "write", "pid": 4, "address": "0x1000", "bytes": [1]}),
        );
        assert!(!denied.allowed);
        assert!(denied.reason.contains("protected or critical"));

        let allowed = evaluate_tool_call(
            "memory",
            &json!({
                "action": "write",
                "pid": 4,
                "address": "0x1000",
                "bytes": [1],
                "allow_protected_target": true
            }),
        );
        assert!(allowed.allowed);

        clear_policy_env();
    }

    #[test]
    fn consent_token_does_not_replace_required_policy_level() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        std::env::set_var("MEMORIC_POLICY", "lab-write");
        std::env::set_var("MEMORIC_CONSENT_TOKEN", "ok");

        let decision = evaluate_tool_call(
            "inject",
            &json!({"action": "dll", "pid": std::process::id(), "dll_path": "C:\\lab\\a.dll", "consent_token": "ok"}),
        );
        assert!(!decision.allowed);
        assert_eq!(decision.required_level, PolicyLevel::Privileged);

        clear_policy_env();
    }

    #[test]
    fn app_origin_state_changing_call_requires_matching_consent_token() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        std::env::set_var("MEMORIC_POLICY", "destructive");
        let request = json!({
            "jsonrpc": "2.0",
            "id": "policy-app-origin",
            "method": "tools/call",
            "params": {
                "name": "memory",
                "arguments": {
                    "action": "write",
                    "pid": std::process::id(),
                    "address": "0x1000",
                    "bytes": [1]
                },
                "_meta": {
                    "io.memoric/app-origin": "ui://memoric/dashboard"
                }
            }
        });
        let context = crate::mcp::request_context::McpRequestContext::from_request(
            &request,
            crate::mcp::request_context::McpTransportKind::Http,
        );
        let _context_guard = crate::mcp::request_context::set_current_request_context(context);

        let decision = evaluate_tool_call(
            "memory",
            &json!({
                "action": "write",
                "pid": std::process::id(),
                "address": "0x1000",
                "bytes": [1]
            }),
        );

        assert!(!decision.allowed);
        assert!(decision.reason.contains("app/widget origin"));

        clear_policy_env();
    }

    #[test]
    fn policy_profile_file_overrides_policy_and_reports_identity() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();

        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let profile_path = std::env::temp_dir().join(format!(
            "memoric-policy-profile-{}-{}.json",
            std::process::id(),
            fixture_id
        ));
        let profile = json!({
            "profile": "lab-policy",
            "version": 2,
            "policy": "privileged"
        });
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        fs::write(&profile_path, &profile_bytes).unwrap();
        fs::write(
            format!("{}.sha256", profile_path.display()),
            crate::artifact::sha256_bytes(&profile_bytes),
        )
        .unwrap();
        std::env::set_var(POLICY_PROFILE_PATH_ENV, profile_path.display().to_string());

        let status = status_json();
        assert_eq!(status["configured_policy"], "privileged");
        assert_eq!(status["policy_profile"]["profile"], "lab-policy");
        assert_eq!(status["policy_profile"]["status"], "loaded");
        assert_eq!(configured_level(), PolicyLevel::Privileged);

        let audit = policy_profile_audit_json();
        assert_eq!(audit["profile"], "lab-policy");
        assert_eq!(audit["hash"]["verified"], true);

        let _ = fs::remove_file(&profile_path);
        let _ = fs::remove_file(format!("{}.sha256", profile_path.display()));
        clear_policy_env();
    }

    #[test]
    fn policy_profile_downgrade_fails_closed_without_override() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        std::env::set_var("MEMORIC_POLICY", "privileged");

        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let profile_path = std::env::temp_dir().join(format!(
            "memoric-policy-profile-downgrade-{}-{}.json",
            std::process::id(),
            fixture_id
        ));
        let profile = json!({
            "profile": "lower-policy",
            "version": 2,
            "policy": "observe"
        });
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        fs::write(&profile_path, &profile_bytes).unwrap();
        fs::write(
            format!("{}.sha256", profile_path.display()),
            crate::artifact::sha256_bytes(&profile_bytes),
        )
        .unwrap();
        std::env::set_var(POLICY_PROFILE_PATH_ENV, profile_path.display().to_string());

        let status = status_json();
        assert_eq!(status["policy_profile"]["status"], "downgraded");
        assert_eq!(status["policy_profile"]["configured"], true);
        assert_eq!(configured_level(), PolicyLevel::Observe);
        assert!(status["policy_profile"]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("downgrade is not allowed"));

        let _ = fs::remove_file(&profile_path);
        let _ = fs::remove_file(format!("{}.sha256", profile_path.display()));
        clear_policy_env();
    }

    #[test]
    fn policy_profile_signature_verification_reports_status() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();

        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let profile_path = std::env::temp_dir().join(format!(
            "memoric-policy-profile-signed-{}-{}.json",
            std::process::id(),
            fixture_id
        ));
        let profile = json!({
            "profile": "signed-lab-policy",
            "version": 3,
            "policy": "research"
        });
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        fs::write(&profile_path, &profile_bytes).unwrap();
        fs::write(
            format!("{}.sha256", profile_path.display()),
            crate::artifact::sha256_bytes(&profile_bytes),
        )
        .unwrap();
        std::env::set_var("MEMORIC_POLICY_PROFILE_SIGNATURE_KEY", "profile-key");
        fs::write(
            format!("{}.sig", profile_path.display()),
            hmac_sha256_hex(b"profile-key", &profile_bytes),
        )
        .unwrap();
        std::env::set_var(POLICY_PROFILE_PATH_ENV, profile_path.display().to_string());

        let status = status_json();
        assert_eq!(status["policy_profile"]["status"], "loaded");
        assert_eq!(status["policy_profile"]["signature"]["verified"], true);
        assert_eq!(configured_level(), PolicyLevel::Research);

        let _ = fs::remove_file(&profile_path);
        let _ = fs::remove_file(format!("{}.sha256", profile_path.display()));
        let _ = fs::remove_file(format!("{}.sig", profile_path.display()));
        clear_policy_env();
    }

    #[test]
    fn malformed_policy_profile_fails_closed() {
        let _guard = crate::state::TEST_ENV_LOCK.lock().unwrap();
        clear_policy_env();
        let fixture_id = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let profile_path = std::env::temp_dir().join(format!(
            "memoric-policy-profile-malformed-{}-{}.json",
            std::process::id(),
            fixture_id
        ));
        fs::write(&profile_path, b"{\"profile\":").unwrap();
        std::env::set_var(POLICY_PROFILE_PATH_ENV, profile_path.display().to_string());

        let status = status_json();
        assert_eq!(status["policy_profile"]["status"], "invalid");
        assert_eq!(configured_level(), PolicyLevel::Observe);
        assert!(status["policy_profile"]["error"]
            .as_str()
            .unwrap_or_default()
            .contains("parse policy profile JSON"));

        let _ = fs::remove_file(&profile_path);
        clear_policy_env();
    }
}

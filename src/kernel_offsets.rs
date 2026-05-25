use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OffsetConfidence {
    Exact,
    Family,
    RuntimeVerified,
    Partial,
    Unknown,
}

impl OffsetConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Family => "family",
            Self::RuntimeVerified => "runtime_verified",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallbackOffsetKind {
    Process,
    Thread,
    Image,
    Registry,
}

impl CallbackOffsetKind {
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "process" => Some(Self::Process),
            "thread" => Some(Self::Thread),
            "image" => Some(Self::Image),
            "registry" => Some(Self::Registry),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Thread => "thread",
            Self::Image => "image",
            Self::Registry => "registry",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct KernelOffsetProfile {
    pub build_min: u32,
    pub build_max: u32,
    pub label: &'static str,
    pub process_notify: u64,
    pub thread_notify: u64,
    pub image_notify: u64,
    pub registry_callback_list: u64,
    pub confidence: OffsetConfidence,
}

impl KernelOffsetProfile {
    fn contains(self, build: u32) -> bool {
        build >= self.build_min && build <= self.build_max
    }

    fn offset_for(self, kind: CallbackOffsetKind) -> u64 {
        match kind {
            CallbackOffsetKind::Process => self.process_notify,
            CallbackOffsetKind::Thread => self.thread_notify,
            CallbackOffsetKind::Image => self.image_notify,
            CallbackOffsetKind::Registry => self.registry_callback_list,
        }
    }

    fn build_range(self) -> String {
        if self.build_min == self.build_max {
            self.build_min.to_string()
        } else {
            format!("{}-{}", self.build_min, self.build_max)
        }
    }

    fn to_json(self) -> Value {
        json!({
            "build_min": self.build_min,
            "build_max": self.build_max,
            "build_range": self.build_range(),
            "label": self.label,
            "confidence": self.confidence.as_str(),
            "offsets": {
                "psp_create_process_notify_routine": format!("0x{:X}", self.process_notify),
                "psp_create_thread_notify_routine": format!("0x{:X}", self.thread_notify),
                "psp_load_image_notify_routine": format!("0x{:X}", self.image_notify),
                "cmp_callback_list_head": format!("0x{:X}", self.registry_callback_list),
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedKernelOffset {
    pub build_number: u32,
    pub kind: CallbackOffsetKind,
    pub offset: Option<u64>,
    pub profile: Option<KernelOffsetProfile>,
    pub confidence: OffsetConfidence,
}

impl ResolvedKernelOffset {
    pub fn to_json(&self) -> Value {
        json!({
            "build_number": self.build_number,
            "kind": self.kind.as_str(),
            "offset": self.offset.map(|offset| format!("0x{:X}", offset)),
            "confidence": self.confidence.as_str(),
            "known_build": self.profile.is_some(),
            "source": if self.profile.is_some() { "kernel_offset_registry" } else { "unknown_build" },
            "profile": self.profile.map(KernelOffsetProfile::to_json),
        })
    }
}

pub const KERNEL_OFFSET_PROFILES: &[KernelOffsetProfile] = &[
    KernelOffsetProfile {
        build_min: 17763,
        build_max: 17763,
        label: "Windows 10 1809",
        process_notify: 0xC4D5C0,
        thread_notify: 0xC4D7C0,
        image_notify: 0xC4D9C0,
        registry_callback_list: 0xC6B700,
        confidence: OffsetConfidence::Exact,
    },
    KernelOffsetProfile {
        build_min: 18362,
        build_max: 18363,
        label: "Windows 10 1903/1909",
        process_notify: 0xC4E5C0,
        thread_notify: 0xC4E7C0,
        image_notify: 0xC4E9C0,
        registry_callback_list: 0xC6C700,
        confidence: OffsetConfidence::Family,
    },
    KernelOffsetProfile {
        build_min: 19041,
        build_max: 19045,
        label: "Windows 10 2004-22H2",
        process_notify: 0xCEC2C0,
        thread_notify: 0xCEC4C0,
        image_notify: 0xCEC6C0,
        registry_callback_list: 0xD0A400,
        confidence: OffsetConfidence::Family,
    },
    KernelOffsetProfile {
        build_min: 22000,
        build_max: 22000,
        label: "Windows 11 21H2",
        process_notify: 0xCEA2C0,
        thread_notify: 0xCEA4C0,
        image_notify: 0xCEA6C0,
        registry_callback_list: 0xD08400,
        confidence: OffsetConfidence::Exact,
    },
    KernelOffsetProfile {
        build_min: 22621,
        build_max: 22631,
        label: "Windows 11 22H2/23H2",
        process_notify: 0xD892C0,
        thread_notify: 0xD894C0,
        image_notify: 0xD896C0,
        registry_callback_list: 0xDA7400,
        confidence: OffsetConfidence::Family,
    },
    KernelOffsetProfile {
        build_min: 26100,
        build_max: 26100,
        label: "Windows 11 24H2",
        process_notify: 0xDBA2C0,
        thread_notify: 0xDBA4C0,
        image_notify: 0xDBA6C0,
        registry_callback_list: 0xDD8400,
        confidence: OffsetConfidence::Exact,
    },
];

pub fn profile_for_build(build_number: u32) -> Option<KernelOffsetProfile> {
    KERNEL_OFFSET_PROFILES
        .iter()
        .copied()
        .find(|profile| profile.contains(build_number))
}

pub fn resolve_callback_offset(
    build_number: u32,
    kind: CallbackOffsetKind,
) -> ResolvedKernelOffset {
    match profile_for_build(build_number) {
        Some(profile) => ResolvedKernelOffset {
            build_number,
            kind,
            offset: Some(profile.offset_for(kind)),
            profile: Some(profile),
            confidence: profile.confidence,
        },
        None => ResolvedKernelOffset {
            build_number,
            kind,
            offset: None,
            profile: None,
            confidence: OffsetConfidence::Unknown,
        },
    }
}

pub fn supported_profiles_json() -> Value {
    json!(KERNEL_OFFSET_PROFILES
        .iter()
        .copied()
        .map(KernelOffsetProfile::to_json)
        .collect::<Vec<_>>())
}

pub fn supported_builds_summary() -> &'static str {
    "17763(1809), 18362-18363(1903/1909), 19041-19045(2004-22H2), 22000(11 21H2), 22621-22631(11 22H2/23H2), 26100(11 24H2)"
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EprocessOffsetSnapshot {
    pub unique_process_id: u32,
    pub active_process_links: u32,
    pub token: u32,
    pub protection: u32,
    pub image_file_name: u32,
    pub vad_root: u32,
}

impl EprocessOffsetSnapshot {
    fn resolved_count(self) -> usize {
        [
            self.unique_process_id,
            self.active_process_links,
            self.token,
            self.protection,
            self.image_file_name,
            self.vad_root,
        ]
        .into_iter()
        .filter(|offset| *offset != 0)
        .count()
    }

    fn to_json(self) -> Value {
        json!({
            "unique_process_id": maybe_hex(self.unique_process_id),
            "active_process_links": maybe_hex(self.active_process_links),
            "token": maybe_hex(self.token),
            "protection": maybe_hex(self.protection),
            "image_file_name": maybe_hex(self.image_file_name),
            "vad_root": maybe_hex(self.vad_root),
        })
    }
}

pub fn driver_offset_profile_json(build_number: u32, offsets_resolved: bool) -> Value {
    let known_profile = profile_for_build(build_number);
    json!({
        "build_number": build_number,
        "known_build": known_profile.is_some(),
        "profile": known_profile.map(KernelOffsetProfile::to_json),
        "eprocess": {
            "strategy": "driver_dynamic_discovery",
            "resolved": offsets_resolved,
            "confidence": if offsets_resolved { OffsetConfidence::RuntimeVerified.as_str() } else { OffsetConfidence::Unknown.as_str() },
            "note": if offsets_resolved {
                "EPROCESS offsets were resolved by the loaded driver at runtime; static build offsets are not required for EPROCESS operations."
            } else {
                "The loaded driver did not report resolved EPROCESS offsets; kernel mutations that need those fields should fail closed."
            }
        },
        "callback_offsets": {
            "strategy": "kernel_offset_registry",
            "confidence": known_profile.map(|p| p.confidence.as_str()).unwrap_or(OffsetConfidence::Unknown.as_str()),
            "supported_builds": supported_builds_summary(),
        }
    })
}

pub fn eprocess_runtime_profile_json(
    build_number: u32,
    offsets_resolved: bool,
    offsets: EprocessOffsetSnapshot,
) -> Value {
    let resolved_count = offsets.resolved_count();
    let confidence = if offsets_resolved && resolved_count == 6 {
        OffsetConfidence::RuntimeVerified
    } else if offsets_resolved && resolved_count > 0 {
        OffsetConfidence::Partial
    } else {
        OffsetConfidence::Unknown
    };

    json!({
        "build_number": build_number,
        "known_build": profile_for_build(build_number).is_some(),
        "source": "driver_eprocess_response",
        "strategy": "driver_dynamic_discovery",
        "confidence": confidence.as_str(),
        "resolved": offsets_resolved,
        "resolved_fields": resolved_count,
        "total_fields": 6,
        "fields": offsets.to_json(),
        "note": if confidence == OffsetConfidence::RuntimeVerified {
            "All exported EPROCESS offsets are non-zero and came from runtime driver discovery."
        } else if confidence == OffsetConfidence::Partial {
            "The driver reported offset resolution, but one or more exported EPROCESS fields are zero."
        } else {
            "EPROCESS offsets are unresolved or unavailable; callers should avoid offset-dependent kernel mutations."
        }
    })
}

fn maybe_hex(offset: u32) -> Value {
    if offset == 0 {
        Value::Null
    } else {
        json!(format!("0x{:X}", offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_supported_callback_offsets_by_build_family() {
        let process = resolve_callback_offset(22631, CallbackOffsetKind::Process);
        assert_eq!(process.offset, Some(0xD892C0));
        assert_eq!(process.confidence, OffsetConfidence::Family);
        assert_eq!(process.to_json()["known_build"], true);

        let registry = resolve_callback_offset(26100, CallbackOffsetKind::Registry);
        assert_eq!(registry.offset, Some(0xDD8400));
        assert_eq!(registry.confidence, OffsetConfidence::Exact);
    }

    #[test]
    fn unknown_build_returns_no_offset_with_unknown_confidence() {
        let resolved = resolve_callback_offset(99999, CallbackOffsetKind::Image);

        assert_eq!(resolved.offset, None);
        assert_eq!(resolved.confidence, OffsetConfidence::Unknown);
        assert_eq!(resolved.to_json()["known_build"], false);
        assert_eq!(resolved.to_json()["offset"], Value::Null);
    }

    #[test]
    fn eprocess_runtime_profile_reports_partial_and_runtime_verified() {
        let full = eprocess_runtime_profile_json(
            26100,
            true,
            EprocessOffsetSnapshot {
                unique_process_id: 0x440,
                active_process_links: 0x448,
                token: 0x4B8,
                protection: 0x87A,
                image_file_name: 0x5A8,
                vad_root: 0x7D8,
            },
        );
        assert_eq!(full["confidence"], "runtime_verified");
        assert_eq!(full["resolved_fields"], 6);

        let partial = eprocess_runtime_profile_json(
            99999,
            true,
            EprocessOffsetSnapshot {
                unique_process_id: 0x440,
                active_process_links: 0x448,
                token: 0,
                protection: 0,
                image_file_name: 0,
                vad_root: 0,
            },
        );
        assert_eq!(partial["confidence"], "partial");
        assert_eq!(partial["known_build"], false);
    }
}

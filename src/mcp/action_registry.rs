//! Central action registry for MCP tool metadata.
//!
//! Tool descriptors are the source of truth for action discovery, handler
//! binding, policy classification, annotations, and schema enhancement.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::redaction::{classification_rule, DataClassification, DataClassificationRule};

pub type ToolHandler = fn(&Value) -> Result<Value, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyLevel {
    Observe,
    Research,
    LabWrite,
    Privileged,
    Kernel,
    Destructive,
}

impl PolicyLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Research => "research",
            Self::LabWrite => "lab-write",
            Self::Privileged => "privileged",
            Self::Kernel => "kernel",
            Self::Destructive => "destructive",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ActionTraits {
    pub read_only: bool,
    pub state_changing: bool,
    pub privileged: bool,
    pub kernel: bool,
    pub destructive: bool,
    pub requires_target: bool,
    pub risk: RiskLevel,
    pub required_policy: PolicyLevel,
}

impl ActionTraits {
    pub fn annotations(self) -> Value {
        json!({
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.read_only,
            "openWorldHint": self.state_changing || self.privileged || self.kernel,
            "memoric": {
                "state_changing": self.state_changing,
                "privileged": self.privileged,
                "kernel": self.kernel,
                "requires_target": self.requires_target,
                "risk": self.risk.as_str(),
                "required_policy": self.required_policy.as_str(),
            }
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ToolDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub action_description: Option<&'static str>,
    pub actions: &'static [&'static str],
    pub handler: ToolHandler,
}

#[derive(Debug, Clone, Copy)]
pub struct GuideInputFieldDescriptor {
    pub name: &'static str,
    pub schema: fn() -> Value,
}

impl GuideInputFieldDescriptor {
    pub fn schema(self) -> Value {
        (self.schema)()
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredAction {
    pub tool: &'static str,
    pub name: &'static str,
    pub ordinal: usize,
    pub traits: ActionTraits,
    pub optional_parameters: Vec<OptionalParameterDescriptor>,
    pub required_parameters: &'static [&'static str],
    pub conditional_required_parameters: Vec<ConditionalRequiredParameterDescriptor>,
    pub alternative_required_parameters: Vec<AlternativeRequiredParameterDescriptor>,
    pub planner_warnings: Vec<PlannerWarningDescriptor>,
    pub required_privileges: Vec<PrivilegeRequirementDescriptor>,
    pub side_effects: Vec<SideEffectDescriptor>,
    pub planned_handles: Vec<PlannedHandleDescriptor>,
    pub rollback_preview: RollbackPreviewDescriptor,
    pub parameter_aliases: Vec<ParameterAliasDescriptor>,
    pub choice_parameters: Vec<ChoiceParameterDescriptor>,
    pub array_choice_parameters: Vec<ArrayChoiceParameterDescriptor>,
    pub parameter_bounds: Vec<ParameterBoundsDescriptor>,
    pub parser_hints: Vec<ParserHintDescriptor>,
}

impl RegisteredAction {
    pub fn as_str(&self) -> &'static str {
        self.name
    }

    pub fn metadata_json(&self) -> Value {
        let traits = self.traits;
        json!({
            "tool": self.tool,
            "action": self.name,
            "ordinal": self.ordinal,
            "typed_action_ref": true,
            "descriptor_backed_action_ref": true,
            "registry_source": "src/mcp/action_registry.rs",
            "read_only": traits.read_only,
            "state_changing": traits.state_changing,
            "privileged": traits.privileged,
            "kernel": traits.kernel,
            "destructive": traits.destructive,
            "requires_target": traits.requires_target,
            "risk": traits.risk.as_str(),
            "required_policy": traits.required_policy.as_str(),
            "optional_parameters": self.optional_parameters.iter().map(|parameter| json!({
                "parameter": parameter.parameter,
                "parser": parameter.parser,
            })).collect::<Vec<_>>(),
            "required_parameters": self.required_parameters,
            "required_parameter_hints": required_parameter_hints(self.tool, self.name).iter().map(|hint| json!({
                "parameter": hint.parameter,
                "parser": hint.parser,
                "array_item_parser": hint.array_item_parser,
                "required": hint.required,
                "aliases": hint.aliases,
                "choices": hint.choices,
                "minimum": hint.minimum,
                "maximum": hint.maximum,
                "object_item_schema": hint.object_item_schema.map(|schema| schema.to_json()),
            })).collect::<Vec<_>>(),
            "conditional_required_parameters": self.conditional_required_parameters.iter().map(|condition| json!({
                "when_parameter": condition.when_parameter,
                "when_values": condition.when_values,
                "parameters": condition.parameters,
                "default_applies": condition.default_applies,
                "description": condition.description,
            })).collect::<Vec<_>>(),
            "alternative_required_parameters": self.alternative_required_parameters.iter().map(|alternative| json!({
                "when_parameter": alternative.when_parameter,
                "when_values": alternative.when_values,
                "parameters": alternative.parameters,
                "default_applies": alternative.default_applies,
                "description": alternative.description,
            })).collect::<Vec<_>>(),
            "planner_warnings": self.planner_warnings.iter().map(|warning| json!({
                "condition": warning.condition.as_str(),
                "parameter": warning.parameter,
                "unless_parameter": warning.unless_parameter,
                "unless_values": warning.unless_values,
                "message": warning.message,
            })).collect::<Vec<_>>(),
            "required_privileges": self.required_privileges.iter().map(|privilege| json!({
                "privilege": privilege.privilege,
                "description": privilege.description,
            })).collect::<Vec<_>>(),
            "side_effects": self.side_effects.iter().map(|effect| json!({
                "effect": effect.effect,
                "description": effect.description,
            })).collect::<Vec<_>>(),
            "planned_handles": self.planned_handles.iter().map(|handle| json!({
                "kind": handle.kind,
                "target": handle.target,
                "access": handle.access,
            })).collect::<Vec<_>>(),
            "rollback": self.rollback_preview.to_json(),
            "parameter_aliases": self.parameter_aliases.iter().map(|alias| json!({
                "canonical": alias.canonical,
                "alias": alias.alias,
            })).collect::<Vec<_>>(),
            "choice_parameters": self.choice_parameters.iter().map(|choice| json!({
                "parameter": choice.parameter,
                "values": choice.values,
            })).collect::<Vec<_>>(),
            "array_choice_parameters": self.array_choice_parameters.iter().map(|choice| json!({
                "parameter": choice.parameter,
                "values": choice.values,
            })).collect::<Vec<_>>(),
            "parameter_bounds": self.parameter_bounds.iter().map(|bound| json!({
                "parameter": bound.parameter,
                "minimum": bound.minimum,
                "maximum": bound.maximum,
            })).collect::<Vec<_>>(),
            "parser_hints": self.parser_hints.iter().map(|hint| json!({
                "parameter": hint.parameter,
                "parser": hint.parser,
                "array_item_parser": hint.array_item_parser,
                "required": hint.required,
                "aliases": hint.aliases,
                "choices": hint.choices,
                "minimum": hint.minimum,
                "maximum": hint.maximum,
                "object_item_schema": hint.object_item_schema.map(|schema| schema.to_json()),
            })).collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterAliasDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub canonical: &'static str,
    pub alias: &'static str,
}

impl ParameterAliasDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && (self.action == "*" || self.action == action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredParameterDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub parameters: &'static [&'static str],
}

impl RequiredParameterDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionalParameterDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub parameter: &'static str,
    pub parser: &'static str,
}

impl OptionalParameterDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && (self.action == "*" || self.action == action)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionalRequiredParameterDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub when_parameter: &'static str,
    pub when_values: &'static [&'static str],
    pub parameters: &'static [&'static str],
    pub default_applies: bool,
    pub description: &'static str,
}

impl ConditionalRequiredParameterDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }

    pub fn matches_args(self, args: &Value) -> bool {
        match args
            .get(self.when_parameter)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => self.when_values.iter().any(|candidate| *candidate == value),
            None => self.default_applies,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlternativeRequiredParameterDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub when_parameter: Option<&'static str>,
    pub when_values: &'static [&'static str],
    pub parameters: &'static [&'static str],
    pub default_applies: bool,
    pub description: &'static str,
}

impl AlternativeRequiredParameterDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }

    pub fn matches_args(self, args: &Value) -> bool {
        let Some(when_parameter) = self.when_parameter else {
            return true;
        };
        match args
            .get(when_parameter)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) => self.when_values.iter().any(|candidate| *candidate == value),
            None => self.default_applies,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannerWarningCondition {
    Always,
    ParameterPresent,
    ParameterMissing,
}

impl PlannerWarningCondition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::ParameterPresent => "parameter_present",
            Self::ParameterMissing => "parameter_missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerWarningDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub condition: PlannerWarningCondition,
    pub parameter: Option<&'static str>,
    pub unless_parameter: Option<&'static str>,
    pub unless_values: &'static [&'static str],
    pub message: &'static str,
}

impl PlannerWarningDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }

    pub fn unless_matches(self, args: &Value) -> bool {
        let Some(parameter) = self.unless_parameter else {
            return false;
        };
        args.get(parameter)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(|value| {
                self.unless_values
                    .iter()
                    .any(|candidate| *candidate == value)
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivilegeRequirementDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub privilege: &'static str,
    pub description: &'static str,
}

impl PrivilegeRequirementDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideEffectDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub effect: &'static str,
    pub description: &'static str,
}

impl SideEffectDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedHandleDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub kind: &'static str,
    pub target: &'static str,
    pub access: &'static str,
}

impl PlannedHandleDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }

    pub fn to_json(self) -> Value {
        json!({
            "kind": self.kind,
            "target": self.target,
            "access": self.access,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackAvailability {
    Boolean(bool),
    Label(&'static str),
}

impl RollbackAvailability {
    fn to_json(self) -> Value {
        match self {
            Self::Boolean(value) => json!(value),
            Self::Label(value) => json!(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackPreviewDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub available: RollbackAvailability,
    pub strategy: &'static str,
    pub captured_fields: &'static [&'static str],
    pub detail: &'static str,
    pub reason: Option<&'static str>,
}

impl RollbackPreviewDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }

    pub fn to_json(self) -> Value {
        let mut object = serde_json::Map::new();
        object.insert("available".to_string(), self.available.to_json());
        object.insert("strategy".to_string(), json!(self.strategy));
        object.insert("captured_fields".to_string(), json!(self.captured_fields));
        object.insert("detail".to_string(), json!(self.detail));
        if let Some(reason) = self.reason {
            object.insert("reason".to_string(), json!(reason));
        }
        Value::Object(object)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChoiceParameterDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub parameter: &'static str,
    pub values: &'static [&'static str],
}

impl ChoiceParameterDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrayChoiceParameterDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub parameter: &'static str,
    pub values: &'static [&'static str],
}

impl ArrayChoiceParameterDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterBoundsDescriptor {
    pub tool: &'static str,
    pub action: &'static str,
    pub parameter: &'static str,
    pub minimum: Option<u64>,
    pub maximum: Option<u64>,
}

impl ParameterBoundsDescriptor {
    pub fn applies_to(self, tool: &str, action: &str) -> bool {
        self.tool == tool && self.action == action
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserHintDescriptor {
    pub parameter: String,
    pub parser: &'static str,
    pub array_item_parser: Option<&'static str>,
    pub required: bool,
    pub aliases: Vec<&'static str>,
    pub choices: Vec<&'static str>,
    pub minimum: Option<u64>,
    pub maximum: Option<u64>,
    pub object_item_schema: Option<ObjectItemSchemaDescriptor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectItemSchemaDescriptor {
    pub required: &'static [&'static str],
    pub properties: &'static [ObjectItemPropertyDescriptor],
}

impl ObjectItemSchemaDescriptor {
    pub(crate) fn to_json(self) -> Value {
        let properties = self
            .properties
            .iter()
            .map(|property| (property.name.to_string(), property.schema_json()))
            .collect::<serde_json::Map<_, _>>();
        json!({
            "required": self.required,
            "properties": properties,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectItemPropertyDescriptor {
    pub name: &'static str,
    pub parser: &'static str,
    pub description: &'static str,
}

impl ObjectItemPropertyDescriptor {
    fn schema_json(self) -> Value {
        let mut schema = schema_for_parser_name(self.parser);
        if let Some(object) = schema.as_object_mut() {
            object.insert("description".to_string(), json!(self.description));
        }
        schema
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadAction {
    PeParse,
    Obfuscate,
    Wait,
    ExitCode,
    Cleanup,
    Serialize,
}

impl TryFrom<&RegisteredAction> for PayloadAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "payload" {
            return Err(());
        }

        match action.name {
            "pe_parse" => Ok(Self::PeParse),
            "obfuscate" => Ok(Self::Obfuscate),
            "wait" => Ok(Self::Wait),
            "exit_code" => Ok(Self::ExitCode),
            "cleanup" => Ok(Self::Cleanup),
            "serialize" => Ok(Self::Serialize),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectAction {
    EdrProducts,
    EdrHooks,
    EdrQuickCheck,
    EdrSuspend,
    EtwSessions,
    VehChain,
    VmSandbox,
    Hypervisor,
    Forensics,
    Integrity,
    Hooks,
    HookFunction,
    SyscallResolve,
    StealthScore,
    BypassRecommendations,
}

impl TryFrom<&RegisteredAction> for DetectAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "detect" {
            return Err(());
        }

        match action.name {
            "edr_products" => Ok(Self::EdrProducts),
            "edr_hooks" => Ok(Self::EdrHooks),
            "edr_quick_check" => Ok(Self::EdrQuickCheck),
            "edr_suspend" => Ok(Self::EdrSuspend),
            "etw_sessions" => Ok(Self::EtwSessions),
            "veh_chain" => Ok(Self::VehChain),
            "vm_sandbox" => Ok(Self::VmSandbox),
            "hypervisor" => Ok(Self::Hypervisor),
            "forensics" => Ok(Self::Forensics),
            "integrity" => Ok(Self::Integrity),
            "hooks" => Ok(Self::Hooks),
            "hook_function" => Ok(Self::HookFunction),
            "syscall_resolve" => Ok(Self::SyscallResolve),
            "stealth_score" => Ok(Self::StealthScore),
            "bypass_recommendations" => Ok(Self::BypassRecommendations),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestrateAction {
    Assess,
    Execute,
    Plan,
    Templates,
    Status,
    Resume,
    Cancel,
    Cleanup,
}

impl TryFrom<&RegisteredAction> for OrchestrateAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "orchestrate" {
            return Err(());
        }

        match action.name {
            "assess" => Ok(Self::Assess),
            "execute" => Ok(Self::Execute),
            "plan" => Ok(Self::Plan),
            "templates" => Ok(Self::Templates),
            "status" => Ok(Self::Status),
            "resume" => Ok(Self::Resume),
            "cancel" => Ok(Self::Cancel),
            "cleanup" => Ok(Self::Cleanup),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeAction {
    Elevate,
    TokenSteal,
    TokenImpersonate,
    TokenRevert,
    TokenScan,
    DebugPriv,
    Check,
    Potato,
    ServiceUnquoted,
    ServiceWeakPerms,
    ServiceAlwaysElevated,
    Symlink,
}

impl TryFrom<&RegisteredAction> for PrivilegeAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "privilege" {
            return Err(());
        }

        match action.name {
            "elevate" => Ok(Self::Elevate),
            "token_steal" => Ok(Self::TokenSteal),
            "token_impersonate" => Ok(Self::TokenImpersonate),
            "token_revert" => Ok(Self::TokenRevert),
            "token_scan" => Ok(Self::TokenScan),
            "debug_priv" => Ok(Self::DebugPriv),
            "check" => Ok(Self::Check),
            "potato" => Ok(Self::Potato),
            "service_unquoted" => Ok(Self::ServiceUnquoted),
            "service_weak_perms" => Ok(Self::ServiceWeakPerms),
            "service_always_elevated" => Ok(Self::ServiceAlwaysElevated),
            "symlink" => Ok(Self::Symlink),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAction {
    PsList,
    PsFind,
    PsInfo,
    Modules,
    Threads,
    ThreadsList,
    ThreadSuspend,
    ThreadResume,
    ThreadContext,
    Handles,
    Env,
    Cmdline,
    Windows,
    Peb,
    ModuleBase,
    MemFind,
    StringRead,
    StringWrite,
    Callstack,
    Heap,
    CredDump,
    SamDump,
    KerberosTickets,
}

impl TryFrom<&RegisteredAction> for TargetAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "target" {
            return Err(());
        }

        match action.name {
            "ps_list" => Ok(Self::PsList),
            "ps_find" => Ok(Self::PsFind),
            "ps_info" => Ok(Self::PsInfo),
            "modules" => Ok(Self::Modules),
            "threads" => Ok(Self::Threads),
            "threads_list" => Ok(Self::ThreadsList),
            "thread_suspend" => Ok(Self::ThreadSuspend),
            "thread_resume" => Ok(Self::ThreadResume),
            "thread_context" => Ok(Self::ThreadContext),
            "handles" => Ok(Self::Handles),
            "env" => Ok(Self::Env),
            "cmdline" => Ok(Self::Cmdline),
            "windows" => Ok(Self::Windows),
            "peb" => Ok(Self::Peb),
            "module_base" => Ok(Self::ModuleBase),
            "mem_find" => Ok(Self::MemFind),
            "string_read" => Ok(Self::StringRead),
            "string_write" => Ok(Self::StringWrite),
            "callstack" => Ok(Self::Callstack),
            "heap" => Ok(Self::Heap),
            "cred_dump" => Ok(Self::CredDump),
            "sam_dump" => Ok(Self::SamDump),
            "kerberos_tickets" => Ok(Self::KerberosTickets),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfAction {
    Peb,
    Heap,
    Test,
    MemoryDiagnostics,
    Status,
    ProtectInit,
    ProtectEncrypt,
    ProtectDecrypt,
    ProtectWipe,
    Info,
    Version,
    AntiDebug,
    State,
    Doctor,
    Diagnostics,
    ExplainError,
    CapabilityDiff,
    NextSteps,
}

impl TryFrom<&RegisteredAction> for SelfAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "self" {
            return Err(());
        }

        match action.name {
            "peb" => Ok(Self::Peb),
            "heap" => Ok(Self::Heap),
            "test" => Ok(Self::Test),
            "memory_diagnostics" => Ok(Self::MemoryDiagnostics),
            "status" => Ok(Self::Status),
            "protect_init" => Ok(Self::ProtectInit),
            "protect_encrypt" => Ok(Self::ProtectEncrypt),
            "protect_decrypt" => Ok(Self::ProtectDecrypt),
            "protect_wipe" => Ok(Self::ProtectWipe),
            "info" => Ok(Self::Info),
            "version" => Ok(Self::Version),
            "anti_debug" => Ok(Self::AntiDebug),
            "state" => Ok(Self::State),
            "doctor" => Ok(Self::Doctor),
            "diagnostics" => Ok(Self::Diagnostics),
            "explain_error" => Ok(Self::ExplainError),
            "capability_diff" => Ok(Self::CapabilityDiff),
            "next_steps" => Ok(Self::NextSteps),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAction {
    Read,
    TypedRead,
    Write,
    TypedWrite,
    WriteString,
    Scan,
    Query,
    QueryFind,
    Alloc,
    Free,
    Protect,
    ScanNew,
    ScanNext,
    ScanUndo,
    ScanList,
    ScanReset,
    ScanFreeze,
    Diagnostics,
}

impl TryFrom<&RegisteredAction> for MemoryAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "memory" {
            return Err(());
        }

        match action.name {
            "read" => Ok(Self::Read),
            "typed_read" => Ok(Self::TypedRead),
            "write" => Ok(Self::Write),
            "typed_write" => Ok(Self::TypedWrite),
            "write_string" => Ok(Self::WriteString),
            "scan" => Ok(Self::Scan),
            "query" => Ok(Self::Query),
            "query_find" => Ok(Self::QueryFind),
            "alloc" => Ok(Self::Alloc),
            "free" => Ok(Self::Free),
            "protect" => Ok(Self::Protect),
            "scan_new" => Ok(Self::ScanNew),
            "scan_next" => Ok(Self::ScanNext),
            "scan_undo" => Ok(Self::ScanUndo),
            "scan_list" => Ok(Self::ScanList),
            "scan_reset" => Ok(Self::ScanReset),
            "scan_freeze" => Ok(Self::ScanFreeze),
            "diagnostics" => Ok(Self::Diagnostics),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    HookFunction,
    Install,
    InstallIat,
    Remove,
    RemoveIat,
    InstallHwbp,
    RemoveHwbp,
    Trampoline,
    Detour,
    Restore,
    Winhook,
    HwbpSyscall,
}

impl HookAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HookFunction => "hook_function",
            Self::Install => "install",
            Self::InstallIat => "install_iat",
            Self::Remove => "remove",
            Self::RemoveIat => "remove_iat",
            Self::InstallHwbp => "install_hwbp",
            Self::RemoveHwbp => "remove_hwbp",
            Self::Trampoline => "trampoline",
            Self::Detour => "detour",
            Self::Restore => "restore",
            Self::Winhook => "winhook",
            Self::HwbpSyscall => "hwbp_syscall",
        }
    }
}

impl TryFrom<&RegisteredAction> for HookAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "hook" {
            return Err(());
        }

        match action.name {
            "hook_function" => Ok(Self::HookFunction),
            "install" => Ok(Self::Install),
            "install_iat" => Ok(Self::InstallIat),
            "remove" => Ok(Self::Remove),
            "remove_iat" => Ok(Self::RemoveIat),
            "install_hwbp" => Ok(Self::InstallHwbp),
            "remove_hwbp" => Ok(Self::RemoveHwbp),
            "trampoline" => Ok(Self::Trampoline),
            "detour" => Ok(Self::Detour),
            "restore" => Ok(Self::Restore),
            "winhook" => Ok(Self::Winhook),
            "hwbp_syscall" => Ok(Self::HwbpSyscall),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectAction {
    Shellcode,
    Dll,
    Spawn,
    HijackEnum,
    HijackBackup,
    HijackRedirect,
    HijackRestore,
    HijackWait,
    CreateRemoteThread,
    NtCreateThread,
    Fiber,
    Threadpool,
    StackBomb,
    PoolPartyWorker,
    PoolPartyWork,
    PoolPartyDirect,
    PoolPartyTimer,
    ExportForward,
    PhantomHollow,
    TransactedHollow,
    Wow64Detect,
}

impl TryFrom<&RegisteredAction> for InjectAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "inject" {
            return Err(());
        }

        match action.name {
            "shellcode" => Ok(Self::Shellcode),
            "dll" => Ok(Self::Dll),
            "spawn" => Ok(Self::Spawn),
            "hijack_enum" => Ok(Self::HijackEnum),
            "hijack_backup" => Ok(Self::HijackBackup),
            "hijack_redirect" => Ok(Self::HijackRedirect),
            "hijack_restore" => Ok(Self::HijackRestore),
            "hijack_wait" => Ok(Self::HijackWait),
            "create_remote_thread" => Ok(Self::CreateRemoteThread),
            "nt_create_thread" => Ok(Self::NtCreateThread),
            "fiber" => Ok(Self::Fiber),
            "threadpool" => Ok(Self::Threadpool),
            "stack_bomb" => Ok(Self::StackBomb),
            "pool_party_worker" => Ok(Self::PoolPartyWorker),
            "pool_party_work" => Ok(Self::PoolPartyWork),
            "pool_party_direct" => Ok(Self::PoolPartyDirect),
            "pool_party_timer" => Ok(Self::PoolPartyTimer),
            "export_forward" => Ok(Self::ExportForward),
            "phantom_hollow" => Ok(Self::PhantomHollow),
            "transacted_hollow" => Ok(Self::TransactedHollow),
            "wow64_detect" => Ok(Self::Wow64Detect),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthAction {
    PatchEtw,
    PatchAmsi,
    PatchCfg,
    PatchCig,
    UnhookNtdll,
    UnhookFunction,
    HideModule,
    FluctuateModule,
    ModuleStomp,
    SleepEkko,
    SleepFoliage,
    SleepGargoyle,
    SleepDeath,
    SpoofCallstack,
    SpoofPpid,
    SpoofReturn,
    DeepStackSpoof,
    SyscallWrite,
    SyscallAlloc,
    SyscallProtect,
    SyscallThread,
    SyscallOpen,
    SyscallRead,
    SyscallQuery,
    SyscallClose,
    SyscallFree,
    SyscallStealthRead,
    SyscallInject,
    EncryptMemory,
    DecryptMemory,
    MutateCode,
    SysmonBlind,
    Timestomp,
    EtwProviderDisable,
    EtwMassDisable,
    CreateSuspended,
    TestsignHideNtquery,
    TestsignHideSelf,
    TestsignHideBcd,
    TestsignQuery,
    TestsignAutoInject,
    TestsignLaunchHooked,
    TestsignKernelBypass,
    TestsignLaunchClean,
    TestsignCiCallback,
    TestsignCiFuncPatch,
    TestsignPteRw,
    WdacDisable,
    WdacRestore,
    DefenderDisable,
    DefenderRestore,
    DefenderStatus,
    DefenderAddExclusion,
    DefenderMpcmdrun,
    FirewallAddRule,
    FirewallRemoveRule,
    FirewallListRules,
    FirewallDisable,
    FirewallEnable,
    FirewallStatus,
    SentinelStart,
    SentinelStop,
    SentinelStatus,
    SentinelSelfDestruct,
    CallbackEnumByDriver,
    CallbackMasquerade,
    EtwTiSelectiveDisable,
    MinifilterEnumClassified,
    MinifilterSelectiveDetach,
    MinifilterPause,
    MinifilterResume,
}

impl StealthAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PatchEtw => "patch_etw",
            Self::PatchAmsi => "patch_amsi",
            Self::PatchCfg => "patch_cfg",
            Self::PatchCig => "patch_cig",
            Self::UnhookNtdll => "unhook_ntdll",
            Self::UnhookFunction => "unhook_function",
            Self::HideModule => "hide_module",
            Self::FluctuateModule => "fluctuate_module",
            Self::ModuleStomp => "module_stomp",
            Self::SleepEkko => "sleep_ekko",
            Self::SleepFoliage => "sleep_foliage",
            Self::SleepGargoyle => "sleep_gargoyle",
            Self::SleepDeath => "sleep_death",
            Self::SpoofCallstack => "spoof_callstack",
            Self::SpoofPpid => "spoof_ppid",
            Self::SpoofReturn => "spoof_return",
            Self::DeepStackSpoof => "deep_stack_spoof",
            Self::SyscallWrite => "syscall_write",
            Self::SyscallAlloc => "syscall_alloc",
            Self::SyscallProtect => "syscall_protect",
            Self::SyscallThread => "syscall_thread",
            Self::SyscallOpen => "syscall_open",
            Self::SyscallRead => "syscall_read",
            Self::SyscallQuery => "syscall_query",
            Self::SyscallClose => "syscall_close",
            Self::SyscallFree => "syscall_free",
            Self::SyscallStealthRead => "syscall_stealth_read",
            Self::SyscallInject => "syscall_inject",
            Self::EncryptMemory => "encrypt_memory",
            Self::DecryptMemory => "decrypt_memory",
            Self::MutateCode => "mutate_code",
            Self::SysmonBlind => "sysmon_blind",
            Self::Timestomp => "timestomp",
            Self::EtwProviderDisable => "etw_provider_disable",
            Self::EtwMassDisable => "etw_mass_disable",
            Self::CreateSuspended => "create_suspended",
            Self::TestsignHideNtquery => "testsign_hide_ntquery",
            Self::TestsignHideSelf => "testsign_hide_self",
            Self::TestsignHideBcd => "testsign_hide_bcd",
            Self::TestsignQuery => "testsign_query",
            Self::TestsignAutoInject => "testsign_auto_inject",
            Self::TestsignLaunchHooked => "testsign_launch_hooked",
            Self::TestsignKernelBypass => "testsign_kernel_bypass",
            Self::TestsignLaunchClean => "testsign_launch_clean",
            Self::TestsignCiCallback => "testsign_ci_callback",
            Self::TestsignCiFuncPatch => "testsign_ci_func_patch",
            Self::TestsignPteRw => "testsign_pte_rw",
            Self::WdacDisable => "wdac_disable",
            Self::WdacRestore => "wdac_restore",
            Self::DefenderDisable => "defender_disable",
            Self::DefenderRestore => "defender_restore",
            Self::DefenderStatus => "defender_status",
            Self::DefenderAddExclusion => "defender_add_exclusion",
            Self::DefenderMpcmdrun => "defender_mpcmdrun",
            Self::FirewallAddRule => "firewall_add_rule",
            Self::FirewallRemoveRule => "firewall_remove_rule",
            Self::FirewallListRules => "firewall_list_rules",
            Self::FirewallDisable => "firewall_disable",
            Self::FirewallEnable => "firewall_enable",
            Self::FirewallStatus => "firewall_status",
            Self::SentinelStart => "sentinel_start",
            Self::SentinelStop => "sentinel_stop",
            Self::SentinelStatus => "sentinel_status",
            Self::SentinelSelfDestruct => "sentinel_self_destruct",
            Self::CallbackEnumByDriver => "callback_enum_by_driver",
            Self::CallbackMasquerade => "callback_masquerade",
            Self::EtwTiSelectiveDisable => "etw_ti_selective_disable",
            Self::MinifilterEnumClassified => "minifilter_enum_classified",
            Self::MinifilterSelectiveDetach => "minifilter_selective_detach",
            Self::MinifilterPause => "minifilter_pause",
            Self::MinifilterResume => "minifilter_resume",
        }
    }
}

impl TryFrom<&RegisteredAction> for StealthAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "stealth" {
            return Err(());
        }

        match action.name {
            "patch_etw" => Ok(Self::PatchEtw),
            "patch_amsi" => Ok(Self::PatchAmsi),
            "patch_cfg" => Ok(Self::PatchCfg),
            "patch_cig" => Ok(Self::PatchCig),
            "unhook_ntdll" => Ok(Self::UnhookNtdll),
            "unhook_function" => Ok(Self::UnhookFunction),
            "hide_module" => Ok(Self::HideModule),
            "fluctuate_module" => Ok(Self::FluctuateModule),
            "module_stomp" => Ok(Self::ModuleStomp),
            "sleep_ekko" => Ok(Self::SleepEkko),
            "sleep_foliage" => Ok(Self::SleepFoliage),
            "sleep_gargoyle" => Ok(Self::SleepGargoyle),
            "sleep_death" => Ok(Self::SleepDeath),
            "spoof_callstack" => Ok(Self::SpoofCallstack),
            "spoof_ppid" => Ok(Self::SpoofPpid),
            "spoof_return" => Ok(Self::SpoofReturn),
            "deep_stack_spoof" => Ok(Self::DeepStackSpoof),
            "syscall_write" => Ok(Self::SyscallWrite),
            "syscall_alloc" => Ok(Self::SyscallAlloc),
            "syscall_protect" => Ok(Self::SyscallProtect),
            "syscall_thread" => Ok(Self::SyscallThread),
            "syscall_open" => Ok(Self::SyscallOpen),
            "syscall_read" => Ok(Self::SyscallRead),
            "syscall_query" => Ok(Self::SyscallQuery),
            "syscall_close" => Ok(Self::SyscallClose),
            "syscall_free" => Ok(Self::SyscallFree),
            "syscall_stealth_read" => Ok(Self::SyscallStealthRead),
            "syscall_inject" => Ok(Self::SyscallInject),
            "encrypt_memory" => Ok(Self::EncryptMemory),
            "decrypt_memory" => Ok(Self::DecryptMemory),
            "mutate_code" => Ok(Self::MutateCode),
            "sysmon_blind" => Ok(Self::SysmonBlind),
            "timestomp" => Ok(Self::Timestomp),
            "etw_provider_disable" => Ok(Self::EtwProviderDisable),
            "etw_mass_disable" => Ok(Self::EtwMassDisable),
            "create_suspended" => Ok(Self::CreateSuspended),
            "testsign_hide_ntquery" => Ok(Self::TestsignHideNtquery),
            "testsign_hide_self" => Ok(Self::TestsignHideSelf),
            "testsign_hide_bcd" => Ok(Self::TestsignHideBcd),
            "testsign_query" => Ok(Self::TestsignQuery),
            "testsign_auto_inject" => Ok(Self::TestsignAutoInject),
            "testsign_launch_hooked" => Ok(Self::TestsignLaunchHooked),
            "testsign_kernel_bypass" => Ok(Self::TestsignKernelBypass),
            "testsign_launch_clean" => Ok(Self::TestsignLaunchClean),
            "testsign_ci_callback" => Ok(Self::TestsignCiCallback),
            "testsign_ci_func_patch" => Ok(Self::TestsignCiFuncPatch),
            "testsign_pte_rw" => Ok(Self::TestsignPteRw),
            "wdac_disable" => Ok(Self::WdacDisable),
            "wdac_restore" => Ok(Self::WdacRestore),
            "defender_disable" => Ok(Self::DefenderDisable),
            "defender_restore" => Ok(Self::DefenderRestore),
            "defender_status" => Ok(Self::DefenderStatus),
            "defender_add_exclusion" => Ok(Self::DefenderAddExclusion),
            "defender_mpcmdrun" => Ok(Self::DefenderMpcmdrun),
            "firewall_add_rule" => Ok(Self::FirewallAddRule),
            "firewall_remove_rule" => Ok(Self::FirewallRemoveRule),
            "firewall_list_rules" => Ok(Self::FirewallListRules),
            "firewall_disable" => Ok(Self::FirewallDisable),
            "firewall_enable" => Ok(Self::FirewallEnable),
            "firewall_status" => Ok(Self::FirewallStatus),
            "sentinel_start" => Ok(Self::SentinelStart),
            "sentinel_stop" => Ok(Self::SentinelStop),
            "sentinel_status" => Ok(Self::SentinelStatus),
            "sentinel_self_destruct" => Ok(Self::SentinelSelfDestruct),
            "callback_enum_by_driver" => Ok(Self::CallbackEnumByDriver),
            "callback_masquerade" => Ok(Self::CallbackMasquerade),
            "etw_ti_selective_disable" => Ok(Self::EtwTiSelectiveDisable),
            "minifilter_enum_classified" => Ok(Self::MinifilterEnumClassified),
            "minifilter_selective_detach" => Ok(Self::MinifilterSelectiveDetach),
            "minifilter_pause" => Ok(Self::MinifilterPause),
            "minifilter_resume" => Ok(Self::MinifilterResume),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelAction {
    Status,
    DriverLoad,
    DriverUnload,
    DriverDiscover,
    DriverAuto,
    Read,
    Write,
    PhysicalRead,
    PhysicalWrite,
    PteModify,
    VadHide,
    SniffStart,
    SniffStop,
    EnumCallbacks,
    RemoveCallback,
    ObjectCallbackEnum,
    ObjectCallbackRemove,
    RegistryCallbackEnum,
    RegistryCallbackRemove,
    DriverNotifyRoutine,
    DriverRegProtect,
    DriverObjectHook,
    DriverPortHide,
    PplBypass,
    DseBypass,
    DseMapDriver,
    DkomHide,
    ModuleHide,
    MinifilterEnum,
    MinifilterRemove,
    TokenEscalate,
    EtwTiRemove,
    DriverEnumProcess,
    DriverModuleHide,
    DriverThreadHide,
    DriverCallbackEnum,
    DriverCallbackRemove,
    DriverPatchKernel,
    DriverApcInject,
    DriverHandleStrip,
    DriverPeDump,
    DriverSetDebugPort,
    DriverDpcTimer,
    DriverTokenDup,
    DriverStats,
    DriverMemoryPool,
    DriverMinifilterEnum,
    DriverProcessDump,
    DriverHypervisorDetect,
    DriverTestsignHide,
    DriverGlobalHook,
    DriverAutoInject,
    DriverInfinityHook,
    DriverCiCallbackPatch,
    DriverCiFuncPatch,
    DriverPteRw,
    DriverMsrRw,
    DriverCloak,
    DriverForceKill,
    DriverForceDelete,
    DriverSystemThread,
    DriverKernelExec,
    DriverPplBypass,
    DriverCrRw,
    DriverIdtRw,
    DriverUnloadedDrvClear,
    DriverTokenSwap,
    DriverProcessProtect,
    DriverKeylogger,
    DriverRegHide,
    DriverFileLock,
    DriverEtwBlind,
    DriverEprocessSpoof,
    DriverEventLogClear,
    DriverCredDump,
    DriverImpersonate,
    DriverCallbackNuke,
    DriverMinifilterDetach,
    DriverKernelApc,
    DriverWfpRemove,
}

impl KernelAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::DriverLoad => "driver_load",
            Self::DriverUnload => "driver_unload",
            Self::DriverDiscover => "driver_discover",
            Self::DriverAuto => "driver_auto",
            Self::Read => "read",
            Self::Write => "write",
            Self::PhysicalRead => "physical_read",
            Self::PhysicalWrite => "physical_write",
            Self::PteModify => "pte_modify",
            Self::VadHide => "vad_hide",
            Self::SniffStart => "sniff_start",
            Self::SniffStop => "sniff_stop",
            Self::EnumCallbacks => "enum_callbacks",
            Self::RemoveCallback => "remove_callback",
            Self::ObjectCallbackEnum => "object_callback_enum",
            Self::ObjectCallbackRemove => "object_callback_remove",
            Self::RegistryCallbackEnum => "registry_callback_enum",
            Self::RegistryCallbackRemove => "registry_callback_remove",
            Self::DriverNotifyRoutine => "driver_notify_routine",
            Self::DriverRegProtect => "driver_reg_protect",
            Self::DriverObjectHook => "driver_object_hook",
            Self::DriverPortHide => "driver_port_hide",
            Self::PplBypass => "ppl_bypass",
            Self::DseBypass => "dse_bypass",
            Self::DseMapDriver => "dse_map_driver",
            Self::DkomHide => "dkom_hide",
            Self::ModuleHide => "module_hide",
            Self::MinifilterEnum => "minifilter_enum",
            Self::MinifilterRemove => "minifilter_remove",
            Self::TokenEscalate => "token_escalate",
            Self::EtwTiRemove => "etw_ti_remove",
            Self::DriverEnumProcess => "driver_enum_process",
            Self::DriverModuleHide => "driver_module_hide",
            Self::DriverThreadHide => "driver_thread_hide",
            Self::DriverCallbackEnum => "driver_callback_enum",
            Self::DriverCallbackRemove => "driver_callback_remove",
            Self::DriverPatchKernel => "driver_patch_kernel",
            Self::DriverApcInject => "driver_apc_inject",
            Self::DriverHandleStrip => "driver_handle_strip",
            Self::DriverPeDump => "driver_pe_dump",
            Self::DriverSetDebugPort => "driver_set_debug_port",
            Self::DriverDpcTimer => "driver_dpc_timer",
            Self::DriverTokenDup => "driver_token_dup",
            Self::DriverStats => "driver_stats",
            Self::DriverMemoryPool => "driver_memory_pool",
            Self::DriverMinifilterEnum => "driver_minifilter_enum",
            Self::DriverProcessDump => "driver_process_dump",
            Self::DriverHypervisorDetect => "driver_hypervisor_detect",
            Self::DriverTestsignHide => "driver_testsign_hide",
            Self::DriverGlobalHook => "driver_global_hook",
            Self::DriverAutoInject => "driver_auto_inject",
            Self::DriverInfinityHook => "driver_infinity_hook",
            Self::DriverCiCallbackPatch => "driver_ci_callback_patch",
            Self::DriverCiFuncPatch => "driver_ci_func_patch",
            Self::DriverPteRw => "driver_pte_rw",
            Self::DriverMsrRw => "driver_msr_rw",
            Self::DriverCloak => "driver_cloak",
            Self::DriverForceKill => "driver_force_kill",
            Self::DriverForceDelete => "driver_force_delete",
            Self::DriverSystemThread => "driver_system_thread",
            Self::DriverKernelExec => "driver_kernel_exec",
            Self::DriverPplBypass => "driver_ppl_bypass",
            Self::DriverCrRw => "driver_cr_rw",
            Self::DriverIdtRw => "driver_idt_rw",
            Self::DriverUnloadedDrvClear => "driver_unloaded_drv_clear",
            Self::DriverTokenSwap => "driver_token_swap",
            Self::DriverProcessProtect => "driver_process_protect",
            Self::DriverKeylogger => "driver_keylogger",
            Self::DriverRegHide => "driver_reg_hide",
            Self::DriverFileLock => "driver_file_lock",
            Self::DriverEtwBlind => "driver_etw_blind",
            Self::DriverEprocessSpoof => "driver_eprocess_spoof",
            Self::DriverEventLogClear => "driver_event_log_clear",
            Self::DriverCredDump => "driver_cred_dump",
            Self::DriverImpersonate => "driver_impersonate",
            Self::DriverCallbackNuke => "driver_callback_nuke",
            Self::DriverMinifilterDetach => "driver_minifilter_detach",
            Self::DriverKernelApc => "driver_kernel_apc",
            Self::DriverWfpRemove => "driver_wfp_remove",
        }
    }
}

impl TryFrom<&RegisteredAction> for KernelAction {
    type Error = ();

    fn try_from(action: &RegisteredAction) -> Result<Self, Self::Error> {
        if action.tool != "kernel" {
            return Err(());
        }

        match action.name {
            "status" => Ok(Self::Status),
            "driver_load" => Ok(Self::DriverLoad),
            "driver_unload" => Ok(Self::DriverUnload),
            "driver_discover" => Ok(Self::DriverDiscover),
            "driver_auto" => Ok(Self::DriverAuto),
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "physical_read" => Ok(Self::PhysicalRead),
            "physical_write" => Ok(Self::PhysicalWrite),
            "pte_modify" => Ok(Self::PteModify),
            "vad_hide" => Ok(Self::VadHide),
            "sniff_start" => Ok(Self::SniffStart),
            "sniff_stop" => Ok(Self::SniffStop),
            "enum_callbacks" => Ok(Self::EnumCallbacks),
            "remove_callback" => Ok(Self::RemoveCallback),
            "object_callback_enum" => Ok(Self::ObjectCallbackEnum),
            "object_callback_remove" => Ok(Self::ObjectCallbackRemove),
            "registry_callback_enum" => Ok(Self::RegistryCallbackEnum),
            "registry_callback_remove" => Ok(Self::RegistryCallbackRemove),
            "driver_notify_routine" => Ok(Self::DriverNotifyRoutine),
            "driver_reg_protect" => Ok(Self::DriverRegProtect),
            "driver_object_hook" => Ok(Self::DriverObjectHook),
            "driver_port_hide" => Ok(Self::DriverPortHide),
            "ppl_bypass" => Ok(Self::PplBypass),
            "dse_bypass" => Ok(Self::DseBypass),
            "dse_map_driver" => Ok(Self::DseMapDriver),
            "dkom_hide" => Ok(Self::DkomHide),
            "module_hide" => Ok(Self::ModuleHide),
            "minifilter_enum" => Ok(Self::MinifilterEnum),
            "minifilter_remove" => Ok(Self::MinifilterRemove),
            "token_escalate" => Ok(Self::TokenEscalate),
            "etw_ti_remove" => Ok(Self::EtwTiRemove),
            "driver_enum_process" => Ok(Self::DriverEnumProcess),
            "driver_module_hide" => Ok(Self::DriverModuleHide),
            "driver_thread_hide" => Ok(Self::DriverThreadHide),
            "driver_callback_enum" => Ok(Self::DriverCallbackEnum),
            "driver_callback_remove" => Ok(Self::DriverCallbackRemove),
            "driver_patch_kernel" => Ok(Self::DriverPatchKernel),
            "driver_apc_inject" => Ok(Self::DriverApcInject),
            "driver_handle_strip" => Ok(Self::DriverHandleStrip),
            "driver_pe_dump" => Ok(Self::DriverPeDump),
            "driver_set_debug_port" => Ok(Self::DriverSetDebugPort),
            "driver_dpc_timer" => Ok(Self::DriverDpcTimer),
            "driver_token_dup" => Ok(Self::DriverTokenDup),
            "driver_stats" => Ok(Self::DriverStats),
            "driver_memory_pool" => Ok(Self::DriverMemoryPool),
            "driver_minifilter_enum" => Ok(Self::DriverMinifilterEnum),
            "driver_process_dump" => Ok(Self::DriverProcessDump),
            "driver_hypervisor_detect" => Ok(Self::DriverHypervisorDetect),
            "driver_testsign_hide" => Ok(Self::DriverTestsignHide),
            "driver_global_hook" => Ok(Self::DriverGlobalHook),
            "driver_auto_inject" => Ok(Self::DriverAutoInject),
            "driver_infinity_hook" => Ok(Self::DriverInfinityHook),
            "driver_ci_callback_patch" => Ok(Self::DriverCiCallbackPatch),
            "driver_ci_func_patch" => Ok(Self::DriverCiFuncPatch),
            "driver_pte_rw" => Ok(Self::DriverPteRw),
            "driver_msr_rw" => Ok(Self::DriverMsrRw),
            "driver_cloak" => Ok(Self::DriverCloak),
            "driver_force_kill" => Ok(Self::DriverForceKill),
            "driver_force_delete" => Ok(Self::DriverForceDelete),
            "driver_system_thread" => Ok(Self::DriverSystemThread),
            "driver_kernel_exec" => Ok(Self::DriverKernelExec),
            "driver_ppl_bypass" => Ok(Self::DriverPplBypass),
            "driver_cr_rw" => Ok(Self::DriverCrRw),
            "driver_idt_rw" => Ok(Self::DriverIdtRw),
            "driver_unloaded_drv_clear" => Ok(Self::DriverUnloadedDrvClear),
            "driver_token_swap" => Ok(Self::DriverTokenSwap),
            "driver_process_protect" => Ok(Self::DriverProcessProtect),
            "driver_keylogger" => Ok(Self::DriverKeylogger),
            "driver_reg_hide" => Ok(Self::DriverRegHide),
            "driver_file_lock" => Ok(Self::DriverFileLock),
            "driver_etw_blind" => Ok(Self::DriverEtwBlind),
            "driver_eprocess_spoof" => Ok(Self::DriverEprocessSpoof),
            "driver_event_log_clear" => Ok(Self::DriverEventLogClear),
            "driver_cred_dump" => Ok(Self::DriverCredDump),
            "driver_impersonate" => Ok(Self::DriverImpersonate),
            "driver_callback_nuke" => Ok(Self::DriverCallbackNuke),
            "driver_minifilter_detach" => Ok(Self::DriverMinifilterDetach),
            "driver_kernel_apc" => Ok(Self::DriverKernelApc),
            "driver_wfp_remove" => Ok(Self::DriverWfpRemove),
            _ => Err(()),
        }
    }
}

const fn memory_region_cache_ttl_bounds(
    action: &'static str,
    parameter: &'static str,
    maximum: u64,
) -> ParameterBoundsDescriptor {
    ParameterBoundsDescriptor {
        tool: "memory",
        action,
        parameter,
        minimum: None,
        maximum: Some(maximum),
    }
}

const fn memory_action_bounds(
    action: &'static str,
    parameter: &'static str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) -> ParameterBoundsDescriptor {
    ParameterBoundsDescriptor {
        tool: "memory",
        action,
        parameter,
        minimum,
        maximum,
    }
}

const fn memory_scan_bounds(
    parameter: &'static str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) -> ParameterBoundsDescriptor {
    memory_action_bounds("scan", parameter, minimum, maximum)
}

const fn action_bounds(
    tool: &'static str,
    action: &'static str,
    parameter: &'static str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) -> ParameterBoundsDescriptor {
    ParameterBoundsDescriptor {
        tool,
        action,
        parameter,
        minimum,
        maximum,
    }
}

const fn target_action_bounds(
    action: &'static str,
    parameter: &'static str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) -> ParameterBoundsDescriptor {
    action_bounds("target", action, parameter, minimum, maximum)
}

const fn inject_action_bounds(
    action: &'static str,
    parameter: &'static str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) -> ParameterBoundsDescriptor {
    action_bounds("inject", action, parameter, minimum, maximum)
}

const fn stealth_action_bounds(
    action: &'static str,
    parameter: &'static str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) -> ParameterBoundsDescriptor {
    action_bounds("stealth", action, parameter, minimum, maximum)
}

const HOOK_DETOUR_HOOK_ITEM_PROPERTIES: &[ObjectItemPropertyDescriptor] = &[
    ObjectItemPropertyDescriptor {
        name: "target_address",
        parser: "address_u64",
        description: "Address to patch with the detour jump",
    },
    ObjectItemPropertyDescriptor {
        name: "hook_address",
        parser: "address_u64",
        description: "Destination address for the detour jump",
    },
];
const HOOK_DETOUR_HOOK_ITEM_SCHEMA: ObjectItemSchemaDescriptor = ObjectItemSchemaDescriptor {
    required: &["target_address", "hook_address"],
    properties: HOOK_DETOUR_HOOK_ITEM_PROPERTIES,
};

const ORCHESTRATE_STEP_ITEM_PROPERTIES: &[ObjectItemPropertyDescriptor] = &[
    ObjectItemPropertyDescriptor {
        name: "id",
        parser: "string",
        description: "Optional stable step ID used for dependencies and checkpoints",
    },
    ObjectItemPropertyDescriptor {
        name: "tool",
        parser: "string",
        description: "Registered MCP tool name",
    },
    ObjectItemPropertyDescriptor {
        name: "action",
        parser: "string",
        description: "Registered action name for the selected tool",
    },
    ObjectItemPropertyDescriptor {
        name: "args",
        parser: "object",
        description: "Tool arguments for this step",
    },
    ObjectItemPropertyDescriptor {
        name: "description",
        parser: "string",
        description: "Operator-facing step description",
    },
    ObjectItemPropertyDescriptor {
        name: "required",
        parser: "boolean",
        description: "Whether a blocked or failed step should halt the chain",
    },
    ObjectItemPropertyDescriptor {
        name: "depends_on",
        parser: "string_array",
        description: "Explicit prerequisite step IDs",
    },
];
const ORCHESTRATE_STEP_ITEM_SCHEMA: ObjectItemSchemaDescriptor = ObjectItemSchemaDescriptor {
    required: &["tool", "action"],
    properties: ORCHESTRATE_STEP_ITEM_PROPERTIES,
};

const MEMORY_MAX_READ_BYTES: u64 = 64 * 1024 * 1024;
const MEMORY_MAX_OPERATION_BYTES: u64 = 64 * 1024 * 1024;
const MEMORY_MAX_SCAN_LIMIT: u64 = crate::args::DEFAULT_MAX_LIMIT as u64;
const MEMORY_MAX_SCAN_TIMEOUT_SECS: u64 = crate::runtime::MAX_TIMEOUT_MS / 1000;
const MEMORY_MAX_PATTERN_CONTEXT_BYTES: u64 = 4096;
const MEMORY_MAX_POINTER_SCAN_DEPTH: u64 = 16;
const MEMORY_MAX_SCAN_ALIGNMENT: u64 = 4096;
const TARGET_MAX_RESULT_LIMIT: u64 = crate::args::DEFAULT_MAX_LIMIT as u64;
const TARGET_MAX_STRING_READ_BYTES: u64 = 1024 * 1024;
const TARGET_MAX_WINDOW_WAIT_MS: u64 = 60 * 1000;
const KERNEL_MAX_ENUM_PROCESS_ENTRIES: u64 = 1024;
const KERNEL_MAX_CALLBACK_ENUM_ENTRIES: u64 = 64;
const KERNEL_MAX_MEMORY_POOL_ENTRIES: u64 = 256;
const KERNEL_MAX_NOTIFY_EVENTS: u64 = 256;
const KERNEL_MAX_PROCESS_DUMP_BYTES: u64 = 16 * 1024 * 1024;
const KERNEL_MAX_KEYLOG_KEYS: u64 = 512;
const KERNEL_MAX_CRED_DUMP_BYTES: u64 = crate::args::DEFAULT_MAX_BYTES as u64;
const KERNEL_MAX_PHYSICAL_READ_BYTES: u64 = 4096;
const KERNEL_MAX_PORT_NUMBER: u64 = 65535;
const KERNEL_MAX_CR_INDEX: u64 = 4;
const KERNEL_MAX_IDT_VECTOR: u64 = 255;
const KERNEL_MAX_DPL: u64 = 3;
const INJECT_MAX_POOL_PARTY_VARIANT: u64 = 8;
const HOOK_MAX_DETOUR_HOOKS: u64 = 128;
const PAYLOAD_MAX_CLEANUP_ITEMS: u64 = 4096;
const PAYLOAD_MAX_SERIALIZE_PARAMS: u64 = 256;
const PAYLOAD_MAX_OBFUSCATION_KEY_BYTES: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFieldType {
    Boolean,
    Integer,
    String,
}

impl InputFieldType {
    fn schema_type(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::String => "string",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFieldDefault {
    Boolean(bool),
    Integer(u64),
    String(&'static str),
}

impl InputFieldDefault {
    fn to_value(self) -> Value {
        match self {
            Self::Boolean(value) => json!(value),
            Self::Integer(value) => json!(value),
            Self::String(value) => json!(value),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InputFieldDescriptor {
    pub name: &'static str,
    pub field_type: InputFieldType,
    pub description: &'static str,
    pub enum_values: &'static [&'static str],
    pub default: Option<InputFieldDefault>,
    pub bounds: Option<InputFieldBounds>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputFieldBounds {
    pub minimum: Option<u64>,
    pub maximum: Option<u64>,
}

impl InputFieldDescriptor {
    fn schema(self) -> Value {
        let mut schema = serde_json::Map::new();
        schema.insert("type".to_string(), json!(self.field_type.schema_type()));
        if let Some(bounds) = self.bounds {
            if let Some(minimum) = bounds.minimum {
                schema.insert("minimum".to_string(), json!(minimum));
            }
            if let Some(maximum) = bounds.maximum {
                schema.insert("maximum".to_string(), json!(maximum));
            }
        }
        if !self.enum_values.is_empty() {
            schema.insert("enum".to_string(), json!(self.enum_values));
        }
        schema.insert("description".to_string(), json!(self.description));
        if let Some(default) = self.default {
            schema.insert("default".to_string(), default.to_value());
        }
        Value::Object(schema)
    }
}

#[derive(Debug, Clone, Copy)]
struct ToolInputFieldDescriptor {
    tool: &'static str,
    name: &'static str,
    description: &'static str,
    default: Option<InputFieldDefault>,
}

impl ToolInputFieldDescriptor {
    fn applies_to(self, tool: &str) -> bool {
        self.tool == tool
    }

    fn schema(self) -> Value {
        let mut schema = serde_json::Map::new();
        schema.insert("description".to_string(), json!(self.description));
        if let Some(default) = self.default {
            schema.insert("default".to_string(), default.to_value());
        }
        Value::Object(schema)
    }
}

const REDACTION_VALUES: &[&str] = &["none", "standard", "strict"];

const COMMON_INPUT_FIELDS: &[InputFieldDescriptor] = &[
    InputFieldDescriptor {
        name: "dry_run",
        field_type: InputFieldType::Boolean,
        description: "Preview a state-changing operation without executing it where supported",
        enum_values: &[],
        default: Some(InputFieldDefault::Boolean(false)),
        bounds: None,
    },
    InputFieldDescriptor {
        name: "as_task",
        field_type: InputFieldType::Boolean,
        description: "Compatibility flag for task-augmented execution: run eligible read-only or dry-run calls in the process-local MCP task registry for polling/cancellation. MCP clients may prefer params.task.",
        enum_values: &[],
        default: Some(InputFieldDefault::Boolean(false)),
        bounds: None,
    },
    InputFieldDescriptor {
        name: "task_id",
        field_type: InputFieldType::String,
        description: "Task ID propagated to long-running handlers for cooperative cancellation",
        enum_values: &[],
        default: None,
        bounds: None,
    },
    InputFieldDescriptor {
        name: "timeout_ms",
        field_type: InputFieldType::Integer,
        description: "Per-call cooperative timeout in milliseconds; long-running handlers check it at safe boundaries",
        enum_values: &[],
        default: Some(InputFieldDefault::Integer(crate::runtime::DEFAULT_TIMEOUT_MS)),
        bounds: Some(InputFieldBounds {
            minimum: Some(1),
            maximum: Some(crate::runtime::MAX_TIMEOUT_MS),
        }),
    },
    InputFieldDescriptor {
        name: "artifact_retention_secs",
        field_type: InputFieldType::Integer,
        description: "Retention window for process-local artifact resource links emitted by this call; values outside the registry bounds are rejected before dispatch",
        enum_values: &[],
        default: Some(InputFieldDefault::Integer(
            crate::artifact::DEFAULT_ARTIFACT_RETENTION_SECS,
        )),
        bounds: Some(InputFieldBounds {
            minimum: Some(1),
            maximum: Some(crate::artifact::MAX_ARTIFACT_RETENTION_SECS),
        }),
    },
    InputFieldDescriptor {
        name: "purpose",
        field_type: InputFieldType::String,
        description: "Caller-provided authorized purpose for audit/provenance",
        enum_values: &[],
        default: None,
        bounds: None,
    },
    InputFieldDescriptor {
        name: "consent_token",
        field_type: InputFieldType::String,
        description: "Explicit consent token for policy-gated state-changing operations",
        enum_values: &[],
        default: None,
        bounds: None,
    },
    InputFieldDescriptor {
        name: "allow_protected_target",
        field_type: InputFieldType::Boolean,
        description: "Explicit override for state-changing operations against protected or critical Windows targets",
        enum_values: &[],
        default: Some(InputFieldDefault::Boolean(false)),
        bounds: None,
    },
    InputFieldDescriptor {
        name: "redaction",
        field_type: InputFieldType::String,
        description: "Result redaction profile. strict suppresses raw bytes, hex blobs, credential-like fields, and paths from inline output.",
        enum_values: REDACTION_VALUES,
        default: Some(InputFieldDefault::String("standard")),
        bounds: None,
    },
    InputFieldDescriptor {
        name: "request_id",
        field_type: InputFieldType::String,
        description: "Optional caller request ID for audit/provenance",
        enum_values: &[],
        default: None,
        bounds: None,
    },
];

pub fn common_input_fields() -> &'static [InputFieldDescriptor] {
    COMMON_INPUT_FIELDS
}

const TARGET_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "target",
        name: "pid",
        description: "Process ID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "tid",
        description: "Thread ID (for suspend/resume/context)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "name",
        description: "Process name pattern (for ps_find)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "module_name",
        description: "Module name for module_base lookup",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "address",
        description: "Memory address for string_read/string_write",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "text",
        description: "String payload for string_write",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "max_len",
        description: "Maximum length for string_read",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "wait_ms",
        description: "Optional readiness wait for actions such as windows",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "suspend",
        description: "Suspend thread while capturing context (for thread_context)",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "output_path",
        description: "Optional artifact output path for cred_dump and kerberos_tickets",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "output_dir",
        description: "Output directory for sam_dump hive files",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "dump_sam",
        description: "Dump SAM hive (default: true)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "dump_security",
        description: "Dump SECURITY hive (default: true)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "all_sessions",
        description: "Extract tickets from all logon sessions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "include_system",
        description: "Include system processes in process listings",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "limit",
        description: "Maximum number of target records to return for paginated list operations",
        default: Some(InputFieldDefault::Integer(100)),
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "type_filter",
        description: "Handle type filter e.g. 'Process', 'Thread', 'File' (for handles)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "target",
        name: "offset",
        description: "Pagination offset (for handles)",
        default: None,
    },
];

const MEMORY_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "pid",
        description: "Target process ID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "address",
        description: "Memory address (int or hex string '0x1234')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "size",
        description: "Size in bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "output_path",
        description: "Optional export path for large memory read results or full scan_list session candidate artifacts",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "limit",
        description: "Maximum number of results to return for scan/query results or scan_list candidate pages",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "offset",
        description: "Pagination offset for scan/query results or scan_list candidate pages",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "cursor",
        description: "Opaque cursor returned by scan_list session candidate pagination; pass nextCursor unchanged to continue",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "sort",
        description: "Sort order for scan_list session candidates; cursors are bound to the selected sort",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "summary_only",
        description: "Return only scan session metadata and pagination summary without inline candidate rows",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "mode",
        description: "read mode: raw=bytes, string=null-terminated, stealth=BYOVD driver, scattered=jitter delays, physical=physical memory",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "bytes",
        description: "Bytes to write (for write)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "text",
        description: "Text to write (for write_string or legacy write(text=...))",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "type",
        description: "Primitive type for typed_read/typed_write",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "endian",
        description: "Byte order for typed_read/typed_write",
        default: Some(InputFieldDefault::String("native")),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "allow_unaligned",
        description: "Allow unaligned typed_read/typed_write while reporting alignment metadata",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "scan_mode",
        description: "scan mode: exact=value, changed=delta, pattern=IDA sig, range=min-max, delta=+/-change, string=ANSI/Unicode, unknown=initial, pointer=chain, aob=raw AOB, aligned=aligned scan, multi=multiple values",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "scan_type",
        description: "Scanner data type for exact/range scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "value",
        description: "Value to scan for or freeze to",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "values",
        description: "Array of values to scan for (multi mode)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "change",
        description: "Change filter for legacy changed scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "delta",
        description: "Delta amount for scan_mode='delta'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "direction",
        description: "Direction for scan_mode='delta'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "min",
        description: "Minimum value (range mode)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "max",
        description: "Maximum value (range mode)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "alignment",
        description: "Alignment in bytes, power of 2 (aligned mode, default 4)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "signature",
        description: "Byte signature e.g. '48 8B 05 ?? ?? ?? ??' (pattern/aob mode)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "pattern",
        description: "String pattern for scan_mode='string' or explicit pattern alias for signatures",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "context_bytes",
        description: "Number of surrounding bytes returned for pattern scan matches",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "encoding",
        description: "Encoding for scan_mode='string'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "case_insensitive",
        description: "Case-insensitive matching for scan_mode='string'",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "target_address",
        description: "Target address for pointer scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "max_depth",
        description: "Maximum pointer depth for pointer scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "protect",
        description: "Protection level alias for alloc/protect; accepts symbolic strings such as RWX or PAGE_EXECUTE_READWRITE, or numeric PAGE_* flags",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "filter",
        description: "Region filter: private/image/mapped/executable/readwrite (for query); OR scan_next filter: changed/unchanged/exact/increased/decreased",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "bypass_protect",
        description: "Auto bypass page protection for writes",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "start_address",
        description: "Starting address for long-running scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "timeout_secs",
        description: "Time budget for scan operations",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "exclude_mapped",
        description: "Skip MEM_MAPPED regions during scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "exclude_image",
        description: "Skip MEM_IMAGE regions during scans",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "module_name",
        description: "Restrict scan results to a named module",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "region_cache",
        description: "Memory region metadata cache mode for memory read and scan operations: auto=reuse fresh per-PID cache, refresh=force query, clear=invalidate then query, off=bypass cache",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "region_cache_ttl_ms",
        description: "Freshness TTL for per-PID memory region cache metadata in milliseconds",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "region_cache_ttl_secs",
        description: "Freshness TTL for per-PID memory region cache metadata in seconds",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "region_cache_refresh",
        description: "Force refresh of cached memory region metadata before memory read or scan operations",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "region_cache_clear",
        description: "Invalidate cached memory region metadata for the PID before memory read or scan operations",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "session_id",
        description: "Scan session ID (for scan_next/scan_undo/scan_reset/scan_freeze, or scan_list result pagination)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "value_type",
        description: "Value type for scan_new (default: u32)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "region_limit",
        description: "Maximum memory regions returned by diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "suspicious_limit",
        description: "Maximum suspicious regions returned by diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "module_limit",
        description: "Maximum modules included by diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "handle_limit",
        description: "Maximum handle samples included by diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "entropy_region_limit",
        description: "Maximum readable regions sampled for diagnostics entropy",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "entropy_sample_bytes",
        description: "Maximum bytes sampled per region for diagnostics entropy",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "include_modules",
        description: "Include module summary in diagnostics",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "include_handles",
        description: "Include handle summary in diagnostics",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "memory",
        name: "include_entropy",
        description: "Include bounded entropy samples in diagnostics",
        default: Some(InputFieldDefault::Boolean(true)),
    },
];

const INJECT_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "pid",
        description: "Target process ID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "tid",
        description: "Thread ID (for APC/hijack)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "method",
        description: "Shellcode injection method",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "dll_method",
        description: "DLL injection method",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "spawn_method",
        description: "Process spawn method",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "shellcode",
        description: "Shellcode bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "dll_path",
        description: "Path to DLL (required for action='dll')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "start_address",
        description: "Thread start address for direct thread creation actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "target_path",
        description: "Executable path for spawn-based actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "target_exe",
        description: "Legacy alias for target_path (still accepted)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "payload",
        description: "PE payload bytes for hollow/transacted spawn methods",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "variant",
        description: "Pool Party variant 1-8",
        default: Some(InputFieldDefault::Integer(1)),
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "module",
        description: "Loaded module name for export_forward",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "export_name",
        description: "Export to hook (threadless)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "module_name",
        description: "Target module (stomping)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "shellcode_addr",
        description: "Pre-allocated shellcode address",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "inject",
        name: "timeout_ms",
        description: "Per-call cooperative timeout in milliseconds; long-running handlers check it at safe boundaries",
        default: Some(InputFieldDefault::Integer(30000)),
    },
];

const PAYLOAD_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "pid",
        description: "Process ID (for pe_parse/cleanup)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "module",
        description: "Module name (for pe_parse)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "function",
        description: "Function name (for iat_entry lookup)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "show",
        description: "PE info to show",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "obf_method",
        description: "Obfuscation method",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "payload",
        description: "Payload bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "payload_hex",
        description: "Hex-encoded payload",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "key",
        description: "Encryption key",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "strings",
        description: "Strings to obfuscate",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "thread_handle",
        description: "Thread handle returned by injection execution helpers (for wait/exit_code)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "addresses",
        description: "Allocated memory addresses to free during cleanup",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "thread_handles",
        description: "Thread handles to close during cleanup",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "params",
        description: "Parameters to serialize for payload invocation",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "format",
        description: "Serialization format (for serialize)",
        default: Some(InputFieldDefault::String("raw")),
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "tid",
        description: "Thread ID for legacy thread-oriented payload helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "handle",
        description: "Handle to close (for cleanup)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "address",
        description: "Memory address (for cleanup)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "size",
        description: "Size (for cleanup)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "rcx",
        description: "RCX register value",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "rdx",
        description: "RDX register value",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "r8",
        description: "R8 register value",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "payload",
        name: "r9",
        description: "R9 register value",
        default: None,
    },
];

const HOOK_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "pid",
        description: "Target process ID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "tid",
        description: "Thread ID (for hwbp)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "method",
        description: "Hook method (legacy, prefer specific action)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "module",
        description: "Imported module name for IAT hooks (e.g. kernel32.dll)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "function",
        description: "Imported function name for IAT hooks",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "target_function",
        description: "Explicit function name for hook_function(action)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "target_address",
        description: "Target function address (inline/hwbp/trampoline)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "address",
        description: "Function address to restore for action='restore'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "hook_address",
        description: "Detour function address",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "dll_path",
        description: "DLL path for action='winhook'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "hooks",
        description: "Transactional detour definitions with target_address and hook_address",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "iat_address",
        description: "IAT entry address returned by install_iat/payload pe_parse show='iat_entry' (for remove_iat)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "original_address",
        description: "Original function address to restore into the IAT entry (for remove_iat)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "dr_index",
        description: "Debug register 0-3 (hwbp)",
        default: Some(InputFieldDefault::Integer(0)),
    },
    ToolInputFieldDescriptor {
        tool: "hook",
        name: "original_bytes",
        description: "Original byte values to restore for action='restore'",
        default: None,
    },
];

const STEALTH_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "pid",
        description: "Target process ID. For encrypt_memory/decrypt_memory, omit pid or use the memoric server PID only; remote PID/address input is rejected.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "target_address",
        description: "Target address for CFG patching actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "target_function",
        description: "Target function address for return-address spoofing actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "function_name",
        description: "Function name for unhook_function",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "dll_path",
        description: "DLL path or name for module_stomp",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "shellcode",
        description: "Hex-encoded shellcode for module_stomp, or shellcode bytes for compatible sleep helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "module_name",
        description: "Module name to hide (sentinel)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "delay_ms",
        description: "Sleep duration",
        default: Some(InputFieldDefault::Integer(5000)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "intensity",
        description: "Mutation intensity for mutate_code (1-3)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "syscall_method",
        description: "Syscall method",
        default: Some(InputFieldDefault::String("indirect")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "address",
        description: "Memory address (integer or hex string). encrypt_memory/decrypt_memory require a committed writable local memoric process address.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "shellcode_address",
        description: "Shellcode address for callstack spoofing and syscall-assisted injection helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "size",
        description: "Size in bytes. Required for encrypt_memory and sleep memory actions.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "protect",
        description: "Protection level alias; accepts symbolic strings such as RWX or PAGE_EXECUTE_READWRITE, or numeric PAGE_* flags",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "bytes",
        description: "Bytes for syscall_write",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "target_exe",
        description: "For spoof_ppid or testsign_launch_hooked (exe path)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "parent_pid",
        description: "Fake parent PID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "key",
        description: "Encryption key hex",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "target",
        description: "Target file path (for timestomp)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "reference",
        description: "Reference file for timestomp (default: kernel32.dll)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "sysmon_method",
        description: "Sysmon blind method: etw_only or full (also unload driver)",
        default: Some(InputFieldDefault::String("etw_only")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "bcd_method",
        description: "BCD bypass method for testsign_hide_bcd",
        default: Some(InputFieldDefault::String("registry")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "exe_path",
        description: "Executable path for testsign_launch_hooked",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "args",
        description: "Command-line arguments for testsign_launch_hooked",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "work_dir",
        description: "Working directory for testsign_launch_hooked / testsign_launch_clean",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "ci_action",
        description: "CI callback/func patch action",
        default: Some(InputFieldDefault::String("patch")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "new_pte",
        description: "New PTE value for pte_rw write/restore",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "method",
        description: "Disable method (wdac_disable/wdac_restore/defender_disable)",
        default: Some(InputFieldDefault::String("auto")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "exclusion_type",
        description: "Exclusion type for defender_add_exclusion",
        default: Some(InputFieldDefault::String("path")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "disable_realtime",
        description: "Also disable realtime monitoring (defender_disable)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "disable_behavior",
        description: "Also disable behavior monitoring (defender_disable)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "disable_cloud",
        description: "Also disable cloud/spynet (defender_disable)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "value",
        description: "Exclusion value or MpCmdRun value",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "path",
        description: "Scan path for defender_mpcmdrun scan command",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "command",
        description: "MpCmdRun command name",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "callback_index",
        description: "Kernel callback array index for callback_masquerade",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "array_address",
        description: "Kernel callback array address for callback_masquerade",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "device_path",
        description: "Explicit BYOVD device path for callback_masquerade",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "ioctl_write_code",
        description: "BYOVD write IOCTL code for callback_masquerade",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "altitude",
        description: "Minifilter altitude returned by minifilter_pause and required by minifilter_resume",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "direction",
        description: "Firewall rule direction",
        default: Some(InputFieldDefault::String("in")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "protocol",
        description: "Firewall rule protocol (tcp, udp, any)",
        default: Some(InputFieldDefault::String("any")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "port",
        description: "Firewall rule local port (e.g. 4444 or 8000-9000)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "name",
        description: "Firewall rule display name (auto-generated stealth name if omitted)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "program",
        description: "Firewall rule program path",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "rule_action",
        description: "Firewall rule action",
        default: Some(InputFieldDefault::String("allow")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "profiles",
        description: "Firewall profiles to affect",
        default: Some(InputFieldDefault::String("all")),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "name_filter",
        description: "String filter for firewall rule names",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "interval_ms",
        description: "Sentinel heartbeat interval in ms",
        default: Some(InputFieldDefault::Integer(5000)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "patch_etw",
        description: "Re-patch ETW each cycle (sentinel)",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "patch_amsi",
        description: "Re-patch AMSI each cycle (sentinel)",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "unhook_ntdll",
        description: "Re-unhook ntdll each cycle (sentinel)",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "hide_module",
        description: "Re-hide module each cycle (sentinel)",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "watchdog",
        description: "Enable watchdog health check (sentinel)",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "self_destruct",
        description: "Auto self-destruct on detection (sentinel)",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "passes",
        description: "DoD wipe passes (sentinel_self_destruct)",
        default: Some(InputFieldDefault::Integer(7)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "delete_files",
        description: "Delete dropped files on self-destruct",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "stealth",
        name: "terminate",
        description: "Terminate process after self-destruct",
        default: Some(InputFieldDefault::Boolean(true)),
    },
];

const DETECT_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "detect",
        name: "pid",
        description: "Target PID (for hooks/suspend)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "detect",
        name: "function_name",
        description: "Function to inspect or resolve (for hook_function/syscall_resolve)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "detect",
        name: "function",
        description: "Legacy alias for function_name in syscall_resolve",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "detect",
        name: "target",
        description: "Substring match used by edr_suspend to suspend a specific process family",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "detect",
        name: "edr_only",
        description: "Suspend only known EDR processes when action='edr_suspend'",
        default: Some(InputFieldDefault::Boolean(true)),
    },
];

const PRIVILEGE_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "method",
        description: "Elevation method (for elevate: auto/fodhelper/eventvwr/computerdefaults/sdclt/disk_cleanup/mock_trusted_dir/request_uac/system, for potato: print_spoofer/god_potato/efs_potato)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "pid",
        description: "Legacy PID field. token_* actions primarily use target_pid; kernel/other tools may still use pid.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "target_pid",
        description: "Target process ID for token_steal/token_impersonate/token_scan",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "command",
        description: "Command to execute elevated/as impersonated user",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "detail",
        description: "Detailed output (for check)",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "link_path",
        description: "Symlink/junction/hardlink path (for symlink)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "target_path",
        description: "Symlink target (for symlink) or spawn target path depending on tool",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "type",
        description: "Filesystem link type for action='symlink'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "exploit",
        description: "Actually exploit (for service abuse, default: scan only)",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "privilege",
        name: "payload_path",
        description: "Payload path for service exploit",
        default: None,
    },
];

const SELF_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "self",
        name: "pid",
        description: "Target PID (for peb/heap/memory_diagnostics; defaults to current process for memory_diagnostics)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "address",
        description: "Memory address (for encrypt/decrypt/wipe)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "size",
        description: "Size in bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "region_limit",
        description: "Maximum memory regions returned by self(action='memory_diagnostics')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "suspicious_limit",
        description: "Maximum suspicious region summaries returned by memory_diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "module_limit",
        description: "Maximum modules returned by memory_diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "handle_limit",
        description: "Maximum handle samples returned by memory_diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "entropy_region_limit",
        description: "Maximum readable regions sampled for entropy by memory_diagnostics",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "entropy_sample_bytes",
        description: "Maximum bytes sampled per region for entropy; raw bytes are not returned",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "include_modules",
        description: "Include module summary in memory_diagnostics",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "include_handles",
        description: "Include non-invasive handle summary in memory_diagnostics",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "include_entropy",
        description: "Include bounded entropy sampling in memory_diagnostics",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "sub_action",
        description: "State sub-action for self(action='state')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "task_id",
        description: "Task ID scope for state cleanup/rollback views",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "chain_id",
        description: "Operation history filter by chain ID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "recent_task_limit",
        description: "Maximum recent task summaries included by self(action='diagnostics')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "output_dir",
        description: "Optional directory for self(action='diagnostics') operator-safe bundle artifact",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "tool",
        description: "Operation history filter by tool",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "status",
        description: "Operation history filter by result status",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "audit_path",
        description: "Optional audit JSONL path override for self(action='state', sub_action='history'|'mutations'|'rollback'|'replay'|'timeline')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "request_id",
        description: "Operation history filter by request ID",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "correlation_id",
        description: "Timeline filter by correlation ID across request, task, audit, worker IPC, and artifacts",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "artifact_uri",
        description: "Timeline filter by memoric artifact resource URI",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "since",
        description: "Operation history lower timestamp bound (ISO-8601 string)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "until",
        description: "Operation history upper timestamp bound (ISO-8601 string)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "offset",
        description: "Operation history pagination offset",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "limit",
        description: "Operation history page size",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "error",
        description: "Error text or payload for explain_error",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "message",
        description: "Alternative error message field for explain_error or next_steps",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "code",
        description: "Stable tool error code for self(action='next_steps')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "result",
        description: "Failed tool result envelope for self(action='next_steps')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "doctor",
        description: "Doctor output for self(action='next_steps')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "baseline",
        description: "Saved capability/doctor/current JSON baseline for self(action='capability_diff')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "baseline_path",
        description: "Path to a saved capability/doctor/current JSON baseline for self(action='capability_diff')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "self",
        name: "include_scan",
        description: "Run optional bytes scan session in self(action='test')",
        default: Some(InputFieldDefault::Boolean(false)),
    },
];

const KERNEL_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "driver_path",
        description: "Path to .sys file",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "device_path",
        description: "Explicit BYOVD device path (e.g. \\\\.\\RTCore64). If present, hybrid actions use BYOVD instead of memoric.sys.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "read_ioctl",
        description: "BYOVD read IOCTL code for pte_modify/vad_hide or hybrid kernel helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "write_ioctl",
        description: "BYOVD write IOCTL code for pte_modify/vad_hide or hybrid kernel helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "ioctl_read_code",
        description: "BYOVD read IOCTL code for legacy callback enumeration helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "ioctl_write_code",
        description: "BYOVD write IOCTL code for legacy callback removal helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "ioctl_code",
        description: "Explicit IOCTL code for kernel read/write device operations",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "input_struct",
        description: "Raw input buffer bytes for custom BYOVD IOCTL layouts",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "service_name",
        description: "Service name",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "address",
        description: "Kernel physical/virtual address. Integer or hex string like '0xFFFFF80000000000'.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cr3",
        description: "Target process CR3 for pte_modify BYOVD page table walks",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "writable",
        description: "Desired writable bit for pte_modify",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "executable",
        description: "Desired executable bit for pte_modify",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "size",
        description: "Size in bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "bytes",
        description: "Bytes to write (canonical for kernel write / physical_write)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "data",
        description: "Legacy alias for bytes on kernel(action='write')",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "physical",
        description: "Use physical addressing",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "pid",
        description: "Target PID (for dkom_hide)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "callback_index",
        description: "Callback array index",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "array_address",
        description: "Kernel callback array address for callback enumeration/removal helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "entry_address",
        description: "Kernel callback entry address returned by callback enumeration helpers",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "object_type_address",
        description: "Optional OBJECT_TYPE pointer address override for object_callback_enum",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "callback_list_offset",
        description: "Optional OBJECT_TYPE.CallbackList offset override for object_callback_enum",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "list_head_address",
        description: "Optional CmpCallBackListHead address override for registry_callback_enum",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "callback_type",
        description: "Callback type",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "altitude",
        description: "Minifilter altitude",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "max_entries",
        description: "Max entries for enum operations",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "module_name",
        description: "Kernel module name for module_hide",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "driver_name",
        description: "Driver module name for hiding (e.g. memoric.sys)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "thread_id",
        description: "Thread ID for thread_hide",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "patch_type",
        description: "Kernel patch target",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "enable",
        description: "true=restore, false=patch(disable)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "index",
        description: "Callback array index",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "callback_address",
        description: "Callback address for verification/removal (hex string or integer)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "shellcode_address",
        description: "VA of mapped shellcode in target (hex string or integer)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "shellcode_size",
        description: "Size of shellcode in bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "strip_type",
        description: "Handle strip type",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "access_mask",
        description: "Access mask to strip (0 = close handle)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "key_path",
        description: "Registry key path (NT format, e.g. \\Registry\\Machine\\SOFTWARE\\...)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "reg_action",
        description: "Registry protection action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "reg_flags",
        description: "Registry protection flags",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "notify_type",
        description: "Notification callback type",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "notify_action",
        description: "Notification action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "max_events",
        description: "Max events to return from ring buffer",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "base_address",
        description: "Base address for driver_pe_dump/driver_process_dump (hex string or integer; 0 = auto/full range)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "max_dump_size",
        description: "Max PE dump size in bytes",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "output_path",
        description: "Optional artifact output path for driver_pe_dump, driver_process_dump, and other large kernel dump results",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "debug_action",
        description: "Anti-debug action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "timer_index",
        description: "DPC timer slot (0-7)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "delay_ms",
        description: "DPC delay in milliseconds",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "dpc_operation",
        description: "DPC operation type",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "dpc_action",
        description: "DPC action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "port",
        description: "Port number to hide",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "protocol",
        description: "Port protocol",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "port_action",
        description: "Port hide action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "source_pid",
        description: "Source PID for token duplication (0 = System)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "token_action",
        description: "Token dup action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "protect_pid",
        description: "PID to protect via object callback",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "strip_access",
        description: "Access bits to strip from handle opens",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "obj_action",
        description: "Object hook action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "testsign_action",
        description: "TestSign action (for driver_testsign_hide)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "hook_action",
        description: "Global hook action (for driver_global_hook)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "hook_type",
        description: "Global hook type for driver_global_hook",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "hook_index",
        description: "Hook slot index for driver_global_hook",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "target_module",
        description: "Kernel module name for global hook target (e.g. ntoskrnl.exe)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "target_function",
        description: "Function name for global hook (e.g. NtQuerySystemInformation)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "replacement_addr",
        description: "Replacement function address for global hook",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "inject_action",
        description: "Auto-inject action (for driver_auto_inject)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "inject_flags",
        description: "Auto-inject flags",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "process_filter",
        description: "Process name filter for auto-inject (empty=all)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "infhook_action",
        description: "Infinity hook action (for driver_infinity_hook)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "syscall_number",
        description: "Syscall number to intercept (infinity hook)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "handler_address",
        description: "Custom handler address for infinity hook",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "ci_action",
        description: "CI callback/func patch action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "msr_index",
        description: "MSR register index (e.g. 0xC0000082 for IA32_LSTAR)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "msr_value",
        description: "Value to write for driver_msr_rw(write)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "pte_action",
        description: "Action for driver_pte_rw",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "ppl_action",
        description: "Action for driver_ppl_bypass",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "protection_level",
        description: "Target PPL level for driver_ppl_bypass(set)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cr_action",
        description: "Action for driver_cr_rw",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cr_index",
        description: "Control register index for driver_cr_rw",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "value",
        description: "Generic integer value used by driver_cr_rw and similar actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "idt_action",
        description: "Action for driver_idt_rw",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "vector",
        description: "Interrupt vector for driver_idt_rw",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "new_handler",
        description: "Replacement handler address for driver_idt_rw(write)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "new_dpl",
        description: "New descriptor privilege level for driver_idt_rw(write)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "unloaded_action",
        description: "Action for driver_unloaded_drv_clear",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "target_pid",
        description: "Target PID for token swap or other driver target actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "swap_action",
        description: "Action for driver_token_swap",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "protect_action",
        description: "Action for driver_process_protect",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "signer_type",
        description: "Signer type byte for driver_process_protect(set)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "signer_audit",
        description: "Signer audit byte for driver_process_protect(set)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "signer_level",
        description: "Signer level byte for driver_process_protect(set)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "msr_action",
        description: "MSR operation",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cloak_action",
        description: "Driver cloak action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "kill_method",
        description: "Force kill method",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "exit_code",
        description: "Process exit code (default: 1)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "file_path",
        description: "File path for force_delete (NT format: \\??\\C:\\...)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "thread_start",
        description: "Kernel address for system thread start routine",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "thread_context",
        description: "Context parameter for system thread",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "thread_action",
        description: "System thread action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "exec_action",
        description: "Kernel exec action",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "pool_tag",
        description: "Kernel pool tag filter for driver_memory_pool. Integer raw tag or 4-char ASCII string like 'Proc'.",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "flags",
        description: "Generic driver flags field used by driver_process_dump and similar actions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "max_size",
        description: "Maximum dump size for driver_process_dump",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "keylog_action",
        description: "Action for driver_keylogger",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "max_keys",
        description: "Maximum key events to read for driver_keylogger",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "hide_type",
        description: "Registry hide type for driver_reg_hide",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "value_name",
        description: "Registry value name for driver_reg_hide",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "lock_action",
        description: "Action for driver_file_lock",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "protect_flags",
        description: "Protection flags for driver_file_lock",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "allowed_pid",
        description: "PID exempted from file lock restrictions",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "etw_action",
        description: "Action for driver_etw_blind",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "provider_guid",
        description: "Provider GUID for driver_etw_blind",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "spoof_action",
        description: "Action for driver_eprocess_spoof",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "new_image_name",
        description: "New image name for driver_eprocess_spoof(image_name)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "new_command_line",
        description: "New command line for driver_eprocess_spoof(command_line)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "new_parent_pid",
        description: "New parent PID for driver_eprocess_spoof(pid)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "log_action",
        description: "Action for driver_event_log_clear",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "log_name",
        description: "Optional event log name for driver_event_log_clear",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cred_action",
        description: "Action for driver_cred_dump",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "imp_action",
        description: "Action for driver_impersonate",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "legit_path",
        description: "Legitimate driver path for driver_impersonate",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cb_action",
        description: "Action for driver_callback_nuke",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "cb_type",
        description: "Callback family for driver_callback_nuke",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "frame_id",
        description: "Filter manager frame ID for driver_minifilter_detach(detach)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "mf_action",
        description: "Action for driver_minifilter_detach",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "filter_name",
        description: "Filter name for driver_minifilter_detach",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "apc_action",
        description: "Action for driver_kernel_apc",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "tid",
        description: "Thread ID for driver_kernel_apc legacy path",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "shellcode_addr",
        description: "Shellcode address for driver_kernel_apc",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "dll_path",
        description: "DLL path for driver_kernel_apc(dll)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "wfp_action",
        description: "Action for driver_wfp_remove",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "callout_id",
        description: "WFP callout ID for driver_wfp_remove(remove)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "provider_name",
        description: "WFP provider name for driver_wfp_remove",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "shellcode_bytes",
        description: "Shellcode bytes for kernel_exec",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "kernel",
        name: "alloc_address",
        description: "Address of previously allocated kernel pool",
        default: None,
    },
];

const ORCHESTRATE_INPUT_FIELDS: &[ToolInputFieldDescriptor] = &[
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "pid",
        description: "Target process ID (for execute)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "shellcode",
        description: "Hex-encoded shellcode to inject (for execute)",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "dry_run",
        description: "If true, plan but don't execute steps",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "limit",
        description: "Maximum items returned per paginated plan/execute result section",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "offset",
        description: "Pagination offset for plan/execute result sections when cursor is omitted",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "cursor",
        description: "Opaque cursor returned in pagination.nextCursor; pass unchanged to continue plan/execute result pagination",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "output_path",
        description: "Optional artifact output path for full plan/execute results; large static plans auto-export when omitted",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "allow_live_execution",
        description: "Required with dry_run=false before orchestrate executes state-changing steps",
        default: Some(InputFieldDefault::Boolean(false)),
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "chain_id",
        description: "Persisted chain checkpoint ID for status/resume/cancel/cleanup",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "skip_completed_steps",
        description: "Resume hint: skip checkpoint-completed step IDs when replaying the original authorized chain request",
        default: Some(InputFieldDefault::Boolean(true)),
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "template",
        description: "Registered static plan template for orchestrate(action='plan') when steps are omitted",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "benign_pid",
        description: "Explicit PID from examples/benign_test_target.rs for template='lab_validation'",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "marker_address",
        description: "Marker address printed by the benign test target for optional read-only validation",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "marker_len",
        description: "Marker byte length for lab_validation marker read",
        default: Some(InputFieldDefault::Integer(28)),
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "counter_address",
        description: "Counter address printed by the benign test target for dry-run write preview only",
        default: None,
    },
    ToolInputFieldDescriptor {
        tool: "orchestrate",
        name: "steps",
        description: "Custom chain steps (for plan action)",
        default: None,
    },
];

const TOOL_INPUT_FIELDS: &[&[ToolInputFieldDescriptor]] = &[
    TARGET_INPUT_FIELDS,
    MEMORY_INPUT_FIELDS,
    INJECT_INPUT_FIELDS,
    PAYLOAD_INPUT_FIELDS,
    HOOK_INPUT_FIELDS,
    STEALTH_INPUT_FIELDS,
    DETECT_INPUT_FIELDS,
    PRIVILEGE_INPUT_FIELDS,
    KERNEL_INPUT_FIELDS,
    SELF_INPUT_FIELDS,
    ORCHESTRATE_INPUT_FIELDS,
];

fn tool_input_fields(tool: &str) -> Vec<ToolInputFieldDescriptor> {
    TOOL_INPUT_FIELDS
        .iter()
        .flat_map(|fields| fields.iter().copied())
        .filter(|field| field.applies_to(tool))
        .collect()
}

const PARAMETER_ALIASES: &[ParameterAliasDescriptor] = &[
    ParameterAliasDescriptor {
        tool: "target",
        action: "module_base",
        canonical: "module_name",
        alias: "module",
    },
    ParameterAliasDescriptor {
        tool: "target",
        action: "string_read",
        canonical: "address",
        alias: "base_address",
    },
    ParameterAliasDescriptor {
        tool: "target",
        action: "string_write",
        canonical: "address",
        alias: "base_address",
    },
    ParameterAliasDescriptor {
        tool: "target",
        action: "mem_find",
        canonical: "address",
        alias: "base_address",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "*",
        canonical: "address",
        alias: "base_address",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "*",
        canonical: "size",
        alias: "length",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "*",
        canonical: "bytes",
        alias: "data",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "alloc",
        canonical: "protection",
        alias: "protect",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "protect",
        canonical: "protection",
        alias: "protect",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "scan",
        canonical: "signature",
        alias: "pattern_bytes",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "scan_new",
        canonical: "signature",
        alias: "pattern_bytes",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "typed_read",
        canonical: "type",
        alias: "value_type",
    },
    ParameterAliasDescriptor {
        tool: "memory",
        action: "typed_write",
        canonical: "type",
        alias: "value_type",
    },
    ParameterAliasDescriptor {
        tool: "payload",
        action: "pe_parse",
        canonical: "address",
        alias: "base_address",
    },
    ParameterAliasDescriptor {
        tool: "payload",
        action: "pe_parse",
        canonical: "module",
        alias: "module_name",
    },
    ParameterAliasDescriptor {
        tool: "payload",
        action: "obfuscate",
        canonical: "payload",
        alias: "payload_hex",
    },
    ParameterAliasDescriptor {
        tool: "hook",
        action: "*",
        canonical: "function",
        alias: "target_function",
    },
    ParameterAliasDescriptor {
        tool: "hook",
        action: "*",
        canonical: "iat_address",
        alias: "iat_entry_address",
    },
    ParameterAliasDescriptor {
        tool: "hook",
        action: "*",
        canonical: "original_address",
        alias: "original_value",
    },
    ParameterAliasDescriptor {
        tool: "hook",
        action: "*",
        canonical: "hook_address",
        alias: "detour_address",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "*",
        canonical: "address",
        alias: "base_address",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "*",
        canonical: "size",
        alias: "length",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "*",
        canonical: "shellcode_address",
        alias: "shellcode_addr",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "syscall_alloc",
        canonical: "protection",
        alias: "protect",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "syscall_protect",
        canonical: "protection",
        alias: "protect",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "sleep_ekko",
        canonical: "sleep_ms",
        alias: "delay_ms",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "sleep_foliage",
        canonical: "sleep_ms",
        alias: "delay_ms",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "sleep_gargoyle",
        canonical: "sleep_ms",
        alias: "delay_ms",
    },
    ParameterAliasDescriptor {
        tool: "stealth",
        action: "sleep_death",
        canonical: "sleep_ms",
        alias: "delay_ms",
    },
    ParameterAliasDescriptor {
        tool: "inject",
        action: "*",
        canonical: "start_address",
        alias: "address",
    },
    ParameterAliasDescriptor {
        tool: "inject",
        action: "*",
        canonical: "shellcode_addr",
        alias: "shellcode_address",
    },
    ParameterAliasDescriptor {
        tool: "inject",
        action: "*",
        canonical: "target_path",
        alias: "target_exe",
    },
    ParameterAliasDescriptor {
        tool: "detect",
        action: "syscall_resolve",
        canonical: "function_name",
        alias: "function",
    },
    ParameterAliasDescriptor {
        tool: "privilege",
        action: "token_steal",
        canonical: "target_pid",
        alias: "pid",
    },
    ParameterAliasDescriptor {
        tool: "privilege",
        action: "token_impersonate",
        canonical: "target_pid",
        alias: "pid",
    },
    ParameterAliasDescriptor {
        tool: "privilege",
        action: "token_scan",
        canonical: "target_pid",
        alias: "pid",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "write",
        canonical: "bytes",
        alias: "data",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "physical_write",
        canonical: "bytes",
        alias: "data",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "ppl_bypass",
        canonical: "pid",
        alias: "target_pid",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "dkom_hide",
        canonical: "pid",
        alias: "target_pid",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "token_escalate",
        canonical: "pid",
        alias: "target_pid",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_notify_routine",
        canonical: "notify_type",
        alias: "callback_type",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_notify_routine",
        canonical: "notify_action",
        alias: "callback_action",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_reg_protect",
        canonical: "reg_action",
        alias: "registry_action",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_reg_protect",
        canonical: "reg_flags",
        alias: "registry_flags",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        canonical: "protect_pid",
        alias: "target_pid",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        canonical: "protect_pid",
        alias: "pid",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        canonical: "strip_access",
        alias: "access_mask",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        canonical: "obj_action",
        alias: "object_action",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_port_hide",
        canonical: "port_action",
        alias: "hide_action",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_port_hide",
        canonical: "protocol",
        alias: "proto",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        canonical: "target_module",
        alias: "module",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        canonical: "target_function",
        alias: "function",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        canonical: "replacement_addr",
        alias: "hook_address",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_auto_inject",
        canonical: "inject_action",
        alias: "auto_action",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_auto_inject",
        canonical: "process_filter",
        alias: "target_process",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_wfp_remove",
        canonical: "provider_name",
        alias: "provider",
    },
    ParameterAliasDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        canonical: "tid",
        alias: "thread_id",
    },
];

pub fn all_parameter_aliases() -> &'static [ParameterAliasDescriptor] {
    PARAMETER_ALIASES
}

pub fn parameter_aliases(tool: &str, action: &str) -> Vec<ParameterAliasDescriptor> {
    all_parameter_aliases()
        .iter()
        .copied()
        .filter(|alias| alias.applies_to(tool, action))
        .collect()
}

const OPTIONAL_PARAMETERS: &[OptionalParameterDescriptor] = &[
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "read",
        parameter: "device_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "read",
        parameter: "ioctl_code",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "read",
        parameter: "size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "read",
        parameter: "input_struct",
        parser: "bytes",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "read",
        parameter: "physical",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "write",
        parameter: "input_struct",
        parser: "bytes",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "physical_read",
        parameter: "size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "pte_modify",
        parameter: "writable",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "pte_modify",
        parameter: "executable",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "object_callback_enum",
        parameter: "object_type_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "object_callback_enum",
        parameter: "callback_list_offset",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "registry_callback_enum",
        parameter: "list_head_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_enum_process",
        parameter: "max_entries",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_enum",
        parameter: "max_entries",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_remove",
        parameter: "callback_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_patch_kernel",
        parameter: "enable",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_apc_inject",
        parameter: "thread_id",
        parser: "tid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_handle_strip",
        parameter: "access_mask",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_protect",
        parameter: "key_path",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_notify_routine",
        parameter: "max_events",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_pe_dump",
        parameter: "base_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_pe_dump",
        parameter: "max_dump_size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_pe_dump",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_dpc_timer",
        parameter: "timer_index",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_dpc_timer",
        parameter: "delay_ms",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_dpc_timer",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_port_hide",
        parameter: "port",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_token_dup",
        parameter: "source_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        parameter: "protect_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        parameter: "strip_access",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_memory_pool",
        parameter: "pool_tag",
        parser: "pool_tag",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_memory_pool",
        parameter: "max_entries",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_dump",
        parameter: "flags",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_dump",
        parameter: "base_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_dump",
        parameter: "max_size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_dump",
        parameter: "max_dump_size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_dump",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        parameter: "hook_index",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        parameter: "target_module",
        parser: "module_name",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        parameter: "target_function",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        parameter: "replacement_addr",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_auto_inject",
        parameter: "process_filter",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_infinity_hook",
        parameter: "syscall_number",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_infinity_hook",
        parameter: "handler_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_pte_rw",
        parameter: "new_pte",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_msr_rw",
        parameter: "msr_index",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_msr_rw",
        parameter: "msr_value",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_cloak",
        parameter: "driver_name",
        parser: "module_name",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_force_kill",
        parameter: "exit_code",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_system_thread",
        parameter: "thread_start",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_system_thread",
        parameter: "thread_context",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_exec",
        parameter: "shellcode_bytes",
        parser: "bytes",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_exec",
        parameter: "alloc_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_ppl_bypass",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_ppl_bypass",
        parameter: "protection_level",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_cr_rw",
        parameter: "cr_index",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_cr_rw",
        parameter: "value",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_idt_rw",
        parameter: "vector",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_idt_rw",
        parameter: "new_handler",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_idt_rw",
        parameter: "new_dpl",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_unloaded_drv_clear",
        parameter: "driver_name",
        parser: "module_name",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_token_swap",
        parameter: "target_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_token_swap",
        parameter: "source_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_protect",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_protect",
        parameter: "signer_type",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_protect",
        parameter: "signer_audit",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_process_protect",
        parameter: "signer_level",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_keylogger",
        parameter: "max_keys",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_hide",
        parameter: "hide_type",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_hide",
        parameter: "key_path",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_hide",
        parameter: "value_name",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_file_lock",
        parameter: "file_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_file_lock",
        parameter: "protect_flags",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_file_lock",
        parameter: "allowed_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_etw_blind",
        parameter: "provider_guid",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        parameter: "new_image_name",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        parameter: "new_command_line",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        parameter: "new_parent_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_event_log_clear",
        parameter: "log_name",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_cred_dump",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_cred_dump",
        parameter: "address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_cred_dump",
        parameter: "size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_impersonate",
        parameter: "target_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_impersonate",
        parameter: "legit_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_nuke",
        parameter: "index",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_minifilter_detach",
        parameter: "filter_name",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_minifilter_detach",
        parameter: "frame_id",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        parameter: "tid",
        parser: "tid_u32",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        parameter: "shellcode_size",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        parameter: "shellcode_addr",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        parameter: "dll_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_wfp_remove",
        parameter: "callout_id",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "kernel",
        action: "driver_wfp_remove",
        parameter: "provider_name",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "thread_context",
        parameter: "suspend",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "cred_dump",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "sam_dump",
        parameter: "output_dir",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "sam_dump",
        parameter: "dump_sam",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "sam_dump",
        parameter: "dump_security",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "kerberos_tickets",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "kerberos_tickets",
        parameter: "all_sessions",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "ps_list",
        parameter: "include_system",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "handles",
        parameter: "type_filter",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "string_read",
        parameter: "max_len",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "string_write",
        parameter: "text",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "target",
        action: "windows",
        parameter: "wait_ms",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "read",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "read",
        parameter: "region_cache_refresh",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "read",
        parameter: "region_cache_clear",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "typed_read",
        parameter: "allow_unaligned",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "write",
        parameter: "bypass_protect",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "typed_write",
        parameter: "allow_unaligned",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "values",
        parser: "number_array",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "delta",
        parser: "number",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "min",
        parser: "number",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "max",
        parser: "number",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "case_insensitive",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "exclude_mapped",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "exclude_image",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "region_cache_refresh",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "region_cache_clear",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan_new",
        parameter: "region_cache_refresh",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan_new",
        parameter: "region_cache_clear",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan_list",
        parameter: "cursor",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan_list",
        parameter: "summary_only",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "scan_list",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "include_modules",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "include_handles",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "include_entropy",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "payload",
        action: "pe_parse",
        parameter: "function",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "patch_cig",
        parameter: "target_exe",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "patch_cig",
        parameter: "disable_acg",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "patch_cig",
        parameter: "disable_cig",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "spoof_ppid",
        parameter: "parent_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "spoof_ppid",
        parameter: "command",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "encrypt_memory",
        parameter: "key",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "decrypt_memory",
        parameter: "key",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "timestomp",
        parameter: "reference",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_hooked",
        parameter: "exe_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_hooked",
        parameter: "target_exe",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_hooked",
        parameter: "args",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_hooked",
        parameter: "work_dir",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_clean",
        parameter: "exe_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_clean",
        parameter: "target_exe",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_clean",
        parameter: "args",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_launch_clean",
        parameter: "work_dir",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "testsign_pte_rw",
        parameter: "new_pte",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "defender_disable",
        parameter: "disable_realtime",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "defender_disable",
        parameter: "disable_behavior",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "defender_disable",
        parameter: "disable_cloud",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "defender_mpcmdrun",
        parameter: "path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "firewall_add_rule",
        parameter: "protocol",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "firewall_add_rule",
        parameter: "port",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "firewall_add_rule",
        parameter: "program",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "firewall_list_rules",
        parameter: "name_filter",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "patch_etw",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "patch_amsi",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "unhook_ntdll",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "hide_module",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "watchdog",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "self_destruct",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_self_destruct",
        parameter: "delete_files",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "stealth",
        action: "sentinel_self_destruct",
        parameter: "terminate",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "detect",
        action: "*",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "detect",
        action: "edr_suspend",
        parameter: "target",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "detect",
        action: "edr_suspend",
        parameter: "edr_only",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "privilege",
        action: "check",
        parameter: "detail",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "privilege",
        action: "service_unquoted",
        parameter: "exploit",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "privilege",
        action: "service_unquoted",
        parameter: "payload_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "privilege",
        action: "service_weak_perms",
        parameter: "exploit",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "include_modules",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "include_handles",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "include_entropy",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "test",
        parameter: "include_scan",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "task_id",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "chain_id",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "tool",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "status",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "audit_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "request_id",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "correlation_id",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "artifact_uri",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "since",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "until",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "diagnostics",
        parameter: "output_dir",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "explain_error",
        parameter: "error",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "explain_error",
        parameter: "message",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "next_steps",
        parameter: "error",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "next_steps",
        parameter: "message",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "next_steps",
        parameter: "code",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "next_steps",
        parameter: "result",
        parser: "object",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "next_steps",
        parameter: "doctor",
        parser: "object",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "capability_diff",
        parameter: "baseline",
        parser: "object",
    },
    OptionalParameterDescriptor {
        tool: "self",
        action: "capability_diff",
        parameter: "baseline_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "execute",
        parameter: "pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "execute",
        parameter: "shellcode",
        parser: "bytes",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "execute",
        parameter: "dry_run",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "execute",
        parameter: "allow_live_execution",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "*",
        parameter: "offset",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "*",
        parameter: "cursor",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "*",
        parameter: "output_path",
        parser: "path",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "*",
        parameter: "chain_id",
        parser: "string",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "execute",
        parameter: "skip_completed_steps",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "resume",
        parameter: "skip_completed_steps",
        parser: "boolean",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "benign_pid",
        parser: "pid_u32",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "marker_address",
        parser: "address_u64",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "marker_len",
        parser: "u64",
    },
    OptionalParameterDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "counter_address",
        parser: "address_u64",
    },
];

pub fn all_optional_parameters() -> &'static [OptionalParameterDescriptor] {
    OPTIONAL_PARAMETERS
}

pub fn optional_parameters(tool: &str, action: &str) -> Vec<OptionalParameterDescriptor> {
    all_optional_parameters()
        .iter()
        .copied()
        .filter(|parameter| parameter.applies_to(tool, action))
        .collect()
}

const REQUIRED_PARAMETERS: &[RequiredParameterDescriptor] = &[
    RequiredParameterDescriptor {
        tool: "target",
        action: "module_base",
        parameters: &["pid", "module_name"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "ps_find",
        parameters: &["name"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "modules",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "threads_list",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "thread_suspend",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "thread_resume",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "thread_context",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "handles",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "env",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "cmdline",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "windows",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "peb",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "mem_find",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "string_read",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "string_write",
        parameters: &["pid", "address", "text"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "callstack",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "target",
        action: "heap",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "read",
        parameters: &["pid", "address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "typed_read",
        parameters: &["pid", "address", "type"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "write",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "typed_write",
        parameters: &["pid", "address", "type", "value"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "write_string",
        parameters: &["pid", "address", "text"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "query",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "query_find",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "alloc",
        parameters: &["pid", "size"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "free",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "protect",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "scan_new",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "scan_next",
        parameters: &["session_id", "filter"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "scan_undo",
        parameters: &["session_id"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "scan_reset",
        parameters: &["session_id"],
    },
    RequiredParameterDescriptor {
        tool: "memory",
        action: "scan_freeze",
        parameters: &["session_id", "value"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "shellcode",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "dll",
        parameters: &["pid", "dll_path"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "hijack_enum",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "hijack_backup",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "hijack_redirect",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "hijack_restore",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "hijack_wait",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "create_remote_thread",
        parameters: &["pid", "start_address"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "nt_create_thread",
        parameters: &["pid", "start_address"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "fiber",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "threadpool",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "stack_bomb",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "pool_party_worker",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "pool_party_work",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "pool_party_direct",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "pool_party_timer",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "export_forward",
        parameters: &["pid", "module", "export_name", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "phantom_hollow",
        parameters: &["pid", "dll_path"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "transacted_hollow",
        parameters: &["pid", "dll_path"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "wow64_detect",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "inject",
        action: "spawn",
        parameters: &["target_path"],
    },
    RequiredParameterDescriptor {
        tool: "payload",
        action: "pe_parse",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "payload",
        action: "obfuscate",
        parameters: &["obf_method"],
    },
    RequiredParameterDescriptor {
        tool: "payload",
        action: "wait",
        parameters: &["thread_handle"],
    },
    RequiredParameterDescriptor {
        tool: "payload",
        action: "exit_code",
        parameters: &["thread_handle"],
    },
    RequiredParameterDescriptor {
        tool: "payload",
        action: "cleanup",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "payload",
        action: "serialize",
        parameters: &["params"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "install_hwbp",
        parameters: &["tid", "target_address"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "install_iat",
        parameters: &["pid", "module", "function", "hook_address"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "remove",
        parameters: &["pid", "iat_address", "original_address"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "remove_iat",
        parameters: &["pid", "iat_address", "original_address"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "trampoline",
        parameters: &["pid", "target_address"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "remove_hwbp",
        parameters: &["tid"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "detour",
        parameters: &["pid", "hooks"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "restore",
        parameters: &["pid", "address", "original_bytes"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "winhook",
        parameters: &["pid", "dll_path"],
    },
    RequiredParameterDescriptor {
        tool: "hook",
        action: "hwbp_syscall",
        parameters: &["function"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "patch_cfg",
        parameters: &["target_address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "hide_module",
        parameters: &["pid", "module_name"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "sleep_ekko",
        parameters: &["address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "sleep_foliage",
        parameters: &["address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "sleep_death",
        parameters: &["address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "spoof_callstack",
        parameters: &["shellcode_address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "spoof_return",
        parameters: &["target_function"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "deep_stack_spoof",
        parameters: &["target_function"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "encrypt_memory",
        parameters: &["address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "decrypt_memory",
        parameters: &["address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "mutate_code",
        parameters: &["address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "timestomp",
        parameters: &["target"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "unhook_function",
        parameters: &["function_name"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "module_stomp",
        parameters: &["dll_path", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_write",
        parameters: &["pid", "address", "bytes"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_alloc",
        parameters: &["pid", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_protect",
        parameters: &["pid", "address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_thread",
        parameters: &["pid", "start_address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_open",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_read",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_query",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_close",
        parameters: &["handle"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_free",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_stealth_read",
        parameters: &["pid", "address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "syscall_inject",
        parameters: &["pid", "shellcode"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "create_suspended",
        parameters: &["shellcode_address"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "defender_add_exclusion",
        parameters: &["value"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "defender_mpcmdrun",
        parameters: &["command"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "firewall_remove_rule",
        parameters: &["name"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "callback_masquerade",
        parameters: &[
            "callback_index",
            "array_address",
            "device_path",
            "ioctl_write_code",
        ],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "minifilter_pause",
        parameters: &["name"],
    },
    RequiredParameterDescriptor {
        tool: "stealth",
        action: "minifilter_resume",
        parameters: &["name", "altitude"],
    },
    RequiredParameterDescriptor {
        tool: "detect",
        action: "hook_function",
        parameters: &["function_name"],
    },
    RequiredParameterDescriptor {
        tool: "detect",
        action: "syscall_resolve",
        parameters: &["function_name"],
    },
    RequiredParameterDescriptor {
        tool: "privilege",
        action: "token_steal",
        parameters: &["target_pid"],
    },
    RequiredParameterDescriptor {
        tool: "privilege",
        action: "token_impersonate",
        parameters: &["target_pid"],
    },
    RequiredParameterDescriptor {
        tool: "privilege",
        action: "token_scan",
        parameters: &["target_pid"],
    },
    RequiredParameterDescriptor {
        tool: "privilege",
        action: "potato",
        parameters: &["command"],
    },
    RequiredParameterDescriptor {
        tool: "privilege",
        action: "symlink",
        parameters: &["link_path", "target_path"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "physical_read",
        parameters: &["address"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "read",
        parameters: &["address"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "write",
        parameters: &["device_path", "ioctl_code", "address", "bytes"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "physical_write",
        parameters: &["address", "bytes"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "sniff_start",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_load",
        parameters: &["driver_path", "service_name"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_unload",
        parameters: &["service_name"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "pte_modify",
        parameters: &["device_path", "read_ioctl", "write_ioctl", "address", "cr3"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "vad_hide",
        parameters: &["pid", "address", "device_path", "read_ioctl", "write_ioctl"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "enum_callbacks",
        parameters: &["device_path", "ioctl_read_code"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "remove_callback",
        parameters: &[
            "device_path",
            "ioctl_write_code",
            "callback_index",
            "array_address",
        ],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "object_callback_enum",
        parameters: &["device_path", "read_ioctl"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "object_callback_remove",
        parameters: &["device_path", "write_ioctl", "entry_address"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "registry_callback_enum",
        parameters: &["device_path", "read_ioctl"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "registry_callback_remove",
        parameters: &["device_path", "write_ioctl", "entry_address"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "dse_bypass",
        parameters: &["device_path", "read_ioctl", "write_ioctl"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "ppl_bypass",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "dkom_hide",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "token_escalate",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "dse_map_driver",
        parameters: &["driver_path"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "module_hide",
        parameters: &["module_name"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "minifilter_remove",
        parameters: &["filter_name"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_module_hide",
        parameters: &["driver_name"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_thread_hide",
        parameters: &["thread_id", "pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_remove",
        parameters: &["callback_type", "index"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_patch_kernel",
        parameters: &["patch_type"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_apc_inject",
        parameters: &["pid", "shellcode_address", "shellcode_size"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_handle_strip",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_notify_routine",
        parameters: &["notify_action"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_pe_dump",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_set_debug_port",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_token_dup",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_process_dump",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_pte_rw",
        parameters: &["address"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_force_kill",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_force_delete",
        parameters: &["file_path"],
    },
    RequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "self",
        action: "peb",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "self",
        action: "heap",
        parameters: &["pid"],
    },
    RequiredParameterDescriptor {
        tool: "self",
        action: "protect_encrypt",
        parameters: &["address", "size"],
    },
    RequiredParameterDescriptor {
        tool: "self",
        action: "protect_decrypt",
        parameters: &["address"],
    },
    RequiredParameterDescriptor {
        tool: "self",
        action: "protect_wipe",
        parameters: &["address", "size"],
    },
];

pub fn all_required_parameters() -> &'static [RequiredParameterDescriptor] {
    REQUIRED_PARAMETERS
}

pub fn required_parameters(tool: &str, action: &str) -> &'static [&'static str] {
    all_required_parameters()
        .iter()
        .find(|descriptor| descriptor.applies_to(tool, action))
        .map(|descriptor| descriptor.parameters)
        .unwrap_or(&[])
}

pub fn required_parameter_hints(tool: &str, action: &str) -> Vec<ParserHintDescriptor> {
    let required = required_parameters(tool, action);
    parser_hints(tool, action)
        .into_iter()
        .filter(|hint| {
            required
                .iter()
                .any(|parameter| *parameter == hint.parameter.as_str())
        })
        .collect()
}

const CONDITIONAL_REQUIRED_PARAMETERS: &[ConditionalRequiredParameterDescriptor] = &[
    ConditionalRequiredParameterDescriptor {
        tool: "inject",
        action: "shellcode",
        when_parameter: "method",
        when_values: &[
            "thread",
            "apc",
            "special_apc",
            "mapping",
            "atom",
            "callback_enum",
            "propagate",
            "instrumentation",
            "kernel_callback",
            "stomp",
            "threadless",
            "workitem",
            "pool_party",
        ],
        parameters: &["shellcode"],
        default_applies: true,
        description: "Most shellcode injection methods require a shellcode byte payload; mockingjay is the documented exception.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "inject",
        action: "shellcode",
        when_parameter: "method",
        when_values: &["wow64", "heaven_gate"],
        parameters: &["shellcode"],
        default_applies: false,
        description: "Cross-architecture shellcode methods require base64 shellcode text.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "inject",
        action: "spawn",
        when_parameter: "spawn_method",
        when_values: &["hollow", "transacted"],
        parameters: &["payload"],
        default_applies: true,
        description: "Hollow and transacted spawn methods require PE payload bytes.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "inject",
        action: "spawn",
        when_parameter: "spawn_method",
        when_values: &["early_bird"],
        parameters: &["shellcode"],
        default_applies: false,
        description: "Early-bird spawn requires shellcode bytes.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "hook",
        action: "install",
        when_parameter: "method",
        when_values: &["iat"],
        parameters: &["pid", "module", "function", "hook_address"],
        default_applies: true,
        description: "IAT hook installation requires target PID, imported module, imported function, and replacement hook address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "hook",
        action: "install",
        when_parameter: "method",
        when_values: &["inline"],
        parameters: &["pid", "target_address", "hook_address"],
        default_applies: false,
        description: "Inline hook installation requires target PID, target function address, and replacement hook address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "hook",
        action: "hook_function",
        when_parameter: "method",
        when_values: &["iat"],
        parameters: &["pid", "module", "function", "hook_address"],
        default_applies: true,
        description: "IAT hook_function requires target PID, imported module, imported function, and replacement hook address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "hook",
        action: "hook_function",
        when_parameter: "method",
        when_values: &["inline"],
        parameters: &["pid", "target_address", "hook_address"],
        default_applies: false,
        description: "Inline hook_function requires target PID, target function address, and replacement hook address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "payload",
        action: "pe_parse",
        when_parameter: "show",
        when_values: &["headers", "imports", "exports", "sections"],
        parameters: &["address"],
        default_applies: true,
        description: "PE parse views require a base address; base_address is accepted as an alias.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "payload",
        action: "pe_parse",
        when_parameter: "show",
        when_values: &["iat_entry"],
        parameters: &["module"],
        default_applies: false,
        description: "IAT entry lookup requires a module name; module_name is accepted as an alias.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_pte_rw",
        when_parameter: "pte_action",
        when_values: &["write", "restore"],
        parameters: &["new_pte"],
        default_applies: false,
        description: "PTE write/restore operations require the replacement PTE value; read and make_writable modes derive values from the current PTE.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_msr_rw",
        when_parameter: "msr_action",
        when_values: &["write"],
        parameters: &["msr_index", "msr_value"],
        default_applies: false,
        description: "MSR writes require the target MSR index and replacement value; reads may use the handler default index.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        when_parameter: "obj_action",
        when_values: &["register"],
        parameters: &["protect_pid"],
        default_applies: false,
        description: "Object hook registration requires the protected process ID; unregister and query modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_system_thread",
        when_parameter: "thread_action",
        when_values: &["create"],
        parameters: &["thread_start"],
        default_applies: false,
        description: "System thread creation requires a kernel start routine address; query mode can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_exec",
        when_parameter: "exec_action",
        when_values: &["run", "alloc"],
        parameters: &["shellcode_bytes"],
        default_applies: true,
        description: "Kernel exec run/alloc operations require shellcode bytes; free mode requires an existing allocation address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_exec",
        when_parameter: "exec_action",
        when_values: &["free"],
        parameters: &["alloc_address"],
        default_applies: false,
        description: "Kernel exec free requires the allocated kernel address returned by a prior allocation.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_cloak",
        when_parameter: "cloak_action",
        when_values: &["target"],
        parameters: &["driver_name"],
        default_applies: false,
        description: "Driver cloak target mode requires the driver module name; self and query modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_hide",
        when_parameter: "reg_action",
        when_values: &["add", "remove"],
        parameters: &["key_path"],
        default_applies: false,
        description: "Registry hide add/remove operations require the target registry key path; list and clear modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_file_lock",
        when_parameter: "lock_action",
        when_values: &["add", "remove"],
        parameters: &["file_path"],
        default_applies: false,
        description: "File lock add/remove operations require the target file path; list and clear modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_ppl_bypass",
        when_parameter: "ppl_action",
        when_values: &["strip", "set"],
        parameters: &["pid"],
        default_applies: false,
        description: "PPL strip/set operations require the target process ID; query mode can omit it only when the handler default is intended.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_token_swap",
        when_parameter: "swap_action",
        when_values: &["steal", "swap"],
        parameters: &["target_pid"],
        default_applies: true,
        description: "Token steal/swap operations require the target process ID; query mode can omit it only when explicitly selected.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_process_protect",
        when_parameter: "protect_action",
        when_values: &["set", "strip"],
        parameters: &["pid"],
        default_applies: false,
        description: "Process protection set/strip operations require the target process ID; query mode can omit it only when explicitly selected.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_cred_dump",
        when_parameter: "cred_action",
        when_values: &["read"],
        parameters: &["pid", "address"],
        default_applies: false,
        description: "Credential memory reads require the source process ID and address; find_lsass and full dump modes derive their target internally.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_impersonate",
        when_parameter: "imp_action",
        when_values: &["swap"],
        parameters: &["target_path", "legit_path"],
        default_applies: false,
        description: "Driver impersonation swap requires both target and legitimate driver paths; restore/query use stored backup state.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_nuke",
        when_parameter: "cb_action",
        when_values: &["remove"],
        parameters: &["index"],
        default_applies: false,
        description: "Callback single-remove requires the callback table index; enum, nuke_all, and restore modes do not use it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_minifilter_detach",
        when_parameter: "mf_action",
        when_values: &["detach"],
        parameters: &["filter_name", "frame_id"],
        default_applies: false,
        description: "Minifilter detach requires the filter name and frame ID; enum and nuke modes can omit a specific target.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        when_parameter: "apc_action",
        when_values: &["inject"],
        parameters: &["tid", "shellcode_size", "shellcode_addr"],
        default_applies: true,
        description: "Kernel APC shellcode injection requires the target thread ID, shellcode size, and shellcode address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        when_parameter: "apc_action",
        when_values: &["dll"],
        parameters: &["tid", "dll_path"],
        default_applies: false,
        description: "Kernel APC DLL injection requires the target thread ID and DLL path.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_wfp_remove",
        when_parameter: "wfp_action",
        when_values: &["remove"],
        parameters: &["callout_id"],
        default_applies: false,
        description: "WFP single-remove requires the target callout ID; enum and nuke modes can omit a single callout target.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_port_hide",
        when_parameter: "port_action",
        when_values: &["add", "remove"],
        parameters: &["port"],
        default_applies: false,
        description: "Port hide add/remove operations require the target port; list and clear modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_token_dup",
        when_parameter: "token_action",
        when_values: &["copy"],
        parameters: &["source_pid"],
        default_applies: false,
        description: "Token copy requires the source process ID; system and restore modes use driver-managed token state.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        when_parameter: "hook_action",
        when_values: &["install"],
        parameters: &["target_module", "target_function", "replacement_addr"],
        default_applies: false,
        description: "Global hook installation requires the target module, target function, and replacement address; query mode can omit hook targets.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        when_parameter: "hook_action",
        when_values: &["remove"],
        parameters: &["hook_index"],
        default_applies: false,
        description: "Global hook removal requires the hook slot index; query mode can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_infinity_hook",
        when_parameter: "infhook_action",
        when_values: &["enable", "disable"],
        parameters: &["syscall_number"],
        default_applies: false,
        description: "Infinity hook enable/disable operations require the target syscall number; query mode can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_infinity_hook",
        when_parameter: "infhook_action",
        when_values: &["enable"],
        parameters: &["handler_address"],
        default_applies: false,
        description: "Infinity hook enable requires the replacement handler address.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_unloaded_drv_clear",
        when_parameter: "unloaded_action",
        when_values: &["clear_name"],
        parameters: &["driver_name"],
        default_applies: false,
        description: "Unloaded-driver clear_name requires the driver module name; query and clear_all modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_etw_blind",
        when_parameter: "etw_action",
        when_values: &["disable", "enable"],
        parameters: &["provider_guid"],
        default_applies: false,
        description: "ETW provider disable/enable operations require the provider GUID; query and kill_all modes can omit it.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        when_parameter: "spoof_action",
        when_values: &["image_name"],
        parameters: &["pid", "new_image_name"],
        default_applies: false,
        description: "EPROCESS image-name spoofing requires the target process ID and new image name.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        when_parameter: "spoof_action",
        when_values: &["command_line"],
        parameters: &["pid", "new_command_line"],
        default_applies: false,
        description: "EPROCESS command-line spoofing requires the target process ID and new command line.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        when_parameter: "spoof_action",
        when_values: &["pid"],
        parameters: &["pid", "new_parent_pid"],
        default_applies: false,
        description: "EPROCESS parent-PID spoofing requires the target process ID and new parent PID.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_cr_rw",
        when_parameter: "cr_action",
        when_values: &["write"],
        parameters: &["cr_index", "value"],
        default_applies: false,
        description: "Control register writes require the target register index and replacement value; reads may default to CR0.",
    },
    ConditionalRequiredParameterDescriptor {
        tool: "kernel",
        action: "driver_idt_rw",
        when_parameter: "idt_action",
        when_values: &["write"],
        parameters: &["vector", "new_handler"],
        default_applies: false,
        description: "IDT writes require the interrupt vector and replacement handler address; read and dump modes may use defaults.",
    },
];

pub fn all_conditional_required_parameters() -> &'static [ConditionalRequiredParameterDescriptor] {
    CONDITIONAL_REQUIRED_PARAMETERS
}

pub fn conditional_required_parameters(
    tool: &str,
    action: &str,
) -> Vec<ConditionalRequiredParameterDescriptor> {
    all_conditional_required_parameters()
        .iter()
        .copied()
        .filter(|descriptor| descriptor.applies_to(tool, action))
        .collect()
}

const ALTERNATIVE_REQUIRED_PARAMETERS: &[AlternativeRequiredParameterDescriptor] =
    &[AlternativeRequiredParameterDescriptor {
        tool: "memory",
        action: "write",
        when_parameter: None,
        when_values: &[],
        parameters: &["bytes", "text"],
        default_applies: true,
        description: "Memory write requires either a byte payload or deprecated text input.",
    }];

pub fn all_alternative_required_parameters() -> &'static [AlternativeRequiredParameterDescriptor] {
    ALTERNATIVE_REQUIRED_PARAMETERS
}

pub fn alternative_required_parameters(
    tool: &str,
    action: &str,
) -> Vec<AlternativeRequiredParameterDescriptor> {
    all_alternative_required_parameters()
        .iter()
        .copied()
        .filter(|descriptor| descriptor.applies_to(tool, action))
        .collect()
}

const PLANNER_WARNINGS: &[PlannerWarningDescriptor] = &[
    PlannerWarningDescriptor {
        tool: "target",
        action: "module_base",
        condition: PlannerWarningCondition::ParameterPresent,
        parameter: Some("name"),
        unless_parameter: None,
        unless_values: &[],
        message: "module_base uses module_name; name is a process search parameter",
    },
    PlannerWarningDescriptor {
        tool: "payload",
        action: "pe_parse",
        condition: PlannerWarningCondition::ParameterMissing,
        parameter: Some("address"),
        unless_parameter: Some("show"),
        unless_values: &["iat_entry"],
        message: "pe_parse reads a PE image at a base address; suspended targets may not have initialized modules yet",
    },
    PlannerWarningDescriptor {
        tool: "stealth",
        action: "encrypt_memory",
        condition: PlannerWarningCondition::Always,
        parameter: None,
        unless_parameter: None,
        unless_values: &[],
        message: "encrypt_memory/decrypt_memory operate on local memoric process memory only; remote PID/address input is rejected",
    },
    PlannerWarningDescriptor {
        tool: "stealth",
        action: "decrypt_memory",
        condition: PlannerWarningCondition::Always,
        parameter: None,
        unless_parameter: None,
        unless_values: &[],
        message: "encrypt_memory/decrypt_memory operate on local memoric process memory only; remote PID/address input is rejected",
    },
    PlannerWarningDescriptor {
        tool: "kernel",
        action: "read",
        condition: PlannerWarningCondition::Always,
        parameter: None,
        unless_parameter: None,
        unless_values: &[],
        message: "kernel generic helpers require an explicit BYOVD device_path",
    },
    PlannerWarningDescriptor {
        tool: "kernel",
        action: "write",
        condition: PlannerWarningCondition::Always,
        parameter: None,
        unless_parameter: None,
        unless_values: &[],
        message: "kernel generic helpers require an explicit BYOVD device_path",
    },
    PlannerWarningDescriptor {
        tool: "kernel",
        action: "enum_callbacks",
        condition: PlannerWarningCondition::Always,
        parameter: None,
        unless_parameter: None,
        unless_values: &[],
        message: "kernel generic helpers require an explicit BYOVD device_path",
    },
];

pub fn all_planner_warnings() -> &'static [PlannerWarningDescriptor] {
    PLANNER_WARNINGS
}

pub fn planner_warnings(tool: &str, action: &str) -> Vec<PlannerWarningDescriptor> {
    all_planner_warnings()
        .iter()
        .copied()
        .filter(|descriptor| descriptor.applies_to(tool, action))
        .collect()
}

const PROCESS_VM_WRITE_PRIVILEGES: &[(&str, &str)] = &[
    (
        "process_vm_write_access",
        "Caller needs process memory mutation access for the target process",
    ),
    (
        "target_allowlist",
        "Target process must pass the state-changing target allowlist",
    ),
];
const SEDEBUG_PROCESS_VM_PRIVILEGES: &[(&str, &str)] = &[
    (
        "SeDebugPrivilege",
        "SeDebugPrivilege may be required for cross-process handle access",
    ),
    (
        "process_vm_write_access",
        "Caller needs process memory mutation access for the target process",
    ),
    (
        "target_allowlist",
        "Target process must pass the state-changing target allowlist",
    ),
];
const ADMIN_POLICY_PRIVILEGES: &[(&str, &str)] = &[
    (
        "administrator",
        "Administrative rights are required for this policy or service surface",
    ),
    (
        "policy approval",
        "Operation requires explicit policy approval before live execution",
    ),
];
const ADMIN_KERNEL_PRIVILEGES: &[(&str, &str)] = &[
    (
        "administrator",
        "Administrative rights are required for kernel-backed operations",
    ),
    (
        "kernel driver access",
        "A reachable kernel driver or equivalent approved capability is required",
    ),
];
const KERNEL_DRIVER_LOAD_PRIVILEGES: &[(&str, &str)] = &[
    (
        "administrator",
        "Administrative rights are required to create or modify driver services",
    ),
    (
        "SeLoadDriverPrivilege",
        "SeLoadDriverPrivilege is required to load or unload a kernel driver",
    ),
    (
        "driver signing readiness",
        "Driver signing, test-signing, or BYOVD readiness must be satisfied",
    ),
];
const KERNEL_OPERATION_PRIVILEGES: &[(&str, &str)] = &[
    (
        "administrator",
        "Administrative rights are required for kernel-backed operations",
    ),
    (
        "kernel driver access",
        "A reachable kernel driver or equivalent approved capability is required",
    ),
    (
        "capability preflight",
        "Capability checks must confirm that the selected kernel path is available",
    ),
];

fn privilege_requirement(
    tool: &'static str,
    action: &'static str,
    privilege: &'static str,
    description: &'static str,
) -> PrivilegeRequirementDescriptor {
    PrivilegeRequirementDescriptor {
        tool,
        action,
        privilege,
        description,
    }
}

fn privilege_requirements_from(
    tool: &'static str,
    action: &'static str,
    requirements: &'static [(&'static str, &'static str)],
) -> Vec<PrivilegeRequirementDescriptor> {
    requirements
        .iter()
        .map(|&(privilege, description)| {
            privilege_requirement(tool, action, privilege, description)
        })
        .collect()
}

fn privilege_requirements_for_registered(
    tool: &'static str,
    action: &'static str,
) -> Vec<PrivilegeRequirementDescriptor> {
    match tool {
        "memory"
            if matches!(
                action,
                "write"
                    | "typed_write"
                    | "write_string"
                    | "alloc"
                    | "free"
                    | "protect"
                    | "scan_freeze"
            ) =>
        {
            privilege_requirements_from(tool, action, PROCESS_VM_WRITE_PRIVILEGES)
        }
        "inject" if !is_read_only_action(tool, action) => {
            privilege_requirements_from(tool, action, SEDEBUG_PROCESS_VM_PRIVILEGES)
        }
        "hook" => privilege_requirements_from(tool, action, SEDEBUG_PROCESS_VM_PRIVILEGES),
        "payload" if action == "cleanup" => {
            privilege_requirements_from(tool, action, PROCESS_VM_WRITE_PRIVILEGES)
        }
        "payload" if action == "obfuscate" => vec![privilege_requirement(
            tool,
            action,
            "local payload material",
            "Caller supplies local payload material for transformation",
        )],
        "detect" if action == "edr_suspend" => vec![
            privilege_requirement(
                tool,
                action,
                "SeDebugPrivilege",
                "SeDebugPrivilege may be required to open protected security processes",
            ),
            privilege_requirement(
                tool,
                action,
                "process_suspend_resume_access",
                "Caller needs suspend/resume access for matched security processes",
            ),
            privilege_requirement(
                tool,
                action,
                "target_allowlist",
                "Matched process must pass the state-changing target allowlist",
            ),
        ],
        "stealth" => stealth_privilege_requirements(tool, action),
        "privilege" => privilege_tool_requirements(tool, action),
        "kernel" if matches!(action, "driver_load" | "driver_unload" | "driver_auto") => {
            privilege_requirements_from(tool, action, KERNEL_DRIVER_LOAD_PRIVILEGES)
        }
        "kernel" if !is_read_only_action(tool, action) => {
            privilege_requirements_from(tool, action, KERNEL_OPERATION_PRIVILEGES)
        }
        "target" if matches!(action, "thread_suspend" | "thread_resume" | "string_write") => {
            vec![
                privilege_requirement(
                    tool,
                    action,
                    "process_or_thread_mutation_access",
                    "Caller needs mutation access for the target process or thread",
                ),
                privilege_requirement(
                    tool,
                    action,
                    "target_allowlist",
                    "Target process must pass the state-changing target allowlist",
                ),
            ]
        }
        "self" if action.starts_with("protect_") => vec![privilege_requirement(
            tool,
            action,
            "current_process_memory_access",
            "Operation mutates the current memoric process memory state",
        )],
        "orchestrate" if action == "execute" => vec![
            privilege_requirement(
                tool,
                action,
                "step-dependent privileges",
                "Each orchestration step contributes its own privilege requirements",
            ),
            privilege_requirement(
                tool,
                action,
                "policy approval",
                "Live orchestration requires explicit policy approval",
            ),
            privilege_requirement(
                tool,
                action,
                "target_allowlist",
                "State-changing target steps must pass the target allowlist",
            ),
        ],
        _ => Vec::new(),
    }
}

fn stealth_privilege_requirements(
    tool: &'static str,
    action: &'static str,
) -> Vec<PrivilegeRequirementDescriptor> {
    match action {
        "patch_etw" | "patch_amsi" | "patch_cfg" | "patch_cig" | "unhook_ntdll"
        | "unhook_function" | "hide_module" | "fluctuate_module" | "module_stomp"
        | "mutate_code" | "encrypt_memory" | "decrypt_memory" | "syscall_write"
        | "syscall_alloc" | "syscall_protect" | "syscall_thread" | "syscall_inject" => {
            privilege_requirements_from(tool, action, SEDEBUG_PROCESS_VM_PRIVILEGES)
        }
        "defender_disable"
        | "defender_restore"
        | "defender_add_exclusion"
        | "defender_mpcmdrun"
        | "firewall_add_rule"
        | "firewall_remove_rule"
        | "firewall_disable"
        | "firewall_enable"
        | "wdac_disable"
        | "wdac_restore" => privilege_requirements_from(tool, action, ADMIN_POLICY_PRIVILEGES),
        "testsign_kernel_bypass"
        | "testsign_auto_inject"
        | "testsign_ci_callback"
        | "testsign_ci_func_patch"
        | "testsign_pte_rw"
        | "callback_masquerade"
        | "etw_ti_selective_disable"
        | "minifilter_selective_detach"
        | "minifilter_pause"
        | "minifilter_resume" => privilege_requirements_from(tool, action, ADMIN_KERNEL_PRIVILEGES),
        "sentinel_start" | "sentinel_stop" | "sentinel_self_destruct" => vec![
            privilege_requirement(
                tool,
                action,
                "administrator",
                "Administrative rights are required to control sentinel services",
            ),
            privilege_requirement(
                tool,
                action,
                "service control access",
                "Caller needs service-control access for sentinel lifecycle changes",
            ),
        ],
        _ => Vec::new(),
    }
}

fn privilege_tool_requirements(
    tool: &'static str,
    action: &'static str,
) -> Vec<PrivilegeRequirementDescriptor> {
    match action {
        "debug_priv" => vec![
            privilege_requirement(
                tool,
                action,
                "TOKEN_ADJUST_PRIVILEGES",
                "Caller token must be adjustable to enable or disable privileges",
            ),
            privilege_requirement(
                tool,
                action,
                "SeDebugPrivilege",
                "SeDebugPrivilege is the requested privilege posture change",
            ),
        ],
        "token_steal" | "token_impersonate" => vec![
            privilege_requirement(
                tool,
                action,
                "SeDebugPrivilege",
                "SeDebugPrivilege may be required to open source token owners",
            ),
            privilege_requirement(
                tool,
                action,
                "TOKEN_DUPLICATE",
                "Source token must be opened with duplication rights",
            ),
            privilege_requirement(
                tool,
                action,
                "TOKEN_IMPERSONATE",
                "Duplicated token must be usable for impersonation",
            ),
        ],
        "token_revert" => vec![privilege_requirement(
            tool,
            action,
            "thread impersonation context",
            "Current thread must have an impersonation context to revert",
        )],
        "elevate" | "potato" => vec![privilege_requirement(
            tool,
            action,
            "administrator or service impersonation context",
            "Privilege escalation path requires an admin token or service impersonation context",
        )],
        "symlink" => vec![privilege_requirement(
            tool,
            action,
            "SeCreateSymbolicLinkPrivilege or developer mode",
            "Creating symlinks requires the symlink privilege or Windows developer mode",
        )],
        _ => Vec::new(),
    }
}

pub fn required_privileges(tool: &str, action: &str) -> Vec<&'static str> {
    registered_action(tool, action)
        .map(|registered| {
            registered
                .required_privileges
                .into_iter()
                .map(|descriptor| descriptor.privilege)
                .collect()
        })
        .unwrap_or_default()
}

fn side_effect(
    tool: &'static str,
    action: &'static str,
    effect: &'static str,
    description: &'static str,
) -> SideEffectDescriptor {
    SideEffectDescriptor {
        tool,
        action,
        effect,
        description,
    }
}

fn side_effects_for_registered(
    tool: &'static str,
    action: &'static str,
) -> Vec<SideEffectDescriptor> {
    match tool {
        "memory" => match action {
            "write" | "typed_write" | "write_string" | "scan_freeze" => vec![side_effect(
                tool,
                action,
                "target memory mutation",
                "Writes or freezes bytes in target process memory",
            )],
            "alloc" => vec![side_effect(
                tool,
                action,
                "remote allocation",
                "Creates a new allocation in the target process",
            )],
            "free" => vec![side_effect(
                tool,
                action,
                "remote allocation release",
                "Releases an existing target process allocation",
            )],
            "protect" => vec![side_effect(
                tool,
                action,
                "remote page protection change",
                "Changes page protection on a target process memory range",
            )],
            _ => Vec::new(),
        },
        "inject" if !is_read_only_action(tool, action) => vec![side_effect(
            tool,
            action,
            "remote memory/thread/process mutation",
            "Injection workflow may allocate memory, create or alter threads, or spawn a process",
        )],
        "hook" => vec![side_effect(
            tool,
            action,
            "code or import table mutation",
            "Hook workflow may patch code, import tables, or hardware breakpoint state",
        )],
        "payload" => match action {
            "cleanup" => vec![side_effect(
                tool,
                action,
                "remote allocation release and handle cleanup",
                "Releases remote payload resources and closes recorded handles",
            )],
            "obfuscate" => vec![side_effect(
                tool,
                action,
                "local payload representation transformation",
                "Transforms caller-provided payload material without remote mutation",
            )],
            _ => Vec::new(),
        },
        "detect" if action == "edr_suspend" => vec![side_effect(
            tool,
            action,
            "matched process suspension",
            "Suspends one or more matched security processes",
        )],
        "stealth" if !is_read_only_action(tool, action) => vec![side_effect(
            tool,
            action,
            "telemetry or process state mutation",
            "Evasion workflow may alter telemetry, module, process, policy, or service state",
        )],
        "privilege" if !is_read_only_action(tool, action) => vec![side_effect(
            tool,
            action,
            "token, privilege, service, or UAC state mutation",
            "Privilege workflow may alter token, privilege, service, symlink, or UAC state",
        )],
        "kernel" if !is_read_only_action(tool, action) => vec![side_effect(
            tool,
            action,
            "kernel driver, kernel memory, or system state mutation",
            "Kernel workflow may load drivers or alter kernel/system state",
        )],
        "target" if matches!(action, "thread_suspend" | "thread_resume" | "string_write") => {
            vec![side_effect(
                tool,
                action,
                "target process/thread state mutation",
                "Mutates target process memory or thread execution state",
            )]
        }
        "self" if action.starts_with("protect_") => vec![side_effect(
            tool,
            action,
            "memoric process memory mutation",
            "Mutates local memoric process protection or memory state",
        )],
        "orchestrate" if action == "execute" => vec![side_effect(
            tool,
            action,
            "multi-step workflow side effects",
            "Executes a chain whose steps may each produce state changes",
        )],
        _ => Vec::new(),
    }
}

pub fn side_effects(tool: &str, action: &str) -> Vec<&'static str> {
    registered_action(tool, action)
        .map(|registered| {
            registered
                .side_effects
                .into_iter()
                .map(|descriptor| descriptor.effect)
                .collect()
        })
        .unwrap_or_default()
}

fn planned_handle(
    tool: &'static str,
    action: &'static str,
    kind: &'static str,
    target: &'static str,
    access: &'static str,
) -> PlannedHandleDescriptor {
    PlannedHandleDescriptor {
        tool,
        action,
        kind,
        target,
        access,
    }
}

fn planned_handles_for_registered(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match tool {
        "memory" => memory_planned_handles(tool, action),
        "inject" => inject_planned_handles(tool, action),
        "payload" => payload_planned_handles(tool, action),
        "detect" if action == "edr_suspend" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "matched EDR/security process",
                "PROCESS_SUSPEND_RESUME",
            ),
            planned_handle(
                tool,
                action,
                "process_snapshot",
                "process list used for EDR matching",
                "query access",
            ),
        ],
        "hook" => hook_planned_handles(tool, action),
        "stealth" => stealth_planned_handles(tool, action),
        "privilege" => privilege_planned_handles(tool, action),
        "kernel" => kernel_planned_handles(tool, action),
        "target" if matches!(action, "thread_suspend" | "thread_resume") => {
            vec![planned_handle(
                tool,
                action,
                "thread",
                "target thread",
                "THREAD_SUSPEND_RESUME",
            )]
        }
        "target" if action == "string_write" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "target string address range",
                "write access",
            ),
        ],
        "self" if action.starts_with("protect_") => vec![planned_handle(
            tool,
            action,
            "memory_region",
            "memoric process protection region",
            "local memory protection access",
        )],
        "orchestrate" if action == "execute" => vec![planned_handle(
            tool,
            action,
            "workflow_task",
            "planned orchestration steps",
            "step-dependent handles",
        )],
        _ => Vec::new(),
    }
}

fn memory_planned_handles(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match action {
        "write" | "typed_write" | "write_string" | "scan_freeze" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "target address range",
                "write access",
            ),
        ],
        "alloc" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "new remote allocation",
                "allocate access",
            ),
        ],
        "free" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "existing remote allocation",
                "free access",
            ),
        ],
        "protect" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "target address range",
                "change protection",
            ),
        ],
        _ => Vec::new(),
    }
}

fn inject_planned_handles(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match action {
        "hijack_enum" => vec![planned_handle(
            tool,
            action,
            "process",
            "target process",
            "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ",
        )],
        "hijack_backup" => vec![planned_handle(
            tool,
            action,
            "thread",
            "target thread",
            "THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME",
        )],
        "hijack_redirect" | "hijack_restore" | "hijack_wait" => vec![planned_handle(
            tool,
            action,
            "thread",
            "target thread",
            "THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME",
        )],
        "spawn" | "phantom_hollow" | "transacted_hollow" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "new or suspended process",
                "create process",
            ),
            planned_handle(
                tool,
                action,
                "thread",
                "primary thread",
                "thread resume/context access",
            ),
            planned_handle(
                tool,
                action,
                "section_or_file",
                "payload image",
                "image/file mapping access",
            ),
        ],
        _ if !is_read_only_action(tool, action) => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "thread",
                "remote execution thread",
                "thread creation/resume access",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "remote payload allocation",
                "execute/read/write access",
            ),
        ],
        _ => Vec::new(),
    }
}

fn payload_planned_handles(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match action {
        "cleanup" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "remote allocation list",
                "free/release access",
            ),
            planned_handle(
                tool,
                action,
                "thread",
                "remote execution thread handles",
                "close/wait access",
            ),
        ],
        "obfuscate" => vec![planned_handle(
            tool,
            action,
            "payload_buffer",
            "caller-provided payload bytes or strings",
            "local transformation only",
        )],
        _ => Vec::new(),
    }
}

fn hook_planned_handles(tool: &'static str, action: &'static str) -> Vec<PlannedHandleDescriptor> {
    match action {
        "install_hwbp" | "remove_hwbp" => vec![planned_handle(
            tool,
            action,
            "thread",
            "target thread",
            "THREAD_GET_CONTEXT | THREAD_SET_CONTEXT",
        )],
        "detour" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "one or more detour target ranges",
                "code patch access",
            ),
        ],
        "restore" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "previously patched code range",
                "restore access",
            ),
        ],
        _ => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "code/IAT address range",
                "patch access",
            ),
        ],
    }
}

fn stealth_planned_handles(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match action {
        "patch_etw" | "patch_amsi" | "patch_cfg" | "patch_cig" | "unhook_ntdll"
        | "unhook_function" | "mutate_code" | "encrypt_memory" | "decrypt_memory" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "current or target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "telemetry/code address range",
                "patch or protection access",
            ),
        ],
        "hide_module" | "fluctuate_module" | "module_stomp" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
            ),
            planned_handle(
                tool,
                action,
                "module",
                "target module",
                "loader/module metadata access",
            ),
        ],
        "spoof_ppid" | "create_suspended" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "parent or suspended process",
                "process creation access",
            ),
            planned_handle(
                tool,
                action,
                "thread",
                "initial suspended thread",
                "thread context/resume access",
            ),
        ],
        "syscall_write" | "syscall_alloc" | "syscall_protect" | "syscall_thread"
        | "syscall_inject" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "direct syscall process access",
            ),
            planned_handle(
                tool,
                action,
                "memory_region",
                "target syscall memory range",
                "operation-dependent access",
            ),
        ],
        "timestomp" => vec![planned_handle(
            tool,
            action,
            "file",
            "target file",
            "FILE_WRITE_ATTRIBUTES",
        )],
        "sentinel_start" | "sentinel_stop" | "sentinel_self_destruct" => vec![planned_handle(
            tool,
            action,
            "service_or_thread",
            "sentinel background worker",
            "worker lifecycle access",
        )],
        "testsign_kernel_bypass"
        | "testsign_auto_inject"
        | "testsign_ci_callback"
        | "testsign_ci_func_patch"
        | "testsign_pte_rw"
        | "wdac_disable"
        | "wdac_restore" => vec![planned_handle(
            tool,
            action,
            "driver",
            "kernel/test-signing control path",
            "driver or boot policy access",
        )],
        "defender_disable"
        | "defender_restore"
        | "defender_add_exclusion"
        | "defender_mpcmdrun"
        | "firewall_add_rule"
        | "firewall_remove_rule"
        | "firewall_disable"
        | "firewall_enable" => vec![planned_handle(
            tool,
            action,
            "service_or_policy",
            "security product or firewall policy",
            "configuration change access",
        )],
        "callback_masquerade"
        | "etw_ti_selective_disable"
        | "minifilter_selective_detach"
        | "minifilter_pause"
        | "minifilter_resume" => vec![planned_handle(
            tool,
            action,
            "driver",
            "kernel callback/minifilter control path",
            "driver IOCTL access",
        )],
        _ => Vec::new(),
    }
}

fn privilege_planned_handles(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match action {
        "elevate" | "potato" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "helper or elevated process",
                "process creation access",
            ),
            planned_handle(
                tool,
                action,
                "token",
                "elevated token",
                "TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY",
            ),
        ],
        "token_steal" | "token_impersonate" => vec![
            planned_handle(
                tool,
                action,
                "process",
                "target process",
                "PROCESS_QUERY_LIMITED_INFORMATION",
            ),
            planned_handle(
                tool,
                action,
                "token",
                "target process token",
                "TOKEN_DUPLICATE | TOKEN_IMPERSONATE",
            ),
        ],
        "token_revert" => vec![planned_handle(
            tool,
            action,
            "token",
            "current thread token",
            "revert impersonation",
        )],
        "debug_priv" => vec![planned_handle(
            tool,
            action,
            "token",
            "current process token",
            "TOKEN_ADJUST_PRIVILEGES",
        )],
        "symlink" => vec![planned_handle(
            tool,
            action,
            "filesystem",
            "link and target paths",
            "reparse point/create file access",
        )],
        _ => Vec::new(),
    }
}

fn kernel_planned_handles(
    tool: &'static str,
    action: &'static str,
) -> Vec<PlannedHandleDescriptor> {
    match action {
        "driver_load" => vec![
            planned_handle(
                tool,
                action,
                "service",
                "kernel driver service",
                "SERVICE_CREATE | SERVICE_START",
            ),
            planned_handle(
                tool,
                action,
                "file",
                "driver image path",
                "read/execute driver image",
            ),
        ],
        "driver_unload" => vec![planned_handle(
            tool,
            action,
            "service",
            "kernel driver service",
            "SERVICE_STOP | DELETE",
        )],
        "write"
        | "physical_write"
        | "pte_modify"
        | "vad_hide"
        | "remove_callback"
        | "object_callback_remove"
        | "registry_callback_remove"
        | "dkom_hide"
        | "module_hide"
        | "token_escalate" => vec![
            planned_handle(
                tool,
                action,
                "driver",
                "kernel driver device",
                "IOCTL write/control access",
            ),
            planned_handle(
                tool,
                action,
                "kernel_memory",
                "target kernel address or structure",
                "write access",
            ),
        ],
        action if action.starts_with("driver_") => vec![planned_handle(
            tool,
            action,
            "driver",
            "memoric driver device",
            "operation-specific IOCTL access",
        )],
        _ => vec![planned_handle(
            tool,
            action,
            "driver",
            "kernel driver device",
            "operation-dependent access",
        )],
    }
}

pub fn planned_handles(tool: &str, action: &str) -> Vec<PlannedHandleDescriptor> {
    registered_action(tool, action)
        .map(|registered| registered.planned_handles)
        .unwrap_or_default()
}

fn rollback_preview(
    tool: &'static str,
    action: &'static str,
    available: RollbackAvailability,
    strategy: &'static str,
    captured_fields: &'static [&'static str],
    detail: &'static str,
    reason: Option<&'static str>,
) -> RollbackPreviewDescriptor {
    RollbackPreviewDescriptor {
        tool,
        action,
        available,
        strategy,
        captured_fields,
        detail,
        reason,
    }
}

fn default_rollback_preview(tool: &'static str, action: &'static str) -> RollbackPreviewDescriptor {
    rollback_preview(
        tool,
        action,
        RollbackAvailability::Boolean(false),
        "none",
        &[],
        "no rollback metadata is currently captured for this action",
        Some("preview-only"),
    )
}

fn rollback_preview_for_registered(
    tool: &'static str,
    action: &'static str,
) -> RollbackPreviewDescriptor {
    match (tool, action) {
        ("memory", "write") | ("memory", "typed_write") | ("memory", "write_string") => {
            rollback_preview(
                tool,
                action,
                RollbackAvailability::Label("partial"),
                "restore_original_bytes",
                &["pid", "address", "size", "original_bytes", "old_protection"],
                "write rollback requires the live handler to capture original bytes before mutation",
                None,
            )
        }
        ("memory", "scan_freeze") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "unfreeze_and_restore_original_value",
            &["session_id", "address", "original_value", "freeze_handle"],
            "scan freeze rollback requires original candidate values and freeze worker state",
            None,
        ),
        ("memory", "protect") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_previous_protection",
            &["pid", "address", "size", "old_protection"],
            "old page protection can be restored if captured by the live handler",
            None,
        ),
        ("memory", "alloc") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(true),
            "free_allocated_region",
            &["pid", "address", "size"],
            "allocated region can usually be freed",
            None,
        ),
        ("memory", "free") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(false),
            "none",
            &[],
            "freed remote memory cannot be reconstructed without an external snapshot",
            Some("irreversible_release"),
        ),
        ("target", "thread_suspend") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(true),
            "resume_thread",
            &["tid", "previous_suspend_count"],
            "a matching resume can usually undo a dry-run-equivalent thread suspend if the live handler captured the previous suspend count",
            None,
        ),
        ("target", "thread_resume") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_suspend_count",
            &["tid", "previous_suspend_count"],
            "resume rollback depends on the previous suspend count and may require re-suspending the thread",
            None,
        ),
        ("target", "string_write") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_original_string_bytes",
            &["pid", "address", "original_bytes", "old_protection"],
            "string write rollback requires original bytes and any temporary page-protection change",
            None,
        ),
        ("detect", "edr_suspend") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "resume_suspended_processes",
            &["matched_pids", "previous_suspend_counts"],
            "EDR suspend rollback requires the live handler to record every suspended PID and prior suspend count",
            None,
        ),
        ("payload", "cleanup") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(false),
            "none",
            &["pid", "addresses", "thread_handles"],
            "cleanup releases remote allocations and closes handles; released resources cannot be restored by Memoric",
            Some("irreversible_cleanup"),
        ),
        ("payload", "obfuscate") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(true),
            "retain_original_payload",
            &["payload", "payload_hex", "strings", "key"],
            "local payload transformations are reversible only if the caller or handler retains the original material",
            None,
        ),
        ("hook", "install")
        | ("hook", "install_iat")
        | ("hook", "detour")
        | ("hook", "trampoline") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_original_bytes_or_pointer",
            &[
                "pid",
                "address",
                "iat_address",
                "original_address",
                "original_bytes",
                "hooks",
            ],
            "requires original bytes/address to restore",
            None,
        ),
        ("hook", "remove") | ("hook", "remove_iat") | ("hook", "restore") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("action-dependent"),
            "reinstall_previous_hook",
            &["pid", "address", "iat_address", "hook_address", "removed_bytes"],
            "hook removal rollback requires the prior hook descriptor and replacement bytes/address",
            None,
        ),
        ("hook", "install_hwbp") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(true),
            "remove_hardware_breakpoint",
            &["tid", "dr_index", "previous_debug_registers"],
            "installed hardware breakpoints can usually be cleared if previous debug register state was captured",
            None,
        ),
        ("hook", "remove_hwbp") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_hardware_breakpoint",
            &["tid", "dr_index", "previous_debug_registers"],
            "hardware-breakpoint removal rollback requires the previous debug register values",
            None,
        ),
        ("inject", "hijack_backup") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(true),
            "discard_backup_snapshot",
            &["tid", "thread_context_snapshot"],
            "backup collection itself is reversible by discarding the stored snapshot",
            None,
        ),
        ("inject", "hijack_redirect") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_thread_context",
            &["tid", "original_context", "redirect_address"],
            "thread hijack rollback requires a captured original thread context",
            None,
        ),
        ("inject", "hijack_restore") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("action-dependent"),
            "restore_previous_hijack_state",
            &["tid", "backup_context", "current_context"],
            "restore is itself a rollback step; undoing it requires the pre-restore hijack state",
            None,
        ),
        ("inject", "shellcode")
        | ("inject", "create_remote_thread")
        | ("inject", "nt_create_thread")
        | ("inject", "fiber")
        | ("inject", "threadpool")
        | ("inject", "pool_party_worker")
        | ("inject", "pool_party_work")
        | ("inject", "pool_party_direct")
        | ("inject", "pool_party_timer") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "terminate_thread_and_free_payload",
            &["pid", "thread_handle", "remote_address", "remote_size"],
            "remote execution rollback depends on whether the live handler captures thread and allocation handles before payload execution",
            None,
        ),
        ("inject", "spawn") | ("inject", "phantom_hollow") | ("inject", "transacted_hollow") => {
            rollback_preview(
                tool,
                action,
                RollbackAvailability::Label("partial"),
                "terminate_spawned_process_and_cleanup_image",
                &[
                    "pid",
                    "process_handle",
                    "thread_handle",
                    "image_section",
                    "created_files",
                ],
                "spawn/hollow rollback can usually terminate the created process but cannot undo external side effects from already-running payload code",
                None,
            )
        }
        ("kernel", "driver_callback_remove") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("partial"),
            "restore_removed_callback_pointer",
            &["callback_type", "index", "callback_address"],
            "rollback requires the live handler or caller to retain the removed callback pointer and driver support to write it back",
            None,
        ),
        ("kernel", "driver_infinity_hook") => rollback_preview(
            tool,
            action,
            RollbackAvailability::Boolean(true),
            "disable_infinity_hook",
            &["syscall_number", "original_handler"],
            "enabled infinity hooks can be disabled; exact handler restoration depends on original_handler captured by the live result",
            None,
        ),
        ("kernel", _) => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("action-dependent"),
            "driver_captured_original_state",
            &["driver_state", "original_state", "target"],
            "kernel rollback requires driver support and captured original state",
            None,
        ),
        ("stealth", _) => rollback_preview(
            tool,
            action,
            RollbackAvailability::Label("action-dependent"),
            "explicit_restore_or_restart",
            &["mutation", "restore_action"],
            "some evasion changes are reversible, others require process restart or explicit restore action",
            None,
        ),
        _ => default_rollback_preview(tool, action),
    }
}

pub fn rollback_preview_metadata(tool: &str, action: &str) -> RollbackPreviewDescriptor {
    registered_action(tool, action)
        .map(|registered| registered.rollback_preview)
        .unwrap_or_else(|| default_rollback_preview("", ""))
}

const MEMORY_READ_MODE_VALUES: &[&str] = &["raw", "string", "stealth", "scattered", "physical"];
const MEMORY_TYPED_PRIMITIVE_VALUES: &[&str] = &["u8", "u16", "u32", "u64", "i32", "f32", "f64"];
const MEMORY_ENDIAN_VALUES: &[&str] = &["native", "little", "big"];
const MEMORY_SCAN_MODE_VALUES: &[&str] = &[
    "exact",
    "changed",
    "pattern",
    "stealth_pattern",
    "range",
    "delta",
    "string",
    "unknown",
    "pointer",
    "aob",
    "aligned",
    "multi",
];
const MEMORY_SCAN_TYPE_VALUES: &[&str] = &[
    "int", "float", "string", "bytes", "long", "double", "short", "byte",
];
const MEMORY_CHANGE_VALUES: &[&str] = &["changed", "unchanged", "increased", "decreased"];
const MEMORY_DELTA_DIRECTION_VALUES: &[&str] = &["increased_by", "decreased_by"];
const MEMORY_STRING_ENCODING_VALUES: &[&str] = &["ansi", "unicode", "both"];
const MEMORY_SCAN_NEW_VALUE_TYPE_VALUES: &[&str] = &[
    "u8", "byte", "u16", "short", "u32", "int", "dword", "u64", "long", "qword", "i32", "i64",
    "f32", "float", "f64", "double", "bytes", "aob",
];
const MEMORY_SCAN_LIST_SORT_VALUES: &[&str] = &[
    "index_asc",
    "index_desc",
    "address_asc",
    "address_desc",
    "value_asc",
    "value_desc",
];
const MEMORY_REGION_CACHE_VALUES: &[&str] = &[
    "auto",
    "use",
    "enabled",
    "on",
    "refresh",
    "force_refresh",
    "clear",
    "invalidate",
    "off",
    "disabled",
    "disable",
    "none",
    "bypass",
];
const PAGE_PROTECTION_SYMBOLIC_VALUES: &[&str] = &[
    "RWX",
    "RW",
    "RX",
    "R",
    "NOACCESS",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_READWRITE",
    "PAGE_EXECUTE_READ",
    "PAGE_READONLY",
    "PAGE_NOACCESS",
];
const PAYLOAD_PE_PARSE_SHOW_VALUES: &[&str] =
    &["headers", "imports", "exports", "sections", "iat_entry"];
const PAYLOAD_OBFUSCATION_METHOD_VALUES: &[&str] = &[
    "xor",
    "rc4",
    "aes_ctr",
    "polymorphic",
    "uuid",
    "ipv4",
    "mac",
    "transform",
    "strings",
];
const PAYLOAD_SERIALIZE_FORMAT_VALUES: &[&str] = &["raw", "struct"];
const INJECT_SHELLCODE_METHOD_VALUES: &[&str] = &[
    "thread",
    "apc",
    "special_apc",
    "mapping",
    "mockingjay",
    "atom",
    "callback_enum",
    "propagate",
    "instrumentation",
    "kernel_callback",
    "wow64",
    "heaven_gate",
    "stomp",
    "threadless",
    "workitem",
    "pool_party",
];
const INJECT_DLL_METHOD_VALUES: &[&str] = &["classic", "manual_map", "phantom", "reflective"];
const INJECT_SPAWN_METHOD_VALUES: &[&str] = &[
    "hollow",
    "ghost",
    "doppelgang",
    "herpaderp",
    "early_bird",
    "transacted",
];
const HOOK_INSTALL_METHOD_VALUES: &[&str] = &["iat", "inline"];
const STEALTH_SYSCALL_METHOD_VALUES: &[&str] = &["direct", "indirect", "int2e"];
const STEALTH_POLICY_METHOD_VALUES: &[&str] = &[
    "auto",
    "driver_ci",
    "ci_options",
    "dse_bypass",
    "registry",
    "wmi",
    "kernel_rw",
];
const STEALTH_SYSMON_METHOD_VALUES: &[&str] = &["etw_only", "full"];
const STEALTH_BCD_METHOD_VALUES: &[&str] = &["registry", "hook"];
const STEALTH_CI_ACTION_VALUES: &[&str] = &["patch", "restore", "query"];
const STEALTH_EXCLUSION_TYPE_VALUES: &[&str] = &["path", "process", "extension"];
const STEALTH_MPCMD_COMMAND_VALUES: &[&str] = &[
    "remove_definitions",
    "restore_defaults",
    "add_exclusion",
    "remove_exclusion",
    "scan",
    "cancel_scan",
];
const STEALTH_FIREWALL_DIRECTION_VALUES: &[&str] = &["in", "out"];
const STEALTH_FIREWALL_RULE_ACTION_VALUES: &[&str] = &["allow", "block"];
const STEALTH_FIREWALL_PROFILE_VALUES: &[&str] = &["domain", "private", "public", "all"];
const ORCHESTRATE_TEMPLATE_VALUES: &[&str] = &[
    "lab_validation",
    "memory_diagnostics",
    "driver_readiness",
    "reconnaissance",
    "cleanup",
    "privilege_review",
];
const KERNEL_REG_ACTION_VALUES: &[&str] = &["add", "remove", "list", "clear"];
const KERNEL_REG_FLAGS_VALUES: &[&str] = &["delete", "modify", "create", "all"];
const KERNEL_NOTIFY_TYPE_VALUES: &[&str] = &["process", "thread", "image"];
const KERNEL_CALLBACK_TYPE_VALUES: &[&str] = &["process", "thread", "image", "load_image"];
const KERNEL_NOTIFY_ACTION_VALUES: &[&str] = &["register", "unregister", "query"];
const KERNEL_OBJ_ACTION_VALUES: &[&str] = &["register", "unregister", "query"];
const KERNEL_DEBUG_ACTION_VALUES: &[&str] = &["clear_port", "no_debug", "hide"];
const KERNEL_DPC_ACTION_VALUES: &[&str] = &["schedule", "cancel", "query"];
const KERNEL_PORT_ACTION_VALUES: &[&str] = &["add", "remove", "list", "clear"];
const KERNEL_PORT_PROTOCOL_VALUES: &[&str] = &["tcp", "udp"];
const KERNEL_TOKEN_ACTION_VALUES: &[&str] = &["copy", "system", "restore"];
const KERNEL_TESTSIGN_ACTION_VALUES: &[&str] = &["query", "hide_shared", "hide_ci", "restore"];
const KERNEL_HOOK_ACTION_VALUES: &[&str] = &["install", "remove", "query"];
const KERNEL_HOOK_TYPE_VALUES: &[&str] = &["inline", "iat", "infinity"];
const KERNEL_INJECT_ACTION_VALUES: &[&str] = &["enable", "disable", "query"];
const KERNEL_INFHOOK_ACTION_VALUES: &[&str] = &["enable", "disable", "query"];
const KERNEL_CI_ACTION_VALUES: &[&str] = &["patch", "restore", "query"];
const KERNEL_PTE_ACTION_VALUES: &[&str] = &["read", "write", "make_writable", "restore"];
const KERNEL_PPL_ACTION_VALUES: &[&str] = &["strip", "set", "query"];
const KERNEL_MSR_ACTION_VALUES: &[&str] = &["read", "write"];
const KERNEL_CLOAK_ACTION_VALUES: &[&str] = &["self", "target", "query"];
const KERNEL_KILL_METHOD_VALUES: &[&str] = &["terminate", "dkom", "thread_kill"];
const KERNEL_THREAD_ACTION_VALUES: &[&str] = &["create", "query"];
const KERNEL_EXEC_ACTION_VALUES: &[&str] = &["run", "alloc", "free"];
const KERNEL_CB_ACTION_VALUES: &[&str] = &["enum", "remove", "nuke_all", "restore"];
const KERNEL_CB_TYPE_VALUES: &[&str] = &["process", "thread", "image", "object", "registry"];
const KERNEL_MF_ACTION_VALUES: &[&str] = &["enum", "detach", "nuke"];
const KERNEL_APC_ACTION_VALUES: &[&str] = &["inject", "dll"];
const KERNEL_WFP_ACTION_VALUES: &[&str] = &["enum", "remove", "nuke"];
const KERNEL_PATCH_TYPE_VALUES: &[&str] = &["etw_ti", "dse"];
const KERNEL_STRIP_TYPE_VALUES: &[&str] = &["process", "thread"];
const KERNEL_DPC_OPERATION_VALUES: &[&str] = &["log", "hide_process", "escalate_token"];
const KERNEL_CR_ACTION_VALUES: &[&str] = &["read", "write"];
const KERNEL_IDT_ACTION_VALUES: &[&str] = &["read", "write", "dump"];
const KERNEL_UNLOADED_ACTION_VALUES: &[&str] = &["query", "clear_all", "clear_name"];
const KERNEL_SWAP_ACTION_VALUES: &[&str] = &["steal", "swap", "query"];
const KERNEL_PROTECT_ACTION_VALUES: &[&str] = &["set", "strip", "query"];
const KERNEL_KEYLOG_ACTION_VALUES: &[&str] = &["start", "stop", "read", "query"];
const KERNEL_LOCK_ACTION_VALUES: &[&str] = &["add", "remove", "list", "clear"];
const KERNEL_ETW_ACTION_VALUES: &[&str] = &["disable", "enable", "kill_all", "query"];
const KERNEL_SPOOF_ACTION_VALUES: &[&str] = &["image_name", "command_line", "pid", "query"];
const KERNEL_LOG_ACTION_VALUES: &[&str] = &[
    "clear_all",
    "clear_security",
    "clear_system",
    "clear_sysmon",
    "kill_service",
];
const KERNEL_CRED_ACTION_VALUES: &[&str] = &["find_lsass", "read", "dump"];
const KERNEL_IMP_ACTION_VALUES: &[&str] = &["swap", "restore", "query"];
const KERNEL_INJECT_FLAG_VALUES: &[&str] = &["ntquery", "etw", "amsi", "custom"];
const PRIVILEGE_ELEVATE_METHOD_VALUES: &[&str] = &[
    "auto",
    "fodhelper",
    "eventvwr",
    "computerdefaults",
    "sdclt",
    "disk_cleanup",
    "mock_trusted_dir",
    "request_uac",
    "system",
];
const PRIVILEGE_POTATO_METHOD_VALUES: &[&str] = &["print_spoofer", "god_potato", "efs_potato"];
const PRIVILEGE_SYMLINK_TYPE_VALUES: &[&str] = &["symlink", "hardlink", "junction"];
const SELF_STATE_SUB_ACTION_VALUES: &[&str] = &[
    "get",
    "reset",
    "score",
    "history",
    "operations",
    "mutations",
    "rollback",
    "replay",
    "replay_dry_run",
    "timeline",
    "observability",
    "artifact_cleanup",
];

const CHOICE_PARAMETERS: &[ChoiceParameterDescriptor] = &[
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "read",
        parameter: "mode",
        values: MEMORY_READ_MODE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "read",
        parameter: "region_cache",
        values: MEMORY_REGION_CACHE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "typed_read",
        parameter: "type",
        values: MEMORY_TYPED_PRIMITIVE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "typed_read",
        parameter: "endian",
        values: MEMORY_ENDIAN_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "typed_write",
        parameter: "type",
        values: MEMORY_TYPED_PRIMITIVE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "typed_write",
        parameter: "endian",
        values: MEMORY_ENDIAN_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "scan_mode",
        values: MEMORY_SCAN_MODE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "scan_type",
        values: MEMORY_SCAN_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "change",
        values: MEMORY_CHANGE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "direction",
        values: MEMORY_DELTA_DIRECTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "encoding",
        values: MEMORY_STRING_ENCODING_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan",
        parameter: "region_cache",
        values: MEMORY_REGION_CACHE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan_new",
        parameter: "value_type",
        values: MEMORY_SCAN_NEW_VALUE_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan_new",
        parameter: "region_cache",
        values: MEMORY_REGION_CACHE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "memory",
        action: "scan_list",
        parameter: "sort",
        values: MEMORY_SCAN_LIST_SORT_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "self",
        action: "state",
        parameter: "sub_action",
        values: SELF_STATE_SUB_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "privilege",
        action: "elevate",
        parameter: "method",
        values: PRIVILEGE_ELEVATE_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "privilege",
        action: "potato",
        parameter: "method",
        values: PRIVILEGE_POTATO_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "privilege",
        action: "symlink",
        parameter: "type",
        values: PRIVILEGE_SYMLINK_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "template",
        values: ORCHESTRATE_TEMPLATE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "payload",
        action: "pe_parse",
        parameter: "show",
        values: PAYLOAD_PE_PARSE_SHOW_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "payload",
        action: "obfuscate",
        parameter: "obf_method",
        values: PAYLOAD_OBFUSCATION_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "payload",
        action: "serialize",
        parameter: "format",
        values: PAYLOAD_SERIALIZE_FORMAT_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "hook",
        action: "hook_function",
        parameter: "method",
        values: HOOK_INSTALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "hook",
        action: "install",
        parameter: "method",
        values: HOOK_INSTALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "inject",
        action: "shellcode",
        parameter: "method",
        values: INJECT_SHELLCODE_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "inject",
        action: "dll",
        parameter: "dll_method",
        values: INJECT_DLL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "inject",
        action: "spawn",
        parameter: "spawn_method",
        values: INJECT_SPAWN_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "syscall_write",
        parameter: "syscall_method",
        values: STEALTH_SYSCALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "syscall_alloc",
        parameter: "syscall_method",
        values: STEALTH_SYSCALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "syscall_protect",
        parameter: "syscall_method",
        values: STEALTH_SYSCALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "syscall_read",
        parameter: "syscall_method",
        values: STEALTH_SYSCALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "syscall_thread",
        parameter: "syscall_method",
        values: STEALTH_SYSCALL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "sysmon_blind",
        parameter: "sysmon_method",
        values: STEALTH_SYSMON_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "testsign_hide_bcd",
        parameter: "bcd_method",
        values: STEALTH_BCD_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "wdac_disable",
        parameter: "method",
        values: STEALTH_POLICY_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "wdac_restore",
        parameter: "method",
        values: STEALTH_POLICY_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "defender_disable",
        parameter: "method",
        values: STEALTH_POLICY_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "defender_restore",
        parameter: "method",
        values: STEALTH_POLICY_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "testsign_ci_callback",
        parameter: "ci_action",
        values: STEALTH_CI_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "testsign_ci_func_patch",
        parameter: "ci_action",
        values: STEALTH_CI_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "defender_add_exclusion",
        parameter: "exclusion_type",
        values: STEALTH_EXCLUSION_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "defender_mpcmdrun",
        parameter: "command",
        values: STEALTH_MPCMD_COMMAND_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "firewall_add_rule",
        parameter: "direction",
        values: STEALTH_FIREWALL_DIRECTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "firewall_add_rule",
        parameter: "rule_action",
        values: STEALTH_FIREWALL_RULE_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "firewall_disable",
        parameter: "profiles",
        values: STEALTH_FIREWALL_PROFILE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "stealth",
        action: "firewall_enable",
        parameter: "profiles",
        values: STEALTH_FIREWALL_PROFILE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_protect",
        parameter: "reg_action",
        values: KERNEL_REG_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_hide",
        parameter: "reg_action",
        values: KERNEL_REG_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_reg_protect",
        parameter: "reg_flags",
        values: KERNEL_REG_FLAGS_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_notify_routine",
        parameter: "notify_type",
        values: KERNEL_NOTIFY_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_notify_routine",
        parameter: "notify_action",
        values: KERNEL_NOTIFY_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_enum",
        parameter: "callback_type",
        values: KERNEL_CALLBACK_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_remove",
        parameter: "callback_type",
        values: KERNEL_CALLBACK_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_object_hook",
        parameter: "obj_action",
        values: KERNEL_OBJ_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_set_debug_port",
        parameter: "debug_action",
        values: KERNEL_DEBUG_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_dpc_timer",
        parameter: "dpc_action",
        values: KERNEL_DPC_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_port_hide",
        parameter: "port_action",
        values: KERNEL_PORT_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_port_hide",
        parameter: "protocol",
        values: KERNEL_PORT_PROTOCOL_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_token_dup",
        parameter: "token_action",
        values: KERNEL_TOKEN_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_testsign_hide",
        parameter: "testsign_action",
        values: KERNEL_TESTSIGN_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        parameter: "hook_action",
        values: KERNEL_HOOK_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_global_hook",
        parameter: "hook_type",
        values: KERNEL_HOOK_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_auto_inject",
        parameter: "inject_action",
        values: KERNEL_INJECT_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_infinity_hook",
        parameter: "infhook_action",
        values: KERNEL_INFHOOK_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_ci_callback_patch",
        parameter: "ci_action",
        values: KERNEL_CI_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_ci_func_patch",
        parameter: "ci_action",
        values: KERNEL_CI_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_pte_rw",
        parameter: "pte_action",
        values: KERNEL_PTE_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_ppl_bypass",
        parameter: "ppl_action",
        values: KERNEL_PPL_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_msr_rw",
        parameter: "msr_action",
        values: KERNEL_MSR_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_cloak",
        parameter: "cloak_action",
        values: KERNEL_CLOAK_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_force_kill",
        parameter: "kill_method",
        values: KERNEL_KILL_METHOD_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_system_thread",
        parameter: "thread_action",
        values: KERNEL_THREAD_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_exec",
        parameter: "exec_action",
        values: KERNEL_EXEC_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_nuke",
        parameter: "cb_action",
        values: KERNEL_CB_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_callback_nuke",
        parameter: "cb_type",
        values: KERNEL_CB_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_minifilter_detach",
        parameter: "mf_action",
        values: KERNEL_MF_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_kernel_apc",
        parameter: "apc_action",
        values: KERNEL_APC_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_wfp_remove",
        parameter: "wfp_action",
        values: KERNEL_WFP_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_patch_kernel",
        parameter: "patch_type",
        values: KERNEL_PATCH_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_handle_strip",
        parameter: "strip_type",
        values: KERNEL_STRIP_TYPE_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_dpc_timer",
        parameter: "dpc_operation",
        values: KERNEL_DPC_OPERATION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_cr_rw",
        parameter: "cr_action",
        values: KERNEL_CR_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_idt_rw",
        parameter: "idt_action",
        values: KERNEL_IDT_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_unloaded_drv_clear",
        parameter: "unloaded_action",
        values: KERNEL_UNLOADED_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_token_swap",
        parameter: "swap_action",
        values: KERNEL_SWAP_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_process_protect",
        parameter: "protect_action",
        values: KERNEL_PROTECT_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_keylogger",
        parameter: "keylog_action",
        values: KERNEL_KEYLOG_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_file_lock",
        parameter: "lock_action",
        values: KERNEL_LOCK_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_etw_blind",
        parameter: "etw_action",
        values: KERNEL_ETW_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_eprocess_spoof",
        parameter: "spoof_action",
        values: KERNEL_SPOOF_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_event_log_clear",
        parameter: "log_action",
        values: KERNEL_LOG_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_cred_dump",
        parameter: "cred_action",
        values: KERNEL_CRED_ACTION_VALUES,
    },
    ChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_impersonate",
        parameter: "imp_action",
        values: KERNEL_IMP_ACTION_VALUES,
    },
];

pub fn all_choice_parameters() -> &'static [ChoiceParameterDescriptor] {
    CHOICE_PARAMETERS
}

pub fn choice_parameters(tool: &str, action: &str) -> Vec<ChoiceParameterDescriptor> {
    all_choice_parameters()
        .iter()
        .copied()
        .filter(|descriptor| descriptor.applies_to(tool, action))
        .collect()
}

pub fn choice_values(tool: &str, action: &str, parameter: &str) -> Option<&'static [&'static str]> {
    all_choice_parameters()
        .iter()
        .find(|descriptor| {
            descriptor.tool == tool
                && descriptor.action == action
                && descriptor.parameter == parameter
        })
        .map(|descriptor| descriptor.values)
}

pub fn choice_values_csv(tool: &str, action: &str, parameter: &str) -> Option<String> {
    choice_values(tool, action, parameter).map(|values| values.join(", "))
}

const ARRAY_CHOICE_PARAMETERS: &[ArrayChoiceParameterDescriptor] =
    &[ArrayChoiceParameterDescriptor {
        tool: "kernel",
        action: "driver_auto_inject",
        parameter: "inject_flags",
        values: KERNEL_INJECT_FLAG_VALUES,
    }];

pub fn all_array_choice_parameters() -> &'static [ArrayChoiceParameterDescriptor] {
    ARRAY_CHOICE_PARAMETERS
}

pub fn array_choice_parameters(tool: &str, action: &str) -> Vec<ArrayChoiceParameterDescriptor> {
    all_array_choice_parameters()
        .iter()
        .copied()
        .filter(|descriptor| descriptor.applies_to(tool, action))
        .collect()
}

pub fn array_choice_values(
    tool: &str,
    action: &str,
    parameter: &str,
) -> Option<&'static [&'static str]> {
    all_array_choice_parameters()
        .iter()
        .find(|descriptor| {
            descriptor.tool == tool
                && descriptor.action == action
                && descriptor.parameter == parameter
        })
        .map(|descriptor| descriptor.values)
}

const PARAMETER_BOUNDS: &[ParameterBoundsDescriptor] = &[
    target_action_bounds("ps_list", "limit", Some(1), Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("ps_list", "offset", None, Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("modules", "limit", Some(1), Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("modules", "offset", None, Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("threads", "limit", Some(1), Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("threads", "offset", None, Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds(
        "threads_list",
        "limit",
        Some(1),
        Some(TARGET_MAX_RESULT_LIMIT),
    ),
    target_action_bounds(
        "threads_list",
        "offset",
        None,
        Some(TARGET_MAX_RESULT_LIMIT),
    ),
    target_action_bounds("handles", "limit", Some(1), Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("handles", "offset", None, Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("windows", "limit", Some(1), Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("windows", "offset", None, Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("windows", "wait_ms", None, Some(TARGET_MAX_WINDOW_WAIT_MS)),
    target_action_bounds("mem_find", "limit", Some(1), Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds("mem_find", "offset", None, Some(TARGET_MAX_RESULT_LIMIT)),
    target_action_bounds(
        "string_read",
        "max_len",
        Some(1),
        Some(TARGET_MAX_STRING_READ_BYTES),
    ),
    action_bounds(
        "kernel",
        "driver_enum_process",
        "max_entries",
        None,
        Some(KERNEL_MAX_ENUM_PROCESS_ENTRIES),
    ),
    action_bounds(
        "kernel",
        "driver_callback_enum",
        "max_entries",
        None,
        Some(KERNEL_MAX_CALLBACK_ENUM_ENTRIES),
    ),
    action_bounds(
        "kernel",
        "driver_memory_pool",
        "max_entries",
        None,
        Some(KERNEL_MAX_MEMORY_POOL_ENTRIES),
    ),
    action_bounds(
        "kernel",
        "driver_notify_routine",
        "max_events",
        None,
        Some(KERNEL_MAX_NOTIFY_EVENTS),
    ),
    action_bounds(
        "kernel",
        "driver_process_dump",
        "max_size",
        None,
        Some(KERNEL_MAX_PROCESS_DUMP_BYTES),
    ),
    action_bounds(
        "kernel",
        "driver_process_dump",
        "max_dump_size",
        None,
        Some(KERNEL_MAX_PROCESS_DUMP_BYTES),
    ),
    action_bounds(
        "kernel",
        "driver_keylogger",
        "max_keys",
        None,
        Some(KERNEL_MAX_KEYLOG_KEYS),
    ),
    action_bounds(
        "kernel",
        "driver_cred_dump",
        "size",
        None,
        Some(KERNEL_MAX_CRED_DUMP_BYTES),
    ),
    action_bounds(
        "kernel",
        "physical_read",
        "size",
        None,
        Some(KERNEL_MAX_PHYSICAL_READ_BYTES),
    ),
    action_bounds(
        "kernel",
        "driver_port_hide",
        "port",
        None,
        Some(KERNEL_MAX_PORT_NUMBER),
    ),
    action_bounds(
        "kernel",
        "driver_cr_rw",
        "cr_index",
        None,
        Some(KERNEL_MAX_CR_INDEX),
    ),
    action_bounds(
        "kernel",
        "driver_idt_rw",
        "vector",
        None,
        Some(KERNEL_MAX_IDT_VECTOR),
    ),
    action_bounds(
        "kernel",
        "driver_idt_rw",
        "new_dpl",
        None,
        Some(KERNEL_MAX_DPL),
    ),
    action_bounds(
        "kernel",
        "driver_apc_inject",
        "shellcode_size",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    action_bounds(
        "kernel",
        "driver_kernel_apc",
        "shellcode_size",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "shellcode",
        "variant",
        Some(1),
        Some(INJECT_MAX_POOL_PARTY_VARIANT),
    ),
    inject_action_bounds(
        "fiber",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "threadpool",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "stack_bomb",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "pool_party_worker",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "pool_party_work",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "pool_party_direct",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "pool_party_timer",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "export_forward",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "spawn",
        "payload",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    inject_action_bounds(
        "spawn",
        "shellcode",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    action_bounds(
        "payload",
        "obfuscate",
        "payload",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    action_bounds(
        "payload",
        "obfuscate",
        "payload_hex",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    action_bounds(
        "payload",
        "obfuscate",
        "key",
        Some(1),
        Some(PAYLOAD_MAX_OBFUSCATION_KEY_BYTES),
    ),
    action_bounds(
        "payload",
        "obfuscate",
        "strings",
        Some(1),
        Some(PAYLOAD_MAX_SERIALIZE_PARAMS),
    ),
    action_bounds(
        "payload",
        "cleanup",
        "addresses",
        None,
        Some(PAYLOAD_MAX_CLEANUP_ITEMS),
    ),
    action_bounds(
        "payload",
        "cleanup",
        "thread_handles",
        None,
        Some(PAYLOAD_MAX_CLEANUP_ITEMS),
    ),
    action_bounds(
        "payload",
        "serialize",
        "params",
        Some(1),
        Some(PAYLOAD_MAX_SERIALIZE_PARAMS),
    ),
    action_bounds(
        "hook",
        "detour",
        "hooks",
        Some(1),
        Some(HOOK_MAX_DETOUR_HOOKS),
    ),
    action_bounds(
        "hook",
        "restore",
        "original_bytes",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    memory_action_bounds("read", "size", Some(1), Some(MEMORY_MAX_READ_BYTES)),
    memory_region_cache_ttl_bounds(
        "read",
        "region_cache_ttl_ms",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS,
    ),
    memory_region_cache_ttl_bounds(
        "read",
        "region_cache_ttl_secs",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS / 1000,
    ),
    memory_region_cache_ttl_bounds(
        "scan",
        "region_cache_ttl_ms",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS,
    ),
    memory_region_cache_ttl_bounds(
        "scan",
        "region_cache_ttl_secs",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS / 1000,
    ),
    memory_region_cache_ttl_bounds(
        "scan_new",
        "region_cache_ttl_ms",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS,
    ),
    memory_region_cache_ttl_bounds(
        "scan_new",
        "region_cache_ttl_secs",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS / 1000,
    ),
    memory_scan_bounds("limit", Some(1), Some(MEMORY_MAX_SCAN_LIMIT)),
    memory_scan_bounds("offset", None, Some(MEMORY_MAX_SCAN_LIMIT)),
    memory_scan_bounds("timeout_secs", Some(1), Some(MEMORY_MAX_SCAN_TIMEOUT_SECS)),
    memory_scan_bounds(
        "context_bytes",
        None,
        Some(MEMORY_MAX_PATTERN_CONTEXT_BYTES),
    ),
    memory_scan_bounds("max_depth", Some(1), Some(MEMORY_MAX_POINTER_SCAN_DEPTH)),
    memory_scan_bounds("alignment", Some(1), Some(MEMORY_MAX_SCAN_ALIGNMENT)),
    memory_scan_bounds(
        "signature",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    memory_action_bounds(
        "scan_new",
        "signature",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    memory_action_bounds(
        "write",
        "bytes",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    memory_action_bounds(
        "scan_list",
        "limit",
        Some(1),
        Some(crate::memory::session::MAX_SCAN_RESULT_PAGE_LIMIT as u64),
    ),
    memory_action_bounds(
        "scan_list",
        "offset",
        None,
        Some(crate::memory::session::MAX_SCAN_RESULT_OFFSET as u64),
    ),
    memory_action_bounds("alloc", "size", Some(1), Some(MEMORY_MAX_OPERATION_BYTES)),
    memory_action_bounds("protect", "size", Some(1), Some(MEMORY_MAX_OPERATION_BYTES)),
    ParameterBoundsDescriptor {
        tool: "hook",
        action: "install_hwbp",
        parameter: "dr_index",
        minimum: Some(0),
        maximum: Some(3),
    },
    ParameterBoundsDescriptor {
        tool: "hook",
        action: "remove_hwbp",
        parameter: "dr_index",
        minimum: Some(0),
        maximum: Some(3),
    },
    ParameterBoundsDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "region_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "suspicious_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "module_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "handle_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "entropy_region_limit",
        minimum: None,
        maximum: Some(128),
    },
    ParameterBoundsDescriptor {
        tool: "memory",
        action: "diagnostics",
        parameter: "entropy_sample_bytes",
        minimum: None,
        maximum: Some(64 * 1024),
    },
    memory_region_cache_ttl_bounds(
        "diagnostics",
        "region_cache_ttl_ms",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS,
    ),
    memory_region_cache_ttl_bounds(
        "diagnostics",
        "region_cache_ttl_secs",
        crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS / 1000,
    ),
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "mutate_code",
        parameter: "size",
        minimum: Some(1),
        maximum: Some(0x10000),
    },
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "module_stomp",
        parameter: "shellcode",
        minimum: Some(1),
        maximum: Some(crate::args::DEFAULT_MAX_BYTES as u64),
    },
    stealth_action_bounds(
        "syscall_write",
        "bytes",
        Some(1),
        Some(crate::args::DEFAULT_MAX_BYTES as u64),
    ),
    stealth_action_bounds(
        "syscall_alloc",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    stealth_action_bounds(
        "syscall_protect",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    stealth_action_bounds("syscall_read", "size", Some(1), Some(MEMORY_MAX_READ_BYTES)),
    stealth_action_bounds(
        "syscall_stealth_read",
        "size",
        Some(1),
        Some(MEMORY_MAX_READ_BYTES),
    ),
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "sleep_gargoyle",
        parameter: "shellcode",
        minimum: Some(1),
        maximum: Some(crate::args::DEFAULT_MAX_BYTES as u64),
    },
    stealth_action_bounds(
        "sleep_ekko",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    stealth_action_bounds(
        "sleep_foliage",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    stealth_action_bounds(
        "sleep_death",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    stealth_action_bounds(
        "encrypt_memory",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "syscall_inject",
        parameter: "shellcode",
        minimum: Some(1),
        maximum: Some(crate::args::DEFAULT_MAX_BYTES as u64),
    },
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "mutate_code",
        parameter: "intensity",
        minimum: Some(1),
        maximum: Some(3),
    },
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "sentinel_start",
        parameter: "interval_ms",
        minimum: Some(1000),
        maximum: Some(300000),
    },
    ParameterBoundsDescriptor {
        tool: "stealth",
        action: "sentinel_self_destruct",
        parameter: "passes",
        minimum: Some(1),
        maximum: Some(7),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "region_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "suspicious_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "module_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "handle_limit",
        minimum: None,
        maximum: Some(1024),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "entropy_region_limit",
        minimum: None,
        maximum: Some(128),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "memory_diagnostics",
        parameter: "entropy_sample_bytes",
        minimum: None,
        maximum: Some(64 * 1024),
    },
    action_bounds(
        "self",
        "protect_encrypt",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    action_bounds(
        "self",
        "protect_wipe",
        "size",
        Some(1),
        Some(MEMORY_MAX_OPERATION_BYTES),
    ),
    ParameterBoundsDescriptor {
        tool: "self",
        action: "diagnostics",
        parameter: "recent_task_limit",
        minimum: Some(1),
        maximum: Some(100),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "diagnostics",
        parameter: "limit",
        minimum: Some(1),
        maximum: Some(100),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "state",
        parameter: "limit",
        minimum: Some(1),
        maximum: Some(500),
    },
    ParameterBoundsDescriptor {
        tool: "self",
        action: "state",
        parameter: "offset",
        minimum: Some(0),
        maximum: None,
    },
    ParameterBoundsDescriptor {
        tool: "orchestrate",
        action: "execute",
        parameter: "limit",
        minimum: Some(1),
        maximum: Some(crate::orchestration::engine::MAX_ORCHESTRATION_PAGE_LIMIT as u64),
    },
    ParameterBoundsDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "limit",
        minimum: Some(1),
        maximum: Some(crate::orchestration::engine::MAX_ORCHESTRATION_PAGE_LIMIT as u64),
    },
    ParameterBoundsDescriptor {
        tool: "orchestrate",
        action: "plan",
        parameter: "steps",
        minimum: Some(1),
        maximum: Some(crate::orchestration::engine::MAX_PLAN_STEPS as u64),
    },
];

pub fn all_parameter_bounds() -> &'static [ParameterBoundsDescriptor] {
    PARAMETER_BOUNDS
}

pub fn parameter_bounds(tool: &str, action: &str) -> Vec<ParameterBoundsDescriptor> {
    all_parameter_bounds()
        .iter()
        .copied()
        .filter(|descriptor| descriptor.applies_to(tool, action))
        .collect()
}

pub fn parser_hints(tool: &str, action: &str) -> Vec<ParserHintDescriptor> {
    let optional = optional_parameters(tool, action);
    let required = required_parameters(tool, action);
    let conditional_required = conditional_required_parameters(tool, action);
    let alternative_required = alternative_required_parameters(tool, action);
    let aliases = parameter_aliases(tool, action);
    let choices = choice_parameters(tool, action);
    let array_choices = array_choice_parameters(tool, action);
    let bounds = parameter_bounds(tool, action);
    let mut parameters = optional
        .iter()
        .map(|value| value.parameter.to_string())
        .collect::<Vec<_>>();
    parameters.extend(required.iter().map(|value| (*value).to_string()));

    parameters.extend(conditional_required.iter().flat_map(|condition| {
        std::iter::once(condition.when_parameter.to_string()).chain(
            condition
                .parameters
                .iter()
                .map(|value| (*value).to_string()),
        )
    }));
    parameters.extend(alternative_required.iter().flat_map(|alternative| {
        alternative
            .when_parameter
            .into_iter()
            .map(str::to_string)
            .chain(
                alternative
                    .parameters
                    .iter()
                    .map(|value| (*value).to_string()),
            )
    }));
    parameters.extend(
        aliases
            .iter()
            .flat_map(|alias| [alias.canonical.to_string(), alias.alias.to_string()]),
    );
    parameters.extend(choices.iter().map(|choice| choice.parameter.to_string()));
    parameters.extend(
        array_choices
            .iter()
            .map(|choice| choice.parameter.to_string()),
    );
    parameters.extend(bounds.iter().map(|bound| bound.parameter.to_string()));
    parameters.sort();
    parameters.dedup();

    parameters
        .into_iter()
        .map(|parameter| {
            let canonical = aliases
                .iter()
                .find(|alias| alias.alias == parameter)
                .map(|alias| alias.canonical)
                .unwrap_or(parameter.as_str());
            let related_aliases = aliases
                .iter()
                .filter(|alias| alias.canonical == canonical)
                .map(|alias| alias.alias)
                .collect::<Vec<_>>();
            let parser = optional
                .iter()
                .find(|optional| optional.parameter == canonical)
                .map(|optional| optional.parser)
                .or_else(|| {
                    array_choices
                        .iter()
                        .any(|choice| choice.parameter == canonical)
                        .then_some("string_array")
                })
                .unwrap_or_else(|| parser_hint_for_tool_parameter(tool, action, canonical));
            let related_choices = choices
                .iter()
                .find(|choice| choice.parameter == canonical)
                .map(|choice| choice.values.to_vec())
                .unwrap_or_else(|| {
                    if parser == "protection" {
                        PAGE_PROTECTION_SYMBOLIC_VALUES.to_vec()
                    } else {
                        Vec::new()
                    }
                });
            let related_bounds = bounds
                .iter()
                .filter(|bound| bound.parameter == canonical)
                .collect::<Vec<_>>();
            let minimum = related_bounds
                .iter()
                .filter_map(|bound| bound.minimum)
                .min();
            let maximum = related_bounds
                .iter()
                .filter_map(|bound| bound.maximum)
                .max();
            let object_item_schema = object_item_schema_for_parameter(tool, action, canonical);

            ParserHintDescriptor {
                parser,
                array_item_parser: array_item_parser_for_parameter(tool, action, canonical, parser),
                required: required.iter().any(|candidate| *candidate == canonical),
                parameter,
                aliases: related_aliases,
                choices: related_choices,
                minimum,
                maximum,
                object_item_schema,
            }
        })
        .collect()
}

pub fn object_item_schema_for_parameter(
    tool: &str,
    action: &str,
    parameter: &str,
) -> Option<ObjectItemSchemaDescriptor> {
    match (tool, action, parameter) {
        ("hook", "detour", "hooks") => Some(HOOK_DETOUR_HOOK_ITEM_SCHEMA),
        ("orchestrate", "plan", "steps") => Some(ORCHESTRATE_STEP_ITEM_SCHEMA),
        _ => None,
    }
}

const MEMORIC_ACTIONS: &[&str] = &["guide", "status", "domain", "goal"];
const TARGET_ACTIONS: &[&str] = &[
    "ps_list",
    "ps_find",
    "ps_info",
    "modules",
    "threads",
    "threads_list",
    "thread_suspend",
    "thread_resume",
    "thread_context",
    "handles",
    "env",
    "cmdline",
    "windows",
    "peb",
    "module_base",
    "mem_find",
    "string_read",
    "string_write",
    "callstack",
    "heap",
    "cred_dump",
    "sam_dump",
    "kerberos_tickets",
];
const MEMORY_ACTIONS: &[&str] = &[
    "read",
    "typed_read",
    "write",
    "typed_write",
    "write_string",
    "scan",
    "query",
    "query_find",
    "alloc",
    "free",
    "protect",
    "scan_new",
    "scan_next",
    "scan_undo",
    "scan_list",
    "scan_reset",
    "scan_freeze",
    "diagnostics",
];
const INJECT_ACTIONS: &[&str] = &[
    "shellcode",
    "dll",
    "spawn",
    "hijack_enum",
    "hijack_backup",
    "hijack_redirect",
    "hijack_restore",
    "hijack_wait",
    "create_remote_thread",
    "nt_create_thread",
    "fiber",
    "threadpool",
    "stack_bomb",
    "pool_party_worker",
    "pool_party_work",
    "pool_party_direct",
    "pool_party_timer",
    "export_forward",
    "phantom_hollow",
    "transacted_hollow",
    "wow64_detect",
];
const PAYLOAD_ACTIONS: &[&str] = &[
    "pe_parse",
    "obfuscate",
    "wait",
    "exit_code",
    "cleanup",
    "serialize",
];
const HOOK_ACTIONS: &[&str] = &[
    "hook_function",
    "install",
    "install_iat",
    "remove",
    "remove_iat",
    "install_hwbp",
    "remove_hwbp",
    "trampoline",
    "detour",
    "restore",
    "winhook",
    "hwbp_syscall",
];
const STEALTH_ACTIONS: &[&str] = &[
    "patch_etw",
    "patch_amsi",
    "patch_cfg",
    "patch_cig",
    "unhook_ntdll",
    "unhook_function",
    "hide_module",
    "fluctuate_module",
    "module_stomp",
    "sleep_ekko",
    "sleep_foliage",
    "sleep_gargoyle",
    "sleep_death",
    "spoof_callstack",
    "spoof_ppid",
    "spoof_return",
    "deep_stack_spoof",
    "syscall_write",
    "syscall_alloc",
    "syscall_protect",
    "syscall_thread",
    "syscall_open",
    "syscall_read",
    "syscall_query",
    "syscall_close",
    "syscall_free",
    "syscall_stealth_read",
    "syscall_inject",
    "encrypt_memory",
    "decrypt_memory",
    "mutate_code",
    "sysmon_blind",
    "timestomp",
    "etw_provider_disable",
    "etw_mass_disable",
    "create_suspended",
    "testsign_hide_ntquery",
    "testsign_hide_self",
    "testsign_hide_bcd",
    "testsign_query",
    "testsign_auto_inject",
    "testsign_launch_hooked",
    "testsign_kernel_bypass",
    "testsign_launch_clean",
    "testsign_ci_callback",
    "testsign_ci_func_patch",
    "testsign_pte_rw",
    "wdac_disable",
    "wdac_restore",
    "defender_disable",
    "defender_restore",
    "defender_status",
    "defender_add_exclusion",
    "defender_mpcmdrun",
    "firewall_add_rule",
    "firewall_remove_rule",
    "firewall_list_rules",
    "firewall_disable",
    "firewall_enable",
    "firewall_status",
    "sentinel_start",
    "sentinel_stop",
    "sentinel_status",
    "sentinel_self_destruct",
    "callback_enum_by_driver",
    "callback_masquerade",
    "etw_ti_selective_disable",
    "minifilter_enum_classified",
    "minifilter_selective_detach",
    "minifilter_pause",
    "minifilter_resume",
];
const DETECT_ACTIONS: &[&str] = &[
    "edr_products",
    "edr_hooks",
    "edr_quick_check",
    "edr_suspend",
    "etw_sessions",
    "veh_chain",
    "vm_sandbox",
    "hypervisor",
    "forensics",
    "integrity",
    "hooks",
    "hook_function",
    "syscall_resolve",
    "stealth_score",
    "bypass_recommendations",
];
const PRIVILEGE_ACTIONS: &[&str] = &[
    "elevate",
    "token_steal",
    "token_impersonate",
    "token_revert",
    "token_scan",
    "debug_priv",
    "check",
    "potato",
    "service_unquoted",
    "service_weak_perms",
    "service_always_elevated",
    "symlink",
];
const SELF_ACTIONS: &[&str] = &[
    "peb",
    "heap",
    "test",
    "memory_diagnostics",
    "status",
    "protect_init",
    "protect_encrypt",
    "protect_decrypt",
    "protect_wipe",
    "info",
    "version",
    "anti_debug",
    "state",
    "doctor",
    "diagnostics",
    "explain_error",
    "capability_diff",
    "next_steps",
];
const ORCHESTRATE_ACTIONS: &[&str] = &[
    "assess",
    "execute",
    "plan",
    "templates",
    "status",
    "resume",
    "cancel",
    "cleanup",
];
const KERNEL_ACTIONS: &[&str] = &[
    "status",
    "driver_load",
    "driver_unload",
    "driver_discover",
    "driver_auto",
    "read",
    "write",
    "physical_read",
    "physical_write",
    "pte_modify",
    "vad_hide",
    "sniff_start",
    "sniff_stop",
    "enum_callbacks",
    "remove_callback",
    "object_callback_enum",
    "object_callback_remove",
    "registry_callback_enum",
    "registry_callback_remove",
    "driver_notify_routine",
    "driver_reg_protect",
    "driver_object_hook",
    "driver_port_hide",
    "ppl_bypass",
    "dse_bypass",
    "dse_map_driver",
    "dkom_hide",
    "module_hide",
    "minifilter_enum",
    "minifilter_remove",
    "token_escalate",
    "etw_ti_remove",
    "driver_enum_process",
    "driver_module_hide",
    "driver_thread_hide",
    "driver_callback_enum",
    "driver_callback_remove",
    "driver_patch_kernel",
    "driver_apc_inject",
    "driver_handle_strip",
    "driver_pe_dump",
    "driver_set_debug_port",
    "driver_dpc_timer",
    "driver_token_dup",
    "driver_stats",
    "driver_memory_pool",
    "driver_minifilter_enum",
    "driver_process_dump",
    "driver_hypervisor_detect",
    "driver_testsign_hide",
    "driver_global_hook",
    "driver_auto_inject",
    "driver_infinity_hook",
    "driver_ci_callback_patch",
    "driver_ci_func_patch",
    "driver_pte_rw",
    "driver_msr_rw",
    "driver_cloak",
    "driver_force_kill",
    "driver_force_delete",
    "driver_system_thread",
    "driver_kernel_exec",
    "driver_ppl_bypass",
    "driver_cr_rw",
    "driver_idt_rw",
    "driver_unloaded_drv_clear",
    "driver_token_swap",
    "driver_process_protect",
    "driver_keylogger",
    "driver_reg_hide",
    "driver_file_lock",
    "driver_etw_blind",
    "driver_eprocess_spoof",
    "driver_event_log_clear",
    "driver_cred_dump",
    "driver_impersonate",
    "driver_callback_nuke",
    "driver_minifilter_detach",
    "driver_kernel_apc",
    "driver_wfp_remove",
];

const TOOL_DESCRIPTORS: &[ToolDescriptor] = &[
    ToolDescriptor {
        name: "memoric",
        description: "CALL THIS FIRST. Memory weapon guide & workflow assistant. Returns available capabilities, suggests optimal attack workflows, and shows current session status.",
        action_description: None,
        actions: MEMORIC_ACTIONS,
        handler: crate::mcp::guide::memoric_guide,
    },
    ToolDescriptor {
        name: "target",
        description: "[TARGET] Process/thread/module operations. List/find processes, enumerate threads, list loaded DLLs, suspend/resume threads, get thread context (RIP/RSP/RAX-R15).",
        action_description: Some("ps_list=enumerate all, ps_find=search by name, ps_info=detailed process info, modules=list DLLs, threads/threads_list=list threads, thread_suspend/resume/context control thread execution and register access"),
        actions: TARGET_ACTIONS,
        handler: crate::mcp::target_tool::handle_target,
    },
    ToolDescriptor {
        name: "memory",
        description: "[MEMORY] Memory read/write/scan/query plus guarded allocation, protection changes, scan sessions, and read-only diagnostics.",
        action_description: Some("Memory operation to perform. typed_read/typed_write handle primitive numeric values with endian and alignment metadata. write_string/query_find are explicit AI-friendly aliases for string writes and filtered region lookups. scan_new/scan_next/scan_undo/scan_list/scan_reset/scan_freeze = Cheat Engine-style persistent scan workflow. diagnostics = read-only defensive memory layout/profile summary."),
        actions: MEMORY_ACTIONS,
        handler: crate::mcp::memory_tool::handle_memory,
    },
    ToolDescriptor {
        name: "inject",
        description: "[INJECT] Authorized lab injection workflows, process hollowing variants, and thread hijacking helpers.",
        action_description: Some("Injection action. Prefer spawn(target_path=...) over legacy target_exe, and use dll_path for DLL-based actions."),
        actions: INJECT_ACTIONS,
        handler: crate::mcp::inject_tool::handle_inject,
    },
    ToolDescriptor {
        name: "payload",
        description: "[PAYLOAD] Payload utilities: PE parsing (imports/exports/sections/IAT), obfuscation (XOR/RC4/AES-256-CTR/polymorphic/UUID/IPv4/MAC), serialization, and injection lifecycle control.",
        action_description: Some("Payload action"),
        actions: PAYLOAD_ACTIONS,
        handler: crate::mcp::payload_tool::handle_payload,
    },
    ToolDescriptor {
        name: "hook",
        description: "[HOOK] Function hooking: IAT patching, inline detours (JMP), and hardware breakpoints (DR0-DR3, invisible to memory integrity checks). Also supports hook removal.",
        action_description: Some("Hook action. Prefer hook_function(method='iat'|'inline') over legacy install/install_iat aliases."),
        actions: HOOK_ACTIONS,
        handler: crate::mcp::hook_tool::handle_hook,
    },
    ToolDescriptor {
        name: "stealth",
        description: "[STEALTH] Defensive posture review plus explicitly authorized evasion lab actions for telemetry, syscall, module, and policy surfaces.",
        action_description: Some("Stealth action"),
        actions: STEALTH_ACTIONS,
        handler: crate::mcp::stealth_tool::handle_stealth,
    },
    ToolDescriptor {
        name: "detect",
        description: "[DETECT] EDR, hook, ETW, VM/sandbox, integrity, and forensic-tool checks.",
        action_description: Some("Detection action. Prefer hook_function(function_name=...) for single-function checks; hooks remains a compatibility umbrella."),
        actions: DETECT_ACTIONS,
        handler: crate::mcp::detect_tool::handle_detect,
    },
    ToolDescriptor {
        name: "privilege",
        description: "[PRIVILEGE] Privilege posture checks, token review, SeDebug handling, and policy-gated elevation workflows.",
        action_description: Some("Privilege action"),
        actions: PRIVILEGE_ACTIONS,
        handler: crate::mcp::privilege_tool::handle_privilege,
    },
    ToolDescriptor {
        name: "kernel",
        description: "[KERNEL] Driver/BYOVD operations, kernel memory, callbacks, ETW, PPL, DKOM, and other policy-gated kernel workflows.",
        action_description: Some("Kernel action. Groups: read-only status/readiness, generic helpers (driver_load/read/pte_modify/etc), hybrid actions (ppl_bypass/dkom_hide/token_escalate use memoric.sys unless device_path is provided), and direct memoric.sys actions (driver_*). Prefer canonical driver_* names over legacy aliases like notify_routine/reg_protect/object_hook/port_hide."),
        actions: KERNEL_ACTIONS,
        handler: crate::mcp::kernel_tool::handle_kernel,
    },
    ToolDescriptor {
        name: "self",
        description: "[SELF] Self introspection: read PEB, query heap info, memory self-test, and self-protection operations.",
        action_description: Some("Self action"),
        actions: SELF_ACTIONS,
        handler: crate::mcp::self_tool::handle_self,
    },
    ToolDescriptor {
        name: "orchestrate",
        description: "[ORCHESTRATE] Static planning, safe templates, environment assessment, and explicitly opted-in chain execution.",
        action_description: Some("assess=scan environment & recommend profile, execute=run chain, plan=static validation only, status=read readiness/checkpoint, resume=preview persisted checkpoint resume, cancel=mark persisted chain cancelled, cleanup=remove persisted chain checkpoint metadata"),
        actions: ORCHESTRATE_ACTIONS,
        handler: crate::mcp::orchestrate::handle_orchestrate,
    },
];

pub fn tool_descriptors() -> &'static [ToolDescriptor] {
    TOOL_DESCRIPTORS
}

pub fn tool_names() -> Vec<&'static str> {
    tool_descriptors()
        .iter()
        .map(|descriptor| descriptor.name)
        .collect()
}

pub fn guide_domain_values() -> Vec<&'static str> {
    let mut domains = tool_descriptors()
        .iter()
        .map(|descriptor| descriptor.name)
        .filter(|name| *name != "memoric")
        .collect::<Vec<_>>();
    domains.push("all");
    domains
}

fn guide_domain_schema() -> Value {
    json!({
        "type": "string",
        "description": "Show detailed help for a specific domain",
        "enum": guide_domain_values(),
    })
}

fn guide_goal_schema() -> Value {
    json!({
        "type": "string",
        "description": "Describe your objective for workflow suggestions (e.g. 'inject shellcode stealthily')",
    })
}

fn guide_status_schema() -> Value {
    json!({
        "type": "boolean",
        "description": "Show current session state",
        "default": false,
    })
}

const GUIDE_INPUT_FIELDS: &[GuideInputFieldDescriptor] = &[
    GuideInputFieldDescriptor {
        name: "domain",
        schema: guide_domain_schema,
    },
    GuideInputFieldDescriptor {
        name: "goal",
        schema: guide_goal_schema,
    },
    GuideInputFieldDescriptor {
        name: "status",
        schema: guide_status_schema,
    },
];

pub fn guide_input_fields() -> &'static [GuideInputFieldDescriptor] {
    GUIDE_INPUT_FIELDS
}

pub fn tool_actions(tool: &str) -> Option<&'static [&'static str]> {
    tool_descriptors()
        .iter()
        .find(|descriptor| descriptor.name == tool)
        .map(|descriptor| descriptor.actions)
}

pub fn tool_description(tool: &str) -> Option<&'static str> {
    tool_descriptors()
        .iter()
        .find(|descriptor| descriptor.name == tool)
        .map(|descriptor| descriptor.description)
}

pub fn registered_action(tool: &str, action: &str) -> Option<RegisteredAction> {
    let descriptor = tool_descriptors()
        .iter()
        .find(|descriptor| descriptor.name == tool)?;
    let (ordinal, name) = descriptor
        .actions
        .iter()
        .copied()
        .enumerate()
        .find(|(_, candidate)| *candidate == action)?;

    Some(RegisteredAction {
        tool: descriptor.name,
        name,
        ordinal,
        traits: classify_action(descriptor.name, name),
        optional_parameters: optional_parameters(descriptor.name, name),
        required_parameters: required_parameters(descriptor.name, name),
        parameter_aliases: parameter_aliases(descriptor.name, name),
        conditional_required_parameters: conditional_required_parameters(descriptor.name, name),
        alternative_required_parameters: alternative_required_parameters(descriptor.name, name),
        planner_warnings: planner_warnings(descriptor.name, name),
        required_privileges: privilege_requirements_for_registered(descriptor.name, name),
        side_effects: side_effects_for_registered(descriptor.name, name),
        planned_handles: planned_handles_for_registered(descriptor.name, name),
        rollback_preview: rollback_preview_for_registered(descriptor.name, name),
        choice_parameters: choice_parameters(descriptor.name, name),
        array_choice_parameters: array_choice_parameters(descriptor.name, name),
        parameter_bounds: parameter_bounds(descriptor.name, name),
        parser_hints: parser_hints(descriptor.name, name),
    })
}

pub fn tool_handler(tool: &str) -> Option<ToolHandler> {
    tool_descriptors()
        .iter()
        .find(|descriptor| descriptor.name == tool)
        .map(|descriptor| descriptor.handler)
}

pub fn is_known_tool(tool: &str) -> bool {
    tool_actions(tool).is_some()
}

pub fn is_known_tool_action(tool: &str, action: &str) -> bool {
    if tool == "memoric" {
        return true;
    }
    tool_actions(tool).is_some_and(|actions| actions.iter().any(|candidate| *candidate == action))
}

pub fn actions_csv(tool: &str) -> String {
    tool_actions(tool)
        .map(|actions| actions.join(", "))
        .unwrap_or_default()
}

pub fn classify_action(tool: &str, action: &str) -> ActionTraits {
    let read_only = is_read_only_action(tool, action);
    let kernel = tool == "kernel" || action_contains_any(action, &["kernel", "driver_", "pte"]);
    let destructive = is_destructive_action(tool, action);
    let state_changing = !read_only || destructive;
    let privileged = kernel
        || matches!(tool, "privilege" | "inject" | "stealth" | "hook")
        || action_contains_any(
            action,
            &[
                "patch",
                "inject",
                "hide",
                "remove",
                "disable",
                "bypass",
                "kill",
                "delete",
                "clear",
                "steal",
                "impersonate",
            ],
        );
    let requires_target = matches!(tool, "target" | "memory" | "inject" | "hook")
        || action_contains_any(action, &["pid", "process", "thread", "token", "ppl"]);
    let required_policy = if destructive {
        PolicyLevel::Destructive
    } else if kernel {
        PolicyLevel::Kernel
    } else if privileged {
        PolicyLevel::Privileged
    } else if state_changing {
        PolicyLevel::LabWrite
    } else if tool == "memory" || tool == "target" || tool == "detect" {
        PolicyLevel::Research
    } else {
        PolicyLevel::Observe
    };
    let risk = match required_policy {
        PolicyLevel::Observe => RiskLevel::Low,
        PolicyLevel::Research => RiskLevel::Low,
        PolicyLevel::LabWrite => RiskLevel::Medium,
        PolicyLevel::Privileged => RiskLevel::High,
        PolicyLevel::Kernel | PolicyLevel::Destructive => RiskLevel::Critical,
    };

    ActionTraits {
        read_only,
        state_changing,
        privileged,
        kernel,
        destructive,
        requires_target,
        risk,
        required_policy,
    }
}

pub fn tool_annotations(tool: &str) -> Value {
    let actions = tool_actions(tool).unwrap_or(&[]);
    let all_read_only = actions
        .iter()
        .all(|action| classify_action(tool, action).read_only);
    let any_destructive = actions
        .iter()
        .any(|action| classify_action(tool, action).destructive);
    let any_state_changing = actions
        .iter()
        .any(|action| classify_action(tool, action).state_changing);
    let highest_policy = actions
        .iter()
        .map(|action| classify_action(tool, action).required_policy)
        .max()
        .unwrap_or(PolicyLevel::Observe);

    json!({
        "readOnlyHint": all_read_only,
        "destructiveHint": any_destructive,
        "idempotentHint": all_read_only,
        "openWorldHint": any_state_changing,
        "memoric": {
            "highest_required_policy": highest_policy.as_str(),
            "actions": actions.len(),
            "title": tool_title(tool),
            "icon": tool_icon(tool),
            "selection_hint": tool_selection_hint(tool),
        }
    })
}

pub fn tool_display_metadata(tool: &str) -> Value {
    json!({
        "title": tool_title(tool),
        "icon": tool_icon(tool),
        "selection_hint": tool_selection_hint(tool),
    })
}

fn tool_title(tool: &str) -> &'static str {
    match tool {
        "memoric" => "Guide",
        "target" => "Target Inspection",
        "memory" => "Memory Operations",
        "inject" => "Injection Workflows",
        "payload" => "Payload Utilities",
        "hook" => "Hook Management",
        "stealth" => "Stealth Controls",
        "detect" => "Detection Review",
        "privilege" => "Privilege Review",
        "kernel" => "Kernel Driver",
        "self" => "Server Diagnostics",
        "orchestrate" => "Orchestration",
        _ => "Tool",
    }
}

fn tool_icon(tool: &str) -> &'static str {
    match tool {
        "memoric" => "compass",
        "target" => "crosshair",
        "memory" => "binary",
        "inject" => "send",
        "payload" => "package",
        "hook" => "plug",
        "stealth" => "shield",
        "detect" => "radar",
        "privilege" => "key",
        "kernel" => "cpu",
        "self" => "activity",
        "orchestrate" => "workflow",
        _ => "tool",
    }
}

fn tool_selection_hint(tool: &str) -> &'static str {
    match tool {
        "memoric" => "Start here for action discovery, server status, and domain-specific guides.",
        "target" => "Use for read-only process, module, thread, handle, and string inspection.",
        "memory" => {
            "Use for authorized memory reads, scans, diagnostics, and guarded write previews."
        }
        "inject" => "Use only for explicitly authorized lab injection workflows and previews.",
        "payload" => "Use for payload parsing, obfuscation, serialization, and lifecycle helpers.",
        "hook" => "Use for hook install, remove, restore, and trampoline workflows.",
        "stealth" => {
            "Use for defensive posture review or explicitly authorized evasion lab actions."
        }
        "detect" => "Use for EDR, telemetry, sandbox, integrity, and environment checks.",
        "privilege" => {
            "Use for privilege posture, token review, and authorized elevation workflows."
        }
        "kernel" => "Use for driver readiness, kernel inspection, and policy-gated kernel actions.",
        "self" => {
            "Use for server status, doctor checks, safe diagnostics bundles, and recovery advice."
        }
        "orchestrate" => {
            "Use for static plans, safe templates, assessment, and gated chain execution."
        }
        _ => "Use when the tool name and action metadata match the requested operation.",
    }
}

pub fn common_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "success": { "type": "boolean" },
            "code": { "type": "string" },
            "message": { "type": "string" },
            "summary": { "type": "string" },
            "data": {},
            "context": { "type": "object" },
            "artifacts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string" },
                        "uri": { "type": "string" },
                        "name": { "type": "string" },
                        "path": { "type": "string" },
                        "mimeType": { "type": "string" },
                        "size_bytes": { "type": "integer" },
                        "sha256": { "type": "string" },
                        "classification": { "type": "string" },
                        "created_at": { "type": "integer" },
                        "last_modified": { "type": "string" },
                        "expires_at": { "type": "integer" },
                        "retention_secs": { "type": "integer" },
                        "verified": { "type": "boolean" }
                    }
                }
            },
            "integrity": { "type": "object" },
            "warnings": { "type": "array", "items": { "type": "string" } },
            "evidence": { "type": "array", "items": { "type": "object" } }
        },
        "required": ["success", "code"]
    })
}

const COMMON_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("artifacts[].kind", DataClassification::Public),
    classification_rule("artifacts[].path", DataClassification::ArtifactReference),
    classification_rule("artifacts[].uri", DataClassification::ArtifactReference),
    classification_rule("artifacts[].name", DataClassification::Public),
    classification_rule("artifacts[].mimeType", DataClassification::Public),
    classification_rule("artifacts[].size_bytes", DataClassification::Public),
    classification_rule("artifacts[].sha256", DataClassification::Public),
    classification_rule("artifacts[].classification", DataClassification::Public),
    classification_rule("artifacts[].created_at", DataClassification::Public),
    classification_rule("artifacts[].last_modified", DataClassification::Public),
    classification_rule("artifacts[].expires_at", DataClassification::Public),
    classification_rule("artifacts[].retention_secs", DataClassification::Public),
    classification_rule("artifacts[].verified", DataClassification::Public),
    classification_rule("context.request_id", DataClassification::LocalSensitive),
    classification_rule("context.purpose", DataClassification::LocalSensitive),
    classification_rule("integrity", DataClassification::Public),
    classification_rule("metadata", DataClassification::Public),
];

const TARGET_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.exe_path", DataClassification::Path),
    classification_rule("data.path", DataClassification::Path),
    classification_rule("data.command_line", DataClassification::LocalSensitive),
    classification_rule("data.cmdline", DataClassification::LocalSensitive),
    classification_rule("data.environment", DataClassification::LocalSensitive),
    classification_rule("data.env", DataClassification::LocalSensitive),
    classification_rule("data.output_path", DataClassification::ArtifactReference),
    classification_rule("data.output_dir", DataClassification::Path),
    classification_rule("data.dump_file", DataClassification::ArtifactReference),
    classification_rule("data.artifact", DataClassification::ArtifactReference),
    classification_rule(
        "data.results[].artifact",
        DataClassification::ArtifactReference,
    ),
    classification_rule("data.credentials", DataClassification::CredentialLike),
    classification_rule("data.tickets", DataClassification::CredentialLike),
    classification_rule(
        "data.rollback.original_bytes",
        DataClassification::RawMemory,
    ),
    classification_rule(
        "data.rollback.action.args.bytes",
        DataClassification::RawMemory,
    ),
];

const MEMORY_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.bytes", DataClassification::RawMemory),
    classification_rule("data.hex", DataClassification::RawMemory),
    classification_rule("data.data_hex", DataClassification::RawMemory),
    classification_rule(
        "data.rollback.original_bytes",
        DataClassification::RawMemory,
    ),
    classification_rule(
        "data.rollback.action.args.bytes",
        DataClassification::RawMemory,
    ),
    classification_rule("data.preview[].bytes", DataClassification::RawMemory),
    classification_rule("data.preview[].hex", DataClassification::RawMemory),
    classification_rule("data.results[].bytes", DataClassification::RawMemory),
    classification_rule("data.results[].hex", DataClassification::RawMemory),
    classification_rule("data.results[].matched_hex", DataClassification::RawMemory),
    classification_rule("data.results[].context_hex", DataClassification::RawMemory),
    classification_rule("data.matches[].matched_hex", DataClassification::RawMemory),
    classification_rule("data.matches[].context_hex", DataClassification::RawMemory),
    classification_rule("data.candidates[].hex", DataClassification::RawMemory),
    classification_rule("data.candidates[].value", DataClassification::RawMemory),
    classification_rule("data.regions[].path", DataClassification::Path),
];

const PAYLOAD_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.payload", DataClassification::RawMemory),
    classification_rule("data.payload_hex", DataClassification::RawMemory),
    classification_rule("data.shellcode", DataClassification::RawMemory),
    classification_rule("data.bytes", DataClassification::RawMemory),
    classification_rule("data.output_path", DataClassification::ArtifactReference),
];

const HOOK_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.payload", DataClassification::RawMemory),
    classification_rule("data.payload_hex", DataClassification::RawMemory),
    classification_rule("data.shellcode", DataClassification::RawMemory),
    classification_rule("data.bytes", DataClassification::RawMemory),
    classification_rule("data.dll_path", DataClassification::Path),
    classification_rule("data.output_path", DataClassification::ArtifactReference),
    classification_rule(
        "data.rollback.original_bytes",
        DataClassification::RawMemory,
    ),
    classification_rule(
        "data.rollback.action.args.original_bytes",
        DataClassification::RawMemory,
    ),
    classification_rule(
        "data.rollback.actions[].args.original_bytes",
        DataClassification::RawMemory,
    ),
    classification_rule(
        "data.rollback.hooks[].rollback.original_bytes",
        DataClassification::RawMemory,
    ),
    classification_rule(
        "data.rollback.hooks[].rollback.action.args.original_bytes",
        DataClassification::RawMemory,
    ),
];

const KERNEL_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.bytes", DataClassification::RawMemory),
    classification_rule("data.hex", DataClassification::RawMemory),
    classification_rule("data.data_hex", DataClassification::RawMemory),
    classification_rule("data.data_preview", DataClassification::RawMemory),
    classification_rule("data.driver_path", DataClassification::Path),
    classification_rule("data.path", DataClassification::Path),
    classification_rule("data.dump_file", DataClassification::ArtifactReference),
    classification_rule("data.output_path", DataClassification::ArtifactReference),
    classification_rule("data.credentials", DataClassification::CredentialLike),
];

const SELF_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.state", DataClassification::LocalSensitive),
    classification_rule("data.process_path", DataClassification::Path),
    classification_rule("data.audit_path", DataClassification::Path),
    classification_rule("data.capabilities[].detail.path", DataClassification::Path),
];

const ORCHESTRATE_OUTPUT_CLASSIFICATION: &[DataClassificationRule] = &[
    classification_rule("data.output_path", DataClassification::ArtifactReference),
    classification_rule("data.artifact_path", DataClassification::ArtifactReference),
    classification_rule("data.artifact", DataClassification::ArtifactReference),
    classification_rule("data.plan", DataClassification::LocalSensitive),
    classification_rule("data.effective_plan", DataClassification::LocalSensitive),
    classification_rule("data.blocked_steps", DataClassification::LocalSensitive),
    classification_rule("data.evidence", DataClassification::LocalSensitive),
];

pub fn tool_output_classification_rules(tool: &str) -> Vec<DataClassificationRule> {
    let mut rules = COMMON_OUTPUT_CLASSIFICATION.to_vec();
    match tool {
        "target" => rules.extend_from_slice(TARGET_OUTPUT_CLASSIFICATION),
        "memory" => rules.extend_from_slice(MEMORY_OUTPUT_CLASSIFICATION),
        "inject" => rules.extend_from_slice(PAYLOAD_OUTPUT_CLASSIFICATION),
        "payload" => rules.extend_from_slice(PAYLOAD_OUTPUT_CLASSIFICATION),
        "hook" => rules.extend_from_slice(HOOK_OUTPUT_CLASSIFICATION),
        "stealth" => rules.extend_from_slice(PAYLOAD_OUTPUT_CLASSIFICATION),
        "detect" => rules.extend_from_slice(TARGET_OUTPUT_CLASSIFICATION),
        "privilege" => rules.extend_from_slice(TARGET_OUTPUT_CLASSIFICATION),
        "kernel" => rules.extend_from_slice(KERNEL_OUTPUT_CLASSIFICATION),
        "self" => rules.extend_from_slice(SELF_OUTPUT_CLASSIFICATION),
        "orchestrate" => rules.extend_from_slice(ORCHESTRATE_OUTPUT_CLASSIFICATION),
        _ => {}
    }
    rules
}

pub fn tool_output_classification_json(tool: &str) -> Value {
    json!(tool_output_classification_rules(tool)
        .into_iter()
        .map(|rule| {
            json!({
                "path": rule.path,
                "classification": rule.classification.as_str(),
            })
        })
        .collect::<Vec<_>>())
}

pub fn tool_classification_summary(tool: &str) -> Value {
    let mut classes = tool_output_classification_rules(tool)
        .into_iter()
        .map(|rule| rule.classification.as_str().to_string())
        .collect::<Vec<_>>();
    classes.sort();
    classes.dedup();

    json!({
        "output": classes,
        "redaction": "classification-aware",
    })
}

pub fn tool_ui_resource_uri(tool: &str) -> Option<&'static str> {
    match tool {
        "memoric" | "self" => Some("ui://memoric/dashboard"),
        "memory" => Some("ui://memoric/scans"),
        "orchestrate" => Some("ui://memoric/plans"),
        _ => None,
    }
}

fn tool_meta(tool: &str) -> Value {
    crate::mcp::meta::tool_meta(tool_ui_resource_uri(tool))
}

pub fn action_metadata_json(tool: &str) -> Value {
    let actions = tool_actions(tool).unwrap_or(&[]);
    let classification = tool_classification_summary(tool);
    let metadata = actions
        .iter()
        .filter_map(|action| {
            let mut metadata = registered_action(tool, action)?.metadata_json();
            if let Some(object) = metadata.as_object_mut() {
                object.insert("data_classification".to_string(), json!(classification));
            }
            Some(metadata)
        })
        .collect::<Vec<_>>();

    json!(metadata)
}

pub fn enhance_tool_definitions(tools: &mut [Value]) {
    for tool in tools {
        let Some(name) = tool
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            continue;
        };

        if let Some(obj) = tool.as_object_mut() {
            if let Some(description) = tool_description(&name) {
                obj.insert("description".to_string(), json!(description));
            }
            obj.insert("annotations".to_string(), tool_annotations(&name));
            obj.insert("_meta".to_string(), tool_meta(&name));
            obj.insert(
                "x-memoric-display".to_string(),
                tool_display_metadata(&name),
            );
            obj.insert(
                "execution".to_string(),
                json!({
                    "taskSupport": "optional",
                    "memoric": {
                        "background_eligibility": "read-only-or-dry-run"
                    }
                }),
            );
            obj.insert("outputSchema".to_string(), common_output_schema());
            obj.insert("x-memoric-actions".to_string(), action_metadata_json(&name));
            obj.insert(
                "x-memoric-data-classification".to_string(),
                tool_output_classification_json(&name),
            );

            if let Some(input_schema) = obj.get_mut("inputSchema") {
                apply_input_schema_shell(input_schema);
                apply_memoric_domain_enum(&name, input_schema);
                apply_action_enum(&name, input_schema);
                apply_action_required_field(&name, input_schema);
                add_tool_input_fields(&name, input_schema);
                add_descriptor_parameter_fields(&name, input_schema);
                apply_action_parameter_conditions(&name, input_schema);
                apply_choice_parameter_enums(&name, input_schema);
                apply_parameter_bounds(&name, input_schema);
                add_common_input_fields(input_schema);
            }
        }
    }
}

fn apply_input_schema_shell(input_schema: &mut Value) {
    let Some(input_schema) = input_schema.as_object_mut() else {
        return;
    };
    input_schema
        .entry("type".to_string())
        .or_insert_with(|| json!("object"));
    input_schema
        .entry("properties".to_string())
        .or_insert_with(|| json!({}));
}

fn apply_memoric_domain_enum(tool: &str, input_schema: &mut Value) {
    if tool != "memoric" {
        return;
    }
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };

    for field in guide_input_fields() {
        let descriptor_schema = (*field).schema();
        match properties.entry(field.name.to_string()) {
            serde_json::map::Entry::Occupied(mut entry) => {
                merge_missing_schema_fields(entry.get_mut(), descriptor_schema);
            }
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(descriptor_schema);
            }
        }
    }
}

fn apply_action_enum(tool: &str, input_schema: &mut Value) {
    let Some(descriptor) = tool_descriptors()
        .iter()
        .find(|descriptor| descriptor.name == tool)
    else {
        return;
    };
    let Some(description) = descriptor.action_description else {
        return;
    };
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };
    let action_schema = properties
        .entry("action".to_string())
        .or_insert_with(|| json!({}));
    let Some(action_schema) = action_schema.as_object_mut() else {
        return;
    };

    action_schema
        .entry("type".to_string())
        .or_insert_with(|| json!("string"));
    action_schema
        .entry("description".to_string())
        .or_insert_with(|| json!(description));
    action_schema.insert("enum".to_string(), json!(descriptor.actions));
}

fn apply_action_required_field(tool: &str, input_schema: &mut Value) {
    if tool == "memoric" || tool_actions(tool).is_none() {
        return;
    }

    let Some(input_schema) = input_schema.as_object_mut() else {
        return;
    };

    match input_schema.entry("required".to_string()) {
        serde_json::map::Entry::Occupied(mut entry) => {
            let Some(required) = entry.get_mut().as_array_mut() else {
                return;
            };
            if !required.iter().any(|value| value == "action") {
                required.push(json!("action"));
            }
        }
        serde_json::map::Entry::Vacant(entry) => {
            entry.insert(json!(["action"]));
        }
    }
}

fn add_tool_input_fields(tool: &str, input_schema: &mut Value) {
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };

    for field in tool_input_fields(tool) {
        let descriptor_schema = field.schema();
        match properties.entry(field.name.to_string()) {
            serde_json::map::Entry::Occupied(mut entry) => {
                merge_missing_schema_fields(entry.get_mut(), descriptor_schema);
            }
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(descriptor_schema);
            }
        }
    }
}

fn add_descriptor_parameter_fields(tool: &str, input_schema: &mut Value) {
    let Some(actions) = tool_actions(tool) else {
        return;
    };
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };

    for action in actions {
        for hint in parser_hints(tool, action) {
            upsert_parser_hint_schema_field(properties, hint.parameter.as_str(), &hint);
            for alias in &hint.aliases {
                upsert_parser_hint_schema_field(properties, alias, &hint);
            }
        }
    }
}

fn upsert_parser_hint_schema_field(
    properties: &mut serde_json::Map<String, Value>,
    parameter: &str,
    hint: &ParserHintDescriptor,
) {
    if hint.parser == "object_array" {
        let generated = schema_for_parser_hint(hint);
        let entry = properties
            .entry(parameter.to_string())
            .or_insert_with(|| generated.clone());
        merge_object_array_schema(entry, generated);
        return;
    }

    if hint.parser != "protection" {
        let generated = schema_for_parser_hint(hint);
        match properties.entry(parameter.to_string()) {
            serde_json::map::Entry::Occupied(mut entry) => {
                merge_missing_schema_fields(entry.get_mut(), generated);
            }
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(generated);
            }
        }
        return;
    }

    let generated = schema_for_parser_hint(hint);
    let description = properties
        .get(parameter)
        .and_then(|value| value.get("description"))
        .cloned()
        .or_else(|| generated.get("description").cloned());
    let entry = properties
        .entry(parameter.to_string())
        .or_insert_with(|| json!({}));
    *entry = generated;
    if let (Some(description), Some(object)) = (description, entry.as_object_mut()) {
        object.insert("description".to_string(), description);
    }
}

fn merge_object_array_schema(target: &mut Value, generated: Value) {
    let Some(target_object) = target.as_object_mut() else {
        *target = generated;
        return;
    };
    let Value::Object(generated_object) = generated else {
        return;
    };
    for key in ["type", "minItems", "maxItems"] {
        if let Some(value) = generated_object.get(key) {
            target_object
                .entry(key.to_string())
                .or_insert(value.clone());
        }
    }
    let Some(generated_items) = generated_object.get("items") else {
        return;
    };
    match target_object.entry("items".to_string()) {
        serde_json::map::Entry::Occupied(mut entry) => {
            merge_missing_schema_fields(entry.get_mut(), generated_items.clone());
        }
        serde_json::map::Entry::Vacant(entry) => {
            entry.insert(generated_items.clone());
        }
    }
}

pub(crate) fn is_supported_parser_hint(parser: &str) -> bool {
    matches!(
        parser,
        "address_u64"
            | "array_length"
            | "boolean"
            | "byte_pattern"
            | "bytes"
            | "module_name"
            | "number"
            | "number_array"
            | "object"
            | "object_array"
            | "path"
            | "pid_u32"
            | "pool_tag"
            | "protection"
            | "string"
            | "string_array"
            | "tid_u32"
            | "u64"
    )
}

fn schema_for_parser_name(parser: &str) -> Value {
    let mut schema = serde_json::Map::new();
    match parser {
        "pid_u32" | "tid_u32" | "u64" => {
            schema.insert("type".to_string(), json!(["integer", "string"]));
        }
        "number" => {
            schema.insert("type".to_string(), json!("number"));
        }
        "address_u64" => {
            schema.insert("type".to_string(), json!(["integer", "string"]));
        }
        "pool_tag" => {
            schema.insert(
                "oneOf".to_string(),
                json!([
                    {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": u32::MAX as u64,
                    },
                    {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4,
                    }
                ]),
            );
        }
        "bytes" => {
            schema.insert(
                "oneOf".to_string(),
                json!([
                    {
                        "type": "array",
                        "items": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 255,
                        }
                    },
                    { "type": "string" }
                ]),
            );
        }
        "array_length" => {
            schema.insert("type".to_string(), json!("array"));
        }
        "object_array" => {
            schema.insert("type".to_string(), json!("array"));
            schema.insert("items".to_string(), json!({ "type": "object" }));
        }
        "object" => {
            schema.insert("type".to_string(), json!("object"));
        }
        "boolean" => {
            schema.insert("type".to_string(), json!("boolean"));
        }
        "string_array" => {
            schema.insert("type".to_string(), json!("array"));
            schema.insert("items".to_string(), json!({ "type": "string" }));
        }
        "number_array" => {
            schema.insert("type".to_string(), json!("array"));
            schema.insert("items".to_string(), json!({ "type": "number" }));
        }
        "byte_pattern" => {
            schema.insert(
                "oneOf".to_string(),
                json!([
                    {
                        "type": "array",
                        "items": {
                            "oneOf": [
                                {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 255,
                                },
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        }
                    },
                    { "type": "string" }
                ]),
            );
        }
        "protection" => {
            schema.insert(
                "oneOf".to_string(),
                json!([
                    {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": u32::MAX as u64,
                    },
                    {
                        "type": "string"
                    }
                ]),
            );
        }
        "module_name" => {
            schema.insert("type".to_string(), json!("string"));
            schema.insert("minLength".to_string(), json!(1));
            schema.insert(
                "maxLength".to_string(),
                json!(crate::args::DEFAULT_MAX_MODULE_NAME_LEN),
            );
            schema.insert("pattern".to_string(), json!("^[^\\\\/:\\x00-\\x1F]+$"));
        }
        "path" => {
            schema.insert("type".to_string(), json!("string"));
            schema.insert("minLength".to_string(), json!(1));
            schema.insert(
                "maxLength".to_string(),
                json!(crate::args::DEFAULT_MAX_PATH_LEN),
            );
        }
        "string" => {
            schema.insert("type".to_string(), json!("string"));
        }
        _ => panic!("unsupported action registry parser hint: {parser}"),
    }
    Value::Object(schema)
}

fn schema_for_parser_hint(hint: &ParserHintDescriptor) -> Value {
    let mut schema = schema_for_parser_name(hint.parser);
    let Some(schema_object) = schema.as_object_mut() else {
        return schema;
    };
    if let Some(object_item_schema) = hint.object_item_schema {
        schema_object.insert("items".to_string(), object_item_schema.to_json());
        if let Some(items) = schema_object
            .get_mut("items")
            .and_then(|items| items.as_object_mut())
        {
            items.insert("type".to_string(), json!("object"));
        }
    } else if let Some(array_item_parser) = hint.array_item_parser {
        schema_object.insert(
            "items".to_string(),
            schema_for_parser_name(array_item_parser),
        );
    }
    if !hint.choices.is_empty() && hint.parser == "protection" {
        schema_object.insert("x-memoric-symbolicValues".to_string(), json!(hint.choices));
        schema_object.insert("x-memoric-caseInsensitive".to_string(), json!(true));
    } else if !hint.choices.is_empty() {
        schema_object.insert("enum".to_string(), json!(hint.choices));
    }
    if parser_hint_uses_item_bounds(hint.parser) {
        if let Some(minimum) = hint.minimum {
            schema_object.insert("minItems".to_string(), json!(minimum));
        }
        if let Some(maximum) = hint.maximum {
            schema_object.insert("maxItems".to_string(), json!(maximum));
        }
    } else {
        if let Some(minimum) = hint.minimum {
            schema_object.insert("minimum".to_string(), json!(minimum));
        }
        if let Some(maximum) = hint.maximum {
            schema_object.insert("maximum".to_string(), json!(maximum));
        }
    }
    schema_object.insert(
        "description".to_string(),
        json!(format!("Registry-described {} parameter", hint.parameter)),
    );
    schema
}

fn apply_action_parameter_conditions(tool: &str, input_schema: &mut Value) {
    let Some(actions) = tool_actions(tool) else {
        return;
    };

    let Some(input_schema_object) = input_schema.as_object_mut() else {
        return;
    };

    let conditions = actions
        .iter()
        .filter_map(|action| {
            let parameters = required_parameters(tool, action);
            let conditional_parameters = conditional_required_parameters(tool, action);
            let alternative_parameters = alternative_required_parameters(tool, action);
            let choices = choice_parameters(tool, action);
            let array_choices = array_choice_parameters(tool, action);
            let bounds = parameter_bounds(tool, action);

            if parameters.is_empty()
                && conditional_parameters.is_empty()
                && alternative_parameters.is_empty()
                && choices.is_empty()
                && array_choices.is_empty()
                && bounds.is_empty()
            {
                return None;
            }

            let mut required = Vec::with_capacity(parameters.len() + 1);
            required.push("action");
            for parameter in parameters {
                if !required.contains(parameter) {
                    required.push(parameter);
                }
            }

            let mut then = serde_json::Map::new();
            if !parameters.is_empty() {
                then.insert("required".to_string(), json!(required));
            }

            let mut properties = serde_json::Map::new();
            let mut nested_conditions = Vec::new();
            for condition in conditional_parameters {
                let mut conditional_required = Vec::with_capacity(condition.parameters.len() + 1);
                conditional_required.push(condition.when_parameter);
                for parameter in condition.parameters {
                    if !conditional_required.contains(parameter) {
                        conditional_required.push(parameter);
                    }
                }
                let mut when_values = condition.when_values.to_vec();
                if condition.default_applies {
                    when_values.push("");
                }
                nested_conditions.push(json!({
                    "if": {
                        "properties": {
                            condition.when_parameter: {
                                "enum": when_values
                            }
                        }
                    },
                    "then": {
                        "required": conditional_required
                    },
                    "description": condition.description,
                }));
            }
            for alternative in alternative_parameters {
                let alternatives = alternative
                    .parameters
                    .iter()
                    .map(|parameter| json!({ "required": [*parameter] }))
                    .collect::<Vec<_>>();
                let then_schema = json!({
                    "anyOf": alternatives,
                    "description": alternative.description,
                });
                if let Some(when_parameter) = alternative.when_parameter {
                    let mut when_values = alternative.when_values.to_vec();
                    if alternative.default_applies {
                        when_values.push("");
                    }
                    nested_conditions.push(json!({
                        "if": {
                            "properties": {
                                when_parameter: {
                                    "enum": when_values
                                }
                            }
                        },
                        "then": then_schema,
                        "description": alternative.description,
                    }));
                } else {
                    nested_conditions.push(then_schema);
                }
            }
            for choice in choices {
                properties.insert(
                    choice.parameter.to_string(),
                    json!({ "enum": choice.values }),
                );
            }
            for choice in array_choices {
                properties.insert(
                    choice.parameter.to_string(),
                    json!({
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": choice.values,
                        }
                    }),
                );
            }
            let hints = parser_hints(tool, action);
            for bound in bounds {
                let parameter_schema = properties
                    .entry(bound.parameter.to_string())
                    .or_insert_with(|| json!({}));
                if let Some(parameter_schema_object) = parameter_schema.as_object_mut() {
                    apply_bound_schema_for_parser_hint(
                        parameter_schema_object,
                        parser_hint_for_bound(&hints, &bound),
                        bound.minimum,
                        bound.maximum,
                    );
                    apply_array_item_schema_for_parameter_hint(
                        parameter_schema_object,
                        parser_hint_for_descriptor(&hints, bound.parameter),
                    );
                }
            }
            if !properties.is_empty() {
                then.insert("properties".to_string(), Value::Object(properties));
            }
            if !nested_conditions.is_empty() {
                then.insert("allOf".to_string(), json!(nested_conditions));
            }

            Some(json!({
                "if": {
                    "properties": {
                        "action": { "const": action }
                    },
                    "required": ["action"]
                },
                "then": Value::Object(then)
            }))
        })
        .collect::<Vec<_>>();

    if conditions.is_empty() {
        return;
    }

    let all_of = input_schema_object
        .entry("allOf".to_string())
        .or_insert_with(|| json!([]));
    if let Some(existing_conditions) = all_of.as_array_mut() {
        existing_conditions.extend(conditions);
    }
}

fn apply_choice_parameter_enums(tool: &str, input_schema: &mut Value) {
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };

    let mut choices_by_parameter: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for choice in all_choice_parameters()
        .iter()
        .copied()
        .filter(|choice| choice.tool == tool)
    {
        let values = choices_by_parameter.entry(choice.parameter).or_default();
        for value in choice.values {
            if !values.contains(value) {
                values.push(value);
            }
        }
    }

    for (parameter, values) in choices_by_parameter {
        let Some(parameter_schema) = properties
            .get_mut(parameter)
            .and_then(|parameter| parameter.as_object_mut())
        else {
            continue;
        };
        parameter_schema.insert("enum".to_string(), json!(values));
    }

    let mut array_choices_by_parameter: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for choice in all_array_choice_parameters()
        .iter()
        .copied()
        .filter(|choice| choice.tool == tool)
    {
        let values = array_choices_by_parameter
            .entry(choice.parameter)
            .or_default();
        for value in choice.values {
            if !values.contains(value) {
                values.push(value);
            }
        }
    }

    for (parameter, values) in array_choices_by_parameter {
        let Some(parameter_schema) = properties
            .get_mut(parameter)
            .and_then(|parameter| parameter.as_object_mut())
        else {
            continue;
        };
        parameter_schema
            .entry("type".to_string())
            .or_insert_with(|| json!("array"));
        let items = parameter_schema
            .entry("items".to_string())
            .or_insert_with(|| json!({ "type": "string" }));
        if let Some(items) = items.as_object_mut() {
            items
                .entry("type".to_string())
                .or_insert_with(|| json!("string"));
            items.insert("enum".to_string(), json!(values));
        }
    }
}

fn apply_parameter_bounds(tool: &str, input_schema: &mut Value) {
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };

    let mut bounds_by_parameter: BTreeMap<&str, (Option<u64>, Option<u64>)> = BTreeMap::new();
    for bounds in all_parameter_bounds()
        .iter()
        .copied()
        .filter(|bounds| bounds.tool == tool)
    {
        let entry = bounds_by_parameter
            .entry(bounds.parameter)
            .or_insert((bounds.minimum, bounds.maximum));
        entry.0 = match (entry.0, bounds.minimum) {
            (Some(current), Some(next)) => Some(current.min(next)),
            _ => None,
        };
        entry.1 = match (entry.1, bounds.maximum) {
            (Some(current), Some(next)) => Some(current.max(next)),
            _ => None,
        };
    }

    for (parameter, (minimum, maximum)) in bounds_by_parameter {
        let Some(parameter_schema) = properties
            .get_mut(parameter)
            .and_then(|parameter| parameter.as_object_mut())
        else {
            continue;
        };
        let parser_hint = registry_parser_hint_for_parameter(tool, parameter);
        apply_bound_schema_for_parser_hint(parameter_schema, parser_hint, minimum, maximum);
        apply_array_item_schema_for_parameter_hint(
            parameter_schema,
            registry_parser_hint_descriptor_for_parameter(tool, parameter).as_ref(),
        );
    }
}

fn registry_parser_hint_for_parameter(tool: &str, parameter: &str) -> &'static str {
    tool_actions(tool)
        .unwrap_or(&[])
        .iter()
        .flat_map(|action| parser_hints(tool, action))
        .find(|hint| hint.parameter == parameter)
        .map(|hint| hint.parser)
        .unwrap_or_else(|| parser_hint_for_parameter(parameter))
}

fn registry_parser_hint_descriptor_for_parameter(
    tool: &str,
    parameter: &str,
) -> Option<ParserHintDescriptor> {
    tool_actions(tool)
        .unwrap_or(&[])
        .iter()
        .flat_map(|action| parser_hints(tool, action))
        .find(|hint| hint.parameter == parameter)
}

fn parser_hint_for_bound<'a>(
    hints: &'a [ParserHintDescriptor],
    bound: &ParameterBoundsDescriptor,
) -> &'a str {
    hints
        .iter()
        .find(|hint| hint.parameter == bound.parameter)
        .map(|hint| hint.parser)
        .unwrap_or_else(|| parser_hint_for_parameter(bound.parameter))
}

fn parser_hint_for_descriptor<'a>(
    hints: &'a [ParserHintDescriptor],
    parameter: &str,
) -> Option<&'a ParserHintDescriptor> {
    hints.iter().find(|hint| hint.parameter == parameter)
}

fn apply_array_item_schema_for_parameter_hint(
    parameter_schema: &mut serde_json::Map<String, Value>,
    hint: Option<&ParserHintDescriptor>,
) {
    let Some(item_parser) = hint.and_then(|hint| hint.array_item_parser) else {
        return;
    };
    parameter_schema.insert("items".to_string(), schema_for_parser_name(item_parser));
}

fn parser_hint_uses_item_bounds(parser: &str) -> bool {
    matches!(
        parser,
        "array_length" | "object_array" | "bytes" | "byte_pattern"
    )
}

fn apply_bound_schema_for_parser_hint(
    parameter_schema: &mut serde_json::Map<String, Value>,
    parser: &str,
    minimum: Option<u64>,
    maximum: Option<u64>,
) {
    if parser_hint_uses_item_bounds(parser) {
        if let Some(minimum) = minimum {
            parameter_schema.insert("minItems".to_string(), json!(minimum));
        }
        if let Some(maximum) = maximum {
            parameter_schema.insert("maxItems".to_string(), json!(maximum));
        }
        if matches!(parser, "bytes" | "byte_pattern") {
            parameter_schema.insert("x-memoric-byteLengthMinimum".to_string(), json!(minimum));
            parameter_schema.insert("x-memoric-byteLengthMaximum".to_string(), json!(maximum));
            apply_byte_item_bounds(parameter_schema, parser);
        }
    } else {
        if let Some(minimum) = minimum {
            parameter_schema.insert("minimum".to_string(), json!(minimum));
        }
        if let Some(maximum) = maximum {
            parameter_schema.insert("maximum".to_string(), json!(maximum));
        }
    }
}

fn apply_byte_item_bounds(parameter_schema: &mut serde_json::Map<String, Value>, parser: &str) {
    if let Some(items) = parameter_schema
        .get_mut("items")
        .and_then(|items| items.as_object_mut())
    {
        apply_byte_item_bounds_to_items(items, parser);
    }

    let Some(one_of) = parameter_schema
        .get_mut("oneOf")
        .and_then(|one_of| one_of.as_array_mut())
    else {
        return;
    };

    for branch in one_of {
        let Some(branch) = branch.as_object_mut() else {
            continue;
        };
        if branch.get("type") != Some(&json!("array")) {
            continue;
        }
        if let Some(items) = branch
            .get_mut("items")
            .and_then(|items| items.as_object_mut())
        {
            apply_byte_item_bounds_to_items(items, parser);
        }
    }
}

fn apply_byte_item_bounds_to_items(items: &mut serde_json::Map<String, Value>, parser: &str) {
    if parser == "bytes" {
        items.insert("minimum".to_string(), json!(0));
        items.insert("maximum".to_string(), json!(u8::MAX));
        return;
    }

    let Some(one_of) = items
        .get_mut("oneOf")
        .and_then(|one_of| one_of.as_array_mut())
    else {
        return;
    };
    for branch in one_of {
        let Some(branch) = branch.as_object_mut() else {
            continue;
        };
        if branch.get("type") == Some(&json!("integer")) {
            branch.insert("minimum".to_string(), json!(0));
            branch.insert("maximum".to_string(), json!(u8::MAX));
        }
    }
}

fn add_common_input_fields(input_schema: &mut Value) {
    let Some(properties) = input_schema
        .get_mut("properties")
        .and_then(|props| props.as_object_mut())
    else {
        return;
    };

    for field in common_input_fields() {
        let descriptor_schema = (*field).schema();
        match properties.entry(field.name.to_string()) {
            serde_json::map::Entry::Occupied(mut entry) => {
                merge_missing_schema_fields(entry.get_mut(), descriptor_schema);
            }
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(descriptor_schema);
            }
        }
    }
}

fn merge_missing_schema_fields(target: &mut Value, descriptor_schema: Value) {
    let Some(target) = target.as_object_mut() else {
        return;
    };
    let Value::Object(descriptor) = descriptor_schema else {
        return;
    };

    for (key, value) in descriptor {
        match target.entry(key) {
            serde_json::map::Entry::Occupied(mut entry)
                if entry.get().is_object() && value.is_object() =>
            {
                merge_missing_schema_fields(entry.get_mut(), value);
            }
            serde_json::map::Entry::Occupied(_) => {}
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
        }
    }
}

fn is_read_only_action(tool: &str, action: &str) -> bool {
    match tool {
        "memoric" => true,
        "detect" => !matches!(action, "edr_suspend"),
        "target" => matches!(
            action,
            "ps_list"
                | "ps_find"
                | "ps_info"
                | "modules"
                | "threads"
                | "threads_list"
                | "thread_context"
                | "handles"
                | "env"
                | "cmdline"
                | "windows"
                | "peb"
                | "module_base"
                | "mem_find"
                | "string_read"
                | "callstack"
                | "heap"
        ),
        "memory" => matches!(
            action,
            "read"
                | "typed_read"
                | "scan"
                | "query"
                | "query_find"
                | "scan_new"
                | "scan_next"
                | "scan_undo"
                | "scan_list"
                | "scan_reset"
                | "diagnostics"
        ),
        "inject" => matches!(action, "hijack_enum" | "wow64_detect"),
        "payload" => matches!(action, "pe_parse" | "serialize" | "wait" | "exit_code"),
        "hook" => false,
        "stealth" => matches!(
            action,
            "defender_status"
                | "firewall_list_rules"
                | "firewall_status"
                | "sentinel_status"
                | "testsign_query"
                | "callback_enum_by_driver"
                | "minifilter_enum_classified"
        ),
        "privilege" => matches!(
            action,
            "check"
                | "token_scan"
                | "service_unquoted"
                | "service_weak_perms"
                | "service_always_elevated"
        ),
        "kernel" => matches!(
            action,
            "status"
                | "driver_discover"
                | "driver_stats"
                | "driver_enum_process"
                | "driver_memory_pool"
                | "driver_minifilter_enum"
                | "driver_hypervisor_detect"
                | "driver_process_dump"
                | "enum_callbacks"
                | "object_callback_enum"
                | "registry_callback_enum"
                | "minifilter_enum"
                | "driver_callback_enum"
        ),
        "self" => matches!(
            action,
            "peb"
                | "heap"
                | "test"
                | "memory_diagnostics"
                | "status"
                | "info"
                | "version"
                | "anti_debug"
                | "state"
                | "doctor"
                | "diagnostics"
                | "explain_error"
                | "capability_diff"
                | "next_steps"
        ),
        "orchestrate" => matches!(action, "assess" | "plan" | "templates" | "status"),
        _ => false,
    }
}

fn parser_hint_for_parameter(parameter: &str) -> &'static str {
    if matches!(
        parameter,
        "pid" | "target_pid" | "protect_pid" | "parent_pid"
    ) {
        return "pid_u32";
    }
    if matches!(parameter, "tid" | "thread_id") {
        return "tid_u32";
    }
    if is_address_parameter(parameter) {
        return "address_u64";
    }
    if matches!(parameter, "pattern_bytes" | "signature" | "pattern") {
        return "byte_pattern";
    }
    if is_byte_payload_parameter(parameter) {
        return "bytes";
    }
    if is_module_name_parameter(parameter) {
        return "module_name";
    }
    if is_path_parameter(parameter) {
        return "path";
    }
    if is_array_length_parameter(parameter) {
        if is_object_array_parameter(parameter) {
            return "object_array";
        }
        return "array_length";
    }
    if matches!(
        parameter,
        "protect" | "protection" | "old_protection" | "new_protection"
    ) {
        return "protection";
    }
    if is_integer_parameter(parameter) {
        return "u64";
    }
    if is_number_parameter(parameter) {
        return "number";
    }
    "string"
}

fn parser_hint_for_tool_parameter(tool: &str, action: &str, parameter: &str) -> &'static str {
    if tool == "stealth"
        && matches!(action, "spoof_return" | "deep_stack_spoof")
        && parameter == "target_function"
    {
        return "address_u64";
    }
    if tool == "stealth" && action == "defender_add_exclusion" && parameter == "value" {
        return "string";
    }
    parser_hint_for_parameter(parameter)
}

fn array_item_parser_for_parameter(
    tool: &str,
    action: &str,
    parameter: &str,
    parser: &str,
) -> Option<&'static str> {
    if parser == "string_array" {
        return Some("string");
    }
    if parser != "array_length" {
        return None;
    }

    match (tool, action, parameter) {
        ("payload", "cleanup", "addresses") => Some("address_u64"),
        ("payload", "cleanup", "thread_handles") => Some("u64"),
        ("payload", "obfuscate", "strings") => Some("string"),
        ("payload", "obfuscate", "transforms") => Some("string"),
        _ => None,
    }
}

pub fn is_byte_payload_parameter(parameter: &str) -> bool {
    matches!(
        parameter,
        "bytes" | "data" | "payload" | "payload_hex" | "shellcode" | "original_bytes" | "key"
    )
}

pub fn is_array_length_parameter(parameter: &str) -> bool {
    matches!(
        parameter,
        "hooks"
            | "addresses"
            | "thread_handles"
            | "params"
            | "strings"
            | "transforms"
            | "steps"
            | "inject_flags"
    )
}

pub fn is_object_array_parameter(parameter: &str) -> bool {
    matches!(parameter, "hooks" | "steps")
}

pub fn is_number_parameter(parameter: &str) -> bool {
    matches!(parameter, "delta" | "min" | "max")
}

pub fn is_module_name_parameter(parameter: &str) -> bool {
    matches!(
        parameter,
        "module" | "module_name" | "target_module" | "driver_name"
    )
}

pub fn is_path_parameter(parameter: &str) -> bool {
    parameter.ends_with("_path")
        || matches!(
            parameter,
            "device_path" | "driver_path" | "dll_path" | "file_path" | "link_path" | "target_path"
        )
}

fn is_address_parameter(parameter: &str) -> bool {
    parameter == "address"
        || parameter.ends_with("_address")
        || parameter.ends_with("_addr")
        || matches!(
            parameter,
            "base_address"
                | "target_address"
                | "hook_address"
                | "iat_address"
                | "original_address"
                | "replacement_addr"
                | "handler_address"
                | "new_handler"
                | "alloc_address"
                | "thread_start"
                | "thread_context"
                | "array_address"
                | "shellcode_address"
                | "shellcode_addr"
                | "start_address"
        )
}

fn is_integer_parameter(parameter: &str) -> bool {
    parameter == "size"
        || parameter.ends_with("_size")
        || parameter.ends_with("_limit")
        || parameter.ends_with("_count")
        || parameter.ends_with("_index")
        || parameter.ends_with("_offset")
        || parameter.ends_with("_code")
        || parameter.ends_with("_flags")
        || parameter.ends_with("_ms")
        || parameter.ends_with("_secs")
        || matches!(
            parameter,
            "limit"
                | "offset"
                | "chunk_size"
                | "timeout_ms"
                | "artifact_retention_secs"
                | "region_cache_ttl_ms"
                | "region_cache_ttl_secs"
                | "cr3"
                | "interval_ms"
                | "intensity"
                | "passes"
                | "entropy_sample_bytes"
                | "read_ioctl"
                | "write_ioctl"
                | "ioctl_code"
                | "ioctl_read_code"
                | "ioctl_write_code"
                | "callback_index"
                | "index"
                | "read_size"
                | "max_size"
                | "value"
                | "alignment"
                | "delay_ms"
        )
}

fn is_destructive_action(tool: &str, action: &str) -> bool {
    matches!(
        (tool, action),
        ("stealth", "sentinel_self_destruct")
            | ("kernel", "driver_force_kill")
            | ("kernel", "driver_force_delete")
            | ("kernel", "driver_event_log_clear")
    ) || action_contains_any(action, &["nuke", "clear_all", "kill_service"])
}

fn action_contains_any(action: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| action.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_integer_or_string_type(value: &Value) {
        assert_eq!(value, &json!(["integer", "string"]));
    }

    #[test]
    fn registry_knows_representative_actions() {
        assert!(is_known_tool_action("target", "ps_list"));
        assert!(is_known_tool_action("memory", "read"));
        assert!(is_known_tool_action("kernel", "status"));
        assert!(is_known_tool_action("kernel", "driver_wfp_remove"));
        assert!(!is_known_tool_action("memory", "not_real"));
    }

    #[test]
    fn parser_hint_descriptors_use_supported_parser_names() {
        for descriptor in tool_descriptors() {
            for action in descriptor.actions {
                for hint in parser_hints(descriptor.name, action) {
                    assert!(
                        is_supported_parser_hint(hint.parser),
                        "{}(action='{}') parameter '{}' uses unsupported parser hint '{}'",
                        descriptor.name,
                        action,
                        hint.parameter,
                        hint.parser
                    );
                    let _ = schema_for_parser_name(hint.parser);

                    if let Some(item_parser) = hint.array_item_parser {
                        assert!(
                            is_supported_parser_hint(item_parser),
                            "{}(action='{}') parameter '{}' uses unsupported array item parser '{}'",
                            descriptor.name,
                            action,
                            hint.parameter,
                            item_parser
                        );
                        let _ = schema_for_parser_name(item_parser);
                    }

                    if let Some(item_schema) = hint.object_item_schema {
                        for property in item_schema.properties {
                            assert!(
                                is_supported_parser_hint(property.parser),
                                "{}(action='{}') parameter '{}.{}' uses unsupported object item parser '{}'",
                                descriptor.name,
                                action,
                                hint.parameter,
                                property.name,
                                property.parser
                            );
                            let _ = schema_for_parser_name(property.parser);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn required_parameter_hints_match_required_parser_hints() {
        for descriptor in tool_descriptors() {
            for action in descriptor.actions {
                let required = required_parameters(descriptor.name, action);
                let hints = parser_hints(descriptor.name, action);
                let required_hints = required_parameter_hints(descriptor.name, action);
                let expected = hints
                    .iter()
                    .filter(|hint| {
                        required
                            .iter()
                            .any(|parameter| *parameter == hint.parameter.as_str())
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                assert_eq!(
                    required_hints, expected,
                    "{}(action='{}') required parameter hints must be derived from parser_hints",
                    descriptor.name, action
                );

                for parameter in required {
                    assert!(
                        required_hints
                            .iter()
                            .any(|hint| hint.parameter == *parameter),
                        "{}(action='{}') required parameter '{}' is missing a parser hint",
                        descriptor.name,
                        action,
                        parameter
                    );
                }

                for hint in required_hints {
                    assert!(
                        hint.required,
                        "{}(action='{}') required parameter hint '{}' was not marked required",
                        descriptor.name, action, hint.parameter
                    );
                }
            }
        }
    }

    #[test]
    fn required_parameter_hints_metadata_marks_hints_required() {
        let metadata = registered_action("memory", "write")
            .expect("memory write action")
            .metadata_json();
        let hints = metadata["required_parameter_hints"]
            .as_array()
            .expect("required parameter hints metadata");

        assert!(
            hints
                .iter()
                .any(|hint| hint["parameter"] == "pid" && hint["required"] == true),
            "required parameter hint metadata should retain required=true"
        );
        assert!(
            hints
                .iter()
                .any(|hint| hint["parameter"] == "address" && hint["required"] == true),
            "required parameter hint metadata should retain required=true"
        );
    }

    #[test]
    fn registry_classifies_read_only_and_destructive_actions() {
        let ps = classify_action("target", "ps_list");
        assert!(ps.read_only);
        assert_eq!(ps.required_policy, PolicyLevel::Research);

        let diagnostics = classify_action("memory", "diagnostics");
        assert!(diagnostics.read_only);
        assert!(!diagnostics.state_changing);
        assert_eq!(diagnostics.required_policy, PolicyLevel::Research);

        let self_diagnostics = classify_action("self", "memory_diagnostics");
        assert!(self_diagnostics.read_only);
        assert!(!self_diagnostics.state_changing);
        assert_eq!(self_diagnostics.required_policy, PolicyLevel::Observe);

        let kernel_status = classify_action("kernel", "status");
        assert!(kernel_status.read_only);
        assert!(!kernel_status.state_changing);
        assert!(kernel_status.kernel);
        assert_eq!(kernel_status.required_policy, PolicyLevel::Kernel);

        let kill = classify_action("kernel", "driver_force_kill");
        assert!(kill.kernel);
        assert!(kill.destructive);
        assert_eq!(kill.required_policy, PolicyLevel::Destructive);
    }

    #[test]
    fn common_input_field_descriptors_generate_schema_fields() {
        let mut tools = vec![json!({
            "name": "memory",
            "description": "test schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Memory action"
                    }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("schema properties");

        for field in common_input_fields() {
            assert_eq!(
                properties.get(field.name),
                Some(&field.schema()),
                "{} schema should be generated from common input descriptor",
                field.name
            );
        }

        assert_eq!(
            properties["action"]["enum"],
            json!(tool_actions("memory").expect("memory actions"))
        );
    }

    #[test]
    fn input_schema_shell_is_registry_generated() {
        let mut tools = vec![
            json!({
                "name": "target",
                "inputSchema": {}
            }),
            json!({
                "name": "memory",
                "inputSchema": {}
            }),
            json!({
                "name": "inject",
                "inputSchema": {}
            }),
            json!({
                "name": "payload",
                "inputSchema": {}
            }),
            json!({
                "name": "hook",
                "inputSchema": {}
            }),
            json!({
                "name": "stealth",
                "inputSchema": {}
            }),
        ];

        enhance_tool_definitions(&mut tools);

        assert_eq!(tools[0]["inputSchema"]["type"], json!("object"));
        assert!(
            tools[0]["inputSchema"]["properties"].is_object(),
            "registry enhancement should create the inputSchema properties object"
        );
        assert_eq!(
            tools[0]["inputSchema"]["properties"]["action"]["enum"],
            json!(tool_actions("target").expect("target actions"))
        );
        let target_properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("target properties");
        assert_eq!(target_properties["pid"]["description"], json!("Process ID"));
        assert_integer_or_string_type(&target_properties["pid"]["type"]);
        assert_eq!(
            target_properties["include_system"]["description"],
            json!("Include system processes in process listings")
        );
        assert_eq!(
            target_properties["include_system"]["type"],
            json!("boolean")
        );
        assert_eq!(target_properties["include_system"]["default"], json!(true));
        assert_eq!(target_properties["limit"]["default"], json!(100));
        assert_eq!(
            target_properties["limit"]["maximum"],
            json!(TARGET_MAX_RESULT_LIMIT)
        );
        assert_eq!(target_properties["output_path"]["minLength"], json!(1));

        assert_eq!(tools[1]["inputSchema"]["type"], json!("object"));
        assert!(
            tools[1]["inputSchema"]["properties"].is_object(),
            "registry enhancement should create the inputSchema properties object"
        );
        assert_eq!(
            tools[1]["inputSchema"]["properties"]["action"]["enum"],
            json!(tool_actions("memory").expect("memory actions"))
        );
        let properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("memory properties");
        assert_eq!(properties["pid"]["description"], json!("Target process ID"));
        assert_integer_or_string_type(&properties["pid"]["type"]);
        assert_eq!(
            properties["pattern"]["description"],
            json!("String pattern for scan_mode='string' or explicit pattern alias for signatures")
        );
        assert_eq!(
            properties["summary_only"]["description"],
            json!("Return only scan session metadata and pagination summary without inline candidate rows")
        );
        assert_eq!(properties["summary_only"]["type"], json!("boolean"));
        assert_eq!(properties["summary_only"]["default"], json!(false));
        assert_eq!(
            properties["protect"]["description"],
            json!("Protection level alias for alloc/protect; accepts symbolic strings such as RWX or PAGE_EXECUTE_READWRITE, or numeric PAGE_* flags")
        );
        assert!(
            properties["protect"].get("oneOf").is_some(),
            "protection parser hints should enhance registry-owned presentation fields"
        );
        assert_eq!(properties["values"]["items"]["type"], json!("number"));

        assert_eq!(tools[2]["inputSchema"]["type"], json!("object"));
        assert!(
            tools[2]["inputSchema"]["properties"].is_object(),
            "registry enhancement should create inject schema properties from an empty shell"
        );
        assert_eq!(
            tools[2]["inputSchema"]["properties"]["action"]["enum"],
            json!(tool_actions("inject").expect("inject actions"))
        );
        let inject_properties = tools[2]["inputSchema"]["properties"]
            .as_object()
            .expect("inject properties");
        assert_eq!(
            inject_properties["method"]["description"],
            json!("Shellcode injection method")
        );
        assert_eq!(
            inject_properties["method"]["enum"],
            json!(choice_values("inject", "shellcode", "method").expect("shellcode method choices"))
        );
        assert_eq!(
            inject_properties["dll_path"]["description"],
            json!("Path to DLL (required for action='dll')")
        );
        assert_eq!(inject_properties["dll_path"]["type"], json!("string"));
        assert_eq!(inject_properties["dll_path"]["minLength"], json!(1));
        assert_eq!(
            inject_properties["target_exe"]["description"],
            json!("Legacy alias for target_path (still accepted)")
        );
        assert_eq!(inject_properties["target_exe"]["type"], json!("string"));
        assert_eq!(inject_properties["target_exe"]["minLength"], json!(1));
        assert_eq!(
            inject_properties["variant"]["description"],
            json!("Pool Party variant 1-8")
        );
        assert_eq!(inject_properties["variant"]["default"], json!(1));
        assert_eq!(inject_properties["variant"]["type"], json!("string"));
        assert_eq!(inject_properties["variant"]["minimum"], json!(1));
        assert_eq!(
            inject_properties["variant"]["maximum"],
            json!(INJECT_MAX_POOL_PARTY_VARIANT)
        );
        assert_eq!(
            inject_properties["timeout_ms"]["description"],
            json!("Per-call cooperative timeout in milliseconds; long-running handlers check it at safe boundaries")
        );
        assert_eq!(inject_properties["timeout_ms"]["default"], json!(30000));
        assert_eq!(inject_properties["timeout_ms"]["minimum"], json!(1));
        assert_eq!(
            inject_properties["timeout_ms"]["maximum"],
            json!(crate::runtime::MAX_TIMEOUT_MS)
        );

        assert_eq!(tools[3]["inputSchema"]["type"], json!("object"));
        assert!(
            tools[3]["inputSchema"]["properties"].is_object(),
            "registry enhancement should create payload schema properties from an empty shell"
        );
        assert_eq!(
            tools[3]["inputSchema"]["properties"]["action"]["enum"],
            json!(tool_actions("payload").expect("payload actions"))
        );
        let payload_properties = tools[3]["inputSchema"]["properties"]
            .as_object()
            .expect("payload properties");
        assert_eq!(
            payload_properties["pid"]["description"],
            json!("Process ID (for pe_parse/cleanup)")
        );
        assert_integer_or_string_type(&payload_properties["pid"]["type"]);
        assert_eq!(
            payload_properties["show"]["description"],
            json!("PE info to show")
        );
        assert_eq!(
            payload_properties["show"]["enum"],
            json!(choice_values("payload", "pe_parse", "show")
                .expect("payload pe_parse show choices"))
        );
        assert_eq!(
            payload_properties["obf_method"]["description"],
            json!("Obfuscation method")
        );
        assert_eq!(
            payload_properties["obf_method"]["enum"],
            json!(choice_values("payload", "obfuscate", "obf_method")
                .expect("payload obfuscation method choices"))
        );
        assert_eq!(
            payload_properties["payload"]["description"],
            json!("Payload bytes")
        );
        assert_eq!(
            payload_properties["payload"]["oneOf"][0]["type"],
            json!("array")
        );
        assert_eq!(payload_properties["payload"]["minItems"], json!(1));
        assert_eq!(
            payload_properties["payload"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            payload_properties["payload_hex"]["description"],
            json!("Hex-encoded payload")
        );
        assert_eq!(payload_properties["payload_hex"]["minItems"], json!(1));
        assert_eq!(
            payload_properties["payload_hex"]["x-memoric-byteLengthMaximum"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            payload_properties["key"]["description"],
            json!("Encryption key")
        );
        assert_eq!(
            payload_properties["key"]["maxItems"],
            json!(PAYLOAD_MAX_OBFUSCATION_KEY_BYTES)
        );
        assert_eq!(
            payload_properties["addresses"]["description"],
            json!("Allocated memory addresses to free during cleanup")
        );
        assert_eq!(payload_properties["addresses"]["type"], json!("array"));
        assert_eq!(
            payload_properties["addresses"]["maxItems"],
            json!(PAYLOAD_MAX_CLEANUP_ITEMS)
        );
        assert_eq!(
            payload_properties["addresses"]["items"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            payload_properties["thread_handles"]["items"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            payload_properties["strings"]["items"]["type"],
            json!("string")
        );
        assert_eq!(
            payload_properties["params"]["description"],
            json!("Parameters to serialize for payload invocation")
        );
        assert_eq!(
            payload_properties["params"]["maxItems"],
            json!(PAYLOAD_MAX_SERIALIZE_PARAMS)
        );
        assert_eq!(
            payload_properties["format"]["description"],
            json!("Serialization format (for serialize)")
        );
        assert_eq!(payload_properties["format"]["default"], json!("raw"));
        assert_eq!(
            payload_properties["format"]["enum"],
            json!(choice_values("payload", "serialize", "format")
                .expect("payload serialize format choices"))
        );
        assert_eq!(
            payload_properties["thread_handle"]["description"],
            json!("Thread handle returned by injection execution helpers (for wait/exit_code)")
        );
        assert_eq!(payload_properties["thread_handle"]["type"], json!("string"));
        assert_eq!(
            payload_properties["address"]["description"],
            json!("Memory address (for cleanup)")
        );
        assert_eq!(
            payload_properties["address"]["type"],
            json!(["integer", "string"])
        );

        assert_eq!(tools[4]["inputSchema"]["type"], json!("object"));
        assert!(
            tools[4]["inputSchema"]["properties"].is_object(),
            "registry enhancement should create hook schema properties from an empty shell"
        );
        assert_eq!(
            tools[4]["inputSchema"]["properties"]["action"]["enum"],
            json!(tool_actions("hook").expect("hook actions"))
        );
        let hook_properties = tools[4]["inputSchema"]["properties"]
            .as_object()
            .expect("hook properties");
        assert_eq!(
            hook_properties["pid"]["description"],
            json!("Target process ID")
        );
        assert_integer_or_string_type(&hook_properties["pid"]["type"]);
        assert_eq!(
            hook_properties["method"]["description"],
            json!("Hook method (legacy, prefer specific action)")
        );
        assert_eq!(
            hook_properties["method"]["enum"],
            json!(choice_values("hook", "install", "method").expect("hook method choices"))
        );
        assert_eq!(
            hook_properties["module"]["description"],
            json!("Imported module name for IAT hooks (e.g. kernel32.dll)")
        );
        assert_eq!(hook_properties["module"]["type"], json!("string"));
        assert_eq!(hook_properties["module"]["minLength"], json!(1));
        assert_eq!(
            hook_properties["target_address"]["description"],
            json!("Target function address (inline/hwbp/trampoline)")
        );
        assert_eq!(
            hook_properties["target_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            hook_properties["hook_address"]["description"],
            json!("Detour function address")
        );
        assert_eq!(
            hook_properties["hook_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            hook_properties["dll_path"]["description"],
            json!("DLL path for action='winhook'")
        );
        assert_eq!(hook_properties["dll_path"]["type"], json!("string"));
        assert_eq!(hook_properties["dll_path"]["minLength"], json!(1));
        assert_eq!(
            hook_properties["hooks"]["description"],
            json!("Transactional detour definitions with target_address and hook_address")
        );
        assert_eq!(hook_properties["hooks"]["type"], json!("array"));
        assert_eq!(hook_properties["hooks"]["minItems"], json!(1));
        assert_eq!(
            hook_properties["hooks"]["maxItems"],
            json!(HOOK_MAX_DETOUR_HOOKS)
        );
        assert_eq!(
            hook_properties["hooks"]["items"]["required"],
            json!(["target_address", "hook_address"])
        );
        assert_eq!(
            hook_properties["iat_address"]["description"],
            json!("IAT entry address returned by install_iat/payload pe_parse show='iat_entry' (for remove_iat)")
        );
        assert_eq!(
            hook_properties["iat_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            hook_properties["dr_index"]["description"],
            json!("Debug register 0-3 (hwbp)")
        );
        assert_eq!(hook_properties["dr_index"]["default"], json!(0));
        assert_integer_or_string_type(&hook_properties["dr_index"]["type"]);
        assert_eq!(hook_properties["dr_index"]["minimum"], json!(0));
        assert_eq!(hook_properties["dr_index"]["maximum"], json!(3));
        assert_eq!(
            hook_properties["original_bytes"]["description"],
            json!("Original byte values to restore for action='restore'")
        );
        assert_eq!(hook_properties["original_bytes"]["minItems"], json!(1));
        assert_eq!(
            hook_properties["original_bytes"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );

        assert_eq!(tools[5]["inputSchema"]["type"], json!("object"));
        assert!(
            tools[5]["inputSchema"]["properties"].is_object(),
            "registry enhancement should create stealth schema properties from an empty shell"
        );
        assert_eq!(
            tools[5]["inputSchema"]["properties"]["action"]["enum"],
            json!(tool_actions("stealth").expect("stealth actions"))
        );
        let stealth_properties = tools[5]["inputSchema"]["properties"]
            .as_object()
            .expect("stealth properties");
        assert_eq!(
            stealth_properties["pid"]["description"],
            json!("Target process ID. For encrypt_memory/decrypt_memory, omit pid or use the memoric server PID only; remote PID/address input is rejected.")
        );
        assert_integer_or_string_type(&stealth_properties["pid"]["type"]);
        assert_eq!(
            stealth_properties["target_function"]["description"],
            json!("Target function address for return-address spoofing actions")
        );
        assert_eq!(
            stealth_properties["target_function"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            stealth_properties["shellcode"]["description"],
            json!("Hex-encoded shellcode for module_stomp, or shellcode bytes for compatible sleep helpers")
        );
        assert_eq!(
            stealth_properties["shellcode"]["oneOf"][0]["type"],
            json!("array")
        );
        assert_eq!(
            stealth_properties["shellcode"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            stealth_properties["protect"]["description"],
            json!("Protection level alias; accepts symbolic strings such as RWX or PAGE_EXECUTE_READWRITE, or numeric PAGE_* flags")
        );
        assert!(
            stealth_properties["protect"].get("oneOf").is_some(),
            "protection parser hints should enhance stealth registry-owned presentation fields"
        );
        assert_eq!(
            stealth_properties["syscall_method"]["enum"],
            json!(choice_values("stealth", "syscall_write", "syscall_method")
                .expect("syscall method choices"))
        );
        assert_eq!(
            stealth_properties["syscall_method"]["default"],
            json!("indirect")
        );
        assert_eq!(
            stealth_properties["sysmon_method"]["enum"],
            json!(choice_values("stealth", "sysmon_blind", "sysmon_method")
                .expect("sysmon method choices"))
        );
        assert_eq!(
            stealth_properties["sysmon_method"]["default"],
            json!("etw_only")
        );
        assert_eq!(
            stealth_properties["bcd_method"]["enum"],
            json!(choice_values("stealth", "testsign_hide_bcd", "bcd_method")
                .expect("bcd method choices"))
        );
        assert_eq!(
            stealth_properties["bcd_method"]["default"],
            json!("registry")
        );
        assert_eq!(
            stealth_properties["method"]["enum"],
            json!(
                choice_values("stealth", "wdac_disable", "method").expect("policy method choices")
            )
        );
        assert_eq!(stealth_properties["method"]["default"], json!("auto"));
        assert_eq!(
            stealth_properties["ci_action"]["enum"],
            json!(
                choice_values("stealth", "testsign_ci_callback", "ci_action")
                    .expect("ci action choices")
            )
        );
        assert_eq!(stealth_properties["ci_action"]["default"], json!("patch"));
        assert_eq!(
            stealth_properties["direction"]["enum"],
            json!(choice_values("stealth", "firewall_add_rule", "direction")
                .expect("firewall direction choices"))
        );
        assert_eq!(stealth_properties["direction"]["default"], json!("in"));
        assert_eq!(
            stealth_properties["rule_action"]["enum"],
            json!(choice_values("stealth", "firewall_add_rule", "rule_action")
                .expect("firewall action choices"))
        );
        assert_eq!(stealth_properties["rule_action"]["default"], json!("allow"));
        assert_eq!(
            stealth_properties["profiles"]["enum"],
            json!(
                choice_values("stealth", "firewall_disable", "profiles").expect("profile choices")
            )
        );
        assert_eq!(stealth_properties["profiles"]["default"], json!("all"));
        assert_eq!(stealth_properties["patch_etw"]["type"], json!("boolean"));
        assert_eq!(stealth_properties["patch_etw"]["default"], json!(true));
        assert_eq!(stealth_properties["unhook_ntdll"]["default"], json!(false));
        assert_eq!(stealth_properties["self_destruct"]["default"], json!(false));
        assert_eq!(stealth_properties["interval_ms"]["default"], json!(5000));
        assert_eq!(stealth_properties["interval_ms"]["minimum"], json!(1000));
        assert_eq!(stealth_properties["interval_ms"]["maximum"], json!(300000));
        assert_eq!(stealth_properties["passes"]["default"], json!(7));
        assert_eq!(stealth_properties["passes"]["minimum"], json!(1));
        assert_eq!(stealth_properties["passes"]["maximum"], json!(7));
    }

    #[test]
    fn action_required_field_is_registry_generated() {
        let mut tools = vec![
            json!({
                "name": "memory",
                "description": "test memory schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" }
                    }
                }
            }),
            json!({
                "name": "memoric",
                "description": "test guide schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": { "type": "string" }
                    }
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);

        assert_eq!(tools[0]["inputSchema"]["required"], json!(["action"]));
        assert!(
            tools[1]["inputSchema"].get("required").is_none(),
            "guide schema should not require an action parameter"
        );
    }

    #[test]
    fn action_schema_field_is_registry_generated() {
        let mut tools = vec![json!({
            "name": "memory",
            "description": "test memory schema",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        })];

        enhance_tool_definitions(&mut tools);

        let action = &tools[0]["inputSchema"]["properties"]["action"];
        assert_eq!(action["type"], json!("string"));
        assert_eq!(
            action["description"],
            json!(tool_descriptors()
                .iter()
                .find(|descriptor| descriptor.name == "memory")
                .and_then(|descriptor| descriptor.action_description)
                .expect("memory action description"))
        );
        assert_eq!(
            action["enum"],
            json!(tool_actions("memory").expect("memory actions"))
        );
    }

    #[test]
    fn memoric_domain_enum_is_registry_generated() {
        let mut tools = vec![json!({
            "name": "memoric",
            "description": "test guide schema",
            "inputSchema": {}
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("guide properties");
        let domain_enum = tools[0]["inputSchema"]["properties"]["domain"]["enum"]
            .as_array()
            .expect("domain enum")
            .iter()
            .map(|value| value.as_str().expect("domain string"))
            .collect::<Vec<_>>();

        for field in guide_input_fields() {
            assert_eq!(
                properties.get(field.name),
                Some(&field.schema()),
                "{} guide schema should be generated from registry descriptors",
                field.name
            );
        }
        assert_eq!(domain_enum, guide_domain_values());
        assert!(domain_enum.contains(&"all"));
        assert!(!domain_enum.contains(&"memoric"));
    }

    #[test]
    fn migrated_bounds_are_restored_from_registry_descriptors() {
        let mut tools = vec![
            json!({
                "name": "stealth",
                "description": "test stealth schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "shellcode": {
                            "oneOf": [
                                { "type": "string" },
                                { "type": "array", "items": { "type": "integer" } }
                            ]
                        },
                        "intensity": { "type": "integer" },
                        "interval_ms": { "type": "integer", "default": 5000 },
                        "passes": { "type": "integer", "default": 7 }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "hook",
                "description": "test hook schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "original_bytes": {
                            "type": "array",
                            "items": { "type": "integer" }
                        }
                    },
                    "required": ["action"]
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);

        let stealth_properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("stealth schema properties");
        assert_eq!(stealth_properties["intensity"]["minimum"], json!(1));
        assert_eq!(stealth_properties["intensity"]["maximum"], json!(3));
        assert_eq!(stealth_properties["interval_ms"]["minimum"], json!(1000));
        assert_eq!(stealth_properties["interval_ms"]["maximum"], json!(300000));
        assert_eq!(stealth_properties["interval_ms"]["default"], json!(5000));
        assert_eq!(stealth_properties["passes"]["minimum"], json!(1));
        assert_eq!(stealth_properties["passes"]["maximum"], json!(7));
        assert_eq!(stealth_properties["passes"]["default"], json!(7));
        assert_eq!(stealth_properties["shellcode"]["minItems"], json!(1));
        assert_eq!(
            stealth_properties["shellcode"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            stealth_properties["shellcode"]["x-memoric-byteLengthMinimum"],
            json!(1)
        );
        assert_eq!(
            stealth_properties["shellcode"]["x-memoric-byteLengthMaximum"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            stealth_properties["shellcode"]["oneOf"][1]["items"]["minimum"],
            json!(0)
        );
        assert_eq!(
            stealth_properties["shellcode"]["oneOf"][1]["items"]["maximum"],
            json!(u8::MAX)
        );

        let hook_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("hook schema properties");
        assert_eq!(hook_properties["original_bytes"]["minItems"], json!(1));
        assert_eq!(
            hook_properties["original_bytes"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            hook_properties["original_bytes"]["x-memoric-byteLengthMinimum"],
            json!(1)
        );
        assert_eq!(
            hook_properties["original_bytes"]["x-memoric-byteLengthMaximum"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            hook_properties["original_bytes"]["items"]["minimum"],
            json!(0),
            "byte item lower bound should be restored by the registry parser hint"
        );
        assert_eq!(
            hook_properties["original_bytes"]["items"]["maximum"],
            json!(u8::MAX),
            "byte item upper bound should be restored by the registry parser hint"
        );
    }

    #[test]
    fn tool_descriptions_are_overwritten_from_registry_descriptors() {
        let mut tools = vec![
            json!({
                "name": "memory",
                "description": "stale schema seed description",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Memory action"
                        }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "target",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pid": { "type": "integer" }
                    }
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);

        assert_eq!(
            tools[0]["description"],
            json!(tool_description("memory").expect("memory registry description"))
        );
        assert_ne!(
            tools[0]["description"],
            json!("stale schema seed description")
        );
        assert_eq!(
            tools[1]["description"],
            json!(tool_description("target").expect("target registry description"))
        );
    }

    #[test]
    fn common_input_field_descriptors_merge_missing_schema_fields() {
        let mut tools = vec![json!({
            "name": "inject",
            "description": "test schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Injection action"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "default": 30000
                    }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("schema properties");
        let timeout_ms = properties
            .get("timeout_ms")
            .expect("timeout_ms should remain present");

        assert_eq!(timeout_ms["default"], json!(30000));
        assert_eq!(timeout_ms["minimum"], json!(1));
        assert_eq!(timeout_ms["maximum"], json!(crate::runtime::MAX_TIMEOUT_MS));
        assert_eq!(
            timeout_ms["description"],
            "Per-call cooperative timeout in milliseconds; long-running handlers check it at safe boundaries"
        );
    }

    #[test]
    fn descriptor_parameter_fields_fill_schema_gaps() {
        let mut tools = vec![json!({
            "name": "kernel",
            "description": "test schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Kernel action"
                    }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("schema properties");

        assert_eq!(properties["device_path"]["type"], json!("string"));
        assert_integer_or_string_type(&properties["callback_index"]["type"]);
        assert_eq!(
            properties["array_address"]["type"],
            json!(["integer", "string"]),
            "address-like parameters should get address-compatible schema"
        );
        assert_eq!(
            properties["notify_type"]["enum"],
            json!(choice_values("kernel", "driver_notify_routine", "notify_type")
                .expect("notify type choices")),
            "choice parameters should get registry enum values even when the base schema omitted them"
        );
        assert_eq!(
            properties["callback_type"]["type"],
            json!("string"),
            "alias parameters should be generated from registry parser hints"
        );
    }

    #[test]
    fn descriptor_parameter_fields_merge_missing_parser_schema_into_seed_fields() {
        let mut tools = vec![json!({
            "name": "target",
            "description": "test target schema",
            "inputSchema": {
                "properties": {
                    "pid": { "description": "Process ID" },
                    "address": { "description": "Target address" },
                    "module_name": { "description": "Module basename" },
                    "limit": { "default": 100 }
                }
            }
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("target properties");

        assert_integer_or_string_type(&properties["pid"]["type"]);
        assert_eq!(properties["pid"]["description"], json!("Process ID"));
        assert_eq!(properties["address"]["type"], json!(["integer", "string"]));
        assert_eq!(
            properties["address"]["description"],
            json!("Target address")
        );
        assert_eq!(properties["module_name"]["type"], json!("string"));
        assert_eq!(
            properties["module_name"]["description"],
            json!("Module basename")
        );
        assert_eq!(properties["module_name"]["minLength"], json!(1));
        assert_integer_or_string_type(&properties["limit"]["type"]);
        assert_eq!(properties["limit"]["default"], json!(100));
    }

    #[test]
    fn hook_schema_fields_are_generated_from_registry_descriptors() {
        let mut tools = vec![json!({
            "name": "hook",
            "description": "test hook schema",
            "inputSchema": {
                "properties": {
                    "pid": { "description": "Target process ID" },
                    "tid": { "description": "Thread ID" },
                    "method": { "description": "Hook method" },
                    "module": { "description": "Imported module name" },
                    "function": { "description": "Imported function name" },
                    "target_function": { "description": "Function alias" },
                    "target_address": { "description": "Target address" },
                    "address": { "description": "Restore address" },
                    "hook_address": { "description": "Hook address" },
                    "dll_path": { "description": "DLL path" },
                    "hooks": { "description": "Detour batch" },
                    "iat_address": { "description": "IAT address" },
                    "original_address": { "description": "Original address" },
                    "original_bytes": { "description": "Original bytes" }
                }
            }
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("hook properties");

        assert_integer_or_string_type(&properties["pid"]["type"]);
        assert_integer_or_string_type(&properties["tid"]["type"]);
        assert_eq!(properties["method"]["type"], json!("string"));
        assert_eq!(
            properties["method"]["enum"],
            json!(choice_values("hook", "install", "method").expect("hook method choices"))
        );
        assert_eq!(properties["module"]["type"], json!("string"));
        assert_eq!(properties["module"]["minLength"], json!(1));
        assert_eq!(properties["function"]["type"], json!("string"));
        assert_eq!(properties["target_function"]["type"], json!("string"));
        assert_eq!(
            properties["target_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(properties["address"]["type"], json!(["integer", "string"]));
        assert_eq!(
            properties["hook_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(properties["dll_path"]["type"], json!("string"));
        assert_eq!(properties["dll_path"]["minLength"], json!(1));
        assert_eq!(
            properties["iat_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            properties["original_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(properties["hooks"]["type"], json!("array"));
        assert_eq!(properties["hooks"]["minItems"], json!(1));
        assert_eq!(
            properties["hooks"]["maxItems"],
            json!(HOOK_MAX_DETOUR_HOOKS)
        );
        assert_eq!(
            properties["hooks"]["items"]["required"],
            json!(["target_address", "hook_address"])
        );
        assert_eq!(
            properties["original_bytes"]["oneOf"][0]["type"],
            json!("array")
        );
        assert_eq!(properties["original_bytes"]["minItems"], json!(1));
        assert_eq!(
            properties["original_bytes"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_integer_or_string_type(&properties["dr_index"]["type"]);
        assert_eq!(properties["dr_index"]["minimum"], json!(0));
        assert_eq!(properties["dr_index"]["maximum"], json!(3));
        assert_eq!(properties["pid"]["description"], json!("Target process ID"));
        assert_eq!(properties["hooks"]["description"], json!("Detour batch"));
        assert_eq!(
            tools[0]["inputSchema"]["required"],
            json!(["action"]),
            "non-guide action requirement should be registry-generated"
        );
    }

    #[test]
    fn inject_and_payload_string_schema_fields_are_generated_from_registry_descriptors() {
        let mut tools = vec![
            json!({
                "name": "inject",
                "description": "test inject schema",
                "inputSchema": {
                    "properties": {
                        "action": { "description": "Inject action" },
                        "target_path": { "description": "Target executable path" },
                        "target_exe": { "description": "Legacy target executable alias" },
                        "module": { "description": "Loaded module name" },
                        "export_name": { "description": "Export function name" }
                    }
                }
            }),
            json!({
                "name": "payload",
                "description": "test payload schema",
                "inputSchema": {
                    "properties": {
                        "action": { "description": "Payload action" },
                        "show": { "description": "PE view" },
                        "module": { "description": "Imported module name" },
                        "function": { "description": "Imported function name" }
                    }
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);

        let inject_properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("inject properties");
        assert_eq!(inject_properties["target_path"]["type"], json!("string"));
        assert_eq!(inject_properties["target_path"]["minLength"], json!(1));
        assert_eq!(
            inject_properties["target_path"]["maxLength"],
            json!(crate::args::DEFAULT_MAX_PATH_LEN)
        );
        assert_eq!(inject_properties["target_exe"]["type"], json!("string"));
        assert_eq!(inject_properties["target_exe"]["minLength"], json!(1));
        assert_eq!(
            inject_properties["target_exe"]["maxLength"],
            json!(crate::args::DEFAULT_MAX_PATH_LEN),
            "target_exe should inherit the target_path parser through registry alias descriptors"
        );
        assert_eq!(inject_properties["module"]["type"], json!("string"));
        assert_eq!(inject_properties["module"]["minLength"], json!(1));
        assert_eq!(
            inject_properties["module"]["maxLength"],
            json!(crate::args::DEFAULT_MAX_MODULE_NAME_LEN)
        );
        assert_eq!(inject_properties["export_name"]["type"], json!("string"));

        let inject_metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("inject action metadata");
        let export_forward = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "export_forward")
            .expect("export_forward metadata");
        assert!(export_forward["parser_hints"]
            .as_array()
            .expect("export_forward parser hints")
            .iter()
            .any(|entry| entry["parameter"] == "module" && entry["parser"] == "module_name"));
        assert!(export_forward["parser_hints"]
            .as_array()
            .expect("export_forward parser hints")
            .iter()
            .any(|entry| entry["parameter"] == "export_name" && entry["parser"] == "string"));

        let payload_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("payload properties");
        assert_eq!(payload_properties["module"]["type"], json!("string"));
        assert_eq!(payload_properties["module"]["minLength"], json!(1));
        assert_eq!(
            payload_properties["module"]["maxLength"],
            json!(crate::args::DEFAULT_MAX_MODULE_NAME_LEN)
        );
        assert_eq!(payload_properties["function"]["type"], json!("string"));

        let payload_metadata = tools[1]["x-memoric-actions"]
            .as_array()
            .expect("payload action metadata");
        let pe_parse = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "pe_parse")
            .expect("pe_parse metadata");
        assert!(pe_parse["parser_hints"]
            .as_array()
            .expect("pe_parse parser hints")
            .iter()
            .any(|entry| entry["parameter"] == "module" && entry["parser"] == "module_name"));
        assert!(pe_parse["parser_hints"]
            .as_array()
            .expect("pe_parse parser hints")
            .iter()
            .any(|entry| entry["parameter"] == "function" && entry["parser"] == "string"));
    }

    #[test]
    fn stealth_schema_fields_are_generated_from_registry_descriptors() {
        let mut tools = vec![json!({
            "name": "stealth",
            "inputSchema": {}
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("stealth properties");

        assert_integer_or_string_type(&properties["pid"]["type"]);
        assert_eq!(
            properties["target_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            properties["target_function"]["type"],
            json!(["integer", "string"]),
            "stealth return-spoof target_function should use the action-specific address parser hint"
        );
        assert_eq!(properties["function_name"]["type"], json!("string"));
        assert_eq!(properties["dll_path"]["type"], json!("string"));
        assert_eq!(properties["dll_path"]["minLength"], json!(1));
        assert_eq!(properties["shellcode"]["oneOf"][0]["type"], json!("array"));
        assert_eq!(properties["shellcode"]["minItems"], json!(1));
        assert_eq!(
            properties["shellcode"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(properties["module_name"]["type"], json!("string"));
        assert_eq!(properties["module_name"]["minLength"], json!(1));
        assert_integer_or_string_type(&properties["delay_ms"]["type"]);
        assert_eq!(properties["delay_ms"]["default"], json!(5000));
        assert_eq!(properties["intensity"]["minimum"], json!(1));
        assert_eq!(properties["intensity"]["maximum"], json!(3));
        assert_eq!(
            properties["syscall_method"]["enum"],
            json!(choice_values("stealth", "syscall_write", "syscall_method")
                .expect("syscall method choices"))
        );
        assert_eq!(properties["address"]["type"], json!(["integer", "string"]));
        assert_eq!(
            properties["shellcode_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            properties["start_address"]["type"],
            json!(["integer", "string"])
        );
        assert_integer_or_string_type(&properties["size"]["type"]);
        assert_eq!(properties["size"]["minimum"], json!(1));
        assert_eq!(
            properties["size"]["maximum"],
            json!(MEMORY_MAX_OPERATION_BYTES),
            "top-level stealth size schema should cover the widest registry-described action"
        );
        assert_eq!(properties["protect"]["oneOf"][0]["type"], json!("integer"));
        assert_eq!(properties["bytes"]["oneOf"][0]["type"], json!("array"));
        assert_eq!(properties["bytes"]["minItems"], json!(1));
        assert_eq!(
            properties["bytes"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(properties["target_exe"]["type"], json!("string"));
        assert_eq!(properties["disable_acg"]["type"], json!("boolean"));
        assert_eq!(properties["disable_cig"]["type"], json!("boolean"));
        assert_integer_or_string_type(&properties["parent_pid"]["type"]);
        assert_eq!(properties["key"]["type"], json!("string"));
        assert_eq!(properties["target"]["type"], json!("string"));
        assert_eq!(properties["reference"]["type"], json!("string"));
        assert_eq!(properties["reference"]["minLength"], json!(1));
        assert_eq!(
            properties["sysmon_method"]["enum"],
            json!(choice_values("stealth", "sysmon_blind", "sysmon_method")
                .expect("sysmon method choices"))
        );
        assert_eq!(
            properties["bcd_method"]["enum"],
            json!(choice_values("stealth", "testsign_hide_bcd", "bcd_method")
                .expect("bcd method choices"))
        );
        assert_eq!(properties["exe_path"]["type"], json!("string"));
        assert_eq!(properties["exe_path"]["minLength"], json!(1));
        assert_eq!(properties["args"]["type"], json!("string"));
        assert_eq!(properties["work_dir"]["type"], json!("string"));
        assert_eq!(properties["work_dir"]["minLength"], json!(1));
        assert_eq!(
            properties["ci_action"]["enum"],
            json!(
                choice_values("stealth", "testsign_ci_callback", "ci_action")
                    .expect("ci action choices")
            )
        );
        assert_integer_or_string_type(&properties["new_pte"]["type"]);
        assert_eq!(
            properties["method"]["enum"],
            json!(
                choice_values("stealth", "wdac_disable", "method").expect("policy method choices")
            )
        );
        assert_eq!(
            properties["exclusion_type"]["enum"],
            json!(
                choice_values("stealth", "defender_add_exclusion", "exclusion_type")
                    .expect("exclusion type choices")
            )
        );
        assert_eq!(properties["disable_realtime"]["type"], json!("boolean"));
        assert_eq!(properties["disable_behavior"]["type"], json!("boolean"));
        assert_eq!(properties["disable_cloud"]["type"], json!("boolean"));
        assert_eq!(properties["value"]["type"], json!("string"));
        assert_eq!(properties["path"]["type"], json!("string"));
        assert_eq!(properties["path"]["minLength"], json!(1));
        assert_eq!(
            properties["command"]["enum"],
            json!(choice_values("stealth", "defender_mpcmdrun", "command")
                .expect("mpcmd command choices"))
        );
        assert_integer_or_string_type(&properties["callback_index"]["type"]);
        assert_eq!(
            properties["array_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(properties["device_path"]["type"], json!("string"));
        assert_integer_or_string_type(&properties["ioctl_write_code"]["type"]);
        assert_eq!(properties["altitude"]["type"], json!("string"));
        assert_eq!(
            properties["direction"]["enum"],
            json!(choice_values("stealth", "firewall_add_rule", "direction")
                .expect("firewall direction choices"))
        );
        assert_eq!(properties["protocol"]["type"], json!("string"));
        assert_eq!(properties["protocol"]["default"], json!("any"));
        assert_eq!(properties["port"]["type"], json!("string"));
        assert_eq!(properties["name"]["type"], json!("string"));
        assert_eq!(properties["program"]["type"], json!("string"));
        assert_eq!(properties["program"]["minLength"], json!(1));
        assert_eq!(
            properties["rule_action"]["enum"],
            json!(choice_values("stealth", "firewall_add_rule", "rule_action")
                .expect("firewall action choices"))
        );
        assert_eq!(
            properties["profiles"]["enum"],
            json!(
                choice_values("stealth", "firewall_disable", "profiles").expect("profile choices")
            )
        );
        assert_eq!(properties["name_filter"]["type"], json!("string"));
        assert_eq!(properties["interval_ms"]["minimum"], json!(1000));
        assert_eq!(properties["interval_ms"]["maximum"], json!(300000));
        for parameter in [
            "patch_etw",
            "patch_amsi",
            "unhook_ntdll",
            "hide_module",
            "watchdog",
            "self_destruct",
            "delete_files",
            "terminate",
        ] {
            assert_eq!(properties[parameter]["type"], json!("boolean"));
        }
        assert_eq!(properties["patch_etw"]["default"], json!(true));
        assert_eq!(properties["patch_amsi"]["default"], json!(true));
        assert_eq!(properties["unhook_ntdll"]["default"], json!(false));
        assert_eq!(properties["hide_module"]["default"], json!(true));
        assert_eq!(properties["watchdog"]["default"], json!(false));
        assert_eq!(properties["self_destruct"]["default"], json!(false));
        assert_eq!(properties["passes"]["minimum"], json!(1));
        assert_eq!(properties["passes"]["maximum"], json!(7));
        assert_eq!(properties["delete_files"]["default"], json!(true));
        assert_eq!(properties["terminate"]["default"], json!(true));
        assert_eq!(
            properties["pid"]["description"],
            json!("Target process ID. For encrypt_memory/decrypt_memory, omit pid or use the memoric server PID only; remote PID/address input is rejected.")
        );
        assert_eq!(
            properties["target_address"]["description"],
            json!("Target address for CFG patching actions")
        );
        assert_eq!(
            properties["target_function"]["description"],
            json!("Target function address for return-address spoofing actions")
        );
        assert_eq!(
            properties["shellcode"]["description"],
            json!("Hex-encoded shellcode for module_stomp, or shellcode bytes for compatible sleep helpers")
        );
        assert_eq!(
            properties["module_name"]["description"],
            json!("Module name to hide (sentinel)")
        );

        let metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("stealth metadata");
        let sentinel_start = metadata
            .iter()
            .find(|entry| entry["action"] == "sentinel_start")
            .expect("sentinel_start metadata");
        assert!(sentinel_start["optional_parameters"]
            .as_array()
            .expect("sentinel_start optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "patch_etw" && entry["parser"] == "boolean"));
        let defender_disable = metadata
            .iter()
            .find(|entry| entry["action"] == "defender_disable")
            .expect("defender_disable metadata");
        assert!(defender_disable["optional_parameters"]
            .as_array()
            .expect("defender_disable optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "disable_cloud" && entry["parser"] == "boolean"));
        let launch_hooked = metadata
            .iter()
            .find(|entry| entry["action"] == "testsign_launch_hooked")
            .expect("testsign_launch_hooked metadata");
        assert!(launch_hooked["optional_parameters"]
            .as_array()
            .expect("testsign_launch_hooked optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "exe_path" && entry["parser"] == "path"));
        let firewall_add_rule = metadata
            .iter()
            .find(|entry| entry["action"] == "firewall_add_rule")
            .expect("firewall_add_rule metadata");
        assert!(firewall_add_rule["optional_parameters"]
            .as_array()
            .expect("firewall_add_rule optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "program" && entry["parser"] == "path"));
    }

    #[test]
    fn kernel_optional_schema_fields_are_generated_from_registry_descriptors() {
        let mut tools = vec![json!({
            "name": "kernel",
            "description": "test kernel schema",
            "inputSchema": {}
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("kernel properties");

        for parameter in ["physical", "writable", "executable", "enable"] {
            assert_eq!(properties[parameter]["type"], json!("boolean"));
        }
        assert_eq!(properties["physical"]["default"], json!(false));
        assert_eq!(
            properties["physical"]["description"],
            json!("Use physical addressing")
        );
        for parameter in [
            "device_path",
            "output_path",
            "file_path",
            "dll_path",
            "target_path",
            "legit_path",
        ] {
            assert_eq!(properties[parameter]["type"], json!("string"));
            assert_eq!(properties[parameter]["minLength"], json!(1));
        }
        assert_eq!(
            properties["device_path"]["description"],
            json!("Explicit BYOVD device path (e.g. \\\\.\\RTCore64). If present, hybrid actions use BYOVD instead of memoric.sys.")
        );
        assert_eq!(
            properties["output_path"]["description"],
            json!("Optional artifact output path for driver_pe_dump, driver_process_dump, and other large kernel dump results")
        );
        for parameter in ["input_struct", "shellcode_bytes", "bytes", "data"] {
            assert_eq!(properties[parameter]["oneOf"][0]["type"], json!("array"));
            assert_eq!(properties[parameter]["oneOf"][1]["type"], json!("string"));
            assert_eq!(
                properties[parameter]["oneOf"][0]["items"]["maximum"],
                json!(255)
            );
        }
        assert_eq!(
            properties["bytes"]["description"],
            json!("Bytes to write (canonical for kernel write / physical_write)")
        );
        assert_eq!(
            properties["data"]["description"],
            json!("Legacy alias for bytes on kernel(action='write')")
        );
        for parameter in [
            "object_type_address",
            "list_head_address",
            "base_address",
            "replacement_addr",
            "handler_address",
            "new_handler",
            "thread_start",
            "alloc_address",
            "shellcode_addr",
        ] {
            assert_eq!(properties[parameter]["type"], json!(["integer", "string"]));
        }
        assert_eq!(
            properties["base_address"]["description"],
            json!("Base address for driver_pe_dump/driver_process_dump (hex string or integer; 0 = auto/full range)")
        );
        assert_eq!(properties["pool_tag"]["oneOf"][0]["type"], json!("integer"));
        assert_eq!(
            properties["pool_tag"]["oneOf"][0]["maximum"],
            json!(u32::MAX as u64)
        );
        assert_eq!(properties["pool_tag"]["oneOf"][1]["type"], json!("string"));
        assert_eq!(properties["pool_tag"]["oneOf"][1]["minLength"], json!(1));
        assert_eq!(properties["pool_tag"]["oneOf"][1]["maxLength"], json!(4));
        assert_eq!(
            properties["pool_tag"]["description"],
            json!("Kernel pool tag filter for driver_memory_pool. Integer raw tag or 4-char ASCII string like 'Proc'.")
        );
        for parameter in [
            "max_entries",
            "timer_index",
            "delay_ms",
            "port",
            "source_pid",
            "hook_index",
            "syscall_number",
            "pid",
            "new_parent_pid",
            "protect_pid",
            "max_keys",
            "frame_id",
            "size",
            "tid",
            "index",
            "callout_id",
        ] {
            assert_integer_or_string_type(&properties[parameter]["type"]);
        }
        for parameter in ["target_module", "driver_name"] {
            assert_eq!(properties[parameter]["type"], json!("string"));
            assert_eq!(properties[parameter]["minLength"], json!(1));
            assert_eq!(
                properties[parameter]["maxLength"],
                json!(crate::args::DEFAULT_MAX_MODULE_NAME_LEN)
            );
            assert_eq!(
                properties[parameter]["pattern"],
                json!("^[^\\\\/:\\x00-\\x1F]+$")
            );
        }
        assert_eq!(
            properties["target_module"]["description"],
            json!("Kernel module name for global hook target (e.g. ntoskrnl.exe)")
        );
        assert_eq!(
            properties["driver_name"]["description"],
            json!("Driver module name for hiding (e.g. memoric.sys)")
        );
        for parameter in [
            "target_function",
            "provider_guid",
            "new_image_name",
            "new_command_line",
        ] {
            assert_eq!(properties[parameter]["type"], json!("string"));
        }

        let metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("kernel metadata");
        for (action, parameter, parser) in [
            ("driver_pe_dump", "output_path", "path"),
            ("driver_dpc_timer", "delay_ms", "u64"),
            ("driver_memory_pool", "pool_tag", "pool_tag"),
            ("driver_object_hook", "protect_pid", "pid_u32"),
            ("driver_object_hook", "strip_access", "u64"),
            ("driver_port_hide", "port", "u64"),
            ("driver_token_dup", "source_pid", "pid_u32"),
            ("driver_global_hook", "hook_index", "u64"),
            ("driver_global_hook", "target_module", "module_name"),
            ("driver_global_hook", "target_function", "string"),
            ("driver_global_hook", "replacement_addr", "address_u64"),
            ("driver_infinity_hook", "syscall_number", "u64"),
            ("driver_infinity_hook", "handler_address", "address_u64"),
            ("driver_cloak", "driver_name", "module_name"),
            ("driver_unloaded_drv_clear", "driver_name", "module_name"),
            ("driver_etw_blind", "provider_guid", "string"),
            ("driver_eprocess_spoof", "pid", "pid_u32"),
            ("driver_eprocess_spoof", "new_image_name", "string"),
            ("driver_eprocess_spoof", "new_command_line", "string"),
            ("driver_eprocess_spoof", "new_parent_pid", "pid_u32"),
            ("driver_kernel_exec", "shellcode_bytes", "bytes"),
            ("driver_cred_dump", "pid", "pid_u32"),
            ("driver_cred_dump", "address", "address_u64"),
            ("driver_cred_dump", "size", "u64"),
            ("driver_callback_nuke", "index", "u64"),
            ("driver_minifilter_detach", "filter_name", "string"),
            ("driver_minifilter_detach", "frame_id", "u64"),
            ("driver_kernel_apc", "tid", "tid_u32"),
            ("driver_kernel_apc", "shellcode_size", "u64"),
            ("driver_kernel_apc", "shellcode_addr", "address_u64"),
            ("driver_kernel_apc", "dll_path", "path"),
            ("driver_wfp_remove", "callout_id", "u64"),
        ] {
            let action_metadata = metadata
                .iter()
                .find(|entry| entry["action"] == action)
                .expect("kernel action metadata");
            assert!(
                action_metadata["optional_parameters"]
                    .as_array()
                    .expect("optional parameters")
                    .iter()
                    .any(|entry| entry["parameter"] == parameter && entry["parser"] == parser),
                "{action}.{parameter} should be registry-described as {parser}"
            );
        }
    }

    #[test]
    fn kernel_required_and_choice_schema_fields_are_generated_from_registry_descriptors() {
        let mut tools = vec![json!({
            "name": "kernel",
            "description": "test kernel schema",
            "inputSchema": {}
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("kernel properties");

        for parameter in ["driver_path"] {
            assert_eq!(properties[parameter]["type"], json!("string"));
            assert_eq!(properties[parameter]["minLength"], json!(1));
        }
        assert_eq!(
            properties["driver_path"]["description"],
            json!("Path to .sys file")
        );
        for parameter in ["service_name"] {
            assert_eq!(properties[parameter]["type"], json!("string"));
        }
        for parameter in [
            "read_ioctl",
            "write_ioctl",
            "ioctl_read_code",
            "ioctl_write_code",
            "cr3",
            "callback_index",
            "pid",
            "thread_id",
            "shellcode_size",
        ] {
            assert_integer_or_string_type(&properties[parameter]["type"]);
        }
        for parameter in [
            "address",
            "array_address",
            "entry_address",
            "shellcode_address",
        ] {
            assert_eq!(properties[parameter]["type"], json!(["integer", "string"]));
        }
        assert_eq!(
            properties["address"]["description"],
            json!(
                "Kernel physical/virtual address. Integer or hex string like '0xFFFFF80000000000'."
            )
        );
        assert_eq!(properties["module_name"]["type"], json!("string"));
        assert_eq!(properties["module_name"]["minLength"], json!(1));
        assert_eq!(
            properties["module_name"]["description"],
            json!("Kernel module name for module_hide")
        );
        assert_eq!(
            properties["reg_action"]["enum"],
            json!(choice_values("kernel", "driver_reg_protect", "reg_action")
                .expect("registry action choices"))
        );
        assert_eq!(
            properties["reg_action"]["description"],
            json!("Registry protection action")
        );
        assert_eq!(
            properties["notify_action"]["enum"],
            json!(
                choice_values("kernel", "driver_notify_routine", "notify_action")
                    .expect("notify action choices")
            )
        );
        assert_eq!(
            properties["patch_type"]["enum"],
            json!(choice_values("kernel", "driver_patch_kernel", "patch_type")
                .expect("kernel patch choices"))
        );
        assert_eq!(
            properties["strip_type"]["enum"],
            json!(choice_values("kernel", "driver_handle_strip", "strip_type")
                .expect("kernel strip choices"))
        );
        let auto_inject_action_values =
            choice_values("kernel", "driver_auto_inject", "inject_action")
                .expect("auto-inject choices");
        assert_eq!(
            auto_inject_action_values,
            &["enable", "disable", "query"],
            "set_payload requires a payload buffer path that is not exposed by the current wrapper"
        );
        assert!(
            !auto_inject_action_values.contains(&"set_payload"),
            "auto-inject schema should only expose handler-supported selectors"
        );
        assert_eq!(
            properties["inject_action"]["enum"],
            json!(auto_inject_action_values)
        );
        assert_eq!(
            properties["cb_type"]["enum"],
            json!(choice_values("kernel", "driver_callback_nuke", "cb_type")
                .expect("callback nuke family choices"))
        );
        assert_eq!(
            properties["cb_action"]["enum"],
            json!(choice_values("kernel", "driver_callback_nuke", "cb_action")
                .expect("callback nuke action choices"))
        );
        assert_eq!(
            properties["mf_action"]["enum"],
            json!(
                choice_values("kernel", "driver_minifilter_detach", "mf_action")
                    .expect("minifilter detach action choices")
            )
        );
        assert_eq!(
            properties["apc_action"]["enum"],
            json!(choice_values("kernel", "driver_kernel_apc", "apc_action")
                .expect("kernel APC action choices"))
        );
        assert_eq!(
            properties["wfp_action"]["enum"],
            json!(choice_values("kernel", "driver_wfp_remove", "wfp_action")
                .expect("WFP action choices"))
        );

        let metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("kernel metadata");
        let pte_modify = metadata
            .iter()
            .find(|entry| entry["action"] == "pte_modify")
            .expect("pte_modify metadata");
        assert_eq!(
            pte_modify["required_parameters"],
            json!(["device_path", "read_ioctl", "write_ioctl", "address", "cr3"])
        );
        assert!(pte_modify["parser_hints"]
            .as_array()
            .expect("pte_modify parser hints")
            .iter()
            .any(|entry| entry["parameter"] == "cr3" && entry["parser"] == "u64"));

        let remove_callback = metadata
            .iter()
            .find(|entry| entry["action"] == "remove_callback")
            .expect("remove_callback metadata");
        assert_eq!(
            remove_callback["required_parameters"],
            json!([
                "device_path",
                "ioctl_write_code",
                "callback_index",
                "array_address"
            ])
        );
    }

    #[test]
    fn small_domain_schema_fields_are_generated_from_registry_descriptors() {
        let mut tools = vec![
            json!({
                "name": "detect",
                "inputSchema": {}
            }),
            json!({
                "name": "privilege",
                "inputSchema": {}
            }),
            json!({
                "name": "self",
                "inputSchema": {}
            }),
            json!({
                "name": "orchestrate",
                "description": "test orchestrate schema",
                "inputSchema": {}
            }),
            json!({
                "name": "target",
                "description": "test target schema",
                "inputSchema": {
                    "properties": {
                        "name": { "description": "Process name" },
                        "text": { "description": "String write text" },
                        "max_len": { "description": "String read limit" },
                        "wait_ms": { "description": "Window wait" },
                        "suspend": { "default": true, "description": "Suspend thread" },
                        "output_path": { "description": "Artifact output path" },
                        "output_dir": { "description": "SAM output directory" },
                        "dump_sam": { "description": "Dump SAM hive" },
                        "dump_security": { "description": "Dump SECURITY hive" },
                        "all_sessions": { "description": "All Kerberos sessions" },
                        "include_system": { "default": true, "description": "Include system processes" },
                        "type_filter": { "description": "Handle type filter" }
                    }
                }
            }),
            json!({
                "name": "memory",
                "description": "test memory schema",
                "inputSchema": {
                    "properties": {
                        "output_path": { "description": "Output path" },
                        "cursor": { "description": "Cursor" },
                        "summary_only": { "default": false, "description": "Summary only" },
                        "text": { "description": "Text write" },
                        "allow_unaligned": { "default": true, "description": "Allow unaligned" },
                        "case_insensitive": { "default": true, "description": "Case insensitive" },
                        "filter": { "description": "Filter" },
                        "bypass_protect": { "default": true, "description": "Bypass protect" },
                        "exclude_mapped": { "description": "Exclude mapped" },
                        "exclude_image": { "description": "Exclude image" },
                        "region_cache_refresh": { "description": "Refresh cache" },
                        "region_cache_clear": { "description": "Clear cache" },
                        "include_modules": { "default": true, "description": "Include modules" },
                        "include_handles": { "default": true, "description": "Include handles" },
                        "include_entropy": { "default": true, "description": "Include entropy" }
                    }
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);

        let detect_properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("detect properties");
        assert_integer_or_string_type(&detect_properties["pid"]["type"]);
        assert_eq!(
            detect_properties["pid"]["description"],
            json!("Target PID (for hooks/suspend)")
        );
        assert_eq!(detect_properties["function_name"]["type"], json!("string"));
        assert_eq!(
            detect_properties["function_name"]["description"],
            json!("Function to inspect or resolve (for hook_function/syscall_resolve)")
        );
        assert_eq!(detect_properties["function"]["type"], json!("string"));
        assert_eq!(
            detect_properties["function"]["description"],
            json!("Legacy alias for function_name in syscall_resolve")
        );
        assert_eq!(detect_properties["target"]["type"], json!("string"));
        assert_eq!(
            detect_properties["target"]["description"],
            json!("Substring match used by edr_suspend to suspend a specific process family")
        );
        assert_eq!(detect_properties["edr_only"]["type"], json!("boolean"));
        assert_eq!(detect_properties["edr_only"]["default"], json!(true));
        assert_eq!(
            detect_properties["edr_only"]["description"],
            json!("Suspend only known EDR processes when action='edr_suspend'")
        );

        let privilege_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("privilege properties");
        let privilege_method_values = privilege_properties["method"]["enum"]
            .as_array()
            .expect("privilege method enum");
        for value in
            choice_values("privilege", "elevate", "method").expect("elevate method choices")
        {
            assert!(privilege_method_values.contains(&json!(value)));
        }
        for value in choice_values("privilege", "potato", "method").expect("potato method choices")
        {
            assert!(privilege_method_values.contains(&json!(value)));
        }
        assert_eq!(
            privilege_properties["method"]["description"],
            json!("Elevation method (for elevate: auto/fodhelper/eventvwr/computerdefaults/sdclt/disk_cleanup/mock_trusted_dir/request_uac/system, for potato: print_spoofer/god_potato/efs_potato)")
        );
        assert_integer_or_string_type(&privilege_properties["pid"]["type"]);
        assert_eq!(
            privilege_properties["pid"]["description"],
            json!("Legacy PID field. token_* actions primarily use target_pid; kernel/other tools may still use pid.")
        );
        assert_integer_or_string_type(&privilege_properties["target_pid"]["type"]);
        assert_eq!(
            privilege_properties["target_pid"]["description"],
            json!("Target process ID for token_steal/token_impersonate/token_scan")
        );
        assert_eq!(privilege_properties["command"]["type"], json!("string"));
        assert_eq!(
            privilege_properties["command"]["description"],
            json!("Command to execute elevated/as impersonated user")
        );
        assert_eq!(privilege_properties["link_path"]["type"], json!("string"));
        assert_eq!(privilege_properties["link_path"]["minLength"], json!(1));
        assert_eq!(
            privilege_properties["link_path"]["description"],
            json!("Symlink/junction/hardlink path (for symlink)")
        );
        assert_eq!(privilege_properties["target_path"]["type"], json!("string"));
        assert_eq!(
            privilege_properties["target_path"]["description"],
            json!("Symlink target (for symlink) or spawn target path depending on tool")
        );
        assert_eq!(
            privilege_properties["type"]["enum"],
            json!(choice_values("privilege", "symlink", "type").expect("symlink type choices"))
        );
        assert_eq!(
            privilege_properties["type"]["description"],
            json!("Filesystem link type for action='symlink'")
        );
        assert_eq!(privilege_properties["detail"]["type"], json!("boolean"));
        assert_eq!(privilege_properties["detail"]["default"], json!(false));
        assert_eq!(
            privilege_properties["detail"]["description"],
            json!("Detailed output (for check)")
        );
        assert_eq!(privilege_properties["exploit"]["type"], json!("boolean"));
        assert_eq!(privilege_properties["exploit"]["default"], json!(false));
        assert_eq!(
            privilege_properties["exploit"]["description"],
            json!("Actually exploit (for service abuse, default: scan only)")
        );
        assert_eq!(
            privilege_properties["payload_path"]["type"],
            json!("string")
        );
        assert_eq!(privilege_properties["payload_path"]["minLength"], json!(1));
        assert_eq!(
            privilege_properties["payload_path"]["description"],
            json!("Payload path for service exploit")
        );

        let privilege_metadata = tools[1]["x-memoric-actions"]
            .as_array()
            .expect("privilege metadata");
        let token_steal = privilege_metadata
            .iter()
            .find(|entry| entry["action"] == "token_steal")
            .expect("token_steal metadata");
        assert_eq!(token_steal["required_parameters"], json!(["target_pid"]));
        assert_eq!(
            token_steal["parameter_aliases"],
            json!([{ "canonical": "target_pid", "alias": "pid" }])
        );
        let privilege_check = privilege_metadata
            .iter()
            .find(|entry| entry["action"] == "check")
            .expect("check metadata");
        assert!(privilege_check["optional_parameters"]
            .as_array()
            .expect("optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "detail" && entry["parser"] == "boolean"));

        let self_properties = tools[2]["inputSchema"]["properties"]
            .as_object()
            .expect("self properties");
        assert_integer_or_string_type(&self_properties["pid"]["type"]);
        assert_eq!(
            self_properties["pid"]["description"],
            json!("Target PID (for peb/heap/memory_diagnostics; defaults to current process for memory_diagnostics)")
        );
        assert_eq!(
            self_properties["address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            self_properties["address"]["description"],
            json!("Memory address (for encrypt/decrypt/wipe)")
        );
        assert_integer_or_string_type(&self_properties["size"]["type"]);
        assert_eq!(
            self_properties["size"]["description"],
            json!("Size in bytes")
        );
        assert_eq!(self_properties["size"]["minimum"], json!(1));
        assert_eq!(
            self_properties["size"]["maximum"],
            json!(MEMORY_MAX_OPERATION_BYTES)
        );
        assert_eq!(self_properties["region_limit"]["maximum"], json!(1024));
        assert_eq!(
            self_properties["region_limit"]["description"],
            json!("Maximum memory regions returned by self(action='memory_diagnostics')")
        );
        assert_eq!(self_properties["suspicious_limit"]["maximum"], json!(1024));
        assert_eq!(self_properties["module_limit"]["maximum"], json!(1024));
        assert_eq!(self_properties["handle_limit"]["maximum"], json!(1024));
        assert_eq!(
            self_properties["entropy_region_limit"]["maximum"],
            json!(128)
        );
        assert_eq!(
            self_properties["entropy_sample_bytes"]["maximum"],
            json!(64 * 1024)
        );
        assert_eq!(
            self_properties["sub_action"]["enum"],
            json!(choice_values("self", "state", "sub_action").expect("self state choices"))
        );
        assert_eq!(self_properties["include_modules"]["type"], json!("boolean"));
        assert_eq!(self_properties["include_modules"]["default"], json!(true));
        assert_eq!(
            self_properties["include_modules"]["description"],
            json!("Include module summary in memory_diagnostics")
        );
        assert_eq!(self_properties["include_handles"]["type"], json!("boolean"));
        assert_eq!(self_properties["include_handles"]["default"], json!(true));
        assert_eq!(self_properties["include_entropy"]["type"], json!("boolean"));
        assert_eq!(self_properties["include_entropy"]["default"], json!(true));
        assert_eq!(self_properties["recent_task_limit"]["maximum"], json!(100));
        assert_eq!(
            self_properties["recent_task_limit"]["description"],
            json!("Maximum recent task summaries included by self(action='diagnostics')")
        );
        assert_eq!(self_properties["task_id"]["type"], json!("string"));
        assert_eq!(
            self_properties["task_id"]["description"],
            json!("Task ID scope for state cleanup/rollback views")
        );
        assert_eq!(self_properties["chain_id"]["type"], json!("string"));
        assert_eq!(
            self_properties["chain_id"]["description"],
            json!("Operation history filter by chain ID")
        );
        assert_eq!(self_properties["output_dir"]["type"], json!("string"));
        assert_eq!(self_properties["output_dir"]["minLength"], json!(1));
        assert_eq!(
            self_properties["output_dir"]["description"],
            json!(
                "Optional directory for self(action='diagnostics') operator-safe bundle artifact"
            )
        );
        assert_eq!(self_properties["tool"]["type"], json!("string"));
        assert_eq!(self_properties["status"]["type"], json!("string"));
        assert_eq!(self_properties["audit_path"]["type"], json!("string"));
        assert_eq!(self_properties["audit_path"]["minLength"], json!(1));
        assert_eq!(self_properties["request_id"]["type"], json!("string"));
        assert_eq!(self_properties["correlation_id"]["type"], json!("string"));
        assert_eq!(self_properties["artifact_uri"]["type"], json!("string"));
        assert_eq!(self_properties["since"]["type"], json!("string"));
        assert_eq!(self_properties["until"]["type"], json!("string"));
        assert_integer_or_string_type(&self_properties["offset"]["type"]);
        assert_eq!(self_properties["limit"]["maximum"], json!(500));
        assert_eq!(self_properties["error"]["type"], json!("string"));
        assert_eq!(self_properties["message"]["type"], json!("string"));
        assert_eq!(self_properties["code"]["type"], json!("string"));
        assert_eq!(self_properties["result"]["type"], json!("object"));
        assert_eq!(self_properties["doctor"]["type"], json!("object"));
        assert_eq!(self_properties["baseline"]["type"], json!("object"));
        assert_eq!(self_properties["baseline_path"]["type"], json!("string"));
        assert_eq!(self_properties["baseline_path"]["minLength"], json!(1));
        assert_eq!(
            self_properties["baseline_path"]["description"],
            json!("Path to a saved capability/doctor/current JSON baseline for self(action='capability_diff')")
        );
        assert_eq!(self_properties["include_scan"]["type"], json!("boolean"));
        assert_eq!(self_properties["include_scan"]["default"], json!(false));
        assert_eq!(
            self_properties["include_scan"]["description"],
            json!("Run optional bytes scan session in self(action='test')")
        );
        let self_metadata = tools[2]["x-memoric-actions"]
            .as_array()
            .expect("self metadata");
        let self_next_steps = self_metadata
            .iter()
            .find(|entry| entry["action"] == "next_steps")
            .expect("next_steps metadata");
        assert!(self_next_steps["optional_parameters"]
            .as_array()
            .expect("next_steps optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "result" && entry["parser"] == "object"));

        let orchestrate_properties = tools[3]["inputSchema"]["properties"]
            .as_object()
            .expect("orchestrate properties");
        assert_eq!(
            orchestrate_properties["limit"]["description"],
            json!("Maximum items returned per paginated plan/execute result section")
        );
        assert_eq!(orchestrate_properties["limit"]["minimum"], json!(1));
        assert_eq!(
            orchestrate_properties["offset"]["description"],
            json!("Pagination offset for plan/execute result sections when cursor is omitted")
        );
        assert_integer_or_string_type(&orchestrate_properties["offset"]["type"]);
        assert_eq!(
            orchestrate_properties["cursor"]["description"],
            json!("Opaque cursor returned in pagination.nextCursor; pass unchanged to continue plan/execute result pagination")
        );
        assert_eq!(orchestrate_properties["cursor"]["type"], json!("string"));
        assert_eq!(
            orchestrate_properties["output_path"]["type"],
            json!("string")
        );
        assert_eq!(orchestrate_properties["output_path"]["minLength"], json!(1));
        assert_eq!(
            orchestrate_properties["output_path"]["description"],
            json!("Optional artifact output path for full plan/execute results; large static plans auto-export when omitted")
        );
        assert_eq!(orchestrate_properties["chain_id"]["type"], json!("string"));
        assert_eq!(
            orchestrate_properties["chain_id"]["description"],
            json!("Persisted chain checkpoint ID for status/resume/cancel/cleanup")
        );
        assert_eq!(
            orchestrate_properties["template"]["description"],
            json!("Registered static plan template for orchestrate(action='plan') when steps are omitted")
        );
        assert_eq!(
            orchestrate_properties["template"]["enum"],
            json!(choice_values("orchestrate", "plan", "template")
                .expect("orchestrate template choices"))
        );
        assert_eq!(
            orchestrate_properties["steps"]["description"],
            json!("Custom chain steps (for plan action)")
        );
        assert_eq!(orchestrate_properties["steps"]["type"], json!("array"));
        assert_eq!(orchestrate_properties["steps"]["minItems"], json!(1));
        assert_eq!(
            orchestrate_properties["steps"]["items"]["required"],
            json!(["tool", "action"])
        );
        assert_eq!(
            orchestrate_properties["steps"]["items"]["properties"]["args"]["type"],
            json!("object")
        );
        assert_eq!(
            orchestrate_properties["pid"]["description"],
            json!("Target process ID (for execute)")
        );
        assert_integer_or_string_type(&orchestrate_properties["pid"]["type"]);
        assert_eq!(
            orchestrate_properties["shellcode"]["description"],
            json!("Hex-encoded shellcode to inject (for execute)")
        );
        assert_eq!(
            orchestrate_properties["shellcode"]["oneOf"][0]["type"],
            json!("array")
        );
        assert_eq!(
            orchestrate_properties["dry_run"]["description"],
            json!("If true, plan but don't execute steps")
        );
        assert_eq!(orchestrate_properties["dry_run"]["type"], json!("boolean"));
        assert_eq!(orchestrate_properties["dry_run"]["default"], json!(true));
        assert_eq!(
            orchestrate_properties["allow_live_execution"]["description"],
            json!("Required with dry_run=false before orchestrate executes state-changing steps")
        );
        assert_eq!(
            orchestrate_properties["allow_live_execution"]["type"],
            json!("boolean")
        );
        assert_eq!(
            orchestrate_properties["allow_live_execution"]["default"],
            json!(false)
        );
        assert_eq!(
            orchestrate_properties["skip_completed_steps"]["type"],
            json!("boolean")
        );
        assert_eq!(
            orchestrate_properties["skip_completed_steps"]["description"],
            json!("Resume hint: skip checkpoint-completed step IDs when replaying the original authorized chain request")
        );
        assert_eq!(
            orchestrate_properties["skip_completed_steps"]["default"],
            json!(true)
        );
        assert_eq!(
            orchestrate_properties["benign_pid"]["description"],
            json!("Explicit PID from examples/benign_test_target.rs for template='lab_validation'")
        );
        assert_integer_or_string_type(&orchestrate_properties["benign_pid"]["type"]);
        assert_eq!(
            orchestrate_properties["marker_address"]["description"],
            json!("Marker address printed by the benign test target for optional read-only validation")
        );
        assert_eq!(
            orchestrate_properties["marker_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            orchestrate_properties["counter_address"]["description"],
            json!(
                "Counter address printed by the benign test target for dry-run write preview only"
            )
        );
        assert_eq!(
            orchestrate_properties["counter_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(
            orchestrate_properties["marker_len"]["description"],
            json!("Marker byte length for lab_validation marker read")
        );
        assert_integer_or_string_type(&orchestrate_properties["marker_len"]["type"]);
        assert_eq!(orchestrate_properties["marker_len"]["default"], json!(28));
        let orchestrate_metadata = tools[3]["x-memoric-actions"]
            .as_array()
            .expect("orchestrate metadata");
        let execute = orchestrate_metadata
            .iter()
            .find(|entry| entry["action"] == "execute")
            .expect("execute metadata");
        assert!(execute["optional_parameters"]
            .as_array()
            .expect("execute optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "allow_live_execution"
                && entry["parser"] == "boolean"));

        let target_properties = tools[4]["inputSchema"]["properties"]
            .as_object()
            .expect("target properties");
        assert_eq!(target_properties["name"]["type"], json!("string"));
        assert_eq!(target_properties["text"]["type"], json!("string"));
        assert_integer_or_string_type(&target_properties["max_len"]["type"]);
        assert_eq!(
            target_properties["max_len"]["maximum"],
            json!(TARGET_MAX_STRING_READ_BYTES)
        );
        assert_integer_or_string_type(&target_properties["wait_ms"]["type"]);
        assert_eq!(
            target_properties["wait_ms"]["maximum"],
            json!(TARGET_MAX_WINDOW_WAIT_MS)
        );
        for parameter in [
            "suspend",
            "dump_sam",
            "dump_security",
            "all_sessions",
            "include_system",
        ] {
            assert_eq!(target_properties[parameter]["type"], json!("boolean"));
        }
        assert_eq!(target_properties["suspend"]["default"], json!(true));
        assert_eq!(target_properties["include_system"]["default"], json!(true));
        assert_eq!(target_properties["output_path"]["type"], json!("string"));
        assert_eq!(target_properties["output_path"]["minLength"], json!(1));
        assert_eq!(target_properties["output_dir"]["type"], json!("string"));
        assert_eq!(target_properties["output_dir"]["minLength"], json!(1));
        assert_eq!(target_properties["type_filter"]["type"], json!("string"));

        let target_metadata = tools[4]["x-memoric-actions"]
            .as_array()
            .expect("target metadata");
        let thread_context = target_metadata
            .iter()
            .find(|entry| entry["action"] == "thread_context")
            .expect("thread_context metadata");
        assert!(thread_context["optional_parameters"]
            .as_array()
            .expect("thread_context optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "suspend" && entry["parser"] == "boolean"));
        let sam_dump = target_metadata
            .iter()
            .find(|entry| entry["action"] == "sam_dump")
            .expect("sam_dump metadata");
        assert!(sam_dump["optional_parameters"]
            .as_array()
            .expect("sam_dump optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "output_dir" && entry["parser"] == "path"));
        assert!(sam_dump["optional_parameters"]
            .as_array()
            .expect("sam_dump optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "dump_sam" && entry["parser"] == "boolean"));
        let kerberos_tickets = target_metadata
            .iter()
            .find(|entry| entry["action"] == "kerberos_tickets")
            .expect("kerberos_tickets metadata");
        assert!(kerberos_tickets["optional_parameters"]
            .as_array()
            .expect("kerberos_tickets optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "all_sessions" && entry["parser"] == "boolean"));

        let memory_properties = tools[5]["inputSchema"]["properties"]
            .as_object()
            .expect("memory properties");
        assert_eq!(memory_properties["output_path"]["type"], json!("string"));
        assert_eq!(memory_properties["output_path"]["minLength"], json!(1));
        assert_eq!(memory_properties["cursor"]["type"], json!("string"));
        assert_eq!(memory_properties["summary_only"]["type"], json!("boolean"));
        assert_eq!(memory_properties["summary_only"]["default"], json!(false));
        assert_eq!(memory_properties["text"]["type"], json!("string"));
        for parameter in [
            "allow_unaligned",
            "case_insensitive",
            "bypass_protect",
            "exclude_mapped",
            "exclude_image",
            "region_cache_refresh",
            "region_cache_clear",
            "include_modules",
            "include_handles",
            "include_entropy",
        ] {
            assert_eq!(memory_properties[parameter]["type"], json!("boolean"));
        }
        assert_eq!(memory_properties["allow_unaligned"]["default"], json!(true));
        assert_eq!(
            memory_properties["case_insensitive"]["default"],
            json!(true)
        );
        assert_eq!(memory_properties["bypass_protect"]["default"], json!(true));
        assert_eq!(memory_properties["include_modules"]["default"], json!(true));
        assert_eq!(memory_properties["include_handles"]["default"], json!(true));
        assert_eq!(memory_properties["include_entropy"]["default"], json!(true));
        assert_eq!(memory_properties["filter"]["type"], json!("string"));

        let memory_metadata = tools[5]["x-memoric-actions"]
            .as_array()
            .expect("memory metadata");
        let scan_list = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "scan_list")
            .expect("scan_list metadata");
        assert!(scan_list["optional_parameters"]
            .as_array()
            .expect("scan_list optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "summary_only" && entry["parser"] == "boolean"));
        assert!(scan_list["optional_parameters"]
            .as_array()
            .expect("scan_list optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "output_path" && entry["parser"] == "path"));
        let typed_read = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "typed_read")
            .expect("typed_read metadata");
        assert!(typed_read["optional_parameters"]
            .as_array()
            .expect("typed_read optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "allow_unaligned" && entry["parser"] == "boolean"));
        let diagnostics = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "diagnostics")
            .expect("diagnostics metadata");
        assert!(diagnostics["optional_parameters"]
            .as_array()
            .expect("diagnostics optional parameters")
            .iter()
            .any(|entry| entry["parameter"] == "include_entropy" && entry["parser"] == "boolean"));
    }

    #[test]
    fn descriptor_parameter_fields_match_parser_hint_shapes() {
        let mut tools = vec![
            json!({
                "name": "kernel",
                "description": "test kernel schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "memory",
                "description": "test memory schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "stealth",
                "description": "test stealth schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "inject",
                "description": "test inject schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "method": { "type": "string" },
                        "dll_method": { "type": "string" },
                        "spawn_method": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);

        let kernel_properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("kernel properties");
        assert_eq!(
            kernel_properties["bytes"]["oneOf"],
            json!([
                {
                    "type": "array",
                    "items": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 255,
                    }
                },
                { "type": "string" }
            ]),
            "bytes parser hints should expose both byte arrays and hex strings"
        );

        let memory_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("memory properties");
        assert_eq!(
            memory_properties["signature"]["oneOf"],
            json!([
                {
                    "type": "array",
                    "items": {
                        "oneOf": [
                            {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 255,
                            },
                            { "type": "string" },
                            { "type": "null" }
                        ]
                    }
                },
                { "type": "string" }
            ]),
            "byte pattern parser hints should expose strings plus byte/wildcard arrays"
        );

        let stealth_properties = tools[2]["inputSchema"]["properties"]
            .as_object()
            .expect("stealth properties");
        assert_eq!(
            stealth_properties["protection"]["oneOf"],
            json!([
                {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": u32::MAX as u64,
                },
                {
                    "type": "string"
                }
            ]),
            "protection parser hints should expose numeric constants and symbolic strings"
        );
        assert_eq!(
            stealth_properties["protection"]["x-memoric-symbolicValues"],
            json!(PAGE_PROTECTION_SYMBOLIC_VALUES),
            "protection parser hints should expose the registry-owned symbolic aliases"
        );

        let memory_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("memory properties");
        assert_eq!(
            memory_properties["protect"]["oneOf"], stealth_properties["protection"]["oneOf"],
            "memory protect aliases should use the same mixed protection schema"
        );
        assert_eq!(
            memory_properties["protection"]["x-memoric-symbolicValues"],
            json!(PAGE_PROTECTION_SYMBOLIC_VALUES),
            "memory protection should expose registry-owned symbolic aliases"
        );

        let mut orchestrate_tools = vec![json!({
            "name": "orchestrate",
            "description": "test orchestrate schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string" }
                },
                "required": ["action"]
            }
        })];
        enhance_tool_definitions(&mut orchestrate_tools);
        let orchestrate_properties = orchestrate_tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("orchestrate properties");
        assert_eq!(
            orchestrate_properties["steps"]["items"]["type"],
            json!("object"),
            "object-array parser hints should generate object item schemas"
        );
        assert_eq!(
            orchestrate_properties["steps"]["items"]["required"],
            json!(["tool", "action"]),
            "object-array parser hints should expose registry item required fields"
        );
        assert_eq!(
            orchestrate_properties["steps"]["items"]["properties"]["args"]["type"],
            json!("object"),
            "object-array parser hints should expose registry item property schemas"
        );
    }

    #[test]
    fn schema_bounds_use_registry_parser_hint_shapes() {
        let mut tools = vec![json!({
            "name": "memory",
            "description": "test memory schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string" }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut tools);

        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("memory properties");
        assert_eq!(
            properties["signature"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES as u64),
            "byte-pattern parser hints should receive item bounds without relying on parameter-name heuristics"
        );
        assert_eq!(
            properties["signature"]["x-memoric-byteLengthMaximum"],
            json!(Some(crate::args::DEFAULT_MAX_BYTES as u64)),
            "byte-pattern parser hints should expose byte-length metadata for string encodings"
        );

        let all_of = tools[0]["inputSchema"]["allOf"]
            .as_array()
            .expect("memory action conditions");
        let scan_condition = all_of
            .iter()
            .find(|condition| condition["if"]["properties"]["action"]["const"] == "scan")
            .expect("scan action condition");
        assert_eq!(
            scan_condition["then"]["properties"]["signature"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES as u64),
            "action-specific bounds should also use the registry parser hint shape"
        );
        assert_eq!(
            scan_condition["then"]["properties"]["signature"]["x-memoric-byteLengthMaximum"],
            json!(Some(crate::args::DEFAULT_MAX_BYTES as u64))
        );
    }

    #[test]
    fn parameter_alias_descriptors_reference_registered_actions() {
        for alias in all_parameter_aliases() {
            assert!(
                is_known_tool(alias.tool),
                "{} alias references unknown tool",
                alias.tool
            );
            if alias.action != "*" {
                assert!(
                    is_known_tool_action(alias.tool, alias.action),
                    "{}({}) alias references unknown action",
                    alias.tool,
                    alias.action
                );
            }
            assert_ne!(
                alias.canonical, alias.alias,
                "{}({}) alias maps a field to itself",
                alias.tool, alias.action
            );
        }
    }

    #[test]
    fn choice_parameter_descriptors_reference_registered_actions() {
        for descriptor in all_choice_parameters() {
            assert!(
                is_known_tool(descriptor.tool),
                "{} choice parameter descriptor references unknown tool",
                descriptor.tool
            );
            assert!(
                is_known_tool_action(descriptor.tool, descriptor.action),
                "{}({}) choice parameter descriptor references unknown action",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.parameter.trim().is_empty(),
                "{}({}) choice parameter name should not be empty",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.values.is_empty(),
                "{}({}) choice parameter '{}' should define at least one value",
                descriptor.tool,
                descriptor.action,
                descriptor.parameter
            );
            for (index, value) in descriptor.values.iter().enumerate() {
                assert!(
                    !value.trim().is_empty(),
                    "{}({}) choice parameter '{}' contains an empty value",
                    descriptor.tool,
                    descriptor.action,
                    descriptor.parameter
                );
                assert!(
                    !descriptor.values[..index].contains(value),
                    "{}({}) choice parameter '{}' duplicates value '{}'",
                    descriptor.tool,
                    descriptor.action,
                    descriptor.parameter,
                    value
                );
            }
        }
    }

    #[test]
    fn array_choice_parameter_descriptors_reference_registered_actions() {
        for descriptor in all_array_choice_parameters() {
            assert!(
                is_known_tool(descriptor.tool),
                "{} array choice parameter descriptor references unknown tool",
                descriptor.tool
            );
            assert!(
                is_known_tool_action(descriptor.tool, descriptor.action),
                "{}({}) array choice parameter descriptor references unknown action",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.parameter.trim().is_empty(),
                "{}({}) array choice parameter name should not be empty",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.values.is_empty(),
                "{}({}) array choice parameter '{}' should define at least one value",
                descriptor.tool,
                descriptor.action,
                descriptor.parameter
            );
            for (index, value) in descriptor.values.iter().enumerate() {
                assert!(
                    !value.trim().is_empty(),
                    "{}({}) array choice parameter '{}' contains an empty value",
                    descriptor.tool,
                    descriptor.action,
                    descriptor.parameter
                );
                assert!(
                    !descriptor.values[..index].contains(value),
                    "{}({}) array choice parameter '{}' duplicates value '{}'",
                    descriptor.tool,
                    descriptor.action,
                    descriptor.parameter,
                    value
                );
            }
        }
    }

    #[test]
    fn parameter_bounds_descriptors_reference_registered_actions() {
        for descriptor in all_parameter_bounds() {
            assert!(
                is_known_tool(descriptor.tool),
                "{} parameter bounds descriptor references unknown tool",
                descriptor.tool
            );
            assert!(
                is_known_tool_action(descriptor.tool, descriptor.action),
                "{}({}) parameter bounds descriptor references unknown action",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.parameter.trim().is_empty(),
                "{}({}) parameter bounds name should not be empty",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                descriptor.minimum.is_some() || descriptor.maximum.is_some(),
                "{}({}) {} parameter bounds should declare at least one bound",
                descriptor.tool,
                descriptor.action,
                descriptor.parameter
            );
            if let (Some(minimum), Some(maximum)) = (descriptor.minimum, descriptor.maximum) {
                assert!(
                    minimum <= maximum,
                    "{}({}) {} parameter bounds should be ordered",
                    descriptor.tool,
                    descriptor.action,
                    descriptor.parameter
                );
            }
        }
    }

    #[test]
    fn required_parameter_descriptors_reference_registered_actions() {
        for descriptor in all_required_parameters() {
            assert!(
                is_known_tool(descriptor.tool),
                "{} required parameter descriptor references unknown tool",
                descriptor.tool
            );
            assert!(
                is_known_tool_action(descriptor.tool, descriptor.action),
                "{}({}) required parameter descriptor references unknown action",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.parameters.is_empty(),
                "{}({}) required parameter descriptor should not be empty",
                descriptor.tool,
                descriptor.action
            );
            for (index, parameter) in descriptor.parameters.iter().enumerate() {
                assert!(
                    !parameter.trim().is_empty(),
                    "{}({}) required parameter name should not be empty",
                    descriptor.tool,
                    descriptor.action
                );
                assert!(
                    !descriptor.parameters[..index].contains(parameter),
                    "{}({}) required parameter '{}' is duplicated",
                    descriptor.tool,
                    descriptor.action,
                    parameter
                );
            }
        }
    }

    #[test]
    fn alternative_required_parameter_descriptors_reference_registered_actions() {
        for descriptor in all_alternative_required_parameters() {
            assert!(
                is_known_tool(descriptor.tool),
                "{} alternative required descriptor references unknown tool",
                descriptor.tool
            );
            assert!(
                is_known_tool_action(descriptor.tool, descriptor.action),
                "{}({}) alternative required descriptor references unknown action",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                descriptor.parameters.len() >= 2,
                "{}({}) alternative required descriptor should describe at least two alternatives",
                descriptor.tool,
                descriptor.action
            );
            for (index, parameter) in descriptor.parameters.iter().enumerate() {
                assert!(
                    !parameter.trim().is_empty(),
                    "{}({}) alternative required parameter name should not be empty",
                    descriptor.tool,
                    descriptor.action
                );
                assert!(
                    !descriptor.parameters[..index].contains(parameter),
                    "{}({}) alternative required parameter '{}' is duplicated",
                    descriptor.tool,
                    descriptor.action,
                    parameter
                );
            }
            if let Some(when_parameter) = descriptor.when_parameter {
                assert!(
                    !when_parameter.trim().is_empty(),
                    "{}({}) alternative required condition parameter should not be empty",
                    descriptor.tool,
                    descriptor.action
                );
                assert!(
                    !descriptor.when_values.is_empty() || descriptor.default_applies,
                    "{}({}) conditional alternative required descriptor should declare values or a default",
                    descriptor.tool,
                    descriptor.action
                );
            }
        }
    }

    #[test]
    fn planner_warning_descriptors_reference_registered_actions() {
        for descriptor in all_planner_warnings() {
            assert!(
                is_known_tool(descriptor.tool),
                "{} planner warning descriptor references unknown tool",
                descriptor.tool
            );
            assert!(
                is_known_tool_action(descriptor.tool, descriptor.action),
                "{}({}) planner warning descriptor references unknown action",
                descriptor.tool,
                descriptor.action
            );
            assert!(
                !descriptor.message.trim().is_empty(),
                "{}({}) planner warning should include a message",
                descriptor.tool,
                descriptor.action
            );
            match descriptor.condition {
                PlannerWarningCondition::Always => {}
                PlannerWarningCondition::ParameterPresent
                | PlannerWarningCondition::ParameterMissing => assert!(
                    descriptor.parameter.is_some(),
                    "{}({}) parameter-based planner warning should name a parameter",
                    descriptor.tool,
                    descriptor.action
                ),
            }
        }
    }

    #[test]
    fn required_privilege_metadata_is_registry_backed() {
        let memory = registered_action("memory", "write").expect("memory write metadata");
        assert!(memory
            .required_privileges
            .iter()
            .any(|descriptor| descriptor.privilege == "target_allowlist"));

        let kernel = registered_action("kernel", "driver_load").expect("driver_load metadata");
        assert!(kernel
            .required_privileges
            .iter()
            .any(|descriptor| descriptor.privilege == "SeLoadDriverPrivilege"));

        let metadata_value = action_metadata_json("kernel");
        let metadata = metadata_value.as_array().expect("kernel metadata");
        let driver_load = metadata
            .iter()
            .find(|entry| entry["action"] == "driver_load")
            .expect("driver_load action metadata");
        assert!(driver_load["required_privileges"]
            .as_array()
            .expect("required privilege metadata")
            .iter()
            .any(|entry| entry["privilege"] == "SeLoadDriverPrivilege"
                && entry["description"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("load or unload")));
    }

    #[test]
    fn side_effect_metadata_is_registry_backed() {
        let memory = registered_action("memory", "write").expect("memory write metadata");
        assert!(memory
            .side_effects
            .iter()
            .any(|descriptor| descriptor.effect == "target memory mutation"));

        let kernel = registered_action("kernel", "driver_load").expect("driver_load metadata");
        assert!(kernel
            .side_effects
            .iter()
            .any(|descriptor| descriptor.effect
                == "kernel driver, kernel memory, or system state mutation"));

        let metadata_value = action_metadata_json("memory");
        let metadata = metadata_value.as_array().expect("memory metadata");
        let write = metadata
            .iter()
            .find(|entry| entry["action"] == "write")
            .expect("memory write action metadata");
        assert!(write["side_effects"]
            .as_array()
            .expect("side effect metadata")
            .iter()
            .any(|entry| entry["effect"] == "target memory mutation"
                && entry["description"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("target process memory")));
    }

    #[test]
    fn planned_handle_metadata_is_registry_backed() {
        let memory = registered_action("memory", "write").expect("memory write metadata");
        assert!(memory
            .planned_handles
            .iter()
            .any(|descriptor| descriptor.kind == "process"
                && descriptor
                    .access
                    .contains("PROCESS_VM_OPERATION | PROCESS_VM_WRITE")));

        let kernel = registered_action("kernel", "driver_load").expect("driver_load metadata");
        assert!(kernel
            .planned_handles
            .iter()
            .any(|descriptor| descriptor.kind == "service"
                && descriptor.access.contains("SERVICE_CREATE")));

        let metadata_value = action_metadata_json("kernel");
        let metadata = metadata_value.as_array().expect("kernel metadata");
        let driver_load = metadata
            .iter()
            .find(|entry| entry["action"] == "driver_load")
            .expect("driver_load action metadata");
        assert!(driver_load["planned_handles"]
            .as_array()
            .expect("planned handle metadata")
            .iter()
            .any(|entry| entry["kind"] == "service"
                && entry["target"] == "kernel driver service"
                && entry["access"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("SERVICE_START")));
    }

    #[test]
    fn rollback_preview_metadata_is_registry_backed() {
        let protect = registered_action("memory", "protect").expect("memory protect metadata");
        assert_eq!(
            protect.rollback_preview.available,
            RollbackAvailability::Label("partial")
        );
        assert_eq!(
            protect.rollback_preview.strategy,
            "restore_previous_protection"
        );
        assert!(protect
            .rollback_preview
            .captured_fields
            .contains(&"old_protection"));

        let cleanup = registered_action("payload", "cleanup").expect("payload cleanup metadata");
        assert_eq!(
            cleanup.rollback_preview.available,
            RollbackAvailability::Boolean(false)
        );
        assert_eq!(
            cleanup.rollback_preview.reason,
            Some("irreversible_cleanup")
        );

        let metadata_value = action_metadata_json("kernel");
        let metadata = metadata_value.as_array().expect("kernel metadata");
        let callback_remove = metadata
            .iter()
            .find(|entry| entry["action"] == "driver_callback_remove")
            .expect("driver_callback_remove action metadata");
        assert_eq!(
            callback_remove["rollback"]["strategy"],
            "restore_removed_callback_pointer"
        );
        assert!(callback_remove["rollback"]["captured_fields"]
            .as_array()
            .expect("rollback captured fields")
            .iter()
            .any(|field| field == "callback_address"));
    }

    #[test]
    fn typed_action_enums_cover_migrated_domains() {
        for action in tool_actions("payload").expect("payload actions") {
            let registered =
                registered_action("payload", action).expect("registered payload action");
            PayloadAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("payload action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("detect").expect("detect actions") {
            let registered = registered_action("detect", action).expect("registered detect action");
            DetectAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("detect action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("orchestrate").expect("orchestrate actions") {
            let registered =
                registered_action("orchestrate", action).expect("registered orchestrate action");
            OrchestrateAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("orchestrate action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("privilege").expect("privilege actions") {
            let registered =
                registered_action("privilege", action).expect("registered privilege action");
            PrivilegeAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("privilege action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("target").expect("target actions") {
            let registered = registered_action("target", action).expect("registered target action");
            TargetAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("target action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("self").expect("self actions") {
            let registered = registered_action("self", action).expect("registered self action");
            SelfAction::try_from(&registered)
                .unwrap_or_else(|_| panic!("self action '{}' missing typed enum variant", action));
        }

        for action in tool_actions("memory").expect("memory actions") {
            let registered = registered_action("memory", action).expect("registered memory action");
            MemoryAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("memory action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("hook").expect("hook actions") {
            let registered = registered_action("hook", action).expect("registered hook action");
            HookAction::try_from(&registered)
                .unwrap_or_else(|_| panic!("hook action '{}' missing typed enum variant", action));
        }

        for action in tool_actions("inject").expect("inject actions") {
            let registered = registered_action("inject", action).expect("registered inject action");
            InjectAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("inject action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("stealth").expect("stealth actions") {
            let registered =
                registered_action("stealth", action).expect("registered stealth action");
            StealthAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("stealth action '{}' missing typed enum variant", action)
            });
        }

        for action in tool_actions("kernel").expect("kernel actions") {
            let registered = registered_action("kernel", action).expect("registered kernel action");
            KernelAction::try_from(&registered).unwrap_or_else(|_| {
                panic!("kernel action '{}' missing typed enum variant", action)
            });
        }
    }

    #[test]
    fn action_metadata_exposes_parameter_alias_descriptors() {
        let metadata_value = action_metadata_json("memory");
        let metadata = metadata_value.as_array().expect("memory metadata");
        let scan_new = metadata
            .iter()
            .find(|entry| entry["action"] == "scan_new")
            .expect("scan_new metadata")
            .clone();
        let aliases = scan_new["parameter_aliases"]
            .as_array()
            .expect("scan_new aliases");

        assert!(aliases
            .iter()
            .any(|alias| alias["canonical"] == "signature" && alias["alias"] == "pattern_bytes"));
        assert!(aliases
            .iter()
            .any(|alias| alias["canonical"] == "address" && alias["alias"] == "base_address"));

        let typed_read = metadata
            .iter()
            .find(|entry| entry["action"] == "typed_read")
            .expect("typed_read metadata");
        let typed_read_aliases = typed_read["parameter_aliases"]
            .as_array()
            .expect("typed_read aliases");
        assert!(typed_read_aliases
            .iter()
            .any(|alias| alias["canonical"] == "type" && alias["alias"] == "value_type"));
    }

    #[test]
    fn choice_parameter_descriptors_generate_schema_and_metadata() {
        let mut tools = vec![json!({
            "name": "memory",
            "description": "test schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Memory action"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["stale"]
                    },
                    "region_cache": {
                        "type": "string"
                    },
                    "scan_mode": {
                        "type": "string"
                    },
                    "scan_type": {
                        "type": "string"
                    },
                    "change": {
                        "type": "string"
                    },
                    "direction": {
                        "type": "string"
                    },
                    "encoding": {
                        "type": "string"
                    },
                    "type": {
                        "type": "string"
                    },
                    "endian": {
                        "type": "string"
                    },
                    "value_type": {
                        "type": "string"
                    },
                    "sort": {
                        "description": "Scan list sort order"
                    },
                    "values": {
                        "description": "Multi-value scan values"
                    },
                    "delta": {
                        "description": "Delta amount"
                    },
                    "min": {
                        "description": "Range minimum"
                    },
                    "max": {
                        "description": "Range maximum"
                    }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("schema properties");

        assert_eq!(
            properties["mode"]["enum"],
            json!(choice_values("memory", "read", "mode").expect("read mode choices"))
        );
        assert_eq!(
            properties["region_cache"]["enum"],
            json!(
                choice_values("memory", "read", "region_cache").expect("region cache mode choices")
            )
        );
        assert_eq!(
            properties["scan_mode"]["enum"],
            json!(choice_values("memory", "scan", "scan_mode").expect("scan mode choices"))
        );
        assert_eq!(
            properties["type"]["enum"],
            json!(choice_values("memory", "typed_read", "type").expect("typed type choices"))
        );
        assert_eq!(
            properties["scan_type"]["enum"],
            json!(choice_values("memory", "scan", "scan_type").expect("scan type choices"))
        );
        assert_eq!(
            properties["change"]["enum"],
            json!(choice_values("memory", "scan", "change").expect("change choices"))
        );
        assert_eq!(
            properties["direction"]["enum"],
            json!(choice_values("memory", "scan", "direction").expect("direction choices"))
        );
        assert_eq!(
            properties["encoding"]["enum"],
            json!(choice_values("memory", "scan", "encoding").expect("encoding choices"))
        );
        assert_eq!(
            properties["endian"]["enum"],
            json!(choice_values("memory", "typed_read", "endian").expect("endian choices"))
        );
        assert_eq!(
            properties["value_type"]["enum"],
            json!(choice_values("memory", "scan_new", "value_type")
                .expect("scan_new value type choices"))
        );
        assert_eq!(properties["sort"]["type"], json!("string"));
        assert_eq!(
            properties["sort"]["enum"],
            json!(choice_values("memory", "scan_list", "sort").expect("scan_list sort choices"))
        );
        assert_eq!(
            properties["sort"]["description"],
            json!("Scan list sort order"),
            "registry enhancement should preserve description-only seed fields"
        );
        assert_eq!(properties["values"]["type"], json!("array"));
        assert_eq!(properties["values"]["items"]["type"], json!("number"));
        assert_eq!(properties["delta"]["type"], json!("number"));
        assert_eq!(properties["min"]["type"], json!("number"));
        assert_eq!(properties["max"]["type"], json!("number"));
        assert_eq!(
            properties["values"]["description"],
            json!("Multi-value scan values")
        );
        assert_eq!(properties["delta"]["description"], json!("Delta amount"));

        let metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("action metadata");
        let read = metadata
            .iter()
            .find(|entry| entry["action"] == "read")
            .expect("read metadata");
        let scan = metadata
            .iter()
            .find(|entry| entry["action"] == "scan")
            .expect("scan metadata");
        let typed_read = metadata
            .iter()
            .find(|entry| entry["action"] == "typed_read")
            .expect("typed_read metadata");
        let scan_new = metadata
            .iter()
            .find(|entry| entry["action"] == "scan_new")
            .expect("scan_new metadata");
        let scan_list = metadata
            .iter()
            .find(|entry| entry["action"] == "scan_list")
            .expect("scan_list metadata");

        assert_eq!(
            read["choice_parameters"],
            json!([
                {
                    "parameter": "mode",
                    "values": choice_values("memory", "read", "mode").expect("read mode choices")
                },
                {
                    "parameter": "region_cache",
                    "values": choice_values("memory", "read", "region_cache")
                        .expect("region cache mode choices")
                }
            ])
        );
        let scan_choices = scan["choice_parameters"]
            .as_array()
            .expect("scan choice metadata");
        for parameter in [
            "scan_mode",
            "scan_type",
            "change",
            "direction",
            "encoding",
            "region_cache",
        ] {
            assert!(
                scan_choices
                    .iter()
                    .any(|entry| entry["parameter"] == parameter),
                "scan choice metadata should expose {}",
                parameter
            );
        }
        assert!(typed_read["choice_parameters"]
            .as_array()
            .expect("typed_read choice metadata")
            .iter()
            .any(|entry| entry["parameter"] == "type"));
        assert!(typed_read["choice_parameters"]
            .as_array()
            .expect("typed_read choice metadata")
            .iter()
            .any(|entry| entry["parameter"] == "endian"));
        assert_eq!(
            scan_new["choice_parameters"],
            json!([
                {
                    "parameter": "value_type",
                    "values": choice_values("memory", "scan_new", "value_type")
                        .expect("scan_new value type choices")
                },
                {
                    "parameter": "region_cache",
                    "values": choice_values("memory", "scan_new", "region_cache")
                        .expect("scan_new region cache choices")
                }
            ])
        );
        assert_eq!(
            scan_list["choice_parameters"],
            json!([{
                "parameter": "sort",
                "values": choice_values("memory", "scan_list", "sort")
                    .expect("scan_list sort choices")
            }])
        );

        let mut self_tools = vec![json!({
            "name": "self",
            "description": "test self schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string" },
                    "sub_action": {
                        "type": "string",
                        "enum": ["stale"]
                    }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut self_tools);
        let self_properties = self_tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("self schema properties");
        assert_eq!(
            self_properties["sub_action"]["enum"],
            json!(choice_values("self", "state", "sub_action")
                .expect("self state sub_action choices"))
        );
        let self_metadata = self_tools[0]["x-memoric-actions"]
            .as_array()
            .expect("self action metadata");
        let state = self_metadata
            .iter()
            .find(|entry| entry["action"] == "state")
            .expect("self state metadata");
        assert_eq!(
            state["choice_parameters"],
            json!([{
                "parameter": "sub_action",
                "values": choice_values("self", "state", "sub_action")
                    .expect("self state sub_action choices")
            }])
        );

        let mut payload_tools = vec![json!({
            "name": "payload",
            "description": "test payload schema",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string" },
                    "show": {
                        "type": "string",
                        "enum": ["stale"]
                    },
                    "obf_method": { "type": "string" },
                    "format": { "type": "string" }
                },
                "required": ["action"]
            }
        })];

        enhance_tool_definitions(&mut payload_tools);
        let payload_properties = payload_tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("payload schema properties");
        assert_eq!(
            payload_properties["show"]["enum"],
            json!(choice_values("payload", "pe_parse", "show")
                .expect("payload pe_parse show choices"))
        );
        assert_eq!(
            payload_properties["obf_method"]["enum"],
            json!(choice_values("payload", "obfuscate", "obf_method")
                .expect("payload obfuscation method choices"))
        );
        assert_eq!(
            payload_properties["format"]["enum"],
            json!(choice_values("payload", "serialize", "format")
                .expect("payload serialize format choices"))
        );
        let payload_metadata = payload_tools[0]["x-memoric-actions"]
            .as_array()
            .expect("payload action metadata");
        let pe_parse = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "pe_parse")
            .expect("pe_parse metadata");
        assert_eq!(pe_parse["required_parameters"], json!(["pid"]));
        assert_eq!(
            pe_parse["conditional_required_parameters"],
            json!([
                {
                    "when_parameter": "show",
                    "when_values": ["headers", "imports", "exports", "sections"],
                    "parameters": ["address"],
                    "default_applies": true,
                    "description": "PE parse views require a base address; base_address is accepted as an alias.",
                },
                {
                    "when_parameter": "show",
                    "when_values": ["iat_entry"],
                    "parameters": ["module"],
                    "default_applies": false,
                    "description": "IAT entry lookup requires a module name; module_name is accepted as an alias.",
                }
            ])
        );
        assert_eq!(pe_parse["alternative_required_parameters"], json!([]));
        assert_eq!(
            pe_parse["choice_parameters"],
            json!([{
                "parameter": "show",
                "values": choice_values("payload", "pe_parse", "show")
                    .expect("payload pe_parse show choices")
            }])
        );
        let obfuscate = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "obfuscate")
            .expect("obfuscate metadata");
        assert_eq!(
            obfuscate["choice_parameters"],
            json!([{
                "parameter": "obf_method",
                "values": choice_values("payload", "obfuscate", "obf_method")
                    .expect("payload obfuscation method choices")
            }])
        );
        let serialize = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "serialize")
            .expect("serialize metadata");
        assert_eq!(
            serialize["choice_parameters"],
            json!([{
                "parameter": "format",
                "values": choice_values("payload", "serialize", "format")
                    .expect("payload serialize format choices")
            }])
        );
    }

    #[test]
    fn choice_parameter_descriptors_cover_non_memory_tools() {
        let mut tools = vec![
            json!({
                "name": "stealth",
                "description": "test stealth schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "syscall_method": { "type": "string" },
                        "command": { "type": "string" },
                        "direction": { "type": "string" },
                        "method": { "type": "string" },
                        "profiles": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "kernel",
                "description": "test kernel schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "reg_action": { "type": "string" },
                        "notify_type": { "type": "string" },
                        "notify_action": { "type": "string" },
                        "obj_action": { "type": "string" },
                        "inject_flags": { "description": "Auto-inject flags" },
                        "port_action": { "type": "string" },
                        "protocol": { "type": "string" },
                        "token_action": { "type": "string" },
                        "hook_action": { "type": "string" },
                        "hook_type": { "type": "string" },
                        "infhook_action": { "type": "string" },
                        "patch_type": { "type": "string" },
                        "strip_type": { "type": "string" },
                        "cr_action": { "type": "string" },
                        "idt_action": { "type": "string" },
                        "cloak_action": { "type": "string" },
                        "unloaded_action": { "type": "string" },
                        "keylog_action": { "type": "string" },
                        "etw_action": { "type": "string" },
                        "spoof_action": { "type": "string" },
                        "log_action": { "type": "string" },
                        "cred_action": { "type": "string" },
                        "imp_action": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "privilege",
                "description": "test privilege schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "type": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "orchestrate",
                "description": "test orchestrate schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "template": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "hook",
                "description": "test hook schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "method": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "inject",
                "description": "test inject schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "method": { "type": "string" },
                        "dll_method": { "type": "string" },
                        "spawn_method": { "type": "string" }
                    },
                    "required": ["action"]
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);
        let stealth_properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("stealth schema properties");
        assert_eq!(
            stealth_properties["syscall_method"]["enum"],
            json!(choice_values("stealth", "syscall_write", "syscall_method")
                .expect("syscall method choices"))
        );
        assert_eq!(
            stealth_properties["command"]["enum"],
            json!(choice_values("stealth", "defender_mpcmdrun", "command")
                .expect("mpcmd command choices"))
        );
        assert_eq!(
            stealth_properties["direction"]["enum"],
            json!(choice_values("stealth", "firewall_add_rule", "direction")
                .expect("firewall direction choices"))
        );
        assert_eq!(
            stealth_properties["method"]["enum"],
            json!(choice_values("stealth", "wdac_disable", "method")
                .expect("stealth policy method choices"))
        );
        assert_eq!(
            stealth_properties["profiles"]["enum"],
            json!(choice_values("stealth", "firewall_disable", "profiles")
                .expect("firewall profile choices"))
        );

        let stealth_metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("stealth action metadata");
        let mpcmdrun = stealth_metadata
            .iter()
            .find(|entry| entry["action"] == "defender_mpcmdrun")
            .expect("defender_mpcmdrun metadata");
        assert_eq!(
            mpcmdrun["choice_parameters"],
            json!([{
                "parameter": "command",
                "values": choice_values("stealth", "defender_mpcmdrun", "command")
                    .expect("mpcmd command choices")
            }])
        );
        let wdac_disable = stealth_metadata
            .iter()
            .find(|entry| entry["action"] == "wdac_disable")
            .expect("wdac_disable metadata");
        assert_eq!(
            wdac_disable["choice_parameters"],
            json!([{
                "parameter": "method",
                "values": choice_values("stealth", "wdac_disable", "method")
                    .expect("stealth policy method choices")
            }])
        );
        let firewall_add_rule = stealth_metadata
            .iter()
            .find(|entry| entry["action"] == "firewall_add_rule")
            .expect("firewall_add_rule metadata");
        assert_eq!(
            firewall_add_rule["choice_parameters"],
            json!([
                {
                    "parameter": "direction",
                    "values": choice_values("stealth", "firewall_add_rule", "direction")
                        .expect("firewall direction choices")
                },
                {
                    "parameter": "rule_action",
                    "values": choice_values("stealth", "firewall_add_rule", "rule_action")
                        .expect("firewall rule action choices")
                }
            ])
        );

        let kernel_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("kernel schema properties");
        assert_eq!(
            kernel_properties["reg_action"]["enum"],
            json!(choice_values("kernel", "driver_reg_protect", "reg_action")
                .expect("registry action choices"))
        );
        assert_eq!(
            kernel_properties["notify_type"]["enum"],
            json!(
                choice_values("kernel", "driver_notify_routine", "notify_type")
                    .expect("notify type choices")
            )
        );
        assert_eq!(
            kernel_properties["callback_type"]["enum"],
            json!(
                choice_values("kernel", "driver_callback_enum", "callback_type")
                    .expect("kernel callback type choices")
            )
        );
        assert_eq!(
            kernel_properties["obj_action"]["enum"],
            json!(choice_values("kernel", "driver_object_hook", "obj_action")
                .expect("object action choices"))
        );
        assert_eq!(
            kernel_properties["cloak_action"]["enum"],
            json!(choice_values("kernel", "driver_cloak", "cloak_action")
                .expect("driver cloak action choices"))
        );
        assert_eq!(
            kernel_properties["port_action"]["enum"],
            json!(choice_values("kernel", "driver_port_hide", "port_action")
                .expect("port hide action choices"))
        );
        assert_eq!(
            kernel_properties["protocol"]["enum"],
            json!(choice_values("kernel", "driver_port_hide", "protocol")
                .expect("port protocol choices"))
        );
        assert_eq!(
            kernel_properties["token_action"]["enum"],
            json!(choice_values("kernel", "driver_token_dup", "token_action")
                .expect("token dup action choices"))
        );
        assert_eq!(
            kernel_properties["hook_action"]["enum"],
            json!(choice_values("kernel", "driver_global_hook", "hook_action")
                .expect("global hook action choices"))
        );
        assert_eq!(
            kernel_properties["hook_type"]["enum"],
            json!(choice_values("kernel", "driver_global_hook", "hook_type")
                .expect("global hook type choices"))
        );
        assert_eq!(
            kernel_properties["infhook_action"]["enum"],
            json!(
                choice_values("kernel", "driver_infinity_hook", "infhook_action")
                    .expect("infinity hook action choices")
            )
        );
        assert_eq!(
            kernel_properties["inject_flags"]["type"],
            json!("array"),
            "array-choice descriptors should generate string-array schema without seed type/items"
        );
        assert_eq!(
            kernel_properties["inject_flags"]["items"]["type"],
            json!("string"),
            "array-choice descriptors should generate string-array item schema"
        );
        assert_eq!(
            kernel_properties["inject_flags"]["items"]["enum"],
            json!(
                array_choice_values("kernel", "driver_auto_inject", "inject_flags")
                    .expect("auto-inject flag choices")
            )
        );

        let kernel_metadata = tools[1]["x-memoric-actions"]
            .as_array()
            .expect("kernel action metadata");
        let notify = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_notify_routine")
            .expect("driver_notify_routine metadata");
        let notify_choices = notify["choice_parameters"]
            .as_array()
            .expect("notify choice metadata");
        assert!(notify_choices
            .iter()
            .any(|entry| entry["parameter"] == "notify_type"));
        assert!(notify_choices
            .iter()
            .any(|entry| entry["parameter"] == "notify_action"));
        let callback_remove = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_callback_remove")
            .expect("driver_callback_remove metadata");
        assert_eq!(
            callback_remove["choice_parameters"],
            json!([{
                "parameter": "callback_type",
                "values": choice_values("kernel", "driver_callback_remove", "callback_type")
                    .expect("kernel callback type choices")
            }])
        );
        let object_hook = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_object_hook")
            .expect("driver_object_hook metadata");
        assert_eq!(
            object_hook["choice_parameters"],
            json!([{
                "parameter": "obj_action",
                "values": choice_values("kernel", "driver_object_hook", "obj_action")
                    .expect("object action choices")
            }])
        );
        let auto_inject = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_auto_inject")
            .expect("driver_auto_inject metadata");
        assert_eq!(
            auto_inject["choice_parameters"],
            json!([{
                "parameter": "inject_action",
                "values": ["enable", "disable", "query"]
            }])
        );
        assert_eq!(
            auto_inject["array_choice_parameters"],
            json!([{
                "parameter": "inject_flags",
                "values": array_choice_values("kernel", "driver_auto_inject", "inject_flags")
                    .expect("auto-inject flag choices")
            }])
        );
        assert_eq!(
            kernel_properties["patch_type"]["enum"],
            json!(choice_values("kernel", "driver_patch_kernel", "patch_type")
                .expect("kernel patch type choices"))
        );
        assert_eq!(
            kernel_properties["strip_type"]["enum"],
            json!(choice_values("kernel", "driver_handle_strip", "strip_type")
                .expect("kernel handle strip choices"))
        );
        assert_eq!(
            kernel_properties["cr_action"]["enum"],
            json!(choice_values("kernel", "driver_cr_rw", "cr_action")
                .expect("kernel CR action choices"))
        );
        assert_eq!(
            kernel_properties["idt_action"]["enum"],
            json!(choice_values("kernel", "driver_idt_rw", "idt_action")
                .expect("kernel IDT action choices"))
        );
        assert_eq!(
            kernel_properties["unloaded_action"]["enum"],
            json!(
                choice_values("kernel", "driver_unloaded_drv_clear", "unloaded_action")
                    .expect("unloaded driver action choices")
            )
        );
        assert_eq!(
            kernel_properties["etw_action"]["enum"],
            json!(choice_values("kernel", "driver_etw_blind", "etw_action")
                .expect("ETW action choices"))
        );
        assert_eq!(
            kernel_properties["spoof_action"]["enum"],
            json!(
                choice_values("kernel", "driver_eprocess_spoof", "spoof_action")
                    .expect("EPROCESS spoof action choices")
            )
        );
        let pte_rw = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_pte_rw")
            .expect("driver_pte_rw metadata");
        assert_eq!(
            pte_rw["conditional_required_parameters"],
            json!([{
                "when_parameter": "pte_action",
                "when_values": ["write", "restore"],
                "parameters": ["new_pte"],
                "default_applies": false,
                "description": "PTE write/restore operations require the replacement PTE value; read and make_writable modes derive values from the current PTE.",
            }])
        );
        let msr_rw = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_msr_rw")
            .expect("driver_msr_rw metadata");
        assert_eq!(
            msr_rw["conditional_required_parameters"],
            json!([{
                "when_parameter": "msr_action",
                "when_values": ["write"],
                "parameters": ["msr_index", "msr_value"],
                "default_applies": false,
                "description": "MSR writes require the target MSR index and replacement value; reads may use the handler default index.",
            }])
        );
        assert_eq!(
            object_hook["conditional_required_parameters"],
            json!([{
                "when_parameter": "obj_action",
                "when_values": ["register"],
                "parameters": ["protect_pid"],
                "default_applies": false,
                "description": "Object hook registration requires the protected process ID; unregister and query modes can omit it.",
            }])
        );
        let system_thread = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_system_thread")
            .expect("driver_system_thread metadata");
        assert_eq!(
            system_thread["conditional_required_parameters"],
            json!([{
                "when_parameter": "thread_action",
                "when_values": ["create"],
                "parameters": ["thread_start"],
                "default_applies": false,
                "description": "System thread creation requires a kernel start routine address; query mode can omit it.",
            }])
        );
        let kernel_exec = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_kernel_exec")
            .expect("driver_kernel_exec metadata");
        assert_eq!(
            kernel_exec["conditional_required_parameters"],
            json!([
                {
                    "when_parameter": "exec_action",
                    "when_values": ["run", "alloc"],
                    "parameters": ["shellcode_bytes"],
                    "default_applies": true,
                    "description": "Kernel exec run/alloc operations require shellcode bytes; free mode requires an existing allocation address.",
                },
                {
                    "when_parameter": "exec_action",
                    "when_values": ["free"],
                    "parameters": ["alloc_address"],
                    "default_applies": false,
                    "description": "Kernel exec free requires the allocated kernel address returned by a prior allocation.",
                }
            ])
        );
        let cloak = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_cloak")
            .expect("driver_cloak metadata");
        assert_eq!(
            cloak["choice_parameters"],
            json!([{
                "parameter": "cloak_action",
                "values": choice_values("kernel", "driver_cloak", "cloak_action")
                    .expect("driver cloak action choices")
            }])
        );
        assert_eq!(
            cloak["conditional_required_parameters"],
            json!([{
                "when_parameter": "cloak_action",
                "when_values": ["target"],
                "parameters": ["driver_name"],
                "default_applies": false,
                "description": "Driver cloak target mode requires the driver module name; self and query modes can omit it.",
            }])
        );
        let reg_hide = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_reg_hide")
            .expect("driver_reg_hide metadata");
        assert_eq!(
            reg_hide["choice_parameters"],
            json!([{
                "parameter": "reg_action",
                "values": choice_values("kernel", "driver_reg_hide", "reg_action")
                    .expect("kernel registry hide action choices")
            }])
        );
        assert_eq!(
            reg_hide["conditional_required_parameters"],
            json!([{
                "when_parameter": "reg_action",
                "when_values": ["add", "remove"],
                "parameters": ["key_path"],
                "default_applies": false,
                "description": "Registry hide add/remove operations require the target registry key path; list and clear modes can omit it.",
            }])
        );
        let file_lock = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_file_lock")
            .expect("driver_file_lock metadata");
        assert_eq!(
            file_lock["conditional_required_parameters"],
            json!([{
                "when_parameter": "lock_action",
                "when_values": ["add", "remove"],
                "parameters": ["file_path"],
                "default_applies": false,
                "description": "File lock add/remove operations require the target file path; list and clear modes can omit it.",
            }])
        );
        let ppl_bypass = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_ppl_bypass")
            .expect("driver_ppl_bypass metadata");
        assert_eq!(
            ppl_bypass["conditional_required_parameters"],
            json!([{
                "when_parameter": "ppl_action",
                "when_values": ["strip", "set"],
                "parameters": ["pid"],
                "default_applies": false,
                "description": "PPL strip/set operations require the target process ID; query mode can omit it only when the handler default is intended.",
            }])
        );
        let token_swap = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_token_swap")
            .expect("driver_token_swap metadata");
        assert_eq!(
            token_swap["conditional_required_parameters"],
            json!([{
                "when_parameter": "swap_action",
                "when_values": ["steal", "swap"],
                "parameters": ["target_pid"],
                "default_applies": true,
                "description": "Token steal/swap operations require the target process ID; query mode can omit it only when explicitly selected.",
            }])
        );
        let process_protect = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_process_protect")
            .expect("driver_process_protect metadata");
        assert_eq!(
            process_protect["conditional_required_parameters"],
            json!([{
                "when_parameter": "protect_action",
                "when_values": ["set", "strip"],
                "parameters": ["pid"],
                "default_applies": false,
                "description": "Process protection set/strip operations require the target process ID; query mode can omit it only when explicitly selected.",
            }])
        );
        let cr_rw = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_cr_rw")
            .expect("driver_cr_rw metadata");
        assert_eq!(
            cr_rw["conditional_required_parameters"],
            json!([{
                "when_parameter": "cr_action",
                "when_values": ["write"],
                "parameters": ["cr_index", "value"],
                "default_applies": false,
                "description": "Control register writes require the target register index and replacement value; reads may default to CR0.",
            }])
        );
        let idt_rw = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_idt_rw")
            .expect("driver_idt_rw metadata");
        assert_eq!(
            idt_rw["conditional_required_parameters"],
            json!([{
                "when_parameter": "idt_action",
                "when_values": ["write"],
                "parameters": ["vector", "new_handler"],
                "default_applies": false,
                "description": "IDT writes require the interrupt vector and replacement handler address; read and dump modes may use defaults.",
            }])
        );
        assert_eq!(
            kernel_properties["keylog_action"]["enum"],
            json!(choice_values("kernel", "driver_keylogger", "keylog_action")
                .expect("kernel keylogger action choices"))
        );
        assert_eq!(
            kernel_properties["log_action"]["enum"],
            json!(
                choice_values("kernel", "driver_event_log_clear", "log_action")
                    .expect("kernel event log action choices")
            )
        );
        assert_eq!(
            kernel_properties["cred_action"]["enum"],
            json!(choice_values("kernel", "driver_cred_dump", "cred_action")
                .expect("kernel credential action choices"))
        );
        assert_eq!(
            kernel_properties["imp_action"]["enum"],
            json!(choice_values("kernel", "driver_impersonate", "imp_action")
                .expect("kernel impersonation action choices"))
        );

        let cred_dump = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_cred_dump")
            .expect("driver_cred_dump metadata");
        assert_eq!(
            cred_dump["choice_parameters"],
            json!([{
                "parameter": "cred_action",
                "values": choice_values("kernel", "driver_cred_dump", "cred_action")
                    .expect("kernel credential action choices")
            }])
        );
        assert_eq!(
            cred_dump["conditional_required_parameters"],
            json!([{
                "when_parameter": "cred_action",
                "when_values": ["read"],
                "parameters": ["pid", "address"],
                "default_applies": false,
                "description": "Credential memory reads require the source process ID and address; find_lsass and full dump modes derive their target internally.",
            }])
        );
        let impersonate = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_impersonate")
            .expect("driver_impersonate metadata");
        assert_eq!(
            impersonate["conditional_required_parameters"],
            json!([{
                "when_parameter": "imp_action",
                "when_values": ["swap"],
                "parameters": ["target_path", "legit_path"],
                "default_applies": false,
                "description": "Driver impersonation swap requires both target and legitimate driver paths; restore/query use stored backup state.",
            }])
        );
        let callback_nuke = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_callback_nuke")
            .expect("driver_callback_nuke metadata");
        assert_eq!(
            callback_nuke["conditional_required_parameters"],
            json!([{
                "when_parameter": "cb_action",
                "when_values": ["remove"],
                "parameters": ["index"],
                "default_applies": false,
                "description": "Callback single-remove requires the callback table index; enum, nuke_all, and restore modes do not use it.",
            }])
        );
        let minifilter_detach = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_minifilter_detach")
            .expect("driver_minifilter_detach metadata");
        assert_eq!(
            minifilter_detach["conditional_required_parameters"],
            json!([{
                "when_parameter": "mf_action",
                "when_values": ["detach"],
                "parameters": ["filter_name", "frame_id"],
                "default_applies": false,
                "description": "Minifilter detach requires the filter name and frame ID; enum and nuke modes can omit a specific target.",
            }])
        );
        let kernel_apc = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_kernel_apc")
            .expect("driver_kernel_apc metadata");
        assert_eq!(
            kernel_apc["conditional_required_parameters"],
            json!([
                {
                    "when_parameter": "apc_action",
                    "when_values": ["inject"],
                    "parameters": ["tid", "shellcode_size", "shellcode_addr"],
                    "default_applies": true,
                    "description": "Kernel APC shellcode injection requires the target thread ID, shellcode size, and shellcode address.",
                },
                {
                    "when_parameter": "apc_action",
                    "when_values": ["dll"],
                    "parameters": ["tid", "dll_path"],
                    "default_applies": false,
                    "description": "Kernel APC DLL injection requires the target thread ID and DLL path.",
                }
            ])
        );
        let wfp_remove = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_wfp_remove")
            .expect("driver_wfp_remove metadata");
        assert_eq!(
            wfp_remove["conditional_required_parameters"],
            json!([{
                "when_parameter": "wfp_action",
                "when_values": ["remove"],
                "parameters": ["callout_id"],
                "default_applies": false,
                "description": "WFP single-remove requires the target callout ID; enum and nuke modes can omit a single callout target.",
            }])
        );
        let port_hide = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_port_hide")
            .expect("driver_port_hide metadata");
        assert_eq!(
            port_hide["conditional_required_parameters"],
            json!([{
                "when_parameter": "port_action",
                "when_values": ["add", "remove"],
                "parameters": ["port"],
                "default_applies": false,
                "description": "Port hide add/remove operations require the target port; list and clear modes can omit it.",
            }])
        );
        let token_dup = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_token_dup")
            .expect("driver_token_dup metadata");
        assert_eq!(
            token_dup["conditional_required_parameters"],
            json!([{
                "when_parameter": "token_action",
                "when_values": ["copy"],
                "parameters": ["source_pid"],
                "default_applies": false,
                "description": "Token copy requires the source process ID; system and restore modes use driver-managed token state.",
            }])
        );
        let global_hook = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_global_hook")
            .expect("driver_global_hook metadata");
        assert_eq!(
            global_hook["conditional_required_parameters"],
            json!([
                {
                    "when_parameter": "hook_action",
                    "when_values": ["install"],
                    "parameters": ["target_module", "target_function", "replacement_addr"],
                    "default_applies": false,
                    "description": "Global hook installation requires the target module, target function, and replacement address; query mode can omit hook targets.",
                },
                {
                    "when_parameter": "hook_action",
                    "when_values": ["remove"],
                    "parameters": ["hook_index"],
                    "default_applies": false,
                    "description": "Global hook removal requires the hook slot index; query mode can omit it.",
                }
            ])
        );
        let infinity_hook = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_infinity_hook")
            .expect("driver_infinity_hook metadata");
        assert_eq!(
            infinity_hook["conditional_required_parameters"],
            json!([
                {
                    "when_parameter": "infhook_action",
                    "when_values": ["enable", "disable"],
                    "parameters": ["syscall_number"],
                    "default_applies": false,
                    "description": "Infinity hook enable/disable operations require the target syscall number; query mode can omit it.",
                },
                {
                    "when_parameter": "infhook_action",
                    "when_values": ["enable"],
                    "parameters": ["handler_address"],
                    "default_applies": false,
                    "description": "Infinity hook enable requires the replacement handler address.",
                }
            ])
        );
        let unloaded_drv_clear = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_unloaded_drv_clear")
            .expect("driver_unloaded_drv_clear metadata");
        assert_eq!(
            unloaded_drv_clear["conditional_required_parameters"],
            json!([{
                "when_parameter": "unloaded_action",
                "when_values": ["clear_name"],
                "parameters": ["driver_name"],
                "default_applies": false,
                "description": "Unloaded-driver clear_name requires the driver module name; query and clear_all modes can omit it.",
            }])
        );
        let etw_blind = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_etw_blind")
            .expect("driver_etw_blind metadata");
        assert_eq!(
            etw_blind["conditional_required_parameters"],
            json!([{
                "when_parameter": "etw_action",
                "when_values": ["disable", "enable"],
                "parameters": ["provider_guid"],
                "default_applies": false,
                "description": "ETW provider disable/enable operations require the provider GUID; query and kill_all modes can omit it.",
            }])
        );
        let eprocess_spoof = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_eprocess_spoof")
            .expect("driver_eprocess_spoof metadata");
        assert_eq!(
            eprocess_spoof["conditional_required_parameters"],
            json!([
                {
                    "when_parameter": "spoof_action",
                    "when_values": ["image_name"],
                    "parameters": ["pid", "new_image_name"],
                    "default_applies": false,
                    "description": "EPROCESS image-name spoofing requires the target process ID and new image name.",
                },
                {
                    "when_parameter": "spoof_action",
                    "when_values": ["command_line"],
                    "parameters": ["pid", "new_command_line"],
                    "default_applies": false,
                    "description": "EPROCESS command-line spoofing requires the target process ID and new command line.",
                },
                {
                    "when_parameter": "spoof_action",
                    "when_values": ["pid"],
                    "parameters": ["pid", "new_parent_pid"],
                    "default_applies": false,
                    "description": "EPROCESS parent-PID spoofing requires the target process ID and new parent PID.",
                }
            ])
        );
        let event_log = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_event_log_clear")
            .expect("driver_event_log_clear metadata");
        assert_eq!(
            event_log["choice_parameters"],
            json!([{
                "parameter": "log_action",
                "values": choice_values("kernel", "driver_event_log_clear", "log_action")
                    .expect("kernel event log action choices")
            }])
        );

        let privilege_properties = tools[2]["inputSchema"]["properties"]
            .as_object()
            .expect("privilege schema properties");
        let privilege_method_schema_values = privilege_properties["method"]["enum"]
            .as_array()
            .expect("privilege method schema enum");
        for value in choice_values("privilege", "elevate", "method")
            .expect("privilege elevation method choices")
        {
            assert!(privilege_method_schema_values.contains(&json!(value)));
        }
        for value in
            choice_values("privilege", "potato", "method").expect("privilege potato method choices")
        {
            assert!(privilege_method_schema_values.contains(&json!(value)));
        }
        assert_eq!(
            privilege_properties["type"]["enum"],
            json!(choice_values("privilege", "symlink", "type").expect("symlink type choices"))
        );
        let privilege_metadata = tools[2]["x-memoric-actions"]
            .as_array()
            .expect("privilege action metadata");
        let elevate = privilege_metadata
            .iter()
            .find(|entry| entry["action"] == "elevate")
            .expect("elevate metadata");
        assert_eq!(
            elevate["choice_parameters"],
            json!([{
                "parameter": "method",
                "values": choice_values("privilege", "elevate", "method")
                    .expect("privilege elevation method choices")
            }])
        );
        let potato = privilege_metadata
            .iter()
            .find(|entry| entry["action"] == "potato")
            .expect("potato metadata");
        assert_eq!(
            potato["choice_parameters"],
            json!([{
                "parameter": "method",
                "values": choice_values("privilege", "potato", "method")
                    .expect("privilege potato method choices")
            }])
        );
        let symlink = privilege_metadata
            .iter()
            .find(|entry| entry["action"] == "symlink")
            .expect("symlink metadata");
        assert_eq!(
            symlink["choice_parameters"],
            json!([{
                "parameter": "type",
                "values": choice_values("privilege", "symlink", "type")
                    .expect("symlink type choices")
            }])
        );

        let orchestrate_properties = tools[3]["inputSchema"]["properties"]
            .as_object()
            .expect("orchestrate schema properties");
        assert_eq!(
            orchestrate_properties["template"]["enum"],
            json!(choice_values("orchestrate", "plan", "template")
                .expect("orchestration template choices"))
        );
        let orchestrate_metadata = tools[3]["x-memoric-actions"]
            .as_array()
            .expect("orchestrate action metadata");
        let plan = orchestrate_metadata
            .iter()
            .find(|entry| entry["action"] == "plan")
            .expect("plan metadata");
        assert_eq!(
            plan["choice_parameters"],
            json!([{
                "parameter": "template",
                "values": choice_values("orchestrate", "plan", "template")
                    .expect("orchestration template choices")
            }])
        );

        let hook_properties = tools[4]["inputSchema"]["properties"]
            .as_object()
            .expect("hook schema properties");
        assert_eq!(
            hook_properties["method"]["enum"],
            json!(choice_values("hook", "install", "method").expect("hook method choices"))
        );
        let hook_metadata = tools[4]["x-memoric-actions"]
            .as_array()
            .expect("hook action metadata");
        let install = hook_metadata
            .iter()
            .find(|entry| entry["action"] == "install")
            .expect("install metadata");
        assert_eq!(
            install["choice_parameters"],
            json!([{
                "parameter": "method",
                "values": choice_values("hook", "install", "method")
                    .expect("hook method choices")
            }])
        );

        let inject_properties = tools[5]["inputSchema"]["properties"]
            .as_object()
            .expect("inject schema properties");
        assert_eq!(
            inject_properties["method"]["enum"],
            json!(choice_values("inject", "shellcode", "method").expect("shellcode method choices"))
        );
        assert_eq!(
            inject_properties["dll_method"]["enum"],
            json!(choice_values("inject", "dll", "dll_method").expect("DLL method choices"))
        );
        assert_eq!(
            inject_properties["spawn_method"]["enum"],
            json!(choice_values("inject", "spawn", "spawn_method").expect("spawn method choices"))
        );

        let inject_metadata = tools[5]["x-memoric-actions"]
            .as_array()
            .expect("inject action metadata");
        let shellcode = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "shellcode")
            .expect("shellcode metadata");
        assert_eq!(
            shellcode["choice_parameters"],
            json!([{
                "parameter": "method",
                "values": choice_values("inject", "shellcode", "method")
                    .expect("shellcode method choices")
            }])
        );
        let dll = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "dll")
            .expect("dll metadata");
        assert_eq!(
            dll["choice_parameters"],
            json!([{
                "parameter": "dll_method",
                "values": choice_values("inject", "dll", "dll_method")
                    .expect("DLL method choices")
            }])
        );
        let spawn = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "spawn")
            .expect("spawn metadata");
        assert_eq!(
            spawn["choice_parameters"],
            json!([{
                "parameter": "spawn_method",
                "values": choice_values("inject", "spawn", "spawn_method")
                    .expect("spawn method choices")
            }])
        );
    }

    #[test]
    fn parameter_bounds_descriptors_generate_schema_and_metadata() {
        let mut tools = vec![
            json!({
                "name": "stealth",
                "description": "test stealth schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "size": { "type": "integer" },
                        "intensity": { "type": "integer" },
                        "interval_ms": { "type": "integer" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "memory",
                "description": "test memory schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "size": { "type": "integer" },
                        "limit": { "type": "integer" },
                        "timeout_secs": { "type": "integer" },
                        "alignment": { "type": "integer" },
                        "region_limit": { "type": "integer" },
                        "entropy_sample_bytes": { "type": "integer" },
                        "region_cache_ttl_ms": { "type": "integer" },
                        "region_cache_ttl_secs": { "type": "integer" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "orchestrate",
                "description": "test orchestrate schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "limit": { "type": "integer" },
                        "steps": { "type": "array", "items": { "type": "object" } }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "target",
                "description": "test target schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "limit": { "type": "integer" },
                        "offset": { "type": "integer" },
                        "wait_ms": { "type": "integer" },
                        "max_len": { "type": "integer" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "inject",
                "description": "test inject schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "variant": { "type": "integer" },
                        "shellcode": { "type": "array", "items": { "type": "integer" } },
                        "payload": { "type": "array", "items": { "type": "integer" } }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "payload",
                "description": "test payload schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "payload": { "type": "array", "items": { "type": "integer" } },
                        "payload_hex": { "type": "string" },
                        "key": { "type": "array", "items": { "type": "integer" } },
                        "strings": { "type": "array", "items": { "type": "string" } },
                        "addresses": { "type": "array", "items": { "type": "integer" } },
                        "thread_handles": { "type": "array", "items": { "type": "integer" } },
                        "params": { "type": "array" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "hook",
                "description": "test hook schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "hooks": { "type": "array", "items": { "type": "object" } },
                        "original_bytes": { "type": "array", "items": { "type": "integer" } }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "self",
                "description": "test self schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "limit": { "type": "integer" },
                        "offset": { "type": "integer" },
                        "recent_task_limit": { "type": "integer" }
                    },
                    "required": ["action"]
                }
            }),
            json!({
                "name": "kernel",
                "description": "test kernel schema",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string" },
                        "max_entries": { "type": "integer" },
                        "max_size": { "type": "integer" },
                        "max_dump_size": { "type": "integer" },
                        "max_keys": { "type": "integer" },
                        "size": { "type": "integer" },
                        "shellcode_size": { "type": "integer" }
                    },
                    "required": ["action"]
                }
            }),
        ];

        enhance_tool_definitions(&mut tools);
        let properties = tools[0]["inputSchema"]["properties"]
            .as_object()
            .expect("stealth schema properties");
        assert_eq!(properties["size"]["minimum"], json!(1));
        assert_eq!(
            properties["size"]["maximum"],
            json!(MEMORY_MAX_OPERATION_BYTES)
        );
        assert_eq!(properties["intensity"]["minimum"], json!(1));
        assert_eq!(properties["intensity"]["maximum"], json!(3));
        assert_eq!(properties["interval_ms"]["minimum"], json!(1000));
        assert_eq!(properties["interval_ms"]["maximum"], json!(300000));

        let metadata = tools[0]["x-memoric-actions"]
            .as_array()
            .expect("stealth action metadata");
        let mutate_code = metadata
            .iter()
            .find(|entry| entry["action"] == "mutate_code")
            .expect("mutate_code metadata");
        assert_eq!(
            mutate_code["parameter_bounds"],
            json!([
                {
                    "parameter": "size",
                    "minimum": 1,
                    "maximum": 0x10000,
                },
                {
                    "parameter": "intensity",
                    "minimum": 1,
                    "maximum": 3,
                }
            ])
        );
        let sentinel_start = metadata
            .iter()
            .find(|entry| entry["action"] == "sentinel_start")
            .expect("sentinel_start metadata");
        assert_eq!(
            sentinel_start["parameter_bounds"],
            json!([{
                "parameter": "interval_ms",
                "minimum": 1000,
                "maximum": 300000,
            }])
        );

        let memory_properties = tools[1]["inputSchema"]["properties"]
            .as_object()
            .expect("memory schema properties");
        assert_eq!(memory_properties["size"]["minimum"], json!(1));
        assert_eq!(
            memory_properties["size"]["maximum"],
            json!(MEMORY_MAX_OPERATION_BYTES)
        );
        assert_eq!(memory_properties["limit"]["minimum"], json!(1));
        assert_eq!(
            memory_properties["limit"]["maximum"],
            json!(MEMORY_MAX_SCAN_LIMIT)
        );
        assert_eq!(memory_properties["timeout_secs"]["minimum"], json!(1));
        assert_eq!(
            memory_properties["timeout_secs"]["maximum"],
            json!(MEMORY_MAX_SCAN_TIMEOUT_SECS)
        );
        assert_eq!(memory_properties["alignment"]["minimum"], json!(1));
        assert_eq!(
            memory_properties["alignment"]["maximum"],
            json!(MEMORY_MAX_SCAN_ALIGNMENT)
        );
        assert_eq!(
            memory_properties["region_cache_ttl_ms"]["maximum"],
            json!(crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS)
        );
        assert_eq!(
            memory_properties["region_cache_ttl_secs"]["maximum"],
            json!(crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS / 1000)
        );
        assert_eq!(memory_properties["region_limit"]["maximum"], json!(1024));
        assert_eq!(
            memory_properties["entropy_sample_bytes"]["maximum"],
            json!(64 * 1024)
        );

        let memory_metadata = tools[1]["x-memoric-actions"]
            .as_array()
            .expect("memory action metadata");
        let read = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "read")
            .expect("read metadata");
        let read_bounds = read["parameter_bounds"].as_array().expect("read bounds");
        assert!(read_bounds.iter().any(|entry| {
            entry["parameter"] == "region_cache_ttl_ms"
                && entry["maximum"] == json!(crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS)
        }));
        assert!(read_bounds.iter().any(|entry| {
            entry["parameter"] == "region_cache_ttl_secs"
                && entry["maximum"]
                    == json!(crate::memory::region_cache::MAX_REGION_CACHE_TTL_MS / 1000)
        }));
        assert!(read_bounds.iter().any(|entry| {
            entry["parameter"] == "size"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(MEMORY_MAX_READ_BYTES)
        }));
        let write = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "write")
            .expect("write metadata");
        let write_bounds = write["parameter_bounds"].as_array().expect("write bounds");
        assert!(write_bounds.iter().any(|entry| {
            entry["parameter"] == "bytes"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(crate::args::DEFAULT_MAX_BYTES)
        }));
        let scan = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "scan")
            .expect("scan metadata");
        let scan_bounds = scan["parameter_bounds"].as_array().expect("scan bounds");
        for (parameter, maximum) in [
            ("limit", MEMORY_MAX_SCAN_LIMIT),
            ("timeout_secs", MEMORY_MAX_SCAN_TIMEOUT_SECS),
            ("context_bytes", MEMORY_MAX_PATTERN_CONTEXT_BYTES),
            ("max_depth", MEMORY_MAX_POINTER_SCAN_DEPTH),
            ("alignment", MEMORY_MAX_SCAN_ALIGNMENT),
        ] {
            assert!(
                scan_bounds
                    .iter()
                    .any(|entry| entry["parameter"] == parameter
                        && entry["maximum"] == json!(maximum)),
                "scan bounds should expose {} <= {}",
                parameter,
                maximum
            );
        }
        let diagnostics = memory_metadata
            .iter()
            .find(|entry| entry["action"] == "diagnostics")
            .expect("diagnostics metadata");
        assert!(diagnostics["parameter_bounds"]
            .as_array()
            .expect("diagnostics bounds")
            .iter()
            .any(|entry| entry["parameter"] == "region_cache_ttl_ms"));

        let orchestrate_properties = tools[2]["inputSchema"]["properties"]
            .as_object()
            .expect("orchestrate schema properties");
        assert_eq!(orchestrate_properties["limit"]["minimum"], json!(1));
        assert_eq!(
            orchestrate_properties["limit"]["maximum"],
            json!(crate::orchestration::engine::MAX_ORCHESTRATION_PAGE_LIMIT)
        );
        assert_eq!(orchestrate_properties["steps"]["minItems"], json!(1));
        assert_eq!(
            orchestrate_properties["steps"]["maxItems"],
            json!(crate::orchestration::engine::MAX_PLAN_STEPS)
        );
        assert_eq!(
            orchestrate_properties["steps"]["items"]["type"],
            json!("object"),
            "orchestrate steps should use the registry object-array descriptor shape"
        );
        assert_eq!(
            orchestrate_properties["steps"]["items"]["required"],
            json!(["tool", "action"])
        );
        assert_eq!(
            orchestrate_properties["steps"]["items"]["properties"]["depends_on"]["items"]["type"],
            json!("string")
        );

        let orchestrate_metadata = tools[2]["x-memoric-actions"]
            .as_array()
            .expect("orchestrate action metadata");
        let plan = orchestrate_metadata
            .iter()
            .find(|entry| entry["action"] == "plan")
            .expect("plan metadata");
        assert_eq!(
            plan["parameter_bounds"],
            json!([
                {
                    "parameter": "limit",
                    "minimum": 1,
                    "maximum": crate::orchestration::engine::MAX_ORCHESTRATION_PAGE_LIMIT,
                },
                {
                    "parameter": "steps",
                    "minimum": 1,
                    "maximum": crate::orchestration::engine::MAX_PLAN_STEPS,
                }
            ])
        );

        let target_properties = tools[3]["inputSchema"]["properties"]
            .as_object()
            .expect("target schema properties");
        assert_eq!(target_properties["limit"]["minimum"], json!(1));
        assert_eq!(
            target_properties["limit"]["maximum"],
            json!(TARGET_MAX_RESULT_LIMIT)
        );
        assert_eq!(
            target_properties["offset"]["maximum"],
            json!(TARGET_MAX_RESULT_LIMIT)
        );
        assert_eq!(
            target_properties["wait_ms"]["maximum"],
            json!(TARGET_MAX_WINDOW_WAIT_MS)
        );
        assert_eq!(
            target_properties["max_len"]["maximum"],
            json!(TARGET_MAX_STRING_READ_BYTES)
        );

        let target_metadata = tools[3]["x-memoric-actions"]
            .as_array()
            .expect("target action metadata");
        let windows = target_metadata
            .iter()
            .find(|entry| entry["action"] == "windows")
            .expect("windows metadata");
        assert!(windows["parameter_bounds"]
            .as_array()
            .expect("windows bounds")
            .iter()
            .any(|entry| entry["parameter"] == "wait_ms"
                && entry["maximum"] == json!(TARGET_MAX_WINDOW_WAIT_MS)));
        let string_read = target_metadata
            .iter()
            .find(|entry| entry["action"] == "string_read")
            .expect("string_read metadata");
        assert_eq!(
            string_read["parameter_bounds"],
            json!([{
                "parameter": "max_len",
                "minimum": 1,
                "maximum": TARGET_MAX_STRING_READ_BYTES,
            }])
        );

        let self_properties = tools[7]["inputSchema"]["properties"]
            .as_object()
            .expect("self schema properties");
        assert_eq!(self_properties["limit"]["minimum"], json!(1));
        assert_eq!(self_properties["limit"]["maximum"], json!(500));
        assert_eq!(self_properties["offset"]["minimum"], json!(0));
        assert_eq!(self_properties["recent_task_limit"]["minimum"], json!(1));
        assert_eq!(self_properties["recent_task_limit"]["maximum"], json!(100));
        assert_eq!(self_properties["size"]["minimum"], json!(1));
        assert_eq!(
            self_properties["size"]["maximum"],
            json!(MEMORY_MAX_OPERATION_BYTES)
        );

        let self_metadata = tools[7]["x-memoric-actions"]
            .as_array()
            .expect("self action metadata");
        let protect_encrypt = self_metadata
            .iter()
            .find(|entry| entry["action"] == "protect_encrypt")
            .expect("protect_encrypt metadata");
        assert_eq!(
            protect_encrypt["parameter_bounds"],
            json!([{
                "parameter": "size",
                "minimum": 1,
                "maximum": MEMORY_MAX_OPERATION_BYTES,
            }])
        );
        let protect_wipe = self_metadata
            .iter()
            .find(|entry| entry["action"] == "protect_wipe")
            .expect("protect_wipe metadata");
        assert_eq!(
            protect_wipe["parameter_bounds"],
            json!([{
                "parameter": "size",
                "minimum": 1,
                "maximum": MEMORY_MAX_OPERATION_BYTES,
            }])
        );
        let state = self_metadata
            .iter()
            .find(|entry| entry["action"] == "state")
            .expect("state metadata");
        assert!(state["parameter_bounds"]
            .as_array()
            .expect("state bounds")
            .iter()
            .any(|entry| entry["parameter"] == "limit"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(500)));
        let diagnostics = self_metadata
            .iter()
            .find(|entry| entry["action"] == "diagnostics")
            .expect("self diagnostics metadata");
        assert!(diagnostics["parameter_bounds"]
            .as_array()
            .expect("self diagnostics bounds")
            .iter()
            .any(
                |entry| entry["parameter"] == "recent_task_limit" && entry["maximum"] == json!(100)
            ));

        let inject_properties = tools[4]["inputSchema"]["properties"]
            .as_object()
            .expect("inject schema properties");
        assert_eq!(inject_properties["variant"]["minimum"], json!(1));
        assert_eq!(
            inject_properties["variant"]["maximum"],
            json!(INJECT_MAX_POOL_PARTY_VARIANT)
        );
        let inject_metadata = tools[4]["x-memoric-actions"]
            .as_array()
            .expect("inject action metadata");
        let shellcode = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "shellcode")
            .expect("shellcode metadata");
        assert_eq!(
            shellcode["required_parameters"],
            json!(["pid"]),
            "shellcode should expose unconditional pid requirement from the registry"
        );
        assert!(shellcode["conditional_required_parameters"]
            .as_array()
            .expect("shellcode conditional required metadata")
            .iter()
            .any(|entry| entry["when_parameter"] == "method"
                && entry["parameters"] == json!(["shellcode"])
                && entry["default_applies"] == true
                && entry["when_values"]
                    .as_array()
                    .expect("method values")
                    .contains(&json!("threadless"))));
        assert!(shellcode["parameter_bounds"]
            .as_array()
            .expect("shellcode bounds")
            .iter()
            .any(|entry| entry["parameter"] == "variant"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(INJECT_MAX_POOL_PARTY_VARIANT)));
        let fiber = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "fiber")
            .expect("fiber metadata");
        assert!(fiber["parameter_bounds"]
            .as_array()
            .expect("fiber bounds")
            .iter()
            .any(|entry| entry["parameter"] == "shellcode"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(crate::args::DEFAULT_MAX_BYTES)));
        let export_forward = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "export_forward")
            .expect("export_forward metadata");
        assert!(export_forward["parameter_bounds"]
            .as_array()
            .expect("export_forward bounds")
            .iter()
            .any(|entry| entry["parameter"] == "shellcode"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(crate::args::DEFAULT_MAX_BYTES)));
        let spawn = inject_metadata
            .iter()
            .find(|entry| entry["action"] == "spawn")
            .expect("spawn metadata");
        assert_eq!(
            spawn["required_parameters"],
            json!(["target_path"]),
            "spawn should expose canonical target_path requirement while target_exe remains an alias"
        );
        assert!(spawn["conditional_required_parameters"]
            .as_array()
            .expect("spawn conditional required metadata")
            .iter()
            .any(|entry| entry["when_parameter"] == "spawn_method"
                && entry["parameters"] == json!(["payload"])
                && entry["default_applies"] == true
                && entry["when_values"]
                    .as_array()
                    .expect("spawn method values")
                    .contains(&json!("hollow"))));
        assert!(spawn["conditional_required_parameters"]
            .as_array()
            .expect("spawn conditional required metadata")
            .iter()
            .any(|entry| entry["when_parameter"] == "spawn_method"
                && entry["parameters"] == json!(["shellcode"])
                && entry["default_applies"] == false
                && entry["when_values"]
                    .as_array()
                    .expect("spawn method values")
                    .contains(&json!("early_bird"))));
        let spawn_bounds = spawn["parameter_bounds"].as_array().expect("spawn bounds");
        assert!(spawn_bounds
            .iter()
            .any(|entry| entry["parameter"] == "payload"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(crate::args::DEFAULT_MAX_BYTES)));
        assert!(spawn_bounds
            .iter()
            .any(|entry| entry["parameter"] == "shellcode"
                && entry["minimum"] == json!(1)
                && entry["maximum"] == json!(crate::args::DEFAULT_MAX_BYTES)));
        assert_eq!(inject_properties["shellcode"]["minItems"], json!(1));
        assert_eq!(
            inject_properties["shellcode"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(inject_properties["payload"]["minItems"], json!(1));
        assert_eq!(
            inject_properties["payload"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );

        let payload_properties = tools[5]["inputSchema"]["properties"]
            .as_object()
            .expect("payload schema properties");
        assert_eq!(payload_properties["payload"]["minItems"], json!(1));
        assert_eq!(
            payload_properties["payload"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(payload_properties["payload_hex"]["minItems"], json!(1));
        assert_eq!(
            payload_properties["payload_hex"]["x-memoric-byteLengthMaximum"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );
        assert_eq!(
            payload_properties["key"]["maxItems"],
            json!(PAYLOAD_MAX_OBFUSCATION_KEY_BYTES)
        );
        assert_eq!(
            payload_properties["addresses"]["maxItems"],
            json!(PAYLOAD_MAX_CLEANUP_ITEMS)
        );
        assert_eq!(
            payload_properties["params"]["maxItems"],
            json!(PAYLOAD_MAX_SERIALIZE_PARAMS)
        );

        let payload_metadata = tools[5]["x-memoric-actions"]
            .as_array()
            .expect("payload action metadata");
        let obfuscate = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "obfuscate")
            .expect("obfuscate metadata");
        assert!(obfuscate["parameter_bounds"]
            .as_array()
            .expect("obfuscate bounds")
            .iter()
            .any(|entry| entry["parameter"] == "key"
                && entry["maximum"] == json!(PAYLOAD_MAX_OBFUSCATION_KEY_BYTES)));
        let cleanup = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "cleanup")
            .expect("cleanup metadata");
        assert!(cleanup["parameter_bounds"]
            .as_array()
            .expect("cleanup bounds")
            .iter()
            .any(|entry| entry["parameter"] == "thread_handles"
                && entry["maximum"] == json!(PAYLOAD_MAX_CLEANUP_ITEMS)));
        let serialize = payload_metadata
            .iter()
            .find(|entry| entry["action"] == "serialize")
            .expect("serialize metadata");
        assert_eq!(
            serialize["parameter_bounds"],
            json!([{
                "parameter": "params",
                "minimum": 1,
                "maximum": PAYLOAD_MAX_SERIALIZE_PARAMS,
            }])
        );

        let hook_properties = tools[6]["inputSchema"]["properties"]
            .as_object()
            .expect("hook schema properties");
        assert_eq!(hook_properties["hooks"]["minItems"], json!(1));
        assert_eq!(
            hook_properties["hooks"]["maxItems"],
            json!(HOOK_MAX_DETOUR_HOOKS)
        );
        assert_eq!(
            hook_properties["hooks"]["items"]["type"],
            json!("object"),
            "hook detour hooks should use the registry object-array descriptor shape"
        );
        assert_eq!(
            hook_properties["hooks"]["items"]["required"],
            json!(["target_address", "hook_address"])
        );
        assert_eq!(
            hook_properties["hooks"]["items"]["properties"]["target_address"]["type"],
            json!(["integer", "string"])
        );
        assert_eq!(hook_properties["original_bytes"]["minItems"], json!(1));
        assert_eq!(
            hook_properties["original_bytes"]["maxItems"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );

        let hook_metadata = tools[6]["x-memoric-actions"]
            .as_array()
            .expect("hook action metadata");
        let install = hook_metadata
            .iter()
            .find(|entry| entry["action"] == "install")
            .expect("install metadata");
        assert!(install["conditional_required_parameters"]
            .as_array()
            .expect("install conditional required metadata")
            .iter()
            .any(|entry| entry["when_parameter"] == "method"
                && entry["parameters"] == json!(["pid", "module", "function", "hook_address"])
                && entry["default_applies"] == true
                && entry["when_values"]
                    .as_array()
                    .expect("install method values")
                    .contains(&json!("iat"))));
        assert!(install["conditional_required_parameters"]
            .as_array()
            .expect("install conditional required metadata")
            .iter()
            .any(|entry| entry["when_parameter"] == "method"
                && entry["parameters"] == json!(["pid", "target_address", "hook_address"])
                && entry["default_applies"] == false
                && entry["when_values"]
                    .as_array()
                    .expect("install method values")
                    .contains(&json!("inline"))));
        let hook_function = hook_metadata
            .iter()
            .find(|entry| entry["action"] == "hook_function")
            .expect("hook_function metadata");
        assert!(hook_function["conditional_required_parameters"]
            .as_array()
            .expect("hook_function conditional required metadata")
            .iter()
            .any(|entry| entry["when_parameter"] == "method"
                && entry["parameters"] == json!(["pid", "target_address", "hook_address"])
                && entry["when_values"]
                    .as_array()
                    .expect("hook_function method values")
                    .contains(&json!("inline"))));
        let detour = hook_metadata
            .iter()
            .find(|entry| entry["action"] == "detour")
            .expect("detour metadata");
        assert_eq!(
            detour["parameter_bounds"],
            json!([{
                "parameter": "hooks",
                "minimum": 1,
                "maximum": HOOK_MAX_DETOUR_HOOKS,
            }])
        );
        let restore = hook_metadata
            .iter()
            .find(|entry| entry["action"] == "restore")
            .expect("restore metadata");
        assert_eq!(
            restore["parameter_bounds"],
            json!([{
                "parameter": "original_bytes",
                "minimum": 1,
                "maximum": crate::args::DEFAULT_MAX_BYTES,
            }])
        );

        let kernel_properties = tools[8]["inputSchema"]["properties"]
            .as_object()
            .expect("kernel schema properties");
        assert_eq!(
            kernel_properties["max_entries"]["maximum"],
            json!(KERNEL_MAX_ENUM_PROCESS_ENTRIES)
        );
        assert_eq!(
            kernel_properties["max_size"]["maximum"],
            json!(KERNEL_MAX_PROCESS_DUMP_BYTES)
        );
        assert_eq!(
            kernel_properties["max_dump_size"]["maximum"],
            json!(KERNEL_MAX_PROCESS_DUMP_BYTES)
        );
        assert_eq!(
            kernel_properties["max_keys"]["maximum"],
            json!(KERNEL_MAX_KEYLOG_KEYS)
        );
        assert_eq!(
            kernel_properties["size"]["maximum"],
            json!(KERNEL_MAX_CRED_DUMP_BYTES)
        );
        assert_eq!(kernel_properties["shellcode_size"]["minimum"], json!(1));
        assert_eq!(
            kernel_properties["shellcode_size"]["maximum"],
            json!(crate::args::DEFAULT_MAX_BYTES)
        );

        let kernel_metadata = tools[8]["x-memoric-actions"]
            .as_array()
            .expect("kernel action metadata");
        let enum_process = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_enum_process")
            .expect("driver_enum_process metadata");
        assert_eq!(
            enum_process["parameter_bounds"],
            json!([{
                "parameter": "max_entries",
                "minimum": null,
                "maximum": KERNEL_MAX_ENUM_PROCESS_ENTRIES,
            }])
        );
        let callback_enum = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_callback_enum")
            .expect("driver_callback_enum metadata");
        assert_eq!(
            callback_enum["parameter_bounds"],
            json!([{
                "parameter": "max_entries",
                "minimum": null,
                "maximum": KERNEL_MAX_CALLBACK_ENUM_ENTRIES,
            }])
        );
        let memory_pool = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_memory_pool")
            .expect("driver_memory_pool metadata");
        assert_eq!(
            memory_pool["parameter_bounds"],
            json!([{
                "parameter": "max_entries",
                "minimum": null,
                "maximum": KERNEL_MAX_MEMORY_POOL_ENTRIES,
            }])
        );
        let process_dump = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_process_dump")
            .expect("driver_process_dump metadata");
        assert_eq!(
            process_dump["parameter_bounds"],
            json!([
                {
                    "parameter": "max_size",
                    "minimum": null,
                    "maximum": KERNEL_MAX_PROCESS_DUMP_BYTES,
                },
                {
                    "parameter": "max_dump_size",
                    "minimum": null,
                    "maximum": KERNEL_MAX_PROCESS_DUMP_BYTES,
                }
            ])
        );
        let keylogger = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_keylogger")
            .expect("driver_keylogger metadata");
        assert_eq!(
            keylogger["parameter_bounds"],
            json!([{
                "parameter": "max_keys",
                "minimum": null,
                "maximum": KERNEL_MAX_KEYLOG_KEYS,
            }])
        );
        let cred_dump = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_cred_dump")
            .expect("driver_cred_dump metadata");
        assert_eq!(
            cred_dump["parameter_bounds"],
            json!([{
                "parameter": "size",
                "minimum": null,
                "maximum": KERNEL_MAX_CRED_DUMP_BYTES,
            }])
        );
        let driver_apc_inject = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_apc_inject")
            .expect("driver_apc_inject metadata");
        assert_eq!(
            driver_apc_inject["parameter_bounds"],
            json!([{
                "parameter": "shellcode_size",
                "minimum": 1,
                "maximum": crate::args::DEFAULT_MAX_BYTES,
            }])
        );
        let kernel_apc = kernel_metadata
            .iter()
            .find(|entry| entry["action"] == "driver_kernel_apc")
            .expect("driver_kernel_apc metadata");
        assert_eq!(
            kernel_apc["parameter_bounds"],
            json!([{
                "parameter": "shellcode_size",
                "minimum": 1,
                "maximum": crate::args::DEFAULT_MAX_BYTES,
            }])
        );
    }

    #[test]
    fn action_metadata_exposes_required_parameter_descriptors() {
        let metadata_value = action_metadata_json("inject");
        let metadata = metadata_value.as_array().expect("inject metadata");
        let dll = metadata
            .iter()
            .find(|entry| entry["action"] == "dll")
            .expect("dll metadata");
        let export_forward = metadata
            .iter()
            .find(|entry| entry["action"] == "export_forward")
            .expect("export_forward metadata");

        assert_eq!(dll["required_parameters"], json!(["pid", "dll_path"]));
        assert_eq!(
            export_forward["required_parameters"],
            json!(["pid", "module", "export_name", "shellcode"])
        );

        let stealth_metadata = action_metadata_json("stealth");
        let stealth = stealth_metadata.as_array().expect("stealth metadata");
        let mutate_code = stealth
            .iter()
            .find(|entry| entry["action"] == "mutate_code")
            .expect("mutate_code metadata")
            .clone();
        assert_eq!(
            mutate_code["required_parameters"],
            json!(["address", "size"])
        );
        let patch_cfg = stealth
            .iter()
            .find(|entry| entry["action"] == "patch_cfg")
            .expect("patch_cfg metadata");
        let hide_module = stealth
            .iter()
            .find(|entry| entry["action"] == "hide_module")
            .expect("hide_module metadata");
        let spoof_return = stealth
            .iter()
            .find(|entry| entry["action"] == "spoof_return")
            .expect("spoof_return metadata");
        let module_stomp = stealth
            .iter()
            .find(|entry| entry["action"] == "module_stomp")
            .expect("module_stomp metadata");
        let callback_masquerade = stealth
            .iter()
            .find(|entry| entry["action"] == "callback_masquerade")
            .expect("callback_masquerade metadata");
        let minifilter_resume = stealth
            .iter()
            .find(|entry| entry["action"] == "minifilter_resume")
            .expect("minifilter_resume metadata");

        assert_eq!(patch_cfg["required_parameters"], json!(["target_address"]));
        assert_eq!(
            hide_module["required_parameters"],
            json!(["pid", "module_name"])
        );
        assert_eq!(
            spoof_return["required_parameters"],
            json!(["target_function"])
        );
        assert_eq!(
            module_stomp["required_parameters"],
            json!(["dll_path", "shellcode"])
        );
        assert_eq!(
            callback_masquerade["required_parameters"],
            json!([
                "callback_index",
                "array_address",
                "device_path",
                "ioctl_write_code"
            ])
        );
        assert_eq!(
            minifilter_resume["required_parameters"],
            json!(["name", "altitude"])
        );

        let kernel_metadata = action_metadata_json("kernel");
        let physical_write = kernel_metadata
            .as_array()
            .expect("kernel metadata")
            .iter()
            .find(|entry| entry["action"] == "physical_write")
            .expect("physical_write metadata")
            .clone();
        assert_eq!(
            physical_write["required_parameters"],
            json!(["address", "bytes"])
        );

        let memory_metadata = action_metadata_json("memory");
        let memory = memory_metadata.as_array().expect("memory metadata");
        let write = memory
            .iter()
            .find(|entry| entry["action"] == "write")
            .expect("write metadata");
        let read = memory
            .iter()
            .find(|entry| entry["action"] == "read")
            .expect("read metadata");
        let typed_write = memory
            .iter()
            .find(|entry| entry["action"] == "typed_write")
            .expect("typed_write metadata");
        let scan_next = memory
            .iter()
            .find(|entry| entry["action"] == "scan_next")
            .expect("scan_next metadata");
        let scan_freeze = memory
            .iter()
            .find(|entry| entry["action"] == "scan_freeze")
            .expect("scan_freeze metadata");

        assert_eq!(
            read["required_parameters"],
            json!(["pid", "address", "size"])
        );
        assert_eq!(write["required_parameters"], json!(["pid", "address"]));
        assert_eq!(
            write["alternative_required_parameters"],
            json!([{
                "when_parameter": null,
                "when_values": [],
                "parameters": ["bytes", "text"],
                "default_applies": true,
                "description": "Memory write requires either a byte payload or deprecated text input.",
            }])
        );
        assert_eq!(
            typed_write["required_parameters"],
            json!(["pid", "address", "type", "value"])
        );
        assert_eq!(
            scan_next["required_parameters"],
            json!(["session_id", "filter"])
        );
        assert_eq!(
            scan_freeze["required_parameters"],
            json!(["session_id", "value"])
        );

        let hook_metadata = action_metadata_json("hook");
        let hook = hook_metadata.as_array().expect("hook metadata");
        let install_hwbp = hook
            .iter()
            .find(|entry| entry["action"] == "install_hwbp")
            .expect("install_hwbp metadata");
        let remove_hwbp = hook
            .iter()
            .find(|entry| entry["action"] == "remove_hwbp")
            .expect("remove_hwbp metadata");
        let detour = hook
            .iter()
            .find(|entry| entry["action"] == "detour")
            .expect("detour metadata");
        let restore = hook
            .iter()
            .find(|entry| entry["action"] == "restore")
            .expect("restore metadata");
        let winhook = hook
            .iter()
            .find(|entry| entry["action"] == "winhook")
            .expect("winhook metadata");
        let hwbp_syscall = hook
            .iter()
            .find(|entry| entry["action"] == "hwbp_syscall")
            .expect("hwbp_syscall metadata");

        assert_eq!(
            install_hwbp["required_parameters"],
            json!(["tid", "target_address"])
        );
        assert_eq!(remove_hwbp["required_parameters"], json!(["tid"]));
        assert_eq!(detour["required_parameters"], json!(["pid", "hooks"]));
        assert_eq!(
            restore["required_parameters"],
            json!(["pid", "address", "original_bytes"])
        );
        assert_eq!(winhook["required_parameters"], json!(["pid", "dll_path"]));
        assert_eq!(hwbp_syscall["required_parameters"], json!(["function"]));

        let self_metadata = action_metadata_json("self");
        let self_actions = self_metadata.as_array().expect("self metadata");
        let peb = self_actions
            .iter()
            .find(|entry| entry["action"] == "peb")
            .expect("self peb metadata");
        let heap = self_actions
            .iter()
            .find(|entry| entry["action"] == "heap")
            .expect("self heap metadata");
        assert_eq!(peb["required_parameters"], json!(["pid"]));
        assert_eq!(heap["required_parameters"], json!(["pid"]));
    }

    #[test]
    fn action_metadata_exposes_planner_warning_descriptors() {
        let target_metadata = action_metadata_json("target");
        let module_base = target_metadata
            .as_array()
            .expect("target metadata")
            .iter()
            .find(|entry| entry["action"] == "module_base")
            .expect("module_base metadata");
        assert_eq!(
            module_base["planner_warnings"],
            json!([{
                "condition": "parameter_present",
                "parameter": "name",
                "unless_parameter": null,
                "unless_values": [],
                "message": "module_base uses module_name; name is a process search parameter",
            }])
        );

        let payload_metadata = action_metadata_json("payload");
        let pe_parse = payload_metadata
            .as_array()
            .expect("payload metadata")
            .iter()
            .find(|entry| entry["action"] == "pe_parse")
            .expect("pe_parse metadata");
        assert_eq!(
            pe_parse["planner_warnings"],
            json!([{
                "condition": "parameter_missing",
                "parameter": "address",
                "unless_parameter": "show",
                "unless_values": ["iat_entry"],
                "message": "pe_parse reads a PE image at a base address; suspended targets may not have initialized modules yet",
            }])
        );

        let kernel_metadata = action_metadata_json("kernel");
        let kernel_read = kernel_metadata
            .as_array()
            .expect("kernel metadata")
            .iter()
            .find(|entry| entry["action"] == "read")
            .expect("kernel read metadata");
        assert_eq!(
            kernel_read["planner_warnings"],
            json!([{
                "condition": "always",
                "parameter": null,
                "unless_parameter": null,
                "unless_values": [],
                "message": "kernel generic helpers require an explicit BYOVD device_path",
            }])
        );
    }

    #[test]
    fn registry_exposes_output_data_classification_rules() {
        let memory_rules = tool_output_classification_rules("memory");
        assert!(memory_rules.iter().any(|rule| {
            rule.path == "data.bytes" && rule.classification == DataClassification::RawMemory
        }));
        assert!(memory_rules.iter().any(|rule| {
            rule.path == "artifacts[].path"
                && rule.classification == DataClassification::ArtifactReference
        }));

        let target_rules = tool_output_classification_rules("target");
        assert!(target_rules.iter().any(|rule| {
            rule.path == "data.credentials"
                && rule.classification == DataClassification::CredentialLike
        }));
    }
}

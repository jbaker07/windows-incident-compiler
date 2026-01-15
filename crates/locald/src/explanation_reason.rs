//! Explanation Reason Codes
//!
//! Precise reason codes for why explanations are available or unavailable.
//! These codes enable diagnosis and improvement of explanation availability rate.
//!
//! ## CONTRACT (TRUTH_CONTRACT.md)
//! - Every signal MUST have an ExplainResponse
//! - available=false is honest; never invent/synthesize data
//! - reason_code tells exactly WHY explanation is unavailable
//!
//! ## Reason Code Categories
//! 1. **Data Missing** - Required data wasn't captured or stored
//! 2. **Build Failure** - Explanation builder encountered an error
//! 3. **Infrastructure** - DB/system errors
//!
//! ## Detection Reason Codes (Phase 2)
//! When `available=true`, the `reasons` array contains stable detection codes
//! explaining WHY the detector fired, grounded in matched slots and real fields.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reason codes for explanation availability status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExplanationReasonCode {
    // ─────────────────────────────────────────────────────────────────────
    // Success (available=true)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Explanation successfully built from hypothesis/playbook
    Ok,

    // ─────────────────────────────────────────────────────────────────────
    // Data Missing (available=false)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Signal row exists but no row in signal_explanations table
    MissingExplanationRow,
    
    /// Hypothesis not found when trying to build explanation
    MissingHypothesis,
    
    /// Playbook definition not found for hypothesis template_id
    MissingPlaybook,
    
    /// Playbook eval rollup entry not found
    MissingPlaybookEval,
    
    /// Evidence pointers were not propagated from capture to explanation
    MissingEvidencePtrs,
    
    /// Facts store was empty when building explanation
    MissingFactsStore,

    // ─────────────────────────────────────────────────────────────────────
    // Build Failures (available=false)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Failed to serialize explanation to JSON
    JsonSerializeFailed,
    
    /// Failed to parse stored explanation JSON
    JsonParseFailed,
    
    /// Explanation builder threw an unexpected error
    ExplainBuildFailed,
    
    /// Slot matching failed during explanation build
    SlotMatchFailed,

    // ─────────────────────────────────────────────────────────────────────
    // Infrastructure (available=false)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Database was locked during write
    DbLocked,
    
    /// Database write failed for other reason
    DbWriteFailed,
    
    /// Database read failed when querying explanation
    DbReadFailed,

    // ─────────────────────────────────────────────────────────────────────
    // Legacy/Migration (available=false)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Signal was created before explanation system existed
    LegacyDataNoExplanation,
    
    /// Signal was imported from bundle without explanation
    ImportedNoExplanation,
    
    /// Unknown reason (should be rare - investigate if seen)
    Unknown,
}

impl ExplanationReasonCode {
    /// Get the string representation for database/API use
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::MissingExplanationRow => "MISSING_EXPLANATION_ROW",
            Self::MissingHypothesis => "MISSING_HYPOTHESIS",
            Self::MissingPlaybook => "MISSING_PLAYBOOK",
            Self::MissingPlaybookEval => "MISSING_PLAYBOOK_EVAL",
            Self::MissingEvidencePtrs => "MISSING_EVIDENCE_PTRS",
            Self::MissingFactsStore => "MISSING_FACTS_STORE",
            Self::JsonSerializeFailed => "JSON_SERIALIZE_FAILED",
            Self::JsonParseFailed => "JSON_PARSE_FAILED",
            Self::ExplainBuildFailed => "EXPLAIN_BUILD_FAILED",
            Self::SlotMatchFailed => "SLOT_MATCH_FAILED",
            Self::DbLocked => "DB_LOCKED",
            Self::DbWriteFailed => "DB_WRITE_FAILED",
            Self::DbReadFailed => "DB_READ_FAILED",
            Self::LegacyDataNoExplanation => "LEGACY_DATA_NO_EXPLANATION",
            Self::ImportedNoExplanation => "IMPORTED_NO_EXPLANATION",
            Self::Unknown => "UNKNOWN",
        }
    }
    
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s {
            "OK" => Self::Ok,
            "MISSING_EXPLANATION_ROW" => Self::MissingExplanationRow,
            "MISSING_HYPOTHESIS" => Self::MissingHypothesis,
            "MISSING_PLAYBOOK" => Self::MissingPlaybook,
            "MISSING_PLAYBOOK_EVAL" => Self::MissingPlaybookEval,
            "MISSING_EVIDENCE_PTRS" => Self::MissingEvidencePtrs,
            "MISSING_FACTS_STORE" => Self::MissingFactsStore,
            "JSON_SERIALIZE_FAILED" => Self::JsonSerializeFailed,
            "JSON_PARSE_FAILED" => Self::JsonParseFailed,
            "EXPLAIN_BUILD_FAILED" => Self::ExplainBuildFailed,
            "SLOT_MATCH_FAILED" => Self::SlotMatchFailed,
            "DB_LOCKED" => Self::DbLocked,
            "DB_WRITE_FAILED" => Self::DbWriteFailed,
            "DB_READ_FAILED" => Self::DbReadFailed,
            "LEGACY_DATA_NO_EXPLANATION" => Self::LegacyDataNoExplanation,
            "IMPORTED_NO_EXPLANATION" => Self::ImportedNoExplanation,
            _ => Self::Unknown,
        }
    }
    
    /// Check if this code indicates availability
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Ok)
    }
    
    /// Human-readable message for this code
    pub fn message(&self) -> &'static str {
        match self {
            Self::Ok => "Explanation available",
            Self::MissingExplanationRow => "No explanation row exists for this signal",
            Self::MissingHypothesis => "Hypothesis not found when building explanation",
            Self::MissingPlaybook => "Playbook definition not found for hypothesis",
            Self::MissingPlaybookEval => "Playbook evaluation record not found",
            Self::MissingEvidencePtrs => "Evidence pointers not propagated to explanation",
            Self::MissingFactsStore => "Facts store was empty during explanation build",
            Self::JsonSerializeFailed => "Failed to serialize explanation to JSON",
            Self::JsonParseFailed => "Failed to parse stored explanation JSON",
            Self::ExplainBuildFailed => "Explanation builder encountered an error",
            Self::SlotMatchFailed => "Slot matching failed during explanation build",
            Self::DbLocked => "Database was locked during write",
            Self::DbWriteFailed => "Database write operation failed",
            Self::DbReadFailed => "Database read operation failed",
            Self::LegacyDataNoExplanation => "Signal predates explanation system",
            Self::ImportedNoExplanation => "Signal imported without explanation data",
            Self::Unknown => "Unknown reason - please investigate",
        }
    }
}

impl std::fmt::Display for ExplanationReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for ExplanationReasonCode {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Struct for unavailable explanation rows in signal_explanations table.
///
/// ## STRICT NON-CLAIMING CONTRACT
/// - `available` MUST be `false`
/// - `reason_code` MUST be present (from ExplanationReasonCode enum)
/// - `message` MUST be present (human-readable reason)
/// - `signal_context` MAY contain ONLY fields copied verbatim from signal row:
///   - signal_id, signal_type, severity, host, ts (no inference, no computed fields)
/// - `matched_slots`, `narrative`, `reasons` MUST be absent (null/None)
///
/// This struct is for HONEST unavailability - never invent or infer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnavailableExplanation {
    /// Always false for unavailable explanations
    pub available: bool,
    /// Reason code from ExplanationReasonCode enum
    pub reason_code: String,
    /// Human-readable explanation of why unavailable
    pub message: String,
    /// ONLY verbatim signal row fields (signal_id, signal_type, severity, host, ts)
    /// NO inference, NO computed fields, NO playbook data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_context: Option<SignalContext>,
}

/// Minimal signal context - ONLY verbatim signal row fields.
/// No inference, no computed fields, no playbook data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalContext {
    pub signal_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<i64>,
}

impl SignalContext {
    pub fn new(signal_id: &str) -> Self {
        Self {
            signal_id: signal_id.to_string(),
            signal_type: None,
            severity: None,
            host: None,
            ts: None,
        }
    }
    
    pub fn with_type(mut self, t: &str) -> Self {
        self.signal_type = Some(t.to_string());
        self
    }
    
    pub fn with_severity(mut self, s: &str) -> Self {
        self.severity = Some(s.to_string());
        self
    }
    
    pub fn with_host(mut self, h: &str) -> Self {
        self.host = Some(h.to_string());
        self
    }
    
    pub fn with_ts(mut self, ts: i64) -> Self {
        self.ts = Some(ts);
        self
    }
}

impl UnavailableExplanation {
    pub fn new(reason: ExplanationReasonCode) -> Self {
        Self {
            available: false,
            reason_code: reason.as_str().to_string(),
            message: reason.message().to_string(),
            signal_context: None,
        }
    }
    
    /// Add minimal signal context (ONLY verbatim signal row fields)
    pub fn with_signal_context(mut self, ctx: SignalContext) -> Self {
        self.signal_context = Some(ctx);
        self
    }
}

// ============================================================================
// Detection Reason Codes (Phase 2)
// ============================================================================
// These codes explain WHY a detection fired, grounded in matched slots.
// They appear in the `reasons` array when `available=true`.

/// Detection reason codes - stable enums for WHY a detector fired.
/// Grounded in specific slot matches and real evidence fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DetectionReasonCode {
    // ─────────────────────────────────────────────────────────────────────
    // Encoded PowerShell (signal_encoded_powershell.yaml)
    // ─────────────────────────────────────────────────────────────────────
    
    /// PowerShell process with -enc/-encodedcommand flag detected
    PowershellEncodedCommand,
    /// PowerShell with execution policy bypass flag
    PowershellBypassPolicy,
    /// PowerShell with hidden window flag
    PowershellHiddenWindow,
    /// PowerShell download cradle pattern (IEX/DownloadString/etc.)
    PowershellDownloadCradle,
    
    // ─────────────────────────────────────────────────────────────────────
    // Schtasks Abuse (signal_schtasks_abuse.yaml)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Scheduled task created
    TaskCreated,
    /// Task created with SYSTEM privilege
    TaskCreatedSystem,
    /// Task created on remote system (lateral movement)
    TaskCreatedRemote,
    /// Task with hidden/v1 attribute
    TaskHidden,
    
    // ─────────────────────────────────────────────────────────────────────
    // Service Persistence (signal_service_persistence.yaml)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Windows service installed
    ServiceInstalled,
    /// Service binary in suspicious location (Temp/AppData/etc.)
    ServiceSuspiciousPath,
    /// Service registry modification detected
    ServiceRegistryModified,
    
    // ─────────────────────────────────────────────────────────────────────
    // Registry Persistence (signal_registry_persistence.yaml)
    // ─────────────────────────────────────────────────────────────────────
    
    /// Run/RunOnce key modified
    RegistryRunKeyModified,
    /// Image File Execution Options debugger set
    RegistryIfeoDebugger,
    /// Winlogon shell modified
    RegistryWinlogonShell,
    /// Services registry modified by non-services.exe
    RegistryServicesModified,
    
    // ─────────────────────────────────────────────────────────────────────
    // Credential Access (signal_credential_access.yaml)
    // ─────────────────────────────────────────────────────────────────────
    
    /// LSASS process accessed (Sysmon Event 10)
    ProcessAccessLsass,
    /// Known credential dump tool detected in command line
    CredentialDumpTool,
    /// SAM/SECURITY/SYSTEM registry export
    SamRegistryExport,
    /// Shadow copy / NTDS.dit access
    NtdsAccess,
    /// Comsvcs.dll LSASS dump technique
    ComsvcsDump,
    
    // ─────────────────────────────────────────────────────────────────────
    // Generic
    // ─────────────────────────────────────────────────────────────────────
    
    /// Detection fired but reason not mapped to specific code
    GenericMatch,
}

impl DetectionReasonCode {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PowershellEncodedCommand => "POWERSHELL_ENCODED_COMMAND",
            Self::PowershellBypassPolicy => "POWERSHELL_BYPASS_POLICY",
            Self::PowershellHiddenWindow => "POWERSHELL_HIDDEN_WINDOW",
            Self::PowershellDownloadCradle => "POWERSHELL_DOWNLOAD_CRADLE",
            Self::TaskCreated => "TASK_CREATED",
            Self::TaskCreatedSystem => "TASK_CREATED_SYSTEM",
            Self::TaskCreatedRemote => "TASK_CREATED_REMOTE",
            Self::TaskHidden => "TASK_HIDDEN",
            Self::ServiceInstalled => "SERVICE_INSTALLED",
            Self::ServiceSuspiciousPath => "SERVICE_SUSPICIOUS_PATH",
            Self::ServiceRegistryModified => "SERVICE_REGISTRY_MODIFIED",
            Self::RegistryRunKeyModified => "REGISTRY_RUN_KEY_MODIFIED",
            Self::RegistryIfeoDebugger => "REGISTRY_IFEO_DEBUGGER",
            Self::RegistryWinlogonShell => "REGISTRY_WINLOGON_SHELL",
            Self::RegistryServicesModified => "REGISTRY_SERVICES_MODIFIED",
            Self::ProcessAccessLsass => "PROCESS_ACCESS_LSASS",
            Self::CredentialDumpTool => "CREDENTIAL_DUMP_TOOL",
            Self::SamRegistryExport => "SAM_REGISTRY_EXPORT",
            Self::NtdsAccess => "NTDS_ACCESS",
            Self::ComsvcsDump => "COMSVCS_DUMP",
            Self::GenericMatch => "GENERIC_MATCH",
        }
    }
    
    /// Human-readable label for this reason code
    pub fn label(&self) -> &'static str {
        match self {
            Self::PowershellEncodedCommand => "Encoded PowerShell Command",
            Self::PowershellBypassPolicy => "Execution Policy Bypass",
            Self::PowershellHiddenWindow => "Hidden Window",
            Self::PowershellDownloadCradle => "Download Cradle Pattern",
            Self::TaskCreated => "Task Created",
            Self::TaskCreatedSystem => "Task Created as SYSTEM",
            Self::TaskCreatedRemote => "Remote Task Created",
            Self::TaskHidden => "Hidden Task",
            Self::ServiceInstalled => "Service Installed",
            Self::ServiceSuspiciousPath => "Suspicious Service Path",
            Self::ServiceRegistryModified => "Service Registry Modified",
            Self::RegistryRunKeyModified => "Run Key Modified",
            Self::RegistryIfeoDebugger => "IFEO Debugger Hijack",
            Self::RegistryWinlogonShell => "Winlogon Shell Override",
            Self::RegistryServicesModified => "Services Registry Modified",
            Self::ProcessAccessLsass => "LSASS Process Access",
            Self::CredentialDumpTool => "Credential Dump Tool",
            Self::SamRegistryExport => "SAM Registry Export",
            Self::NtdsAccess => "NTDS.dit Access",
            Self::ComsvcsDump => "Comsvcs LSASS Dump",
            Self::GenericMatch => "Detection Match",
        }
    }
}

/// A single detection reason entry in the `reasons` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReason {
    /// Stable reason code (enum)
    pub code: String,
    /// Human-readable label
    pub label: String,
    /// Additional detail from matched evidence (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Slot ID that backs this reason
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backed_by_slot: Option<String>,
}

impl DetectionReason {
    pub fn new(code: DetectionReasonCode) -> Self {
        Self {
            code: code.as_str().to_string(),
            label: code.label().to_string(),
            detail: None,
            backed_by_slot: None,
        }
    }
    
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    
    pub fn with_slot(mut self, slot_id: impl Into<String>) -> Self {
        self.backed_by_slot = Some(slot_id.into());
        self
    }
}

// ============================================================================
// Playbook Explanation Templates (Phase 2)
// ============================================================================
// Define canonical mappings for the 5 core playbooks.
// Each template specifies:
// - reason_codes: Which DetectionReasonCode values apply
// - key_fields: Which fields to extract and display
// - slot_to_reason: Mapping from slot ID to reason code

/// Key field name constants for explanation templates
pub mod key_field {
    pub const PROC_KEY: &str = "proc_key";
    pub const CMDLINE: &str = "cmdline";
    pub const PARENT_PROC: &str = "parent_proc";
    pub const USER: &str = "user";
    pub const HOST: &str = "host";
    pub const TARGET_IMAGE: &str = "target_image";
    pub const GRANTED_ACCESS: &str = "granted_access";
    pub const CALL_TRACE: &str = "call_trace";
    pub const SOURCE_PROC: &str = "source_proc";
    pub const TASK_NAME: &str = "task_name";
    pub const TASK_COMMAND: &str = "task_command";
    pub const TASK_TRIGGER: &str = "task_trigger";
    pub const SERVICE_NAME: &str = "service_name";
    pub const BINARY_PATH: &str = "binary_path";
    pub const START_TYPE: &str = "start_type";
    pub const REGISTRY_KEY: &str = "registry_key";
    pub const REGISTRY_VALUE: &str = "registry_value";
    pub const EVENT_ID: &str = "event_id";
}

/// Template definition for a playbook explanation
#[derive(Debug, Clone)]
pub struct PlaybookExplainTemplate {
    /// Playbook ID this template applies to
    pub playbook_id: &'static str,
    /// Required fields to extract from facts/events
    pub key_fields: &'static [&'static str],
    /// Mapping from slot name pattern to reason code
    pub slot_reason_map: &'static [(&'static str, DetectionReasonCode)],
    /// Default reason code if no slot mapping matches
    pub default_reason: DetectionReasonCode,
    /// Narrative template (placeholders: {proc_key}, {cmdline}, etc.)
    pub narrative_template: &'static str,
}

/// Get the explanation template for a playbook ID
pub fn get_playbook_template(playbook_id: &str) -> Option<&'static PlaybookExplainTemplate> {
    PLAYBOOK_TEMPLATES.get(playbook_id).copied()
}

lazy_static::lazy_static! {
    /// Canonical playbook explanation templates
    pub static ref PLAYBOOK_TEMPLATES: HashMap<&'static str, &'static PlaybookExplainTemplate> = {
        let mut m = HashMap::new();
        m.insert(ENCODED_POWERSHELL_TEMPLATE.playbook_id, &ENCODED_POWERSHELL_TEMPLATE);
        m.insert(SCHTASKS_ABUSE_TEMPLATE.playbook_id, &SCHTASKS_ABUSE_TEMPLATE);
        m.insert(SERVICE_PERSISTENCE_TEMPLATE.playbook_id, &SERVICE_PERSISTENCE_TEMPLATE);
        m.insert(REGISTRY_PERSISTENCE_TEMPLATE.playbook_id, &REGISTRY_PERSISTENCE_TEMPLATE);
        m.insert(CREDENTIAL_ACCESS_TEMPLATE.playbook_id, &CREDENTIAL_ACCESS_TEMPLATE);
        m
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Template: Encoded PowerShell
// ─────────────────────────────────────────────────────────────────────────────
pub static ENCODED_POWERSHELL_TEMPLATE: PlaybookExplainTemplate = PlaybookExplainTemplate {
    playbook_id: "windows_encoded_powershell_001",
    key_fields: &[
        key_field::PROC_KEY,
        key_field::CMDLINE,
        key_field::PARENT_PROC,
        key_field::USER,
        key_field::HOST,
        key_field::EVENT_ID,
    ],
    slot_reason_map: &[
        ("encoded_flag", DetectionReasonCode::PowershellEncodedCommand),
        ("bypass_flag", DetectionReasonCode::PowershellBypassPolicy),
        ("hidden_flag", DetectionReasonCode::PowershellHiddenWindow),
        ("download", DetectionReasonCode::PowershellDownloadCradle),
    ],
    default_reason: DetectionReasonCode::PowershellEncodedCommand,
    narrative_template: "PowerShell process detected with encoded command flag. \
        Process: {proc_key}. Command line contains '-enc' or '-encodedcommand' \
        followed by Base64-encoded payload. This is commonly used for obfuscation \
        in malicious scripts.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Template: Schtasks Abuse
// ─────────────────────────────────────────────────────────────────────────────
pub static SCHTASKS_ABUSE_TEMPLATE: PlaybookExplainTemplate = PlaybookExplainTemplate {
    playbook_id: "windows_schtasks_abuse_001",
    key_fields: &[
        key_field::PROC_KEY,
        key_field::CMDLINE,
        key_field::TASK_NAME,
        key_field::USER,
        key_field::HOST,
        key_field::EVENT_ID,
    ],
    slot_reason_map: &[
        ("create_flag", DetectionReasonCode::TaskCreated),
        ("run_as_system", DetectionReasonCode::TaskCreatedSystem),
        ("remote_target", DetectionReasonCode::TaskCreatedRemote),
        ("hidden", DetectionReasonCode::TaskHidden),
    ],
    default_reason: DetectionReasonCode::TaskCreated,
    narrative_template: "Scheduled task operation detected via schtasks.exe. \
        Process: {proc_key}. Command line indicates task creation or modification. \
        Scheduled tasks are commonly abused for persistence and privilege escalation.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Template: Service Persistence
// ─────────────────────────────────────────────────────────────────────────────
pub static SERVICE_PERSISTENCE_TEMPLATE: PlaybookExplainTemplate = PlaybookExplainTemplate {
    playbook_id: "windows_service_persistence_001",
    key_fields: &[
        key_field::SERVICE_NAME,
        key_field::BINARY_PATH,
        key_field::START_TYPE,
        key_field::USER,
        key_field::HOST,
        key_field::EVENT_ID,
    ],
    slot_reason_map: &[
        ("service_install", DetectionReasonCode::ServiceInstalled),
        ("suspicious_path", DetectionReasonCode::ServiceSuspiciousPath),
        ("service_modify", DetectionReasonCode::ServiceRegistryModified),
    ],
    default_reason: DetectionReasonCode::ServiceInstalled,
    narrative_template: "Windows service installation detected. \
        Service: {service_name}. Binary path: {binary_path}. \
        Service installation is a common persistence mechanism for malware.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Template: Registry Persistence
// ─────────────────────────────────────────────────────────────────────────────
pub static REGISTRY_PERSISTENCE_TEMPLATE: PlaybookExplainTemplate = PlaybookExplainTemplate {
    playbook_id: "windows_registry_persistence_001",
    key_fields: &[
        key_field::REGISTRY_KEY,
        key_field::REGISTRY_VALUE,
        key_field::PROC_KEY,
        key_field::USER,
        key_field::HOST,
        key_field::EVENT_ID,
    ],
    slot_reason_map: &[
        ("run", DetectionReasonCode::RegistryRunKeyModified),
        ("runonce", DetectionReasonCode::RegistryRunKeyModified),
        ("ifeo", DetectionReasonCode::RegistryIfeoDebugger),
        ("debugger", DetectionReasonCode::RegistryIfeoDebugger),
        ("winlogon", DetectionReasonCode::RegistryWinlogonShell),
        ("shell", DetectionReasonCode::RegistryWinlogonShell),
        ("services", DetectionReasonCode::RegistryServicesModified),
    ],
    default_reason: DetectionReasonCode::RegistryRunKeyModified,
    narrative_template: "Registry persistence mechanism detected. \
        Registry key: {registry_key}. Modified by process: {proc_key}. \
        Registry-based persistence allows malware to survive reboots.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Template: Credential Access
// ─────────────────────────────────────────────────────────────────────────────
pub static CREDENTIAL_ACCESS_TEMPLATE: PlaybookExplainTemplate = PlaybookExplainTemplate {
    playbook_id: "windows_credential_access_001",
    key_fields: &[
        key_field::SOURCE_PROC,
        key_field::TARGET_IMAGE,
        key_field::GRANTED_ACCESS,
        key_field::CALL_TRACE,
        key_field::CMDLINE,
        key_field::USER,
        key_field::HOST,
        key_field::EVENT_ID,
    ],
    slot_reason_map: &[
        ("lsass", DetectionReasonCode::ProcessAccessLsass),
        ("mimikatz", DetectionReasonCode::CredentialDumpTool),
        ("procdump", DetectionReasonCode::CredentialDumpTool),
        ("sekurlsa", DetectionReasonCode::CredentialDumpTool),
        ("sam", DetectionReasonCode::SamRegistryExport),
        ("ntds", DetectionReasonCode::NtdsAccess),
        ("vssadmin", DetectionReasonCode::NtdsAccess),
        ("comsvcs", DetectionReasonCode::ComsvcsDump),
    ],
    default_reason: DetectionReasonCode::CredentialDumpTool,
    narrative_template: "Credential access attempt detected. \
        Source process: {source_proc}. Target: {target_image}. \
        Access flags: {granted_access}. This indicates potential credential theft.",
};

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reason_code_roundtrip() {
        let codes = vec![
            ExplanationReasonCode::Ok,
            ExplanationReasonCode::MissingHypothesis,
            ExplanationReasonCode::MissingPlaybook,
            ExplanationReasonCode::DbLocked,
        ];
        
        for code in codes {
            let s = code.as_str();
            let parsed = ExplanationReasonCode::from_str(s);
            assert_eq!(code, parsed);
        }
    }
    
    #[test]
    fn test_unavailable_explanation_json() {
        let ctx = SignalContext::new("sig_123")
            .with_type("playbook:test")
            .with_severity("high");
        let unavail = UnavailableExplanation::new(ExplanationReasonCode::MissingHypothesis)
            .with_signal_context(ctx);
        
        let json = serde_json::to_string(&unavail).unwrap();
        assert!(json.contains("\"available\":false"));
        assert!(json.contains("MISSING_HYPOTHESIS"));
        // Verify NO matched_slots, narrative, reasons fields
        assert!(!json.contains("matched_slots"));
        assert!(!json.contains("narrative"));
        assert!(!json.contains("reasons"));
    }
    
    #[test]
    fn test_unavailable_no_inference() {
        // Verify signal_context only contains verbatim fields
        let ctx = SignalContext::new("sig_abc");
        let unavail = UnavailableExplanation::new(ExplanationReasonCode::MissingPlaybook)
            .with_signal_context(ctx);
        
        let json = serde_json::to_string(&unavail).unwrap();
        // Should NOT contain any inference fields
        assert!(!json.contains("playbook_id"));
        assert!(!json.contains("hypothesis_id"));
        assert!(!json.contains("template_id"));
        assert!(!json.contains("incident_id"));
    }
    
    // ========================================================================
    // Detection Reason Code Tests
    // ========================================================================
    
    #[test]
    fn test_detection_reason_code_as_str() {
        assert_eq!(DetectionReasonCode::PowershellEncodedCommand.as_str(), "POWERSHELL_ENCODED_COMMAND");
        assert_eq!(DetectionReasonCode::TaskCreatedSystem.as_str(), "TASK_CREATED_SYSTEM");
        assert_eq!(DetectionReasonCode::ProcessAccessLsass.as_str(), "PROCESS_ACCESS_LSASS");
        assert_eq!(DetectionReasonCode::RegistryRunKeyModified.as_str(), "REGISTRY_RUN_KEY_MODIFIED");
    }
    
    #[test]
    fn test_detection_reason_has_label() {
        // All reason codes must have a human-readable label
        let codes = [
            DetectionReasonCode::PowershellEncodedCommand,
            DetectionReasonCode::TaskCreatedSystem,
            DetectionReasonCode::ServiceInstalled,
            DetectionReasonCode::RegistryRunKeyModified,
            DetectionReasonCode::ProcessAccessLsass,
            DetectionReasonCode::GenericMatch,
        ];
        
        for code in codes {
            let label = code.label();
            assert!(!label.is_empty(), "Code {:?} has empty label", code);
            assert!(label.len() > 3, "Code {:?} has too short label", code);
        }
    }
    
    #[test]
    fn test_detection_reason_serialization() {
        let reason = DetectionReason::new(DetectionReasonCode::PowershellEncodedCommand)
            .with_detail("-enc SQBFAFgA...")
            .with_slot("encoded_flag");
        
        let json = serde_json::to_string(&reason).unwrap();
        assert!(json.contains("POWERSHELL_ENCODED_COMMAND"));
        assert!(json.contains("Encoded PowerShell Command"));
        assert!(json.contains("-enc SQBFAFgA"));
        assert!(json.contains("encoded_flag"));
    }
    
    #[test]
    fn test_playbook_template_lookup() {
        // Encoded powershell
        let tmpl = get_playbook_template("windows_encoded_powershell_001");
        assert!(tmpl.is_some());
        let tmpl = tmpl.unwrap();
        assert!(tmpl.key_fields.contains(&key_field::CMDLINE));
        assert!(tmpl.key_fields.contains(&key_field::PROC_KEY));
        
        // Credential access
        let tmpl = get_playbook_template("windows_credential_access_001");
        assert!(tmpl.is_some());
        let tmpl = tmpl.unwrap();
        assert!(tmpl.key_fields.contains(&key_field::TARGET_IMAGE));
        assert!(tmpl.key_fields.contains(&key_field::GRANTED_ACCESS));
        
        // Unknown playbook returns None
        assert!(get_playbook_template("nonexistent_playbook").is_none());
    }
    
    #[test]
    fn test_all_templates_have_key_fields() {
        for (_id, tmpl) in PLAYBOOK_TEMPLATES.iter() {
            // Each template must have at least 3 key fields
            assert!(
                tmpl.key_fields.len() >= 3,
                "Template {} has too few key_fields",
                tmpl.playbook_id
            );
            // Each template must have a narrative template
            assert!(
                !tmpl.narrative_template.is_empty(),
                "Template {} has empty narrative",
                tmpl.playbook_id
            );
            // Each template must have at least one slot_reason mapping
            assert!(
                !tmpl.slot_reason_map.is_empty(),
                "Template {} has no slot_reason_map",
                tmpl.playbook_id
            );
        }
    }
    
    #[test]
    fn test_narrative_template_uses_key_fields() {
        // Verify narrative templates reference their declared key fields
        let encoded_ps = get_playbook_template("windows_encoded_powershell_001").unwrap();
        assert!(
            encoded_ps.narrative_template.contains("{proc_key}"),
            "Encoded PS narrative should reference proc_key"
        );
        
        let cred_access = get_playbook_template("windows_credential_access_001").unwrap();
        assert!(
            cred_access.narrative_template.contains("{target_image}"),
            "Credential access narrative should reference target_image"
        );
    }
}

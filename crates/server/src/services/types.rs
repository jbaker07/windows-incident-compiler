//! Shared types for the service layer
//!
//! Contains structs, enums, and type aliases used across multiple services.
//! These types were previously defined inline in locint.rs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ============================================================================
// Core State Types
// ============================================================================

/// Application state shared across all handlers
pub struct LocintState {
    pub data_dir: PathBuf,
    pub port: u16,
    pub supervisor: crate::supervisor::Supervisor,
    pub db: crate::db::Database,
    pub flight_recorder: crate::flight_recorder::SharedFlightRecorder,
}

/// Type alias for thread-safe shared state
pub type SharedState = Arc<LocintState>;

// ============================================================================
// Product Tier System
// ============================================================================

/// Product tiers for feature gating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProductTier {
    Free,
    Pro,
    Team,
    Dev,
}

impl ProductTier {
    pub fn display_name(&self) -> &'static str {
        match self {
            ProductTier::Free => "Free",
            ProductTier::Pro => "Pro",
            ProductTier::Team => "Team",
            ProductTier::Dev => "Developer",
        }
    }
    
    /// Check if this tier has access to a feature requiring `required` tier
    pub fn has_access(&self, required: ProductTier) -> bool {
        match required {
            ProductTier::Free => true,
            ProductTier::Dev => *self == ProductTier::Dev,
            ProductTier::Pro => matches!(self, ProductTier::Pro | ProductTier::Team | ProductTier::Dev),
            ProductTier::Team => matches!(self, ProductTier::Team | ProductTier::Dev),
        }
    }
}

/// Resolve current tier from environment/license
pub fn resolve_current_tier() -> ProductTier {
    // Check for license key in environment
    if let Ok(key) = std::env::var("LOCINT_LICENSE_KEY") {
        if key.starts_with("TEAM-") {
            return ProductTier::Team;
        }
        if key.starts_with("PRO-") {
            return ProductTier::Pro;
        }
    }
    
    // Check for license.json file
    if let Ok(contents) = std::fs::read_to_string("license.json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
            if let Some(tier) = v.get("tier").and_then(|t| t.as_str()) {
                match tier.to_lowercase().as_str() {
                    "team" => return ProductTier::Team,
                    "pro" => return ProductTier::Pro,
                    _ => {}
                }
            }
        }
    }
    
    // Dev tier for debug builds
    if cfg!(debug_assertions) {
        return ProductTier::Dev;
    }
    
    ProductTier::Free
}

// ============================================================================
// Route Registry Types
// ============================================================================

/// Route information for wiring audit
#[derive(Clone, Serialize)]
pub struct RouteInfo {
    pub method: String,
    pub path: String,
    pub description: String,
    pub mutates: bool,
}

impl RouteInfo {
    pub fn new(method: &str, path: &str, description: &str, mutates: bool) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            description: description.to_string(),
            mutates,
        }
    }
}

// ============================================================================
// Run Control Types
// ============================================================================

/// Request body for starting a run
#[derive(Deserialize)]
pub struct StartRunRequest {
    #[serde(default)]
    pub run_label: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub duration_seconds: Option<u64>,
    /// Playbook selection for this run
    #[serde(default)]
    pub playbook_selection: Option<PlaybookSelection>,
}

/// Playbook selection configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PlaybookSelection {
    /// Selection mode: "preset" or "custom"
    #[serde(default = "default_selection_mode")]
    pub mode: String,
    /// Preset ID: "general", "admin", "sysmon", "powershell", "extended", "all"
    #[serde(default)]
    pub preset: Option<String>,
    /// Explicitly selected playbook IDs (for custom mode or preset override)
    #[serde(default)]
    pub selected_playbooks: Vec<String>,
}

fn default_selection_mode() -> String {
    "preset".to_string()
}

impl Default for PlaybookSelection {
    fn default() -> Self {
        Self {
            mode: "preset".to_string(),
            preset: Some("extended".to_string()),
            selected_playbooks: Vec::new(),
        }
    }
}

/// Request body for renaming a run
#[derive(Deserialize)]
pub struct RenameRunRequest {
    pub name: Option<String>,
}

/// Request body for deleting a run
#[derive(Deserialize)]
pub struct DeleteRunRequest {
    #[serde(default)]
    pub delete_files: bool,
}

// ============================================================================
// Baseline Types
// ============================================================================

/// Request body for marking a run as baseline
#[derive(Deserialize)]
pub struct SetBaselineRequest {
    #[serde(default = "default_baseline_scope")]
    pub scope: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub set_as_default: bool,
}

fn default_baseline_scope() -> String {
    "host".to_string()
}

fn default_true() -> bool {
    true
}

/// Response structure for baseline operations
#[derive(Serialize)]
pub struct BaselineInfo {
    pub run_id: String,
    pub scope: String,
    pub marked_at: String,
    pub description: String,
    pub is_default: bool,
    pub metrics_snapshot: Option<BaselineMetricsSnapshot>,
}

/// Metrics snapshot for baseline comparison
#[derive(Serialize, Clone)]
pub struct BaselineMetricsSnapshot {
    pub events_count: u64,
    pub segments_count: u32,
    pub facts_count: u64,
    pub signals_count: u64,
}

// ============================================================================
// Signals Types
// ============================================================================

/// Query parameters for signals endpoint
#[derive(Deserialize)]
pub struct SignalsQuery {
    pub run_id: Option<String>,
    /// Cursor for incremental fetching - only return signals with ts > since_ts_ms
    pub since_ts_ms: Option<i64>,
}

// ============================================================================
// Entity Explorer Types (Pro)
// ============================================================================

/// Pivot query parameters
#[derive(Deserialize)]
pub struct PivotQuery {
    pub kind: String,
    pub key: String,
    pub window_ms: Option<i64>,
}

// ============================================================================
// Case Pack Types (Pro)
// ============================================================================

/// Case pack export request body
#[derive(Deserialize)]
pub struct CasePackRequest {
    pub include: Option<CasePackInclude>,
    pub evidence: Option<CasePackEvidence>,
}

#[derive(Deserialize)]
pub struct CasePackInclude {
    pub summary: Option<bool>,
    pub findings: Option<bool>,
    pub changes: Option<bool>,
    pub next_steps: Option<bool>,
}

#[derive(Deserialize)]
pub struct CasePackEvidence {
    pub include_records: Option<bool>,
    pub max_records: Option<usize>,
    pub max_bytes: Option<usize>,
}

// ============================================================================
// Diff Types
// ============================================================================

/// Canonical Change object for Diff v2
#[derive(Debug, Clone, Serialize)]
pub struct DiffChange {
    pub change_id: String,
    pub ts_ms: i64,
    pub ts_end_ms: Option<i64>,
    pub category: DiffCategory,
    pub direction: DiffDirection,
    pub title: String,
    pub summary: String,
    pub entities: DiffEntities,
    pub severity: String,
    pub severity_basis: String,
    pub evidence_ptrs: Vec<serde_json::Value>,
    pub evidence_unavailable_reason: Option<String>,
    pub supporting_facts_count: i64,
    pub stable_key: String,
    pub novelty: Option<String>,
    pub novelty_basis: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffCategory {
    Process,
    Persistence,
    Auth,
    Network,
    Evasion,
    File,
    Other,
}

impl DiffCategory {
    pub fn from_fact_type(fact_type: &str) -> Self {
        match fact_type.to_lowercase().as_str() {
            "exec" | "processexec" | "processcreate" | "processexit" | "moduleload" | "memread" => DiffCategory::Process,
            "fileop" | "filecreate" | "filedelete" | "filemodify" | "fileaccess" => DiffCategory::File,
            "netconn" | "networkconnection" | "dnsquery" | "dns" => DiffCategory::Network,
            "persistartifact" | "servicecreate" | "schedtask" | "regop" | "registryop" | "wmiop" => DiffCategory::Persistence,
            "authevent" | "authlogon" | "logon" | "logoff" | "authfailure" => DiffCategory::Auth,
            "logtamper" | "defenseevasion" | "securityevasion" => DiffCategory::Evasion,
            _ => DiffCategory::Other,
        }
    }
    
    pub fn as_str(&self) -> &'static str {
        match self {
            DiffCategory::Process => "Process",
            DiffCategory::Persistence => "Persistence",
            DiffCategory::Auth => "Auth",
            DiffCategory::Network => "Network",
            DiffCategory::Evasion => "Evasion",
            DiffCategory::File => "File",
            DiffCategory::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffDirection {
    Added,
    Removed,
    Increased,
    Decreased,
    Modified,
}

impl DiffDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiffDirection::Added => "added",
            DiffDirection::Removed => "removed",
            DiffDirection::Increased => "increased",
            DiffDirection::Decreased => "decreased",
            DiffDirection::Modified => "modified",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiffEntities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_proc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<String>,
}

/// Capability snapshot for comparing telemetry surfaces
#[derive(Debug, Clone, Default, Serialize)]
pub struct CapabilitySnapshot {
    pub is_admin: bool,
    pub sysmon_installed: bool,
    pub security_log_accessible: bool,
    pub enabled_sensors: Vec<String>,
    pub fact_types_observed: Vec<String>,
}

/// Diff mode query parameter
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Baseline,
    Phase,
    Marker,
}

/// Query parameters for diff endpoint
#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    pub mode: Option<String>,
    pub baseline_run_id: Option<String>,
    pub phase_minutes: Option<i64>,
    pub marker_ts: Option<i64>,
    pub category: Option<String>,
    pub direction: Option<String>,
    #[serde(default)]
    pub baseline_filter: Option<bool>,
}

// ============================================================================
// Evidence Types
// ============================================================================

/// Evidence dereference reason codes
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceDerefReasonCode {
    Success,
    MissingRunId,
    MissingSegmentId,
    RunNotFound,
    SegmentNotFound,
    OffsetOutOfBounds,
    ParseError,
    IoError,
    PathTraversal,
}

/// Evidence dereference query
#[derive(Deserialize)]
pub struct EvidenceDerefQuery {
    pub run_id: Option<String>,
    pub segment_id: Option<String>,
    pub offset: Option<usize>,
    pub context_lines: Option<usize>,
}

// ============================================================================
// Export/Import Types
// ============================================================================

/// Export bundle request
#[derive(Deserialize)]
pub struct ExportBundleRequest {
    pub run_id: String,
    #[serde(default)]
    pub include_segments: bool,
}

// ============================================================================
// Pack Types
// ============================================================================

/// Pack validation result
#[derive(Serialize)]
pub struct PackValidation {
    pub valid: bool,
    pub reason_code: Option<String>,
    pub reason_message: Option<String>,
}

// ============================================================================
// Team Types
// ============================================================================

/// Lock owner info for display in UI
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LockOwnerInfo {
    pub install_id: String,
    pub host_name: String,
    pub pid: u32,
    pub acquired_at: String,
    pub last_heartbeat_at: String,
}

/// Configure store request
#[derive(Deserialize)]
pub struct ConfigureStoreRequest {
    pub store_path: String,
}

/// Create case request
#[derive(Deserialize)]
pub struct CreateCaseRequest {
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Update tags request
#[derive(Deserialize)]
pub struct UpdateTagsRequest {
    pub tags: Vec<String>,
}

/// Add note request
#[derive(Deserialize)]
pub struct AddNoteRequest {
    pub content: String,
}

/// Publish run request
#[derive(Deserialize)]
pub struct PublishRunRequest {
    pub run_id: String,
}

/// Import run request
#[derive(Deserialize)]
pub struct ImportRunRequest {
    pub run_id: String,
}

// ============================================================================
// Next Steps Types
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextStepsScenario {
    NotRunning,
    JustStarted,
    Capturing,
    Completed,
    HasFindings,
    NoFindings,
}

#[derive(Debug, Clone, Serialize)]
pub struct NextStepAction {
    pub action: String,
    pub reason: String,
    pub priority: u8,
    pub ui_hint: Option<String>,
}

// ============================================================================
// Helpers
// ============================================================================

/// Helper to return 403 with FEATURE_LOCKED body
pub fn feature_locked_403(feature: &str, required_tier: ProductTier) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    let current = resolve_current_tier();
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "success": false,
            "error": {
                "code": "FEATURE_LOCKED",
                "message": format!("{} requires {} tier", feature, required_tier.display_name()),
                "feature": feature,
                "required_tier": required_tier,
                "current_tier": current,
                "upgrade_url": "https://locint.io/upgrade"
            }
        }))
    )
}

// ============================================================================
// Case Management Types
// ============================================================================

/// Case metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMeta {
    pub case_id: String,
    pub name: String,
    pub created_at: String,
    pub created_by: String,
    pub modified_at: String,
    pub status: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub source_runs: Vec<String>,
    pub signals_count: usize,
}

/// Case note
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseNote {
    pub note_id: String,
    pub created_at: String,
    pub modified_at: String,
    pub author: String,
    pub content: String,
    pub signal_id: Option<String>,
}

/// Publish manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishManifest {
    pub run_id: String,
    pub case_id: String,
    pub published_at: String,
    pub files: Vec<PublishedFile>,
    pub signals_count: usize,
    pub segments_count: usize,
    pub total_bytes: u64,
}

/// Published file info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedFile {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}


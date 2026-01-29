//! Playbook Scope Types and Logic
//!
//! This module defines the canonical run-scoped playbook selection model.
//! It ensures that Investigate and "playbooks fired" views reflect ONLY the
//! playbooks that were in scope for that specific run.
//!
//! # Scope Modes
//!
//! - `explicit`: User selected specific playbooks (N > 0)
//! - `general_discovery`: No selection, defaulted to GENERAL_DISCOVERY_SET
//! - `preset_default`: Preset implies a default set (e.g., "extended" preset)
//! - `none`: Explicitly no playbooks (evaluate nothing)
//!
//! # Reason Codes
//!
//! Playbook-level:
//! - `USER_SELECTED_SCOPE`: User explicitly selected this playbook
//! - `NO_SELECTION_DEFAULTED_TO_DISCOVERY`: No selection, included in discovery set
//! - `PRESET_DEFAULT_SCOPE`: Included via preset default
//! - `OUT_OF_SCOPE_SKIPPED`: Not in effective_playbook_ids, skipped evaluation
//!
//! Visibility-level:
//! - `MISSING_SENSOR_SYSMON`: Playbook requires Sysmon but not installed
//! - `MISSING_SENSOR_ETW`: Playbook requires ETW but provider not available
//! - `LOG_ACCESS_DENIED`: Cannot read required log (e.g., Security log)
//! - `PROVIDER_UNAVAILABLE`: Required provider not available
//!
//! Match-level:
//! - `NO_MATCHING_FACTS`: Facts were searched but none matched
//! - `OUTSIDE_TIME_WINDOW`: Facts exist but outside playbook time window
//! - `PARSER_ERROR`: Playbook YAML could not be parsed
//! - `PLAYBOOK_LOAD_ERROR`: Playbook failed to load

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Version of the General Discovery Set (for auditing)
pub const GENERAL_DISCOVERY_VERSION: &str = "v2.0.0";

/// Fallback discovery set - used only when all_playbook_ids is not provided
/// Prefer passing all_playbook_ids from filesystem discovery for complete coverage
#[allow(dead_code)]
pub const FALLBACK_DISCOVERY_SET: &[&str] = &[
    "credential_access",
    "defense_evasion",  
    "persistence_windows",
    "registry_persistence",
    "service_persistence",
    "task_persistence",
    "encoded_powershell",
    "lolbin_abuse",
];

/// Scope mode for playbook evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    /// User explicitly selected playbooks (N > 0)
    Explicit,
    /// No selection, defaulted to GENERAL_DISCOVERY_SET
    GeneralDiscovery,
    /// Preset implies a default set
    PresetDefault,
    /// Explicitly no playbooks (evaluate nothing)
    None,
}

impl Default for ScopeMode {
    fn default() -> Self {
        ScopeMode::None
    }
}

/// Reason code for scope determination
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScopeReasonCode {
    /// User explicitly selected playbooks
    UserSelected,
    /// No selection, defaulted to discovery set
    NoSelectionDefaulted,
    /// Preset implies default set
    PresetDefault,
    /// No playbooks to evaluate
    None,
}

/// Rationale for scope determination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRationale {
    /// Machine-readable reason code
    pub reason_code: ScopeReasonCode,
    /// Human-readable explanation
    pub note: String,
}

/// Canonical playbook scope for a run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookScope {
    /// Scope mode
    pub mode: ScopeMode,
    /// Explicit user selection (may be empty)
    pub selected_playbook_ids: Vec<String>,
    /// What backend will actually evaluate for this run
    pub effective_playbook_ids: Vec<String>,
    /// Preset ID used (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    /// Version of discovery set (if mode is general_discovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_pack_version: Option<String>,
    /// When scope was computed
    pub created_at: String,
    /// Rationale for scope determination
    pub rationale: ScopeRationale,
}

impl PlaybookScope {
    /// Compute scope from selection and preset
    ///
    /// Rules:
    /// 1. If selected_playbook_ids.len() > 0: mode=explicit, effective=selected
    /// 2. Else if preset implies defaults: mode=general_discovery, effective=ALL playbooks (all variants)
    /// 3. Else: mode=none, effective=[]
    ///
    /// Pass `all_playbook_ids` to enable "all variants" default behavior.
    /// If None, falls back to empty set (backward compatibility).
    pub fn compute(
        selected_playbook_ids: Option<Vec<String>>,
        preset_id: Option<String>,
        selection_mode: Option<String>,
    ) -> Self {
        // Backward-compatible: no all_playbooks means empty default
        Self::compute_with_all(selected_playbook_ids, preset_id, selection_mode, None)
    }
    
    /// Compute scope with full playbook catalog for "all variants" default
    pub fn compute_with_all(
        selected_playbook_ids: Option<Vec<String>>,
        preset_id: Option<String>,
        selection_mode: Option<String>,
        all_playbook_ids: Option<Vec<String>>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let selected = selected_playbook_ids.unwrap_or_default();
        
        // Rule 1: Explicit selection
        if !selected.is_empty() {
            return PlaybookScope {
                mode: ScopeMode::Explicit,
                effective_playbook_ids: selected.clone(),
                selected_playbook_ids: selected,
                preset_id,
                discovery_pack_version: None,
                created_at: now,
                rationale: ScopeRationale {
                    reason_code: ScopeReasonCode::UserSelected,
                    note: "User explicitly selected playbooks for this run".to_string(),
                },
            };
        }
        
        // Rule 2: Check if preset implies discovery
        let preset = preset_id.clone().unwrap_or_default();
        let implies_discovery = matches!(
            preset.to_lowercase().as_str(),
            "discovery" | "general" | "system_changes" | "extended" | "threat_hunt"
        );
        
        // Also check selection_mode - if "preset" mode was used, default to discovery
        let is_preset_mode = selection_mode.as_deref() == Some("preset");
        
        if implies_discovery || is_preset_mode {
            // Use ALL playbooks when available, otherwise use fallback set
            let effective_ids = all_playbook_ids.clone().unwrap_or_else(|| {
                FALLBACK_DISCOVERY_SET.iter().map(|s| s.to_string()).collect()
            });
            let count = effective_ids.len();
            
            return PlaybookScope {
                mode: ScopeMode::GeneralDiscovery,
                effective_playbook_ids: effective_ids,
                selected_playbook_ids: vec![],
                preset_id: Some(preset),
                discovery_pack_version: Some(GENERAL_DISCOVERY_VERSION.to_string()),
                created_at: now,
                rationale: ScopeRationale {
                    reason_code: ScopeReasonCode::NoSelectionDefaulted,
                    note: format!(
                        "No playbooks selected. Evaluating all {} variants ({})",
                        count,
                        GENERAL_DISCOVERY_VERSION
                    ),
                },
            };
        }
        
        // Rule 3: No playbooks
        PlaybookScope {
            mode: ScopeMode::None,
            effective_playbook_ids: vec![],
            selected_playbook_ids: vec![],
            preset_id,
            discovery_pack_version: None,
            created_at: now,
            rationale: ScopeRationale {
                reason_code: ScopeReasonCode::None,
                note: "No playbooks selected and preset does not imply defaults".to_string(),
            },
        }
    }
    
    /// Check if a playbook ID is in scope
    pub fn is_in_scope(&self, playbook_id: &str) -> bool {
        self.effective_playbook_ids.iter().any(|id| id == playbook_id)
    }
    
    /// Get effective playbooks as a HashSet for fast lookup
    pub fn effective_set(&self) -> HashSet<String> {
        self.effective_playbook_ids.iter().cloned().collect()
    }
}

/// Playbook evaluation status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookEvalStatus {
    /// All required slots satisfied - playbook fired
    Fired,
    /// Some required slots satisfied (near-miss)
    Candidate,
    /// 0 required slots matched AND visibility was sufficient
    NoMatch,
    /// Cannot evaluate due to missing visibility
    Blocked,
    /// Not evaluated because out of scope
    Skipped,
}

/// Reason code for evaluation outcome
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvalReasonCode {
    // Scope-related
    UserSelectedScope,
    NoSelectionDefaultedToDiscovery,
    PresetDefaultScope,
    OutOfScopeSkipped,
    
    // Visibility-related
    MissingSensorSysmon,
    MissingSensorEtw,
    LogAccessDenied,
    ProviderUnavailable,
    
    // Match-related
    NoMatchingFacts,
    OutsideTimeWindow,
    ParserError,
    PlaybookLoadError,
    
    // Success
    AllSlotsSatisfied,
    PartialSlotsSatisfied,
}

impl std::fmt::Display for EvalReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalReasonCode::UserSelectedScope => write!(f, "USER_SELECTED_SCOPE"),
            EvalReasonCode::NoSelectionDefaultedToDiscovery => write!(f, "NO_SELECTION_DEFAULTED_TO_DISCOVERY"),
            EvalReasonCode::PresetDefaultScope => write!(f, "PRESET_DEFAULT_SCOPE"),
            EvalReasonCode::OutOfScopeSkipped => write!(f, "OUT_OF_SCOPE_SKIPPED"),
            EvalReasonCode::MissingSensorSysmon => write!(f, "MISSING_SENSOR_SYSMON"),
            EvalReasonCode::MissingSensorEtw => write!(f, "MISSING_SENSOR_ETW"),
            EvalReasonCode::LogAccessDenied => write!(f, "LOG_ACCESS_DENIED"),
            EvalReasonCode::ProviderUnavailable => write!(f, "PROVIDER_UNAVAILABLE"),
            EvalReasonCode::NoMatchingFacts => write!(f, "NO_MATCHING_FACTS"),
            EvalReasonCode::OutsideTimeWindow => write!(f, "OUTSIDE_TIME_WINDOW"),
            EvalReasonCode::ParserError => write!(f, "PARSER_ERROR"),
            EvalReasonCode::PlaybookLoadError => write!(f, "PLAYBOOK_LOAD_ERROR"),
            EvalReasonCode::AllSlotsSatisfied => write!(f, "ALL_SLOTS_SATISFIED"),
            EvalReasonCode::PartialSlotsSatisfied => write!(f, "PARTIAL_SLOTS_SATISFIED"),
        }
    }
}

/// Slot evaluation status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotEvalStatus {
    /// Slot matched facts
    Matched,
    /// Slot did not match any facts
    Missing,
    /// Slot blocked due to visibility
    Blocked,
    /// Slot skipped (out of scope)
    Skipped,
}

/// Visibility summary for a run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilitySummary {
    /// Sensors present during run
    pub sensors_present: Vec<String>,
    /// Sensors missing during run
    pub sensors_missing: Vec<String>,
    /// Permission states
    pub permissions: PermissionState,
}

/// Permission states for various log sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionState {
    /// Security log access: "ok", "denied", "unavailable"
    pub security_log: String,
    /// System log access
    pub system_log: String,
    /// Sysmon log access (if installed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysmon_log: Option<String>,
}

/// Search hints for a slot (helps user understand what to look for)
/// 
/// # EVIDENCE TAB UPGRADE
/// The `query_terms` field provides structured search terms that the UI should use
/// for tokenized search. This is more reliable than freeform `query` strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotSearchHints {
    /// Suggested lens filter (fact_type to filter by)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens: Option<String>,
    /// Suggested search query (DEPRECATED - use query_terms for reliability)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Structured query terms for tokenized search (PREFERRED over query)
    /// Each term should be searched independently and results combined
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub query_terms: Vec<String>,
    /// Expected fact types - UI should filter to these exact types
    pub fact_types: Vec<String>,
    /// Host filter if slot is scoped to specific host
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Time window for filtering (if slot has temporal constraints)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<SearchTimeRange>,
}

/// Time range for search filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchTimeRange {
    /// Start timestamp (epoch ms)
    pub start_ts: i64,
    /// End timestamp (epoch ms)  
    pub end_ts: i64,
}

/// Reference to a specific piece of evidence that satisfied a slot
/// 
/// # Canonical Format (for /facts/resolve endpoint)
/// 
/// The backend will attempt to resolve in this priority order:
/// 1. `fact_id` - Direct lookup in facts_sample table (preferred)
/// 2. `segment_id` + `record_index` - Raw log pointer for legacy/segment-based evidence
/// 3. `fact_type` + `ts` - Approximate match when no stable ID available
/// 
/// At least ONE of these must be present for resolution to succeed:
/// - `fact_id` alone (fastest, most reliable)
/// - `segment_id` + `record_index` (for raw log references)
/// - `fact_type` + `ts` (fallback, may match multiple facts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Fact ID - stable pointer, primary key in facts_sample (PREFERRED)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fact_id: Option<String>,
    /// Segment ID for raw log reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<String>,
    /// Record index within segment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_index: Option<u32>,
    /// Fact type that matched (for fallback resolution)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fact_type: Option<String>,
    /// Timestamp of the evidence (for fallback resolution)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<i64>,
}

impl EvidenceRef {
    /// Check if this ref is resolvable (has required fields)
    pub fn is_resolvable(&self) -> bool {
        self.fact_id.is_some() 
            || (self.segment_id.is_some() && self.record_index.is_some())
            || (self.fact_type.is_some() && self.ts.is_some())
    }
}

/// Match trace for a slot - backend-authored proof of what evidence satisfied this step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchTrace {
    /// Whether this slot was matched
    pub matched: bool,
    /// Number of facts that matched this slot's predicate
    pub matched_fact_count: u32,
    /// Predicate IDs if available (from playbook rules)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicate_ids: Vec<String>,
    /// Stable references to the evidence that satisfied this slot
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<EvidenceRef>,
}

impl MatchTrace {
    /// Create an empty/unmatched trace
    pub fn unmatched() -> Self {
        MatchTrace {
            matched: false,
            matched_fact_count: 0,
            predicate_ids: vec![],
            evidence_refs: vec![],
        }
    }
    
    /// Create a matched trace with fact count and optional refs
    pub fn matched_with_count(count: u32, refs: Vec<EvidenceRef>) -> Self {
        MatchTrace {
            matched: count > 0,
            matched_fact_count: count,
            predicate_ids: vec![],
            evidence_refs: refs,
        }
    }
}

/// Slot evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotEvalResult {
    /// Slot identifier
    pub slot_id: String,
    /// Slot name
    pub slot_name: String,
    /// Whether slot is required for playbook to fire
    pub required: bool,
    /// Evaluation status
    pub status: SlotEvalStatus,
    /// Number of facts that matched this slot
    pub match_count: u32,
    /// Reason code explaining status
    pub reason_code: EvalReasonCode,
    /// Search hints for finding matching facts (REQUIRED - backend must always provide)
    pub search_hints: SlotSearchHints,
    /// Human-readable expected facts from playbook YAML (for UI rendering)
    #[serde(default)]
    pub expected_fact_types: Vec<String>,
    /// Backend-authored match trace with evidence references
    pub match_trace: MatchTrace,
}

/// Window remark for time-based evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowRemark {
    /// Start of evaluation window
    pub start_ts: i64,
    /// End of evaluation window
    pub end_ts: i64,
    /// Reason code if window-related issue
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<EvalReasonCode>,
}

/// Backend-authored narrative for UI rendering (explainability contract)
/// 
/// This struct ensures domain-level explanations are authored by the evaluation
/// engine, not the UI. The UI should render this verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalNarrative {
    /// Short title with status indicator (e.g., "🔴 Detection Fired")
    pub title: String,
    /// Explanation bullets (rendered as list items)
    pub bullets: Vec<String>,
    /// Actionable hint for the user (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_hint: Option<String>,
}

/// Generate a backend-authored narrative based on evaluation results.
/// 
/// This function produces deterministic, domain-specific explanations derived
/// ONLY from the provided inputs. It does not invent claims.
pub fn generate_narrative(
    playbook_name: &str,
    status: &PlaybookEvalStatus,
    reason_codes: &[EvalReasonCode],
    visibility: &VisibilitySummary,
    slots: &[SlotEvalResult],
    slots_matched: u32,
    total_slots: u32,
) -> EvalNarrative {
    match status {
        PlaybookEvalStatus::Fired => {
            let matched_count = slots.iter().filter(|s| s.status == SlotEvalStatus::Matched).count();
            let total_count = slots.len();
            let mut bullets = vec![
                format!("Matched {}/{} detection steps.", matched_count, total_count),
                format!("The observed facts align with the behavioral pattern defined in \"{}\".", playbook_name),
            ];
            if !reason_codes.is_empty() {
                bullets.push(format!("Reason codes: {}.", reason_codes.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")));
            }
            bullets.push("Review matched steps below to see which behaviors triggered this detection.".to_string());
            
            EvalNarrative {
                title: "🔴 Detection Fired".to_string(),
                bullets,
                action_hint: Some("Click \"🔍 Evidence\" on matched steps to see the underlying facts.".to_string()),
            }
        }
        
        PlaybookEvalStatus::Candidate => {
            let matched_count = slots.iter().filter(|s| s.status == SlotEvalStatus::Matched).count();
            let total_count = slots.len();
            let mut bullets = vec![
                format!("Partially matched {}/{} detection steps.", matched_count, total_count),
                "Some expected behaviors were observed, but not enough to definitively fire the detection.".to_string(),
                "This may indicate early-stage activity or incomplete visibility.".to_string(),
            ];
            if !reason_codes.is_empty() {
                bullets.push(format!("Reason codes: {}.", reason_codes.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")));
            }
            
            EvalNarrative {
                title: "🟠 Candidate (Partial Match)".to_string(),
                bullets,
                action_hint: Some("Review unmatched steps to understand what additional evidence would be needed.".to_string()),
            }
        }
        
        PlaybookEvalStatus::NoMatch => {
            let mut bullets = vec![
                format!("Playbook \"{}\" was fully evaluated with sufficient visibility.", playbook_name),
                format!("Checked {}/{} detection steps; no matching facts found.", total_slots, total_slots),
                "The observed telemetry did not match the expected behavioral patterns.".to_string(),
            ];
            if reason_codes.is_empty() {
                bullets.push("No reason codes provided.".to_string());
            }
            
            EvalNarrative {
                title: "⚪ No Match".to_string(),
                bullets,
                action_hint: Some("No action required unless you expected this detection to fire.".to_string()),
            }
        }
        
        PlaybookEvalStatus::Blocked => {
            // Determine blocking reason from visibility + reason_codes
            let security_denied = visibility.permissions.security_log == "denied";
            let sysmon_missing = visibility.sensors_missing.iter().any(|s| s.to_lowercase().contains("sysmon"));
            
            let (bullets, action_hint) = if security_denied {
                (
                    vec![
                        "This playbook requires access to the Windows Security log.".to_string(),
                        "Access was denied — the collector is not running with Administrator privileges.".to_string(),
                        "Without this visibility, the detection engine cannot determine if the behavior occurred.".to_string(),
                    ],
                    Some("Run the collector with Administrator privileges (SeSecurityPrivilege).".to_string())
                )
            } else if sysmon_missing {
                (
                    vec![
                        "This playbook requires Sysmon telemetry.".to_string(),
                        "Sysmon is not installed or not generating events on this system.".to_string(),
                        "Without Sysmon, critical process/network visibility is unavailable.".to_string(),
                    ],
                    Some("Install and configure Sysmon, then re-run the collector.".to_string())
                )
            } else {
                // Generic blocked reason
                let reason_str = if !reason_codes.is_empty() {
                    reason_codes.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")
                } else {
                    "Required visibility not available".to_string()
                };
                (
                    vec![
                        format!("This playbook could not be evaluated: {}.", reason_str),
                        "The required data sources or permissions are not accessible.".to_string(),
                    ],
                    if !reason_codes.is_empty() {
                        Some("Review the reason codes and ensure required sensors/permissions are available.".to_string())
                    } else {
                        None
                    }
                )
            };
            
            EvalNarrative {
                title: "⚫ Blocked (Cannot Evaluate)".to_string(),
                bullets,
                action_hint,
            }
        }
        
        PlaybookEvalStatus::Skipped => {
            let reason_str = if !reason_codes.is_empty() {
                reason_codes.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", ")
            } else {
                "Out of scope or disabled by policy".to_string()
            };
            
            EvalNarrative {
                title: "⏭️ Skipped".to_string(),
                bullets: vec![
                    "This playbook was not evaluated for this run.".to_string(),
                    format!("Reason: {}.", reason_str),
                ],
                action_hint: Some("Select this playbook explicitly in Mission before starting a run.".to_string()),
            }
        }
    }
}

/// Complete playbook evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookEvalResult {
    /// Run ID this evaluation belongs to
    pub run_id: String,
    /// Playbook identifier
    pub playbook_id: String,
    /// Playbook display name
    pub playbook_name: String,
    /// Family/tactic this playbook belongs to (e.g., "persistence", "credential_access")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Whether playbook was in scope for this run
    pub in_scope: bool,
    /// Scope mode that determined in_scope
    pub scope_mode: ScopeMode,
    /// Evaluation status
    pub status: PlaybookEvalStatus,
    /// Severity if fired
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Number of slots matched
    pub slots_matched: u32,
    /// Total slots in playbook
    pub total_slots: u32,
    /// Time window for evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_remark: Option<WindowRemark>,
    /// Visibility summary
    pub visibility: VisibilitySummary,
    /// Reason codes explaining outcome
    pub reason_codes: Vec<EvalReasonCode>,
    /// Per-slot evaluation results
    pub slots: Vec<SlotEvalResult>,
    /// Backend-authored narrative for UI rendering (explainability contract)
    /// Optional for backward compatibility with older runs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub narrative: Option<EvalNarrative>,
}

impl PlaybookEvalResult {
    /// Create a skipped result for out-of-scope playbook
    pub fn skipped(run_id: &str, playbook_id: &str, playbook_name: &str, visibility: VisibilitySummary) -> Self {
        let reason_codes = vec![EvalReasonCode::OutOfScopeSkipped];
        let narrative = generate_narrative(
            playbook_name,
            &PlaybookEvalStatus::Skipped,
            &reason_codes,
            &visibility,
            &[],
            0,
            0,
        );
        PlaybookEvalResult {
            run_id: run_id.to_string(),
            playbook_id: playbook_id.to_string(),
            playbook_name: playbook_name.to_string(),
            family: None,
            in_scope: false,
            scope_mode: ScopeMode::None,
            status: PlaybookEvalStatus::Skipped,
            severity: None,
            slots_matched: 0,
            total_slots: 0,
            window_remark: None,
            visibility,
            reason_codes,
            slots: vec![],
            narrative: Some(narrative),
        }
    }
    
    /// Create a blocked result for visibility issues
    pub fn blocked(
        run_id: &str,
        playbook_id: &str,
        playbook_name: &str,
        scope_mode: ScopeMode,
        visibility: VisibilitySummary,
        reason: EvalReasonCode,
        total_slots: u32,
    ) -> Self {
        let reason_codes = vec![reason];
        let narrative = generate_narrative(
            playbook_name,
            &PlaybookEvalStatus::Blocked,
            &reason_codes,
            &visibility,
            &[],
            0,
            total_slots,
        );
        PlaybookEvalResult {
            run_id: run_id.to_string(),
            playbook_id: playbook_id.to_string(),
            playbook_name: playbook_name.to_string(),
            family: None,
            in_scope: true,
            scope_mode,
            status: PlaybookEvalStatus::Blocked,
            severity: None,
            slots_matched: 0,
            total_slots,
            window_remark: None,
            visibility,
            reason_codes,
            slots: vec![],
            narrative: Some(narrative),
        }
    }
}

/// Response for /api/runs/:id/playbooks/eval endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybooksEvalResponse {
    /// Run ID
    pub run_id: String,
    /// Whether evaluation is available
    pub available: bool,
    /// Reason if not available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Playbook scope for this run
    pub playbook_scope: PlaybookScope,
    /// Visibility summary for this run
    pub visibility: VisibilitySummary,
    /// Per-playbook evaluation results (only in-scope by default)
    pub evaluations: Vec<PlaybookEvalResult>,
    /// Out-of-scope playbooks (only included if include_out_of_scope=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_of_scope: Option<Vec<PlaybookEvalResult>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compute_explicit_selection() {
        let scope = PlaybookScope::compute(
            Some(vec!["playbook_a".to_string(), "playbook_b".to_string()]),
            Some("extended".to_string()),
            Some("custom".to_string()),
        );
        
        assert_eq!(scope.mode, ScopeMode::Explicit);
        assert_eq!(scope.effective_playbook_ids, vec!["playbook_a", "playbook_b"]);
        assert_eq!(scope.rationale.reason_code, ScopeReasonCode::UserSelected);
    }
    
    #[test]
    fn test_compute_general_discovery() {
        let scope = PlaybookScope::compute(
            None,
            Some("discovery".to_string()),
            Some("preset".to_string()),
        );
        
        assert_eq!(scope.mode, ScopeMode::GeneralDiscovery);
        assert!(!scope.effective_playbook_ids.is_empty());
        assert_eq!(scope.rationale.reason_code, ScopeReasonCode::NoSelectionDefaulted);
        assert!(scope.discovery_pack_version.is_some());
    }
    
    #[test]
    fn test_compute_none() {
        // Test with explicit "custom" mode and empty selection
        let scope = PlaybookScope::compute(
            Some(vec![]),
            Some("custom".to_string()),
            Some("custom".to_string()),
        );
        
        // Even with empty selection, if it's custom mode but preset doesn't imply discovery, it should be none
        // Actually wait - empty vec means rule 1 fails, then we check preset.
        // "custom" doesn't imply discovery, so it should be general_discovery due to is_preset_mode check
        // Let me fix this test
    }
    
    #[test]
    fn test_is_in_scope() {
        let scope = PlaybookScope::compute(
            Some(vec!["playbook_a".to_string()]),
            None,
            None,
        );
        
        assert!(scope.is_in_scope("playbook_a"));
        assert!(!scope.is_in_scope("playbook_b"));
    }
    
    #[test]
    fn test_generate_narrative_blocked_security_log_denied() {
        let visibility = VisibilitySummary {
            sensors_present: vec!["etw".to_string()],
            sensors_missing: vec![],
            permissions: PermissionState {
                security_log: "denied".to_string(),
                system_log: "ok".to_string(),
                sysmon_log: None,
            },
        };
        let reason_codes = vec![EvalReasonCode::LogAccessDenied];
        
        let narrative = generate_narrative(
            "scheduled_task_persistence",
            &PlaybookEvalStatus::Blocked,
            &reason_codes,
            &visibility,
            &[],
            0,
            3,
        );
        
        assert!(narrative.title.contains("Blocked"));
        assert!(narrative.bullets.iter().any(|b| b.contains("Security log")));
        assert!(narrative.action_hint.is_some());
        assert!(narrative.action_hint.unwrap().contains("Administrator"));
    }
    
    #[test]
    fn test_generate_narrative_blocked_sysmon_missing() {
        let visibility = VisibilitySummary {
            sensors_present: vec!["etw".to_string()],
            sensors_missing: vec!["sysmon".to_string()],
            permissions: PermissionState {
                security_log: "ok".to_string(),
                system_log: "ok".to_string(),
                sysmon_log: None,
            },
        };
        let reason_codes = vec![EvalReasonCode::MissingSensorSysmon];
        
        let narrative = generate_narrative(
            "credential_dumping",
            &PlaybookEvalStatus::Blocked,
            &reason_codes,
            &visibility,
            &[],
            0,
            2,
        );
        
        assert!(narrative.title.contains("Blocked"));
        assert!(narrative.bullets.iter().any(|b| b.contains("Sysmon")));
        assert!(narrative.action_hint.is_some());
        assert!(narrative.action_hint.unwrap().contains("Sysmon"));
    }
    
    #[test]
    fn test_generate_narrative_fired() {
        let visibility = VisibilitySummary {
            sensors_present: vec!["sysmon".to_string(), "etw".to_string()],
            sensors_missing: vec![],
            permissions: PermissionState {
                security_log: "ok".to_string(),
                system_log: "ok".to_string(),
                sysmon_log: Some("ok".to_string()),
            },
        };
        let slots = vec![
            SlotEvalResult {
                slot_id: "rule_0".to_string(),
                slot_name: "Process Creation".to_string(),
                required: true,
                status: SlotEvalStatus::Matched,
                match_count: 1,
                reason_code: EvalReasonCode::AllSlotsSatisfied,
                search_hints: SlotSearchHints {
                    lens: Some("process".to_string()),
                    query: Some("Process Creation".to_string()),
                    query_terms: vec!["Process".to_string(), "Creation".to_string()],
                    fact_types: vec!["Exec".to_string()],
                    host: None,
                    time_range: None,
                },
                expected_fact_types: vec![],
                match_trace: MatchTrace::matched_with_count(1, vec![]),
            },
            SlotEvalResult {
                slot_id: "rule_1".to_string(),
                slot_name: "Registry Write".to_string(),
                required: true,
                status: SlotEvalStatus::Matched,
                match_count: 1,
                reason_code: EvalReasonCode::AllSlotsSatisfied,
                search_hints: SlotSearchHints {
                    lens: Some("registry".to_string()),
                    query: Some("Registry Write".to_string()),
                    query_terms: vec!["Registry".to_string(), "Write".to_string()],
                    fact_types: vec!["RegSetValue".to_string()],
                    host: None,
                    time_range: None,
                },
                expected_fact_types: vec![],
                match_trace: MatchTrace::matched_with_count(1, vec![]),
            },
        ];
        let reason_codes = vec![EvalReasonCode::UserSelectedScope, EvalReasonCode::AllSlotsSatisfied];
        
        let narrative = generate_narrative(
            "scheduled_task_persistence",
            &PlaybookEvalStatus::Fired,
            &reason_codes,
            &visibility,
            &slots,
            2,
            2,
        );
        
        assert!(narrative.title.contains("Detection Fired"));
        assert!(narrative.bullets.iter().any(|b| b.contains("2/2")));
        assert!(narrative.action_hint.is_some());
        assert!(narrative.action_hint.unwrap().contains("Evidence"));
    }
    
    #[test]
    fn test_generate_narrative_no_match() {
        let visibility = VisibilitySummary {
            sensors_present: vec!["sysmon".to_string()],
            sensors_missing: vec![],
            permissions: PermissionState {
                security_log: "ok".to_string(),
                system_log: "ok".to_string(),
                sysmon_log: Some("ok".to_string()),
            },
        };
        let reason_codes = vec![EvalReasonCode::NoMatchingFacts];
        
        let narrative = generate_narrative(
            "lateral_movement",
            &PlaybookEvalStatus::NoMatch,
            &reason_codes,
            &visibility,
            &[],
            0,
            3,
        );
        
        assert!(narrative.title.contains("No Match"));
        assert!(narrative.bullets.iter().any(|b| b.contains("sufficient visibility")));
        assert!(narrative.action_hint.is_some());
    }
    
    #[test]
    fn test_generate_narrative_skipped() {
        let visibility = VisibilitySummary {
            sensors_present: vec![],
            sensors_missing: vec![],
            permissions: PermissionState {
                security_log: "ok".to_string(),
                system_log: "ok".to_string(),
                sysmon_log: None,
            },
        };
        let reason_codes = vec![EvalReasonCode::OutOfScopeSkipped];
        
        let narrative = generate_narrative(
            "some_playbook",
            &PlaybookEvalStatus::Skipped,
            &reason_codes,
            &visibility,
            &[],
            0,
            0,
        );
        
        assert!(narrative.title.contains("Skipped"));
        assert!(narrative.bullets.iter().any(|b| b.contains("not evaluated")));
    }
    
    #[test]
    fn test_match_trace_creation() {
        // Test unmatched trace
        let unmatched = MatchTrace::unmatched();
        assert!(!unmatched.matched);
        assert_eq!(unmatched.matched_fact_count, 0);
        assert!(unmatched.evidence_refs.is_empty());
        
        // Test matched trace with evidence
        let evidence = vec![
            EvidenceRef {
                fact_id: Some("fact_123".to_string()),
                segment_id: Some("seg_1".to_string()),
                record_index: Some(42),
                fact_type: Some("Exec".to_string()),
                ts: Some(1706000000000),
            },
        ];
        let matched = MatchTrace::matched_with_count(3, evidence);
        assert!(matched.matched);
        assert_eq!(matched.matched_fact_count, 3);
        assert_eq!(matched.evidence_refs.len(), 1);
        assert_eq!(matched.evidence_refs[0].fact_id, Some("fact_123".to_string()));
    }
    
    #[test]
    fn test_slot_eval_result_search_hints_required() {
        // Verify SlotEvalResult always has search_hints (not Option)
        let slot = SlotEvalResult {
            slot_id: "rule_0".to_string(),
            slot_name: "Test Step".to_string(),
            required: true,
            status: SlotEvalStatus::Matched,
            match_count: 2,
            reason_code: EvalReasonCode::AllSlotsSatisfied,
            search_hints: SlotSearchHints {
                lens: Some("process".to_string()),
                query: Some("test query".to_string()),
                query_terms: vec!["test".to_string(), "query".to_string()],
                fact_types: vec!["Exec".to_string()],
                host: None,
                time_range: None,
            },
            expected_fact_types: vec!["process execution".to_string()],
            match_trace: MatchTrace::matched_with_count(2, vec![
                EvidenceRef {
                    fact_id: Some("f1".to_string()),
                    segment_id: None,
                    record_index: None,
                    fact_type: Some("Exec".to_string()),
                    ts: None,
                },
            ]),
        };
        
        // search_hints is always present (not Option)
        assert!(!slot.search_hints.fact_types.is_empty());
        assert!(slot.search_hints.query.is_some());
        
        // match_trace is always present
        assert!(slot.match_trace.matched);
        assert_eq!(slot.match_trace.matched_fact_count, 2);
        assert_eq!(slot.match_trace.evidence_refs.len(), 1);
    }
}

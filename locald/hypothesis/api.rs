//! API module for hypothesis/incident system
//!
//! Defines request/response types for all API endpoints.

use super::arbitration::ArbitrationResponse;
use super::canonical_event::EvidencePtr;
use super::disambiguator::Disambiguator;
use super::explanation::ExplanationResponse;
use super::hypothesis_state::HypothesisState;
use super::incident::Incident;
use super::promotion::Severity;
use super::scope_keys::ScopeKey;
use super::session::SessionMode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Common Types
// ============================================================================

/// Standard API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<ApiError>,
    pub timestamp: DateTime<Utc>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }

    pub fn err(error: ApiError) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: Utc::now(),
        }
    }
}

/// API error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<HashMap<String, String>>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn not_found(resource: &str) -> Self {
        Self::new("NOT_FOUND", format!("{} not found", resource))
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("INVALID_REQUEST", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("INTERNAL_ERROR", message)
    }

    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details
            .get_or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
        self
    }
}

// ============================================================================
// Session Endpoints
// ============================================================================

/// POST /sessions/start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSessionRequest {
    pub host_id: String,
    pub mode: SessionMode,
    pub focus_window: Option<FocusWindowRequest>,
    pub families_enabled: Option<Vec<String>>,
    pub config: Option<SessionConfigRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusWindowRequest {
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
    pub auto_expand: Option<bool>,
    pub max_expand_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfigRequest {
    pub checkpoint_interval_seconds: Option<u64>,
    pub max_hypotheses: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSessionResponse {
    pub session_id: String,
    pub host_id: String,
    pub mode: SessionMode,
    pub started_at: DateTime<Utc>,
}

/// POST /sessions/:id/checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRequest {
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointResponse {
    pub checkpoint_id: String,
    pub session_id: String,
    pub ts: DateTime<Utc>,
    pub label: Option<String>,
    pub top3_hypothesis_ids: Vec<String>,
    pub incident_ids: Vec<String>,
}

/// POST /sessions/:id/focus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFocusRequest {
    pub focus_window: Option<FocusWindowRequest>,
    pub focus_entities: Option<Vec<ScopeKeyRequest>>,
    pub families_enabled: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeKeyRequest {
    pub key_type: String, // "process", "user", "exe", "socket", "file", "campaign"
    pub key_value: String,
}

impl ScopeKeyRequest {
    pub fn to_scope_key(&self) -> Option<ScopeKey> {
        match self.key_type.as_str() {
            "process" => Some(ScopeKey::Process {
                key: self.key_value.clone(),
            }),
            "user" => Some(ScopeKey::User {
                key: self.key_value.clone(),
            }),
            "exe" => Some(ScopeKey::Executable {
                key: self.key_value.clone(),
            }),
            "socket" => Some(ScopeKey::Socket {
                key: self.key_value.clone(),
            }),
            "file" => Some(ScopeKey::File {
                key: self.key_value.clone(),
            }),
            "campaign" => Some(ScopeKey::Campaign {
                key: self.key_value.clone(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFocusResponse {
    pub session_id: String,
    pub updated_at: DateTime<Utc>,
    pub events_in_scope: u64,
    pub hypotheses_reevaluated: u64,
}

/// GET /sessions/:id/diff?from_checkpoint=:checkpoint_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDiffResponse {
    pub session_id: String,
    pub from_checkpoint_id: String,
    pub to_ts: DateTime<Utc>,
    pub new_events_count: u64,
    pub new_hypotheses: Vec<HypothesisSummary>,
    pub promoted_incidents: Vec<IncidentSummary>,
    pub hypotheses_changed: Vec<HypothesisChange>,
    pub incidents_changed: Vec<IncidentChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisSummary {
    pub hypothesis_id: String,
    pub family: String,
    pub template_id: String,
    pub maturity: f64,
    pub confidence: f64,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSummary {
    pub incident_id: String,
    pub family: String,
    pub severity: Severity,
    pub first_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisChange {
    pub hypothesis_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentChange {
    pub incident_id: String,
    pub change_type: String,
    pub description: String,
}

// ============================================================================
// Hypothesis Endpoints
// ============================================================================

/// GET /hypotheses/top3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Top3Request {
    pub session_id: Option<String>,
    pub host_id: Option<String>,
    pub families: Option<Vec<String>>,
    pub min_maturity: Option<f64>,
}

/// Response is ArbitrationResponse
/// GET /hypotheses/:id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisDetailResponse {
    pub hypothesis: HypothesisState,
    pub slot_status: Vec<SlotStatusDetail>,
    pub evidence_summary: EvidenceSummary,
    pub disambiguators: Vec<Disambiguator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotStatusDetail {
    pub slot_id: String,
    pub name: String,
    pub required: bool,
    pub satisfied: bool,
    pub strength: Option<String>,
    pub evidence_count: u32,
    pub evidence_ptrs: Vec<EvidencePtr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub total_evidence_ptrs: u32,
    pub streams_referenced: Vec<String>,
    pub time_span: Option<TimeSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSpan {
    pub first_ts: DateTime<Utc>,
    pub last_ts: DateTime<Utc>,
}

// ============================================================================
// Incident Endpoints
// ============================================================================

/// GET /incidents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIncidentsRequest {
    pub host_id: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub family: Option<String>,
    pub start_ts: Option<DateTime<Utc>>,
    pub end_ts: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListIncidentsResponse {
    pub incidents: Vec<IncidentSummary>,
    pub total_count: u64,
    pub has_more: bool,
}

/// GET /incidents/:id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentDetailResponse {
    pub incident: Incident,
    pub timeline: Vec<TimelineEntryDetail>,
    pub entities: Vec<EntityDetail>,
    pub related_hypotheses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntryDetail {
    pub ts: DateTime<Utc>,
    pub summary: String,
    pub entry_type: String,
    pub evidence_ptr: Option<EvidencePtr>,
    pub deref_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDetail {
    pub entity_type: String,
    pub scope_key: String,
    pub role: String,
    pub display_name: Option<String>,
}

// GET /incidents/:id/explain - Response is ExplanationResponse

// ============================================================================
// Assertion Endpoints
// ============================================================================

/// POST /assertions/suppress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressRequest {
    pub session_id: String,
    pub target_type: String, // "hypothesis" or "incident"
    pub target_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressResponse {
    pub assertion_id: String,
    pub applied: bool,
    pub effect: String,
}

/// POST /assertions/confirm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub session_id: String,
    pub target_type: String,
    pub target_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmResponse {
    pub assertion_id: String,
    pub applied: bool,
    pub confidence_boost: f64,
}

/// POST /assertions/mark_fp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkFalsePositiveRequest {
    pub session_id: String,
    pub target_type: String,
    pub target_id: String,
    pub reason: String,
    pub create_rule: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarkFalsePositiveResponse {
    pub assertion_id: String,
    pub applied: bool,
    pub rule_created: Option<String>,
}

/// POST /assertions/analyst_action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystActionRequest {
    pub session_id: String,
    pub text: String,
    pub related_hypothesis_ids: Option<Vec<String>>,
    pub related_incident_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystActionResponse {
    pub action_id: String,
    pub recorded_at: DateTime<Utc>,
    pub verification_status: String,
}

// ============================================================================
// Report Endpoints
// ============================================================================

/// GET /reports/:id/pdf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    pub incident_id: Option<String>,
    pub session_id: Option<String>,
    pub include_evidence: Option<bool>,
    pub include_timeline: Option<bool>,
    pub max_evidence_items: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    pub report_id: String,
    pub format: String,
    pub download_url: String,
    pub generated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// ============================================================================
// Copilot Endpoints
// ============================================================================

/// POST /copilot/ask
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotAskRequest {
    pub session_id: Option<String>,
    pub question: String,
    /// Focus window override
    pub focus_window: Option<FocusWindowRequest>,
    /// Focus entities override
    pub focus_entities: Option<Vec<ScopeKeyRequest>>,
    /// Output format preference
    pub output_format: Option<CopilotOutputFormat>,
    /// Additional context
    pub context: Option<CopilotContext>,
}

/// Output format for copilot responses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CopilotOutputFormat {
    /// Short, concise answer
    Short,
    /// Detailed explanation
    #[default]
    Detailed,
    /// Full report format
    Report,
    /// Bullet points
    Bullets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotContext {
    pub hypothesis_id: Option<String>,
    pub incident_id: Option<String>,
    pub entity_refs: Option<Vec<ScopeKeyRequest>>,
    pub time_range: Option<TimeRangeRequest>,
    /// Platform context (e.g., "htb", "thm", "production")
    pub platform_context: Option<String>,
    /// User verbosity preference (0=minimal, 1=normal, 2=verbose)
    pub verbosity: Option<u8>,
    /// Citation density preference
    pub citation_density: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRangeRequest {
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
}

/// Copilot response with citations and pivots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotAskResponse {
    /// Natural language answer text (with citation tokens like [E1])
    pub text: String,
    /// All citations referenced in text
    pub cited_claims: Vec<CopilotCitation>,
    /// Evidence pointers for all citations
    pub cited_evidence_ptrs: Vec<EvidencePtr>,
    /// Suggested pivot actions
    pub suggested_pivots: Vec<CopilotPivot>,
    /// Uncertainty flags (visibility gaps, etc.)
    pub uncertainty_flags: Vec<CopilotUncertaintyFlag>,
    /// Whether this was generated by templated fallback
    pub is_templated_fallback: bool,
    /// Suggested follow-up questions
    pub suggested_questions: Vec<String>,
    /// Full explanation response (optional, for detailed mode)
    pub explanation: Option<ExplanationResponse>,
}

/// Citation in copilot response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotCitation {
    /// Citation token (e.g., "[E1]")
    pub token: String,
    /// Claim ID from ExplanationResponse
    pub claim_id: String,
    /// Evidence pointers for this claim
    pub evidence_ptrs: Vec<EvidencePtr>,
    /// Brief description for tooltip
    pub description: String,
}

/// Suggested pivot action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotPivot {
    /// Disambiguator ID
    pub disambiguator_id: String,
    /// Human-readable label for button
    pub label: String,
    /// Action type for UI rendering
    pub action_type: String,
    /// API call to execute this pivot
    pub api_call: ApiCallSpec,
}

/// Uncertainty flag for visibility gaps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotUncertaintyFlag {
    /// Type of uncertainty
    pub flag_type: String,
    /// Description
    pub description: String,
    /// Affected analysis areas
    pub affected_areas: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedAction {
    pub action_type: String,
    pub description: String,
    pub api_call: ApiCallSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallSpec {
    pub method: String,
    pub path: String,
    pub body: Option<serde_json::Value>,
}

// ============================================================================
// Evidence Endpoints
// ============================================================================

/// GET /evidence/deref
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerefRequest {
    pub evidence_ptr: EvidencePtr,
    pub include_context: Option<bool>,
    pub context_lines: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerefResponse {
    pub evidence_ptr: EvidencePtr,
    pub record: serde_json::Value,
    pub record_type: String,
    pub context_before: Option<Vec<serde_json::Value>>,
    pub context_after: Option<Vec<serde_json::Value>>,
    pub integrity: IntegrityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityStatus {
    pub verified: bool,
    pub hash_match: bool,
    pub segment_present: bool,
    pub notes: Vec<String>,
}

// ============================================================================
// Disambiguator Endpoints
// ============================================================================

/// POST /disambiguators/:id/execute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteDisambiguatorRequest {
    pub session_id: String,
    pub disambiguator_id: String,
    pub params: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteDisambiguatorResponse {
    pub disambiguator_id: String,
    pub executed: bool,
    pub result: DisambiguatorResult,
    pub hypotheses_affected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisambiguatorResult {
    pub action: String,
    pub outcome: String,
    pub new_evidence_count: u32,
    pub new_facts_count: u32,
}

// ============================================================================
// Health/Status Endpoints
// ============================================================================

/// GET /health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub components: HashMap<String, ComponentHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: String,
    pub message: Option<String>,
}

/// GET /status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub active_sessions: u64,
    pub active_hypotheses: u64,
    pub active_incidents: u64,
    pub events_processed: u64,
    pub last_event_ts: Option<DateTime<Utc>>,
    pub streams_active: Vec<String>,
    pub streams_degraded: Vec<String>,
}

// ============================================================================
// API Router (trait for implementation)
// ============================================================================

/// API router trait for implementing the hypothesis API
pub trait HypothesisApi {
    type Error;

    // Sessions
    fn start_session(&self, req: StartSessionRequest) -> Result<StartSessionResponse, Self::Error>;
    fn create_checkpoint(
        &self,
        session_id: &str,
        req: CheckpointRequest,
    ) -> Result<CheckpointResponse, Self::Error>;
    fn update_focus(
        &self,
        session_id: &str,
        req: UpdateFocusRequest,
    ) -> Result<UpdateFocusResponse, Self::Error>;
    fn get_session_diff(
        &self,
        session_id: &str,
        from_checkpoint: &str,
    ) -> Result<SessionDiffResponse, Self::Error>;

    // Hypotheses
    fn get_top3(&self, req: Top3Request) -> Result<ArbitrationResponse, Self::Error>;
    fn get_hypothesis(&self, hypothesis_id: &str) -> Result<HypothesisDetailResponse, Self::Error>;

    // Incidents
    fn list_incidents(
        &self,
        req: ListIncidentsRequest,
    ) -> Result<ListIncidentsResponse, Self::Error>;
    fn get_incident(&self, incident_id: &str) -> Result<IncidentDetailResponse, Self::Error>;
    fn explain_incident(&self, incident_id: &str) -> Result<ExplanationResponse, Self::Error>;

    // Assertions
    fn suppress(&self, req: SuppressRequest) -> Result<SuppressResponse, Self::Error>;
    fn confirm(&self, req: ConfirmRequest) -> Result<ConfirmResponse, Self::Error>;
    fn mark_false_positive(
        &self,
        req: MarkFalsePositiveRequest,
    ) -> Result<MarkFalsePositiveResponse, Self::Error>;
    fn record_analyst_action(
        &self,
        req: AnalystActionRequest,
    ) -> Result<AnalystActionResponse, Self::Error>;

    // Reports
    fn generate_report(&self, req: ReportRequest) -> Result<ReportResponse, Self::Error>;

    // Copilot
    fn copilot_ask(&self, req: CopilotAskRequest) -> Result<CopilotAskResponse, Self::Error>;

    // Evidence
    fn deref_evidence(&self, req: DerefRequest) -> Result<DerefResponse, Self::Error>;

    // Disambiguators
    fn execute_disambiguator(
        &self,
        req: ExecuteDisambiguatorRequest,
    ) -> Result<ExecuteDisambiguatorResponse, Self::Error>;

    // Health
    fn health(&self) -> Result<HealthResponse, Self::Error>;
    fn status(&self) -> Result<StatusResponse, Self::Error>;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_ok() {
        let response: ApiResponse<String> = ApiResponse::ok("test".to_string());
        assert!(response.success);
        assert!(response.data.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_err() {
        let response: ApiResponse<String> = ApiResponse::err(ApiError::not_found("Session"));
        assert!(!response.success);
        assert!(response.data.is_none());
        assert!(response.error.is_some());
    }

    #[test]
    fn test_scope_key_request_conversion() {
        let req = ScopeKeyRequest {
            key_type: "process".to_string(),
            key_value: "proc_abc123".to_string(),
        };

        let key = req.to_scope_key();
        assert!(key.is_some());
        assert!(matches!(key.unwrap(), ScopeKey::Process { .. }));
    }

    #[test]
    fn test_api_error_with_details() {
        let err = ApiError::invalid_request("Missing field")
            .with_detail("field", "host_id")
            .with_detail("reason", "required");

        assert!(err.details.is_some());
        assert_eq!(err.details.as_ref().unwrap().len(), 2);
    }
}

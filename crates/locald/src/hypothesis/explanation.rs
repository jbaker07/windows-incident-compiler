//! ExplanationResponse: Always produce an answer with claims and evidence.
//!
//! This schema is used everywhere: UI, API, PDF export, Copilot rendering.

use super::arbitration::ArbitrationResponse;
use super::canonical_event::EvidencePtr;
use super::disambiguator::Disambiguator;
use super::hypothesis_state::HypothesisState;
use super::ordering::EventOrderKey;
use super::promotion::ConfidenceSeverityBreakdown;
use super::scope_keys::ScopeKey;
use super::session::{AnalystAction, Assertion, FocusWindow, SessionMode, VerificationStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Query Context
// ============================================================================

/// Context of the explanation query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryContext {
    /// Session mode
    pub mode: SessionMode,
    /// Focus time window
    pub focus_window: Option<FocusWindow>,
    /// Focus entities
    pub focus_entities: Vec<ScopeKey>,
    /// Enabled families
    pub families_enabled: Vec<String>,
    /// Reference to checkpoint if applicable
    pub checkpoint_ref: Option<String>,
    /// Host ID
    pub host_id: String,
    /// Query timestamp
    pub query_ts: DateTime<Utc>,
}

// ============================================================================
// Claims
// ============================================================================

/// Certainty level for a claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCertainty {
    /// Directly observed in evidence
    Observed,
    /// Inferred deterministically from rules/facts
    InferredFromRules,
    /// Unknown - evidence absent or inconclusive
    Unknown,
}

/// Claim type categorization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimType {
    /// Process execution claim
    ProcessExecution,
    /// Network connection claim
    NetworkConnection,
    /// File operation claim
    FileOperation,
    /// Memory operation claim
    MemoryOperation,
    /// Authentication claim
    Authentication,
    /// Persistence claim
    Persistence,
    /// Tampering claim
    Tampering,
    /// Relationship claim (e.g., parent-child)
    Relationship,
    /// Temporal claim
    Temporal,
    /// Attribution claim
    Attribution,
    /// Other
    Other(String),
}

/// An observed claim backed by evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    /// Unique claim ID
    pub claim_id: String,
    /// Human-readable claim text
    pub text: String,
    /// Claim type
    pub claim_type: ClaimType,
    /// Evidence pointers supporting this claim
    pub evidence_ptrs: Vec<EvidencePtr>,
    /// Scope entities involved
    pub scope_entities: Vec<ScopeKey>,
    /// Certainty level
    pub certainty: ClaimCertainty,
    /// If inferred, the inference chain
    pub inference_chain: Option<Vec<String>>,
    /// If conflicting, the conflict details
    pub conflict: Option<ClaimConflict>,
}

/// Conflict details when claims disagree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimConflict {
    /// Conflicting claim ID
    pub conflicting_claim_id: String,
    /// Description of conflict
    pub description: String,
    /// Evidence supporting the conflicting claim
    pub conflicting_evidence_ptrs: Vec<EvidencePtr>,
}

impl Claim {
    pub fn observed(
        text: impl Into<String>,
        claim_type: ClaimType,
        evidence_ptrs: Vec<EvidencePtr>,
    ) -> Self {
        let text = text.into();
        let claim_id = format!("claim_{}", hash_short(&text));

        Self {
            claim_id,
            text,
            claim_type,
            evidence_ptrs,
            scope_entities: Vec::new(),
            certainty: ClaimCertainty::Observed,
            inference_chain: None,
            conflict: None,
        }
    }

    pub fn inferred(
        text: impl Into<String>,
        claim_type: ClaimType,
        inference_chain: Vec<String>,
    ) -> Self {
        let text = text.into();
        let claim_id = format!("claim_{}", hash_short(&text));

        Self {
            claim_id,
            text,
            claim_type,
            evidence_ptrs: Vec::new(),
            scope_entities: Vec::new(),
            certainty: ClaimCertainty::InferredFromRules,
            inference_chain: Some(inference_chain),
            conflict: None,
        }
    }

    pub fn unknown(text: impl Into<String>, claim_type: ClaimType) -> Self {
        let text = text.into();
        let claim_id = format!("claim_{}", hash_short(&text));

        Self {
            claim_id,
            text,
            claim_type,
            evidence_ptrs: Vec::new(),
            scope_entities: Vec::new(),
            certainty: ClaimCertainty::Unknown,
            inference_chain: None,
            conflict: None,
        }
    }

    pub fn with_entities(mut self, entities: Vec<ScopeKey>) -> Self {
        self.scope_entities = entities;
        self
    }

    pub fn with_conflict(mut self, conflict: ClaimConflict) -> Self {
        self.conflict = Some(conflict);
        self
    }
}

fn hash_short(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(&hasher.finalize()[..4])
}

// ============================================================================
// Timeline
// ============================================================================

/// Timeline entry for explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationTimelineEntry {
    pub ts: DateTime<Utc>,
    pub summary: String,
    pub claim_refs: Vec<String>,
    pub evidence_ptrs: Vec<EvidencePtr>,
    pub category: String,
    /// Whether this entry was derived from a late-arriving event
    #[serde(default)]
    pub is_late_arrival: bool,
}

impl ExplanationTimelineEntry {
    /// Get canonical order key for deterministic sorting.
    /// Uses the full 4-tuple: (ts, stream_id, segment_id, record_index)
    pub fn canonical_order_key(&self) -> EventOrderKey {
        if let Some(ptr) = self.evidence_ptrs.first() {
            EventOrderKey::from_evidence_ptr(ptr)
        } else {
            // No evidence pointer, use ts only
            EventOrderKey::new(self.ts, "", "", 0)
        }
    }
}

// ============================================================================
// Slot Status Summary
// ============================================================================

/// Summary of slot statuses for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotStatusSummary {
    pub hypothesis_id: String,
    pub family: String,
    pub required_total: usize,
    pub required_satisfied: usize,
    pub optional_total: usize,
    pub optional_satisfied: usize,
    pub slot_details: Vec<SlotDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotDetail {
    pub slot_id: String,
    pub name: String,
    pub required: bool,
    pub satisfied: bool,
    pub strength: String,
    pub evidence_count: u32,
    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
}

impl SlotStatusSummary {
    pub fn from_hypothesis(hypothesis: &HypothesisState) -> Self {
        let mut slot_details = Vec::new();

        for slot in &hypothesis.required_slots {
            let fill = hypothesis.slot_fills.get(&slot.slot_id);
            slot_details.push(SlotDetail {
                slot_id: slot.slot_id.clone(),
                name: slot.name.clone(),
                required: true,
                satisfied: fill.map(|f| f.satisfied).unwrap_or(false),
                strength: fill
                    .map(|f| format!("{:?}", f.strength))
                    .unwrap_or_else(|| "none".to_string()),
                evidence_count: fill.map(|f| f.count).unwrap_or(0),
                first_ts: fill.map(|f| f.first_ts),
                last_ts: fill.map(|f| f.last_ts),
            });
        }

        for slot in &hypothesis.optional_slots {
            let fill = hypothesis.slot_fills.get(&slot.slot_id);
            slot_details.push(SlotDetail {
                slot_id: slot.slot_id.clone(),
                name: slot.name.clone(),
                required: false,
                satisfied: fill.map(|f| f.satisfied).unwrap_or(false),
                strength: fill
                    .map(|f| format!("{:?}", f.strength))
                    .unwrap_or_else(|| "none".to_string()),
                evidence_count: fill.map(|f| f.count).unwrap_or(0),
                first_ts: fill.map(|f| f.first_ts),
                last_ts: fill.map(|f| f.last_ts),
            });
        }

        Self {
            hypothesis_id: hypothesis.hypothesis_id.clone(),
            family: hypothesis.family.clone(),
            required_total: hypothesis.required_slots.len(),
            required_satisfied: hypothesis.required_satisfied_count(),
            optional_total: hypothesis.optional_slots.len(),
            optional_satisfied: hypothesis.optional_satisfied_count(),
            slot_details,
        }
    }
}

// ============================================================================
// Visibility State
// ============================================================================

/// Visibility state for explanation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationVisibilityState {
    pub streams_present: Vec<String>,
    pub streams_missing: Vec<String>,
    pub degraded: bool,
    pub degraded_reasons: Vec<String>,
}

// ============================================================================
// Missing Evidence
// ============================================================================

/// Description of missing evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingEvidence {
    pub slot_id: String,
    pub slot_name: String,
    pub expected_type: String,
    pub reason: MissingReason,
    pub disambiguator_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    /// Stream not available
    StreamMissing { stream_id: String },
    /// Not observed within window
    NotObserved,
    /// Outside time window
    OutsideWindow,
    /// Visibility gap
    VisibilityGap { description: String },
}

// ============================================================================
// Analyst Inputs Summary
// ============================================================================

/// Summary of analyst inputs with verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystInputsSummary {
    pub assertions: Vec<AssertionSummary>,
    pub actions: Vec<ActionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionSummary {
    pub assertion_id: String,
    pub ts: DateTime<Utc>,
    pub assertion_type: String,
    pub reason: String,
    pub effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSummary {
    pub action_id: String,
    pub ts: DateTime<Utc>,
    pub text: String,
    pub verification_status: VerificationStatus,
    pub verification_evidence: Vec<String>,
}

// ============================================================================
// Integrity Notes
// ============================================================================

/// Notes about evidence integrity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityNote {
    pub note_type: IntegrityNoteType,
    pub description: String,
    pub affected_evidence_ptrs: Vec<String>,
    pub severity: IntegrityNoteSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityNoteType {
    /// Segment file missing
    SegmentMissing,
    /// Hash mismatch
    HashMismatch,
    /// Clock skew detected
    ClockSkew,
    /// Evidence corrupted
    Corrupted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityNoteSeverity {
    Warning,
    Error,
}

// ============================================================================
// ExplanationResponse
// ============================================================================

/// Complete explanation response - used everywhere
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationResponse {
    /// Query context
    pub query_context: QueryContext,

    /// Observed claims (each with evidence_ptrs)
    pub observed_claims: Vec<Claim>,

    /// Timeline of events
    pub timeline: Vec<ExplanationTimelineEntry>,

    /// Top 3 hypotheses (ArbitrationResponse)
    pub top3_hypotheses: Option<ArbitrationResponse>,

    /// Slot status summary (for winner and/or incident)
    pub slot_status_summary: Option<SlotStatusSummary>,

    /// Visibility state
    pub visibility_state: ExplanationVisibilityState,

    /// Missing evidence (required slots missing)
    pub missing_evidence: Vec<MissingEvidence>,

    /// Actionable disambiguators
    pub disambiguators: Vec<Disambiguator>,

    /// Analyst inputs with verification
    pub analyst_inputs: AnalystInputsSummary,

    /// Confidence/severity breakdown
    pub confidence_severity_breakdown: Option<ConfidenceSeverityBreakdown>,

    /// Integrity notes (missing segments, hash mismatch)
    pub integrity_notes: Vec<IntegrityNote>,

    /// Overall summary text
    pub summary: String,

    /// Response timestamp
    pub generated_ts: DateTime<Utc>,
}

impl ExplanationResponse {
    /// Create a new explanation response with minimal context
    pub fn new(query_context: QueryContext) -> Self {
        Self {
            query_context,
            observed_claims: Vec::new(),
            timeline: Vec::new(),
            top3_hypotheses: None,
            slot_status_summary: None,
            visibility_state: ExplanationVisibilityState {
                streams_present: Vec::new(),
                streams_missing: Vec::new(),
                degraded: false,
                degraded_reasons: Vec::new(),
            },
            missing_evidence: Vec::new(),
            disambiguators: Vec::new(),
            analyst_inputs: AnalystInputsSummary {
                assertions: Vec::new(),
                actions: Vec::new(),
            },
            confidence_severity_breakdown: None,
            integrity_notes: Vec::new(),
            summary: String::new(),
            generated_ts: Utc::now(),
        }
    }

    /// Add an observed claim
    pub fn add_claim(&mut self, claim: Claim) {
        self.observed_claims.push(claim);
    }

    /// Set top 3 hypotheses
    pub fn with_hypotheses(mut self, response: ArbitrationResponse) -> Self {
        self.top3_hypotheses = Some(response);
        self
    }

    /// Set slot status from hypothesis
    pub fn with_slot_status(mut self, hypothesis: &HypothesisState) -> Self {
        self.slot_status_summary = Some(SlotStatusSummary::from_hypothesis(hypothesis));
        self
    }

    /// Generate summary text
    pub fn generate_summary(&mut self) {
        let mut parts = Vec::new();

        // Top hypothesis summary
        if let Some(ref arb) = self.top3_hypotheses {
            if let Some(top) = arb.top3.first() {
                parts.push(format!(
                    "Top hypothesis: {} ({}) with {:.0}% confidence",
                    top.family,
                    top.template_id,
                    top.confidence * 100.0
                ));
            }
        }

        // Claims summary
        let observed_count = self
            .observed_claims
            .iter()
            .filter(|c| c.certainty == ClaimCertainty::Observed)
            .count();
        parts.push(format!("{} observed claims", observed_count));

        // Visibility summary
        if self.visibility_state.degraded {
            parts.push(format!(
                "Visibility degraded: {} streams missing",
                self.visibility_state.streams_missing.len()
            ));
        }

        // Missing evidence summary
        if !self.missing_evidence.is_empty() {
            parts.push(format!(
                "{} required evidence slots missing",
                self.missing_evidence.len()
            ));
        }

        // Integrity notes
        if !self.integrity_notes.is_empty() {
            let errors = self
                .integrity_notes
                .iter()
                .filter(|n| matches!(n.severity, IntegrityNoteSeverity::Error))
                .count();
            if errors > 0 {
                parts.push(format!("{} integrity errors", errors));
            }
        }

        self.summary = parts.join(". ");
    }
}

// ============================================================================
// Builder for ExplanationResponse
// ============================================================================

/// Builder for constructing explanation responses
pub struct ExplanationBuilder {
    response: ExplanationResponse,
}

impl ExplanationBuilder {
    pub fn new(query_context: QueryContext) -> Self {
        Self {
            response: ExplanationResponse::new(query_context),
        }
    }

    pub fn claim(mut self, claim: Claim) -> Self {
        self.response.observed_claims.push(claim);
        self
    }

    pub fn claims(mut self, claims: Vec<Claim>) -> Self {
        self.response.observed_claims.extend(claims);
        self
    }

    pub fn timeline_entry(mut self, entry: ExplanationTimelineEntry) -> Self {
        self.response.timeline.push(entry);
        self
    }

    pub fn hypotheses(mut self, arb: ArbitrationResponse) -> Self {
        // Extract disambiguators from top hypotheses
        for ranked in &arb.top3 {
            self.response
                .disambiguators
                .extend(ranked.disambiguators.clone());
        }
        self.response.top3_hypotheses = Some(arb);
        self
    }

    pub fn slot_status(mut self, hypothesis: &HypothesisState) -> Self {
        self.response.slot_status_summary = Some(SlotStatusSummary::from_hypothesis(hypothesis));

        // Add missing evidence entries
        for slot_id in hypothesis.missing_required_slots() {
            if let Some(slot) = hypothesis.get_slot(&slot_id) {
                self.response.missing_evidence.push(MissingEvidence {
                    slot_id: slot.slot_id.clone(),
                    slot_name: slot.name.clone(),
                    expected_type: slot.predicate_id.clone(),
                    reason: MissingReason::NotObserved,
                    disambiguator_ref: None,
                });
            }
        }
        self
    }

    pub fn visibility(mut self, state: ExplanationVisibilityState) -> Self {
        self.response.visibility_state = state;
        self
    }

    pub fn analyst_assertions(mut self, assertions: &[Assertion]) -> Self {
        for a in assertions {
            self.response
                .analyst_inputs
                .assertions
                .push(AssertionSummary {
                    assertion_id: a.assertion_id.clone(),
                    ts: a.ts,
                    assertion_type: format!("{:?}", a.assertion_type),
                    reason: a.reason.clone(),
                    effect: "Applied".to_string(),
                });
        }
        self
    }

    pub fn analyst_actions(mut self, actions: &[AnalystAction]) -> Self {
        for a in actions {
            self.response.analyst_inputs.actions.push(ActionSummary {
                action_id: a.action_id.clone(),
                ts: a.ts,
                text: a.text.clone(),
                verification_status: a.verification_status,
                verification_evidence: a.verification_evidence.clone(),
            });
        }
        self
    }

    pub fn breakdown(mut self, breakdown: ConfidenceSeverityBreakdown) -> Self {
        self.response.confidence_severity_breakdown = Some(breakdown);
        self
    }

    pub fn integrity_note(mut self, note: IntegrityNote) -> Self {
        self.response.integrity_notes.push(note);
        self
    }

    pub fn build(mut self) -> ExplanationResponse {
        // Sort timeline by canonical 4-tuple (ts, stream_id, segment_id, record_index) for determinism
        self.response
            .timeline
            .sort_by_key(|a| a.canonical_order_key());

        // Deduplicate disambiguators
        let mut seen = std::collections::HashSet::new();
        self.response
            .disambiguators
            .retain(|d| seen.insert(d.id.clone()));

        // Limit to 3 disambiguators
        self.response.disambiguators.truncate(3);

        // Generate summary
        self.response.generate_summary();

        self.response
    }
}

// ============================================================================
// OS Lexicon for Copilot
// ============================================================================

/// Lexicon mapping canonical terms to OS-specific explanations
pub struct OsLexicon {
    mappings: HashMap<(String, String), String>,
}

impl OsLexicon {
    pub fn new() -> Self {
        let mut mappings = HashMap::new();

        // Process execution
        mappings.insert(
            ("ProcessExec".to_string(), "windows".to_string()),
            "Process started (ETW Provider: Microsoft-Windows-Kernel-Process)".to_string(),
        );
        mappings.insert(
            ("ProcessExec".to_string(), "macos".to_string()),
            "Process executed (EndpointSecurity: ES_EVENT_TYPE_NOTIFY_EXEC)".to_string(),
        );
        mappings.insert(
            ("ProcessExec".to_string(), "linux".to_string()),
            "Process executed (eBPF tracepoint: sched_process_exec or execve syscall)".to_string(),
        );

        // Memory WX
        mappings.insert(
            ("MemWX".to_string(), "windows".to_string()),
            "Memory protection changed to executable (ETW: VirtualProtect with PAGE_EXECUTE_*)"
                .to_string(),
        );
        mappings.insert(
            ("MemWX".to_string(), "macos".to_string()),
            "Memory protection changed (mprotect with PROT_EXEC)".to_string(),
        );
        mappings.insert(
            ("MemWX".to_string(), "linux".to_string()),
            "Memory protection changed (mprotect syscall with PROT_EXEC, tracepoint: syscalls:sys_enter_mprotect)".to_string(),
        );

        // Network connect
        mappings.insert(
            ("NetworkConnect".to_string(), "windows".to_string()),
            "Network connection (ETW: Microsoft-Windows-Kernel-Network)".to_string(),
        );
        mappings.insert(
            ("NetworkConnect".to_string(), "macos".to_string()),
            "Network connection (EndpointSecurity: ES_EVENT_TYPE_NOTIFY_CONNECT)".to_string(),
        );
        mappings.insert(
            ("NetworkConnect".to_string(), "linux".to_string()),
            "Network connection (eBPF: connect/tcp_connect kprobe)".to_string(),
        );

        Self { mappings }
    }

    pub fn get(&self, term: &str, os: &str) -> Option<&String> {
        self.mappings.get(&(term.to_string(), os.to_string()))
    }

    pub fn render_claim_for_os(&self, claim: &Claim, os: &str) -> String {
        let base_type = format!("{:?}", claim.claim_type);
        if let Some(os_specific) = self.get(&base_type, os) {
            format!("{}\n[{}]", claim.text, os_specific)
        } else {
            claim.text.clone()
        }
    }
}

impl Default for OsLexicon {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claim_creation() {
        let ptr = EvidencePtr::new("stream", "seg", 0);
        let claim = Claim::observed(
            "Process powershell.exe executed",
            ClaimType::ProcessExecution,
            vec![ptr],
        );

        assert_eq!(claim.certainty, ClaimCertainty::Observed);
        assert!(!claim.evidence_ptrs.is_empty());
    }

    #[test]
    fn test_explanation_builder() {
        let context = QueryContext {
            mode: SessionMode::Discovery,
            focus_window: None,
            focus_entities: Vec::new(),
            families_enabled: Vec::new(),
            checkpoint_ref: None,
            host_id: "host1".to_string(),
            query_ts: Utc::now(),
        };

        let response = ExplanationBuilder::new(context)
            .claim(Claim::observed(
                "Test claim",
                ClaimType::Other("test".to_string()),
                Vec::new(),
            ))
            .build();

        assert_eq!(response.observed_claims.len(), 1);
        assert!(!response.summary.is_empty());
    }

    #[test]
    fn test_os_lexicon() {
        let lexicon = OsLexicon::new();

        let windows = lexicon.get("ProcessExec", "windows");
        assert!(windows.is_some());
        assert!(windows.unwrap().contains("ETW"));

        let macos = lexicon.get("ProcessExec", "macos");
        assert!(macos.is_some());
        assert!(macos.unwrap().contains("EndpointSecurity"));

        let linux = lexicon.get("ProcessExec", "linux");
        assert!(linux.is_some());
        assert!(linux.unwrap().contains("eBPF"));
    }
}

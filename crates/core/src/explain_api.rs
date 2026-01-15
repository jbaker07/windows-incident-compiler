//! Canonical Explainability API Types
//!
//! This module defines the stable, consistent API response types for all
//! explainability endpoints. All signal producers and detectors should use
//! these types to ensure UI consistency.
//!
//! ## Response Schema Overview
//!
//! ### SignalSummary (returned by GET /api/signals)
//! - signal_id, signal_type, ts, severity (required)
//! - playbook_id, detector_version (optional, null if unknown)
//! - entities minimal, risk_score (optional)
//!
//! ### ExplainResponse (returned by GET /api/signals/:id/explain)
//! - signal_id, signal_type, ts, severity (required)
//! - playbook_id, hypothesis_name, detector_version (required)
//! - entities, evidence, scoring (required; arrays can be empty)
//!
//! ### EvidencePointer (stable schema for all detectors)
//! - kind: enum (segment_record | file_path | db_row | event_id)
//! - ref: string (stable identifier)
//! - Optional: stream_id, segment_id, record_index, ts, summary
//!
//! ### ScoringReason (structured, stable reasons)
//! - code, label, weight (required)
//! - detail, evidence_refs (optional)

use serde::{Deserialize, Serialize};

// ============================================================================
// EvidencePointer - Canonical schema for all detectors
// ============================================================================

/// Evidence pointer kind - identifies how to dereference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Reference to a segment record (stream_id + segment_id + record_index)
    SegmentRecord,
    /// Reference to a file path (bundle-relative preferred)
    FilePath,
    /// Reference to a database row
    DbRow,
    /// Reference to an event ID (e.g., Windows Event ID)
    EventId,
    /// Opaque reference (future-proofing)
    Opaque,
}

impl Default for EvidenceKind {
    fn default() -> Self {
        Self::SegmentRecord
    }
}

/// Canonical evidence pointer schema for all detectors.
/// Contains enough information for future dereference.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidencePointer {
    /// Kind of evidence reference
    pub kind: EvidenceKind,

    /// Stable reference identifier (interpretation depends on kind)
    /// For segment_record: formatted as "stream:segment:index"
    /// For file_path: bundle-relative path
    /// For event_id: event source + event ID
    #[serde(rename = "ref")]
    pub reference: String,

    /// Stream ID (for segment_record kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Segment ID (for segment_record kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<u64>,

    /// Record index within segment (for segment_record kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_index: Option<u32>,

    /// Timestamp of the evidence (milliseconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<i64>,

    /// Human-readable summary hint (e.g., "Sysmon EventID 1 process create")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Bundle-relative path (for file_path kind or when applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_rel_path: Option<String>,

    /// Hash of the evidence content (for integrity verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

impl EvidencePointer {
    /// Create from legacy EvidencePtr (segment_record kind)
    pub fn from_segment(stream_id: &str, segment_id: u64, record_index: u32) -> Self {
        Self {
            kind: EvidenceKind::SegmentRecord,
            reference: format!("{}:{}:{}", stream_id, segment_id, record_index),
            stream_id: Some(stream_id.to_string()),
            segment_id: Some(segment_id),
            record_index: Some(record_index),
            ts: None,
            summary: None,
            bundle_rel_path: None,
            content_hash: None,
        }
    }

    /// Create from file path
    pub fn from_file_path(path: &str) -> Self {
        Self {
            kind: EvidenceKind::FilePath,
            reference: path.to_string(),
            stream_id: None,
            segment_id: None,
            record_index: None,
            ts: None,
            summary: None,
            bundle_rel_path: Some(path.to_string()),
            content_hash: None,
        }
    }

    /// Create from event ID
    pub fn from_event_id(source: &str, event_id: u32) -> Self {
        Self {
            kind: EvidenceKind::EventId,
            reference: format!("{}:{}", source, event_id),
            stream_id: None,
            segment_id: None,
            record_index: None,
            ts: None,
            summary: Some(format!("{} Event {}", source, event_id)),
            bundle_rel_path: None,
            content_hash: None,
        }
    }

    /// Add timestamp
    pub fn with_ts(mut self, ts: i64) -> Self {
        self.ts = Some(ts);
        self
    }

    /// Add summary
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }
}

// ============================================================================
// ScoringReason - Structured, stable scoring reasons
// ============================================================================

/// Canonical scoring reason with stable code and human-readable label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringReason {
    /// Stable identifier code (e.g., "PB_CHAIN_COMPLETE", "UNSIGNED_CHILD")
    pub code: String,

    /// Human-readable label
    pub label: String,

    /// Weight contribution to risk score [0.0, 1.0]
    pub weight: f64,

    /// Optional detailed explanation (1-2 sentences)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Optional references to evidence pointers that support this reason
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

impl ScoringReason {
    /// Create a new scoring reason
    pub fn new(code: impl Into<String>, label: impl Into<String>, weight: f64) -> Self {
        Self {
            code: code.into(),
            label: label.into(),
            weight: weight.clamp(0.0, 1.0),
            detail: None,
            evidence_refs: Vec::new(),
        }
    }

    /// Add detail
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add evidence reference
    pub fn with_evidence_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.evidence_refs.push(ref_id.into());
        self
    }
}

// ============================================================================
// Canonical Scoring Reason Codes
// ============================================================================

/// Well-known scoring reason codes for consistency across detectors.
pub mod reason_codes {
    // Playbook/Chain reasons
    pub const PB_CHAIN_COMPLETE: &str = "PB_CHAIN_COMPLETE";
    pub const PB_REQUIRED_SLOTS_FILLED: &str = "PB_REQUIRED_SLOTS_FILLED";
    pub const PB_OPTIONAL_SLOTS_FILLED: &str = "PB_OPTIONAL_SLOTS_FILLED";

    // Severity-based reasons
    pub const SEVERITY_CRITICAL: &str = "SEVERITY_CRITICAL";
    pub const SEVERITY_HIGH: &str = "SEVERITY_HIGH";
    pub const SEVERITY_MEDIUM: &str = "SEVERITY_MEDIUM";
    pub const SEVERITY_LOW: &str = "SEVERITY_LOW";

    // Process-based reasons
    pub const UNSIGNED_CHILD: &str = "UNSIGNED_CHILD";
    pub const ANOMALOUS_PARENT: &str = "ANOMALOUS_PARENT";
    pub const RARE_EXECUTABLE: &str = "RARE_EXECUTABLE";
    pub const SUSPICIOUS_CMDLINE: &str = "SUSPICIOUS_CMDLINE";

    // Network-based reasons
    pub const NETWORK_EGRESS: &str = "NETWORK_EGRESS";
    pub const RARE_DESTINATION: &str = "RARE_DESTINATION";
    pub const C2_INDICATOR: &str = "C2_INDICATOR";

    // File-based reasons
    pub const SENSITIVE_PATH: &str = "SENSITIVE_PATH";
    pub const CREDENTIAL_FILE: &str = "CREDENTIAL_FILE";
    pub const CONFIG_MODIFICATION: &str = "CONFIG_MODIFICATION";

    // Advanced scoring reasons
    pub const MAHALANOBIS_ANOMALY: &str = "MAHALANOBIS_ANOMALY";
    pub const ELLIPTIC_ENVELOPE: &str = "ELLIPTIC_ENVELOPE";
    pub const KRIM_ENTROPY: &str = "KRIM_ENTROPY";

    // Missing data reasons
    pub const MISSING_SCORING: &str = "MISSING_SCORING";
    pub const INCOMPLETE_EVIDENCE: &str = "INCOMPLETE_EVIDENCE";
}

// ============================================================================
// ScoringBreakdown - Complete scoring information
// ============================================================================

/// Complete scoring breakdown for a signal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScoringBreakdown {
    /// Final risk score [0.0, 1.0]
    pub risk_score: f64,

    /// Structured scoring reasons
    #[serde(default)]
    pub scoring_reasons: Vec<ScoringReason>,

    /// Advanced scoring fields (optional, from ScoredSignal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mahalanobis_distance: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub elliptic_envelope_score: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub krim_score: Option<f64>,

    /// Explicit marker for when scoring is unavailable
    /// If true, UI should show "Not available" instead of 0
    #[serde(default)]
    pub scoring_unavailable: bool,
}

impl ScoringBreakdown {
    /// Create a scoring breakdown from risk score and reasons
    pub fn new(risk_score: f64, reasons: Vec<ScoringReason>) -> Self {
        Self {
            risk_score,
            scoring_reasons: reasons,
            mahalanobis_distance: None,
            elliptic_envelope_score: None,
            krim_score: None,
            scoring_unavailable: false,
        }
    }

    /// Create a marker for unavailable scoring
    pub fn unavailable() -> Self {
        Self {
            risk_score: 0.0,
            scoring_reasons: vec![ScoringReason::new(
                reason_codes::MISSING_SCORING,
                "Scoring not available",
                0.0,
            )
            .with_detail("Signal was created before scoring was enabled or data is insufficient")],
            mahalanobis_distance: None,
            elliptic_envelope_score: None,
            krim_score: None,
            scoring_unavailable: true,
        }
    }

    /// Add advanced scoring fields
    pub fn with_advanced(
        mut self,
        mahalanobis: Option<f64>,
        elliptic: Option<f64>,
        krim: Option<f64>,
    ) -> Self {
        self.mahalanobis_distance = mahalanobis;
        self.elliptic_envelope_score = elliptic;
        self.krim_score = krim;
        self
    }
}

// ============================================================================
// SignalEntities - Canonical entity container
// ============================================================================

/// Canonical entities container for signal/explain responses.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SignalEntities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_key: Option<String>,

    /// Additional entity keys as key-value pairs
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub extra: std::collections::HashMap<String, String>,
}

impl SignalEntities {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    pub fn with_proc_key(mut self, key: impl Into<String>) -> Self {
        self.proc_key = Some(key.into());
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_file_key(mut self, key: impl Into<String>) -> Self {
        self.file_key = Some(key.into());
        self
    }

    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip = Some(ip.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.host.is_none()
            && self.proc_key.is_none()
            && self.user.is_none()
            && self.file_key.is_none()
            && self.ip.is_none()
            && self.registry_key.is_none()
            && self.extra.is_empty()
    }
}

// ============================================================================
// SignalSummary - Response for GET /api/signals
// ============================================================================

/// Signal summary returned by GET /api/signals (list view).
/// Minimal fields for list display; full detail via explain endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSummary {
    /// Signal ID (required)
    pub signal_id: String,

    /// Signal type (required)
    pub signal_type: String,

    /// Timestamp in milliseconds since epoch (required)
    pub ts: i64,

    /// Severity level (required)
    pub severity: String,

    /// Playbook ID that generated this signal (null if unknown)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub playbook_id: Option<String>,

    /// Detector/playbook version (null if unknown)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detector_version: Option<String>,

    /// Host where signal originated
    pub host: String,

    /// Risk score [0.0, 1.0] (null if scoring unavailable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,

    /// Minimal entity info for list display
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<SignalEntities>,

    /// Evidence pointer count (not full pointers, just count for list view)
    #[serde(default)]
    pub evidence_count: usize,
}

// ============================================================================
// ExplainResponse - Response for GET /api/signals/:id/explain
// ============================================================================

/// Full explanation response for GET /api/signals/:id/explain.
/// Contains all detail needed for the UI's Explain tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResponse {
    // === REQUIRED CORE FIELDS ===
    /// Signal ID
    pub signal_id: String,

    /// Signal type
    pub signal_type: String,

    /// Timestamp in milliseconds
    pub ts: i64,

    /// Severity level
    pub severity: String,

    // === DETECTOR IDENTIFICATION (required) ===
    /// Playbook/detector ID that generated this signal
    pub playbook_id: String,

    /// Hypothesis name (if from hypothesis-based detection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypothesis_name: Option<String>,

    /// Detector version for reproducibility
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detector_version: Option<String>,

    // === ENTITIES (required, can be empty) ===
    /// All relevant entities for this signal
    pub entities: SignalEntities,

    // === EVIDENCE (required, can be empty) ===
    /// Evidence pointers (empty array if none, never null)
    pub evidence: Vec<EvidencePointer>,

    // === SCORING (required, can indicate unavailable) ===
    /// Complete scoring breakdown
    pub scoring: ScoringBreakdown,

    // === OPTIONAL ENRICHMENT ===
    /// Human-readable summary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Security family (e.g., "persistence", "defense_evasion")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,

    /// Slot fill details (from ExplanationBundle)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slots: Option<serde_json::Value>,

    /// Matched facts (from ExplanationBundle)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_facts: Option<serde_json::Value>,

    /// Limitations/caveats
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,

    /// Generated timestamp
    pub generated_at: i64,
}

// ============================================================================
// Normalization Helpers
// ============================================================================

/// Normalize legacy EvidencePtr to canonical EvidencePointer
pub fn normalize_evidence_ptr(
    stream_id: &str,
    segment_id: u64,
    record_index: u32,
) -> EvidencePointer {
    EvidencePointer::from_segment(stream_id, segment_id, record_index)
}

/// Normalize legacy JSON evidence to canonical EvidencePointer
pub fn normalize_evidence_from_json(json: &serde_json::Value) -> Option<EvidencePointer> {
    // Handle legacy format: {stream_id, segment_id, record_index}
    if let (Some(stream), Some(seg), Some(idx)) = (
        json.get("stream_id").and_then(|v| v.as_str()),
        json.get("segment_id").and_then(|v| v.as_u64()),
        json.get("record_index").and_then(|v| v.as_u64()),
    ) {
        return Some(EvidencePointer::from_segment(stream, seg, idx as u32));
    }

    // Handle already-canonical format
    if let Ok(ptr) = serde_json::from_value::<EvidencePointer>(json.clone()) {
        return Some(ptr);
    }

    None
}

/// Normalize an array of evidence JSON to canonical pointers
pub fn normalize_evidence_array(arr: &[serde_json::Value]) -> Vec<EvidencePointer> {
    arr.iter().filter_map(normalize_evidence_from_json).collect()
}

/// Build scoring breakdown from legacy signal data
pub fn build_scoring_from_signal(
    severity: &str,
    risk_score: Option<f64>,
    metadata: &serde_json::Value,
) -> ScoringBreakdown {
    let mut reasons = Vec::new();

    // Add severity-based reason
    let (sev_code, sev_label, sev_weight) = match severity {
        "critical" => (
            reason_codes::SEVERITY_CRITICAL,
            "Critical severity",
            0.95,
        ),
        "high" => (reason_codes::SEVERITY_HIGH, "High severity", 0.75),
        "medium" => (reason_codes::SEVERITY_MEDIUM, "Medium severity", 0.50),
        "low" => (reason_codes::SEVERITY_LOW, "Low severity", 0.25),
        _ => (reason_codes::SEVERITY_LOW, "Unknown severity", 0.10),
    };
    reasons.push(ScoringReason::new(sev_code, sev_label, sev_weight));

    // Check metadata for advanced scoring
    let mahalanobis = metadata
        .get("mahalanobis_distance")
        .and_then(|v| v.as_f64());
    let elliptic = metadata
        .get("elliptic_envelope_score")
        .and_then(|v| v.as_f64());
    let krim = metadata.get("krim_score").and_then(|v| v.as_f64());

    // Add advanced scoring reasons if present
    if let Some(maha) = mahalanobis {
        reasons.push(
            ScoringReason::new(
                reason_codes::MAHALANOBIS_ANOMALY,
                "Mahalanobis anomaly score",
                (maha / 10.0).clamp(0.0, 1.0), // Normalize distance to weight
            )
            .with_detail(format!("Distance from normal: {:.2}", maha)),
        );
    }

    if let Some(env) = elliptic {
        reasons.push(ScoringReason::new(
            reason_codes::ELLIPTIC_ENVELOPE,
            "Elliptic envelope anomaly",
            env,
        ));
    }

    if let Some(k) = krim {
        reasons.push(ScoringReason::new(
            reason_codes::KRIM_ENTROPY,
            "KRIM entropy score",
            k,
        ));
    }

    // Determine final risk score
    let final_score = risk_score.unwrap_or(sev_weight);

    ScoringBreakdown::new(final_score, reasons).with_advanced(mahalanobis, elliptic, krim)
}

/// Normalize entities from signal data
pub fn normalize_entities(
    host: &str,
    proc_key: Option<&str>,
    file_key: Option<&str>,
    identity_key: Option<&str>,
) -> SignalEntities {
    SignalEntities {
        host: Some(host.to_string()),
        proc_key: proc_key.map(|s| s.to_string()),
        user: identity_key.map(|s| s.to_string()),
        file_key: file_key.map(|s| s.to_string()),
        ip: None,
        registry_key: None,
        extra: std::collections::HashMap::new(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_pointer_from_segment() {
        let ptr = EvidencePointer::from_segment("evtx", 42, 100);
        assert_eq!(ptr.kind, EvidenceKind::SegmentRecord);
        assert_eq!(ptr.reference, "evtx:42:100");
        assert_eq!(ptr.stream_id, Some("evtx".to_string()));
        assert_eq!(ptr.segment_id, Some(42));
        assert_eq!(ptr.record_index, Some(100));
    }

    #[test]
    fn test_scoring_reason_creation() {
        let reason = ScoringReason::new(reason_codes::SEVERITY_HIGH, "High severity", 0.75)
            .with_detail("Signal marked as high severity by playbook");
        assert_eq!(reason.code, "SEVERITY_HIGH");
        assert_eq!(reason.weight, 0.75);
        assert!(reason.detail.is_some());
    }

    #[test]
    fn test_scoring_breakdown_unavailable() {
        let breakdown = ScoringBreakdown::unavailable();
        assert!(breakdown.scoring_unavailable);
        assert_eq!(breakdown.scoring_reasons.len(), 1);
        assert_eq!(breakdown.scoring_reasons[0].code, reason_codes::MISSING_SCORING);
    }

    #[test]
    fn test_normalize_evidence_from_json() {
        let json = serde_json::json!({
            "stream_id": "sysmon",
            "segment_id": 5,
            "record_index": 42
        });
        let ptr = normalize_evidence_from_json(&json).unwrap();
        assert_eq!(ptr.kind, EvidenceKind::SegmentRecord);
        assert_eq!(ptr.reference, "sysmon:5:42");
    }

    #[test]
    fn test_build_scoring_from_signal() {
        let metadata = serde_json::json!({
            "mahalanobis_distance": 3.5
        });
        let scoring = build_scoring_from_signal("high", Some(0.8), &metadata);
        assert_eq!(scoring.risk_score, 0.8);
        assert!(!scoring.scoring_unavailable);
        assert!(scoring.mahalanobis_distance.is_some());
        // Should have severity reason + mahalanobis reason
        assert!(scoring.scoring_reasons.len() >= 2);
    }

    #[test]
    fn test_signal_entities() {
        let entities = normalize_entities("host1", Some("proc_123"), None, Some("user@domain"));
        assert_eq!(entities.host, Some("host1".to_string()));
        assert_eq!(entities.proc_key, Some("proc_123".to_string()));
        assert_eq!(entities.user, Some("user@domain".to_string()));
        assert!(entities.file_key.is_none());
    }
}

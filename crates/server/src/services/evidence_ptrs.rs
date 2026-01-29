//! Evidence Pointer Utilities (RUN_BRIEF-1 Refactor)
//!
//! Shared utilities for parsing evidence_ptrs JSON arrays and normalizing
//! signal_type/playbook_id values. Used by run_brief, step_status, and other
//! evidence-related endpoints.
//!
//! ## Design
//! - Pure functions, no DB access
//! - Unit testable
//! - Preserves exact behavior from original locint.rs inline code

use serde::{Deserialize, Serialize};

// ============================================================================
// Evidence Pointer Types
// ============================================================================

/// A single evidence pointer reference
/// 
/// Maps to the JSON structure stored in signals.evidence_ptrs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidencePtr {
    /// Segment identifier (e.g., segment file path or ID)
    #[serde(default)]
    pub seg: Option<String>,
    
    /// Row index within segment
    #[serde(default)]
    pub row: Option<i64>,
    
    /// Timestamp of the evidence
    #[serde(default)]
    pub ts: Option<i64>,
    
    /// Alternative timestamp field
    #[serde(default)]
    pub timestamp: Option<i64>,
    
    /// Fact type if available
    #[serde(default)]
    pub fact_type: Option<String>,
    
    /// Entity key if available
    #[serde(default)]
    pub entity_key: Option<String>,
}

impl EvidencePtr {
    /// Get the effective timestamp (prefers `ts` over `timestamp`)
    pub fn effective_ts(&self) -> Option<i64> {
        self.ts.or(self.timestamp)
    }
    
    /// Convert to serde_json::Value (preserves original JSON structure)
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::json!({}))
    }
}

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse evidence_ptrs JSON string into Vec<EvidencePtr>
/// 
/// Handles malformed JSON gracefully by returning empty vec.
/// This preserves the original behavior from locint.rs:
/// ```ignore
/// let evidence_ptrs: Vec<serde_json::Value> = evidence_ptrs_json
///     .as_ref()
///     .and_then(|s| serde_json::from_str(s).ok())
///     .unwrap_or_default();
/// ```
pub fn parse_evidence_ptrs_json(json_str: Option<&str>) -> Vec<EvidencePtr> {
    json_str
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Parse evidence_ptrs JSON string into Vec<serde_json::Value>
/// 
/// Returns raw JSON values for cases where we don't need typed access.
/// Used when passing evidence_ptrs directly to response JSON.
pub fn parse_evidence_ptrs_raw(json_str: Option<&str>) -> Vec<serde_json::Value> {
    json_str
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

// ============================================================================
// Signal Type / Playbook ID Normalization
// ============================================================================

/// Strip "playbook:" prefix from signal_type to get playbook_id
/// 
/// Constraint 5 from RUN_PIPELINE_TRUTH_REPORT.md:
/// Signal `signal_type` is stored as `"playbook:{playbook_id}"`.
/// When matching signals to playbooks, strip the `"playbook:"` prefix.
///
/// # Examples
/// ```ignore
/// assert_eq!(strip_playbook_prefix("playbook:persistence"), "persistence");
/// assert_eq!(strip_playbook_prefix("custom_signal"), "custom_signal");
/// ```
pub fn strip_playbook_prefix(signal_type: &str) -> &str {
    signal_type.strip_prefix("playbook:").unwrap_or(signal_type)
}

/// Convert signal_type to playbook_id (owned String version)
pub fn signal_type_to_playbook_id(signal_type: &str) -> String {
    strip_playbook_prefix(signal_type).to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_playbook_prefix() {
        assert_eq!(strip_playbook_prefix("playbook:persistence"), "persistence");
        assert_eq!(strip_playbook_prefix("playbook:execution"), "execution");
        assert_eq!(strip_playbook_prefix("custom_signal"), "custom_signal");
        assert_eq!(strip_playbook_prefix(""), "");
        assert_eq!(strip_playbook_prefix("playbook:"), "");
    }

    #[test]
    fn test_parse_evidence_ptrs_json_valid() {
        let json = r#"[{"seg": "seg1", "row": 42, "ts": 1706000000}]"#;
        let ptrs = parse_evidence_ptrs_json(Some(json));
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].seg, Some("seg1".to_string()));
        assert_eq!(ptrs[0].row, Some(42));
        assert_eq!(ptrs[0].ts, Some(1706000000));
    }

    #[test]
    fn test_parse_evidence_ptrs_json_empty() {
        assert!(parse_evidence_ptrs_json(None).is_empty());
        assert!(parse_evidence_ptrs_json(Some("")).is_empty());
        assert!(parse_evidence_ptrs_json(Some("[]")).is_empty());
    }

    #[test]
    fn test_parse_evidence_ptrs_json_malformed() {
        // Malformed JSON should return empty vec, not panic
        assert!(parse_evidence_ptrs_json(Some("{invalid}")).is_empty());
        assert!(parse_evidence_ptrs_json(Some("[{\"broken")).is_empty());
    }

    #[test]
    fn test_parse_evidence_ptrs_raw() {
        let json = r#"[{"seg": "seg1", "row": 42}]"#;
        let ptrs = parse_evidence_ptrs_raw(Some(json));
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0]["seg"], "seg1");
        assert_eq!(ptrs[0]["row"], 42);
    }

    #[test]
    fn test_evidence_ptr_effective_ts() {
        let ptr_with_ts = EvidencePtr {
            seg: None,
            row: None,
            ts: Some(100),
            timestamp: Some(200),
            fact_type: None,
            entity_key: None,
        };
        assert_eq!(ptr_with_ts.effective_ts(), Some(100)); // prefers ts

        let ptr_with_timestamp_only = EvidencePtr {
            seg: None,
            row: None,
            ts: None,
            timestamp: Some(200),
            fact_type: None,
            entity_key: None,
        };
        assert_eq!(ptr_with_timestamp_only.effective_ts(), Some(200));

        let ptr_with_neither = EvidencePtr {
            seg: None,
            row: None,
            ts: None,
            timestamp: None,
            fact_type: None,
            entity_key: None,
        };
        assert_eq!(ptr_with_neither.effective_ts(), None);
    }
}

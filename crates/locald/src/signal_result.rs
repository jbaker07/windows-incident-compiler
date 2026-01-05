//! Shared signal result types used by all platform signal engines

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Reference to evidence in the telemetry stream
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvidenceRef {
    pub stream_id: String,
    pub segment_id: String,
    pub record_index: u64,
}

/// Signal detection result - output from any platform's signal detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalResult {
    /// Deterministic sha256(host|signal_type|entity_hash|ts_bucket)
    pub signal_id: String,
    /// Signal type (e.g., "LogEvasion", "LSASSAccessSuspicious", "PersistenceLaunchd")
    pub signal_type: String,
    /// Severity: critical|high|medium|low
    pub severity: String,
    /// Hostname
    pub host: String,
    /// Detection timestamp (milliseconds)
    pub ts: i64,
    /// Episode start timestamp (milliseconds)
    pub ts_start: i64,
    /// Episode end timestamp (milliseconds)
    pub ts_end: i64,
    /// Process key reference
    pub proc_key: Option<String>,
    /// File key reference
    pub file_key: Option<String>,
    /// Identity key reference
    pub identity_key: Option<String>,
    /// Evidence pointers (capped at 10)
    pub evidence_ptrs: Vec<EvidenceRef>,
    /// Count of evidence pointers dropped due to cap
    pub dropped_evidence_count: u32,
    /// Signal-specific metadata as JSON
    pub metadata: serde_json::Value,
}

impl SignalResult {
    /// Generate deterministic signal_id: sha256(host|signal_type|entity_hash|ts_bucket_minute)
    pub fn compute_signal_id(
        host: &str,
        signal_type: &str,
        entity_hash: &str,
        ts_ms: i64,
    ) -> String {
        let ts_bucket = (ts_ms / 60000).to_string(); // bucket by minute
        let input = format!("{}|{}|{}|{}", host, signal_type, entity_hash, ts_bucket);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Truncate evidence pointers to max 10, record dropped count
    pub fn cap_evidence(evidence: Vec<EvidenceRef>) -> (Vec<EvidenceRef>, u32) {
        if evidence.len() <= 10 {
            (evidence, 0)
        } else {
            let dropped = (evidence.len() - 10) as u32;
            (evidence[..10].to_vec(), dropped)
        }
    }

    /// Create a new SignalResult with minimal required fields
    pub fn new(host: &str, signal_type: &str, severity: &str, entity_hash: &str, ts: i64) -> Self {
        Self {
            signal_id: Self::compute_signal_id(host, signal_type, entity_hash, ts),
            signal_type: signal_type.to_string(),
            severity: severity.to_string(),
            host: host.to_string(),
            ts,
            ts_start: ts,
            ts_end: ts,
            proc_key: None,
            file_key: None,
            identity_key: None,
            evidence_ptrs: Vec::new(),
            dropped_evidence_count: 0,
            metadata: serde_json::json!({}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_id_deterministic() {
        let id1 = SignalResult::compute_signal_id("HOST1", "LogEvasion", "hash123", 1000000);
        let id2 = SignalResult::compute_signal_id("HOST1", "LogEvasion", "hash123", 1000500);
        assert_eq!(id1, id2); // same minute bucket = same ID
    }

    #[test]
    fn test_different_bucket_different_id() {
        let id1 = SignalResult::compute_signal_id("HOST1", "LogEvasion", "hash123", 1000000);
        let id2 = SignalResult::compute_signal_id("HOST1", "LogEvasion", "hash123", 1060000);
        assert_ne!(id1, id2); // different minute bucket
    }

    #[test]
    fn test_evidence_capping() {
        let evidence: Vec<EvidenceRef> = (0..15)
            .map(|i| EvidenceRef {
                stream_id: format!("s{}", i),
                segment_id: format!("g{}", i),
                record_index: i as u64,
            })
            .collect();
        let (capped, dropped) = SignalResult::cap_evidence(evidence);
        assert_eq!(capped.len(), 10);
        assert_eq!(dropped, 5);
    }

    #[test]
    fn test_signal_result_new() {
        let signal =
            SignalResult::new("host1", "SuspiciousExec", "high", "proc_123", 1700000000000);
        assert!(!signal.signal_id.is_empty());
        assert_eq!(signal.signal_type, "SuspiciousExec");
        assert_eq!(signal.severity, "high");
    }
}

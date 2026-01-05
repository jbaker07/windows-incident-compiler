// core/signal_result.rs
// Signal detection results - persisted output from Windows signal detectors

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub stream_id: String,
    pub segment_id: String,
    pub record_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalResult {
    pub signal_id: String,                      // deterministic sha256(host|signal_type|entity_hash|ts_bucket)
    pub signal_type: String,                    // e.g., "LogEvasion", "LSASSAccessSuspicious"
    pub severity: String,                       // critical|high|medium|low
    pub host: String,
    pub ts: i64,                                // detection timestamp (ms)
    pub ts_start: i64,                          // episode start (ms)
    pub ts_end: i64,                            // episode end (ms)
    pub proc_key: Option<String>,
    pub file_key: Option<String>,
    pub identity_key: Option<String>,
    pub evidence_ptrs: Vec<EvidenceRef>,        // capped at 10
    pub dropped_evidence_count: u32,            // count of evidence ptrs dropped
    pub metadata: serde_json::Value,            // signal-specific fields as JSON
}

impl SignalResult {
    /// Generate deterministic signal_id: sha256(host|signal_type|entity_hash|ts_bucket_minute)
    pub fn compute_signal_id(host: &str, signal_type: &str, entity_hash: &str, ts_ms: i64) -> String {
        let ts_bucket = (ts_ms / 60000).to_string();  // bucket by minute
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_id_deterministic() {
        let id1 = SignalResult::compute_signal_id("HOST1", "LogEvasion", "hash123", 1000000);
        let id2 = SignalResult::compute_signal_id("HOST1", "LogEvasion", "hash123", 1000500);  // same bucket
        assert_eq!(id1, id2);  // same minute bucket = same ID
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
}

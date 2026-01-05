use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{EvidencePtr, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalResult {
    pub signal_id: String,
    pub signal_type: String,
    pub severity: Severity,

    pub host: String,
    pub ts_ms: i64,
    pub ts_start_ms: i64,
    pub ts_end_ms: i64,

    pub evidence_ptrs: Vec<EvidencePtr>,
    pub dropped_evidence_count: u32,

    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

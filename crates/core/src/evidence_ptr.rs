use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EvidencePtr {
    pub stream_id: String,
    pub segment_id: u64,
    pub record_index: u32,
}

/// Minimal error taxonomy for UI server
/// Just what's needed for evidence dereferencing and incident explanation
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    SegmentMissing,
    EvidenceMissing,
    InvalidRecord,
}

impl ErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::SegmentMissing => "segment_missing",
            ErrorCode::EvidenceMissing => "evidence_missing",
            ErrorCode::InvalidRecord => "invalid_record",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<(String, u32)>, // (segment_id, record_index)
}

//! EvidencePtr: Stable, deterministic, globally unique evidence pointer
//!
//! Format: EvidencePtr = { stream_id, segment_id, record_index, sha256_of_record_bytes(optional), ts(optional) }
//!
//! Properties:
//! - Stable across replays
//! - Globally unique (stream_id disambiguates duplicates)
//! - Supports integrity verification via optional sha256
//! - Clock-skew resistant (relies on ordering within stream, not ts alone)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Stable evidence pointer - globally unique and replay-deterministic
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidencePtr {
    /// Stream identifier (e.g., "windows-etw-process", "macos-es-exec", "linux-ebpf-syscall")
    pub stream_id: String,

    /// Segment identifier (rotated file or partition)
    pub segment_id: String,

    /// Record index within segment (0-based, monotonic)
    pub record_index: u64,

    /// Optional SHA256 of record bytes for integrity verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,

    /// Optional timestamp (informational, do not rely on for ordering)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<i64>,
}

impl EvidencePtr {
    /// Create new evidence pointer with all fields
    pub fn new(
        stream_id: impl Into<String>,
        segment_id: impl Into<String>,
        record_index: u64,
        sha256: Option<String>,
        ts: Option<i64>,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            segment_id: segment_id.into(),
            record_index,
            sha256,
            ts,
        }
    }

    /// Create minimal pointer (no sha256/ts)
    pub fn minimal(
        stream_id: impl Into<String>,
        segment_id: impl Into<String>,
        record_index: u64,
    ) -> Self {
        Self::new(stream_id, segment_id, record_index, None, None)
    }

    /// Compute SHA256 of record bytes
    pub fn compute_sha256(record_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(record_bytes);
        format!("{:x}", hasher.finalize())
    }

    /// Verify integrity against provided record bytes
    #[allow(clippy::result_large_err)] // Forensic context requires full details
    pub fn verify_integrity(&self, record_bytes: &[u8]) -> Result<(), EvidenceIntegrityError> {
        if let Some(expected_sha256) = &self.sha256 {
            let actual_sha256 = Self::compute_sha256(record_bytes);
            if &actual_sha256 != expected_sha256 {
                return Err(EvidenceIntegrityError::Sha256Mismatch {
                    expected: expected_sha256.clone(),
                    actual: actual_sha256,
                    ptr: self.clone(),
                });
            }
        }
        Ok(())
    }

    /// Generate deterministic canonical key for DB lookup
    pub fn canonical_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.stream_id, self.segment_id, self.record_index
        )
    }

    /// Parse from canonical key string
    pub fn from_canonical_key(key: &str) -> Option<Self> {
        let parts: Vec<&str> = key.splitn(3, ':').collect();
        if parts.len() == 3 {
            let record_index = parts[2].parse().ok()?;
            Some(Self::minimal(parts[0], parts[1], record_index))
        } else {
            None
        }
    }

    /// Compare ordering within same stream (clock-skew safe)
    /// Returns None if different streams (not comparable)
    pub fn ordering_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.stream_id != other.stream_id {
            return None; // Different streams are not comparable
        }
        // Compare by segment_id first, then record_index
        match self.segment_id.cmp(&other.segment_id) {
            std::cmp::Ordering::Equal => Some(self.record_index.cmp(&other.record_index)),
            ord => Some(ord),
        }
    }

    /// Check if this pointer is before another in the same stream
    pub fn is_before(&self, other: &Self) -> Option<bool> {
        self.ordering_cmp(other)
            .map(|ord| ord == std::cmp::Ordering::Less)
    }
}

impl fmt::Display for EvidencePtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.stream_id, self.segment_id, self.record_index
        )?;
        if let Some(ts) = self.ts {
            write!(f, "@{}", ts)?;
        }
        if self.sha256.is_some() {
            write!(f, "[verified]")?;
        }
        Ok(())
    }
}

impl Ord for EvidencePtr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Deterministic ordering: stream_id, segment_id, record_index
        (&self.stream_id, &self.segment_id, self.record_index).cmp(&(
            &other.stream_id,
            &other.segment_id,
            other.record_index,
        ))
    }
}

impl PartialOrd for EvidencePtr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Evidence integrity errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceIntegrityError {
    /// SHA256 hash mismatch
    Sha256Mismatch {
        expected: String,
        actual: String,
        ptr: EvidencePtr,
    },
    /// Segment rotated/deleted
    SegmentNotFound { ptr: EvidencePtr, reason: String },
    /// Record index out of bounds
    RecordNotFound { ptr: EvidencePtr, segment_size: u64 },
    /// Stream not recognized
    UnknownStream { stream_id: String },
    /// Ship Hardening: Path validation failed (traversal, absolute path, etc.)
    ValidationError { ptr: EvidencePtr, reason: String },
}

impl fmt::Display for EvidenceIntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256Mismatch {
                expected,
                actual,
                ptr,
            } => {
                write!(
                    f,
                    "SHA256 mismatch for {}: expected {}, got {}",
                    ptr, expected, actual
                )
            }
            Self::SegmentNotFound { ptr, reason } => {
                write!(f, "Segment not found for {}: {}", ptr, reason)
            }
            Self::RecordNotFound { ptr, segment_size } => {
                write!(
                    f,
                    "Record {} not found (segment size: {})",
                    ptr, segment_size
                )
            }
            Self::UnknownStream { stream_id } => {
                write!(f, "Unknown stream: {}", stream_id)
            }
            Self::ValidationError { ptr, reason } => {
                write!(f, "Path validation failed for {}: {}", ptr, reason)
            }
        }
    }
}

impl std::error::Error for EvidenceIntegrityError {}

/// Builder for EvidencePtr with fluent API
#[allow(dead_code)]
pub struct EvidencePtrBuilder {
    stream_id: String,
    segment_id: String,
    record_index: u64,
    sha256: Option<String>,
    ts: Option<i64>,
}

#[allow(dead_code)]
impl EvidencePtrBuilder {
    pub fn new(
        stream_id: impl Into<String>,
        segment_id: impl Into<String>,
        record_index: u64,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            segment_id: segment_id.into(),
            record_index,
            sha256: None,
            ts: None,
        }
    }

    pub fn with_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.sha256 = Some(sha256.into());
        self
    }

    pub fn with_sha256_from_bytes(mut self, bytes: &[u8]) -> Self {
        self.sha256 = Some(EvidencePtr::compute_sha256(bytes));
        self
    }

    pub fn with_ts(mut self, ts: i64) -> Self {
        self.ts = Some(ts);
        self
    }

    pub fn build(self) -> EvidencePtr {
        EvidencePtr {
            stream_id: self.stream_id,
            segment_id: self.segment_id,
            record_index: self.record_index,
            sha256: self.sha256,
            ts: self.ts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_ptr_determinism() {
        let ptr1 = EvidencePtr::new("stream-a", "seg-001", 42, None, None);
        let ptr2 = EvidencePtr::new("stream-a", "seg-001", 42, None, None);
        assert_eq!(ptr1, ptr2);
        assert_eq!(ptr1.canonical_key(), ptr2.canonical_key());
    }

    #[test]
    fn test_evidence_ptr_ordering() {
        let ptr1 = EvidencePtr::minimal("stream-a", "seg-001", 10);
        let ptr2 = EvidencePtr::minimal("stream-a", "seg-001", 20);
        let ptr3 = EvidencePtr::minimal("stream-a", "seg-002", 5);

        assert!(ptr1.is_before(&ptr2) == Some(true));
        assert!(ptr2.is_before(&ptr3) == Some(true));
        assert!(ptr1.is_before(&ptr3) == Some(true));
    }

    #[test]
    fn test_evidence_ptr_different_streams() {
        let ptr1 = EvidencePtr::minimal("stream-a", "seg-001", 10);
        let ptr2 = EvidencePtr::minimal("stream-b", "seg-001", 5);

        // Different streams are not comparable within-stream
        assert!(ptr1.ordering_cmp(&ptr2).is_none());
    }

    #[test]
    fn test_sha256_verification() {
        let data = b"test record data";
        let sha256 = EvidencePtr::compute_sha256(data);

        let ptr = EvidencePtrBuilder::new("stream", "seg", 0)
            .with_sha256(&sha256)
            .build();

        assert!(ptr.verify_integrity(data).is_ok());
        assert!(ptr.verify_integrity(b"different data").is_err());
    }

    #[test]
    fn test_canonical_key_roundtrip() {
        let ptr = EvidencePtr::minimal("windows-etw-process", "seg-2024-001", 12345);
        let key = ptr.canonical_key();
        let parsed = EvidencePtr::from_canonical_key(&key).unwrap();

        assert_eq!(ptr.stream_id, parsed.stream_id);
        assert_eq!(ptr.segment_id, parsed.segment_id);
        assert_eq!(ptr.record_index, parsed.record_index);
    }
}

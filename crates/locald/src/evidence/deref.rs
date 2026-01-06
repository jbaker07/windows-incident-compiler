//! Evidence Deref: Resolve EvidencePtr to actual record content
//!
//! Deref strategy:
//! 1. First attempt DB lookup (canonical table keyed by EvidencePtr)
//! 2. Fallback to segment file read using segment_id + record_index
//! 3. Verify sha256 if present; if mismatch, return EvidenceIntegrityError
//!
//! Ship Hardening: All file reads are validated to stay within telemetry_root.
//! Absolute paths and ".." traversal are rejected with ValidationError.

use super::evidence_ptr::{EvidenceIntegrityError, EvidencePtr};
use super::evidence_store::{EvidenceStore, RecordSource};
use super::path_safety::validate_segment_id;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Result of dereferencing an evidence pointer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerefResult {
    /// The evidence pointer
    pub ptr: EvidencePtr,

    /// Dereferenced content (canonical JSON)
    pub content: Option<String>,

    /// Deref status
    pub status: DerefStatus,

    /// Source of the content
    pub source: Option<RecordSource>,

    /// Integrity verification result
    pub integrity_verified: bool,

    /// Error details if deref failed
    pub error: Option<String>,
}

/// Status of evidence deref operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerefStatus {
    /// Successfully retrieved from DB
    ResolvedFromDb,

    /// Successfully retrieved from segment file
    ResolvedFromSegment,

    /// Retrieved from cache
    ResolvedFromCache,

    /// Segment file not found (rotated/deleted)
    SegmentNotFound,

    /// Record not found in segment
    RecordNotFound,

    /// Integrity verification failed
    IntegrityError,

    /// Unknown stream type
    UnknownStream,
}

/// Evidence dereferencer
pub struct EvidenceDeref<'a> {
    store: &'a EvidenceStore,
}

impl<'a> EvidenceDeref<'a> {
    pub fn new(store: &'a EvidenceStore) -> Self {
        Self { store }
    }

    /// Dereference an evidence pointer to its content
    pub fn deref(&self, ptr: &EvidencePtr) -> DerefResult {
        // Step 1: Try DB lookup first (preferred)
        if let Some(record) = self.store.get(ptr) {
            // Verify integrity if sha256 present
            if let Some(expected_sha256) = &ptr.sha256 {
                let actual_sha256 = EvidencePtr::compute_sha256(record.canonical_json.as_bytes());
                if &actual_sha256 != expected_sha256 {
                    return DerefResult {
                        ptr: ptr.clone(),
                        content: Some(record.canonical_json),
                        status: DerefStatus::IntegrityError,
                        source: Some(record.source),
                        integrity_verified: false,
                        error: Some(format!(
                            "SHA256 mismatch: expected {}, got {}",
                            expected_sha256, actual_sha256
                        )),
                    };
                }
            }

            let status = match record.source {
                RecordSource::Cache => DerefStatus::ResolvedFromCache,
                RecordSource::Database => DerefStatus::ResolvedFromDb,
                RecordSource::SegmentFile => DerefStatus::ResolvedFromSegment,
            };

            return DerefResult {
                ptr: ptr.clone(),
                content: Some(record.canonical_json),
                status,
                source: Some(record.source),
                integrity_verified: ptr.sha256.is_some(),
                error: None,
            };
        }

        // Step 2: Fallback to segment file
        match self.read_from_segment(ptr) {
            Ok(content) => {
                // Verify integrity
                if let Some(expected_sha256) = &ptr.sha256 {
                    let actual_sha256 = EvidencePtr::compute_sha256(content.as_bytes());
                    if &actual_sha256 != expected_sha256 {
                        return DerefResult {
                            ptr: ptr.clone(),
                            content: Some(content),
                            status: DerefStatus::IntegrityError,
                            source: Some(RecordSource::SegmentFile),
                            integrity_verified: false,
                            error: Some(format!(
                                "SHA256 mismatch: expected {}, got {}",
                                expected_sha256, actual_sha256
                            )),
                        };
                    }
                }

                DerefResult {
                    ptr: ptr.clone(),
                    content: Some(content),
                    status: DerefStatus::ResolvedFromSegment,
                    source: Some(RecordSource::SegmentFile),
                    integrity_verified: ptr.sha256.is_some(),
                    error: None,
                }
            }
            Err(e) => {
                let status = match &e {
                    EvidenceIntegrityError::SegmentNotFound { .. } => DerefStatus::SegmentNotFound,
                    EvidenceIntegrityError::RecordNotFound { .. } => DerefStatus::RecordNotFound,
                    EvidenceIntegrityError::UnknownStream { .. } => DerefStatus::UnknownStream,
                    _ => DerefStatus::IntegrityError,
                };

                DerefResult {
                    ptr: ptr.clone(),
                    content: None,
                    status,
                    source: None,
                    integrity_verified: false,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Dereference multiple pointers in batch
    pub fn deref_batch(&self, ptrs: &[EvidencePtr]) -> Vec<DerefResult> {
        ptrs.iter().map(|ptr| self.deref(ptr)).collect()
    }

    /// Read record from segment file
    ///
    /// Ship Hardening: Validates segment_id format and path safety before any file read.
    /// Rejects absolute paths and ".." traversal with IntegrityError.
    #[allow(clippy::result_large_err)] // Forensic context requires full error details
    fn read_from_segment(&self, ptr: &EvidencePtr) -> Result<String, EvidenceIntegrityError> {
        // Ship Hardening: Validate segment_id format BEFORE any file operations
        if let Err(e) = validate_segment_id(&ptr.segment_id) {
            return Err(EvidenceIntegrityError::ValidationError {
                ptr: ptr.clone(),
                reason: format!("Invalid segment_id: {}", e),
            });
        }

        // Check if segment is available
        if !self.store.segment_available(&ptr.segment_id) {
            return Err(EvidenceIntegrityError::SegmentNotFound {
                ptr: ptr.clone(),
                reason: "Segment rotated or deleted".to_string(),
            });
        }

        // Get segment file path (includes path safety validation)
        let segment_path = self
            .store
            .get_segment_path(&ptr.segment_id)
            .ok_or_else(|| EvidenceIntegrityError::SegmentNotFound {
                ptr: ptr.clone(),
                reason: "Segment metadata not found or path validation failed".to_string(),
            })?;

        Self::read_record_from_file(&segment_path, ptr)
    }

    /// Read a specific record from segment file
    /// Assumes newline-delimited JSON format
    #[allow(clippy::result_large_err)] // Forensic context requires full error details
    fn read_record_from_file(
        path: &Path,
        ptr: &EvidencePtr,
    ) -> Result<String, EvidenceIntegrityError> {
        let file = File::open(path).map_err(|e| EvidenceIntegrityError::SegmentNotFound {
            ptr: ptr.clone(),
            reason: format!("Cannot open segment file: {}", e),
        })?;

        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Skip to the target record
        for _ in 0..ptr.record_index {
            if lines.next().is_none() {
                return Err(EvidenceIntegrityError::RecordNotFound {
                    ptr: ptr.clone(),
                    segment_size: ptr.record_index, // Approximate
                });
            }
        }

        // Read the target record
        lines
            .next()
            .ok_or_else(|| EvidenceIntegrityError::RecordNotFound {
                ptr: ptr.clone(),
                segment_size: ptr.record_index,
            })?
            .map_err(|e| EvidenceIntegrityError::SegmentNotFound {
                ptr: ptr.clone(),
                reason: format!("Read error: {}", e),
            })
    }

    /// Check if evidence can be dereferenced
    pub fn can_deref(&self, ptr: &EvidencePtr) -> bool {
        self.store.get(ptr).is_some() || self.store.segment_available(&ptr.segment_id)
    }

    /// Get deref status without fetching content
    pub fn probe(&self, ptr: &EvidencePtr) -> DerefStatus {
        if self.store.get(ptr).is_some() {
            DerefStatus::ResolvedFromDb
        } else if self.store.segment_available(&ptr.segment_id) {
            DerefStatus::ResolvedFromSegment
        } else {
            DerefStatus::SegmentNotFound
        }
    }
}

/// Bulk deref result with statistics
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDerefResult {
    pub results: Vec<DerefResult>,
    pub total: usize,
    pub resolved: usize,
    pub from_db: usize,
    pub from_segment: usize,
    pub from_cache: usize,
    pub missing: usize,
    pub integrity_errors: usize,
}

#[allow(dead_code)]
impl BulkDerefResult {
    pub fn from_results(results: Vec<DerefResult>) -> Self {
        let total = results.len();
        let mut resolved = 0;
        let mut from_db = 0;
        let mut from_segment = 0;
        let mut from_cache = 0;
        let mut missing = 0;
        let mut integrity_errors = 0;

        for result in &results {
            match result.status {
                DerefStatus::ResolvedFromDb => {
                    resolved += 1;
                    from_db += 1;
                }
                DerefStatus::ResolvedFromSegment => {
                    resolved += 1;
                    from_segment += 1;
                }
                DerefStatus::ResolvedFromCache => {
                    resolved += 1;
                    from_cache += 1;
                }
                DerefStatus::SegmentNotFound
                | DerefStatus::RecordNotFound
                | DerefStatus::UnknownStream => {
                    missing += 1;
                }
                DerefStatus::IntegrityError => {
                    integrity_errors += 1;
                }
            }
        }

        Self {
            results,
            total,
            resolved,
            from_db,
            from_segment,
            from_cache,
            missing,
            integrity_errors,
        }
    }

    /// Get all successfully resolved contents
    pub fn resolved_contents(&self) -> Vec<(&EvidencePtr, &str)> {
        self.results
            .iter()
            .filter(|r| r.content.is_some())
            .map(|r| (&r.ptr, r.content.as_ref().unwrap().as_str()))
            .collect()
    }

    /// Get all missing pointers
    pub fn missing_ptrs(&self) -> Vec<&EvidencePtr> {
        self.results
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    DerefStatus::SegmentNotFound | DerefStatus::RecordNotFound
                )
            })
            .map(|r| &r.ptr)
            .collect()
    }

    /// Check if any integrity errors occurred
    pub fn has_integrity_errors(&self) -> bool {
        self.integrity_errors > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deref_from_db() {
        let mut store = EvidenceStore::open_memory().unwrap();
        let ptr = EvidencePtr::minimal("stream-a", "seg-001", 0);
        let json = r#"{"event":"test"}"#;

        store.store(&ptr, json).unwrap();

        let deref = EvidenceDeref::new(&store);
        let result = deref.deref(&ptr);

        assert_eq!(result.status, DerefStatus::ResolvedFromCache); // Cached after store
        assert_eq!(result.content.as_deref(), Some(json));
    }

    #[test]
    fn test_deref_missing() {
        let store = EvidenceStore::open_memory().unwrap();
        let ptr = EvidencePtr::minimal("stream-a", "seg-missing", 0);

        let deref = EvidenceDeref::new(&store);
        let result = deref.deref(&ptr);

        assert_eq!(result.status, DerefStatus::SegmentNotFound);
        assert!(result.content.is_none());
    }

    #[test]
    fn test_bulk_deref_stats() {
        let mut store = EvidenceStore::open_memory().unwrap();

        // Store some records
        for i in 0..5 {
            let ptr = EvidencePtr::minimal("stream-a", "seg-001", i);
            store.store(&ptr, &format!(r#"{{"i":{}}}"#, i)).unwrap();
        }

        let deref = EvidenceDeref::new(&store);

        // Query mix of existing and missing
        let ptrs: Vec<EvidencePtr> = (0..10)
            .map(|i| EvidencePtr::minimal("stream-a", "seg-001", i))
            .collect();

        let results = deref.deref_batch(&ptrs);
        let bulk = BulkDerefResult::from_results(results);

        assert_eq!(bulk.total, 10);
        assert_eq!(bulk.resolved, 5);
        assert_eq!(bulk.missing, 5);
    }
}

//! Evidence Service
//!
//! Handles evidence dereference and segment access.
//! All business logic for evidence retrieval lives here.

use crate::services::types::EvidenceDerefReasonCode;
use std::path::Path;

// ============================================================================
// Evidence Dereference
// ============================================================================

/// Result of evidence dereference operation
pub struct DerefResult {
    pub success: bool,
    pub reason_code: EvidenceDerefReasonCode,
    pub message: Option<String>,
    pub record: Option<serde_json::Value>,
    pub context: Option<Vec<String>>,
    pub segment_info: Option<SegmentInfo>,
}

/// Segment metadata
pub struct SegmentInfo {
    pub segment_id: String,
    pub total_lines: usize,
    pub file_size: u64,
}

/// Safe path join that prevents path traversal attacks
pub fn safe_segment_path_join(
    segments_dir: &Path,
    segment_id: &str,
) -> Result<std::path::PathBuf, String> {
    // Reject obviously dangerous patterns
    if segment_id.contains("..")
        || segment_id.contains('/')
        || segment_id.contains('\\')
        || segment_id.contains('\0')
    {
        return Err("Invalid segment_id: path traversal detected".to_string());
    }

    // Only allow alphanumeric, underscore, hyphen
    let is_safe = segment_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if !is_safe || segment_id.is_empty() {
        return Err("Invalid segment_id: contains unsafe characters".to_string());
    }

    let segment_file = format!("{}.jsonl", segment_id);
    let joined = segments_dir.join(&segment_file);

    // Double-check the path is under segments_dir
    if let (Ok(canon_base), Ok(canon_joined)) = (segments_dir.canonicalize(), joined.canonicalize())
    {
        if !canon_joined.starts_with(&canon_base) {
            return Err("Invalid segment_id: path escape detected".to_string());
        }
    }

    Ok(joined)
}

/// Dereference an evidence pointer to retrieve the source record
pub fn dereference_evidence(
    data_dir: &Path,
    run_id: &str,
    segment_id: &str,
    offset: usize,
    context_lines: usize,
) -> DerefResult {
    let run_dir = data_dir.join("runs").join(run_id);
    let segments_dir = run_dir.join("segments");

    if !run_dir.exists() {
        return DerefResult {
            success: false,
            reason_code: EvidenceDerefReasonCode::RunNotFound,
            message: Some(format!("Run '{}' not found", run_id)),
            record: None,
            context: None,
            segment_info: None,
        };
    }

    if !segments_dir.exists() {
        return DerefResult {
            success: false,
            reason_code: EvidenceDerefReasonCode::SegmentNotFound,
            message: Some("Segments directory not found".to_string()),
            record: None,
            context: None,
            segment_info: None,
        };
    }

    // Safe path join
    let segment_path = match safe_segment_path_join(&segments_dir, segment_id) {
        Ok(p) => p,
        Err(msg) => {
            return DerefResult {
                success: false,
                reason_code: EvidenceDerefReasonCode::PathTraversal,
                message: Some(msg),
                record: None,
                context: None,
                segment_info: None,
            };
        }
    };

    if !segment_path.exists() {
        return DerefResult {
            success: false,
            reason_code: EvidenceDerefReasonCode::SegmentNotFound,
            message: Some(format!("Segment '{}' not found", segment_id)),
            record: None,
            context: None,
            segment_info: None,
        };
    }

    // Read the segment file
    let content = match std::fs::read_to_string(&segment_path) {
        Ok(c) => c,
        Err(e) => {
            return DerefResult {
                success: false,
                reason_code: EvidenceDerefReasonCode::IoError,
                message: Some(format!("Failed to read segment: {}", e)),
                record: None,
                context: None,
                segment_info: None,
            };
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    // Get file size
    let file_size = std::fs::metadata(&segment_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let segment_info = Some(SegmentInfo {
        segment_id: segment_id.to_string(),
        total_lines,
        file_size,
    });

    if offset >= total_lines {
        return DerefResult {
            success: false,
            reason_code: EvidenceDerefReasonCode::OffsetOutOfBounds,
            message: Some(format!(
                "Offset {} out of bounds (segment has {} lines)",
                offset, total_lines
            )),
            record: None,
            context: None,
            segment_info,
        };
    }

    // Get the target record
    let record_str = lines[offset];
    let record: serde_json::Value = match serde_json::from_str(record_str) {
        Ok(r) => r,
        Err(e) => {
            return DerefResult {
                success: false,
                reason_code: EvidenceDerefReasonCode::ParseError,
                message: Some(format!("Failed to parse record: {}", e)),
                record: None,
                context: None,
                segment_info,
            };
        }
    };

    // Get context lines
    let context = if context_lines > 0 {
        let start = offset.saturating_sub(context_lines);
        let end = (offset + context_lines + 1).min(total_lines);
        Some(
            lines[start..end]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
    } else {
        None
    };

    DerefResult {
        success: true,
        reason_code: EvidenceDerefReasonCode::Success,
        message: None,
        record: Some(record),
        context,
        segment_info,
    }
}

// ============================================================================
// Evidence Statistics
// ============================================================================

/// Get evidence statistics from signals table
pub fn get_evidence_stats(db_path: &Path) -> (usize, usize) {
    use crate::services::run_control::open_db_with_wal;

    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };

    let mut total_ptrs = 0usize;
    let mut valid_ptrs = 0usize;

    let query = "SELECT evidence_ptrs FROM signals WHERE evidence_ptrs IS NOT NULL";
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let evidence_ptrs: Option<String> = row.get(0)?;
            Ok(evidence_ptrs)
        }) {
            for row in rows.flatten() {
                if let Some(json_str) = row {
                    if let Ok(evidence) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(ptrs) = evidence.as_array() {
                            total_ptrs += ptrs.len();
                            for ptr in ptrs {
                                if ptr.get("segment_id").and_then(|v| v.as_str()).is_some() {
                                    valid_ptrs += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (total_ptrs, valid_ptrs)
}

/// Get all evidence pointers from signals (for case pack export)
pub fn get_all_evidence_pointers(db_path: &Path, limit: usize) -> Vec<serde_json::Value> {
    use crate::services::run_control::open_db_with_wal;

    let conn = match open_db_with_wal(db_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut all_ptrs = Vec::new();

    let query = "SELECT evidence_ptrs FROM signals WHERE evidence_ptrs IS NOT NULL LIMIT 1000";
    if let Ok(mut stmt) = conn.prepare(query) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let evidence_ptrs: Option<String> = row.get(0)?;
            Ok(evidence_ptrs)
        }) {
            for row in rows.flatten() {
                if all_ptrs.len() >= limit {
                    break;
                }
                if let Some(json_str) = row {
                    if let Ok(evidence) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        if let Some(ptrs) = evidence.as_array() {
                            for ptr in ptrs {
                                if all_ptrs.len() >= limit {
                                    break;
                                }
                                all_ptrs.push(ptr.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    all_ptrs
}

//! Evidence Dereference Helper: Read raw records from segment files.
//!
//! Given an EvidencePtr, this module can locate and read the referenced
//! record from segments/*.jsonl under EDR_TELEMETRY_ROOT.

use edr_core::EvidencePtr;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Result of dereferencing an evidence pointer.
#[derive(Debug, Clone)]
pub enum DerefResult {
    /// Successfully dereferenced with excerpt
    Success {
        excerpt: String,
        full_record: String,
        ts_ms: Option<i64>,
        source: String,
    },
    /// Segment file not found
    SegmentNotFound { path: String },
    /// Record index out of bounds
    RecordNotFound {
        segment_id: u64,
        record_index: u32,
        total_records: u32,
    },
    /// Parse error
    ParseError { reason: String },
    /// IO error
    IoError { reason: String },
}

impl DerefResult {
    /// Get excerpt if successful
    pub fn excerpt(&self) -> Option<&str> {
        match self {
            DerefResult::Success { excerpt, .. } => Some(excerpt),
            _ => None,
        }
    }

    /// Get source if successful
    pub fn source(&self) -> Option<&str> {
        match self {
            DerefResult::Success { source, .. } => Some(source),
            _ => None,
        }
    }

    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, DerefResult::Success { .. })
    }

    /// Get error message if not successful
    pub fn error_message(&self) -> Option<String> {
        match self {
            DerefResult::Success { .. } => None,
            DerefResult::SegmentNotFound { path } => Some(format!("Segment not found: {}", path)),
            DerefResult::RecordNotFound {
                segment_id,
                record_index,
                total_records,
            } => Some(format!(
                "Record {} not found in segment {} (total: {})",
                record_index, segment_id, total_records
            )),
            DerefResult::ParseError { reason } => Some(format!("Parse error: {}", reason)),
            DerefResult::IoError { reason } => Some(format!("IO error: {}", reason)),
        }
    }
}

/// Dereference an evidence pointer to get the raw record excerpt.
///
/// # Arguments
/// * `telemetry_root` - Root directory containing segments/
/// * `ptr` - Evidence pointer to dereference
/// * `max_excerpt_len` - Maximum length of excerpt (default: 500)
///
/// # Returns
/// DerefResult with excerpt or error information
pub fn deref_evidence(
    telemetry_root: &Path,
    ptr: &EvidencePtr,
    max_excerpt_len: usize,
) -> DerefResult {
    // Build segment file path
    let segment_filename = format!("{}.jsonl", ptr.segment_id);
    let segment_path = telemetry_root.join("segments").join(&segment_filename);

    // Check if segment exists
    if !segment_path.exists() {
        // Try alternate formats (evtx_NNNNNN.jsonl, etc.)
        let alt_patterns = [
            format!("evtx_{:06}.jsonl", ptr.segment_id),
            format!("segment_{}.jsonl", ptr.segment_id),
        ];

        for pattern in &alt_patterns {
            let alt_path = telemetry_root.join("segments").join(pattern);
            if alt_path.exists() {
                return deref_from_file(&alt_path, ptr, max_excerpt_len);
            }
        }

        return DerefResult::SegmentNotFound {
            path: segment_path.display().to_string(),
        };
    }

    deref_from_file(&segment_path, ptr, max_excerpt_len)
}

/// Read the record from a specific file
fn deref_from_file(path: &Path, ptr: &EvidencePtr, max_excerpt_len: usize) -> DerefResult {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            return DerefResult::IoError {
                reason: e.to_string(),
            }
        }
    };

    let reader = BufReader::new(file);
    let mut line_count: u32 = 0;

    for (idx, line_result) in reader.lines().enumerate() {
        line_count = idx as u32 + 1;

        if idx as u32 == ptr.record_index {
            match line_result {
                Ok(line) => {
                    return parse_record_excerpt(&line, max_excerpt_len);
                }
                Err(e) => {
                    return DerefResult::IoError {
                        reason: e.to_string(),
                    };
                }
            }
        }
    }

    DerefResult::RecordNotFound {
        segment_id: ptr.segment_id,
        record_index: ptr.record_index,
        total_records: line_count,
    }
}

/// Parse a record line and extract useful excerpt
fn parse_record_excerpt(line: &str, max_len: usize) -> DerefResult {
    // Try to parse as JSON for structured excerpt
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(parsed) => {
            let ts_ms = parsed.get("ts_ms").and_then(|v| v.as_i64());

            // Build source from tags
            let source = parsed
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "unknown".to_string());

            // Build excerpt from key fields
            let excerpt = build_excerpt(&parsed, max_len);

            DerefResult::Success {
                excerpt,
                full_record: line.to_string(),
                ts_ms,
                source,
            }
        }
        Err(e) => {
            // If not valid JSON, return raw truncated line
            let excerpt = if line.len() > max_len {
                format!("{}...", &line[..max_len])
            } else {
                line.to_string()
            };

            DerefResult::Success {
                excerpt,
                full_record: line.to_string(),
                ts_ms: None,
                source: format!("parse_error: {}", e),
            }
        }
    }
}

/// Build a human-readable excerpt from parsed JSON
fn build_excerpt(parsed: &serde_json::Value, max_len: usize) -> String {
    let mut parts = Vec::new();

    // Add timestamp
    if let Some(ts) = parsed.get("ts_ms").and_then(|v| v.as_i64()) {
        parts.push(format!("ts={}", ts));
    }

    // Add host
    if let Some(host) = parsed.get("host").and_then(|v| v.as_str()) {
        parts.push(format!("host={}", host));
    }

    // Add tags
    if let Some(tags) = parsed.get("tags").and_then(|v| v.as_array()) {
        let tag_strs: Vec<&str> = tags.iter().filter_map(|v| v.as_str()).collect();
        if !tag_strs.is_empty() {
            parts.push(format!("tags=[{}]", tag_strs.join(",")));
        }
    }

    // Add key fields
    if let Some(fields) = parsed.get("fields").and_then(|v| v.as_object()) {
        // Prioritize certain fields
        let priority_fields = [
            "EventID",
            "event_id",
            "Channel",
            "channel",
            "ProcessId",
            "process_id",
            "CommandLine",
            "cmdline",
            "Image",
            "image",
            "TargetFilename",
            "target_filename",
            "SourceIp",
            "DestinationIp",
            "LogonType",
        ];

        for key in &priority_fields {
            if let Some(value) = fields.get(*key) {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };
                parts.push(format!("{}={}", key, value_str));

                // Stop if we're getting long
                if parts.iter().map(|s| s.len()).sum::<usize>() > max_len {
                    break;
                }
            }
        }
    }

    let result = parts.join(" ");
    if result.len() > max_len {
        format!("{}...", &result[..max_len])
    } else {
        result
    }
}

/// Convenience function to dereference with default excerpt length
pub fn deref_evidence_default(telemetry_root: &Path, ptr: &EvidencePtr) -> DerefResult {
    deref_evidence(telemetry_root, ptr, 500)
}

/// Batch dereference multiple evidence pointers
pub fn deref_evidence_batch(
    telemetry_root: &Path,
    ptrs: &[EvidencePtr],
    max_excerpt_len: usize,
    max_results: usize,
) -> Vec<(EvidencePtr, DerefResult)> {
    ptrs.iter()
        .take(max_results)
        .map(|ptr| {
            (
                ptr.clone(),
                deref_evidence(telemetry_root, ptr, max_excerpt_len),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_segment(dir: &Path, segment_id: u64, records: &[&str]) {
        let segments_dir = dir.join("segments");
        std::fs::create_dir_all(&segments_dir).unwrap();

        let segment_path = segments_dir.join(format!("{}.jsonl", segment_id));
        let mut file = File::create(segment_path).unwrap();
        for record in records {
            writeln!(file, "{}", record).unwrap();
        }
    }

    #[test]
    fn test_deref_success() {
        let dir = TempDir::new().unwrap();
        let records = [
            r#"{"ts_ms": 1700000000000, "host": "test-host", "tags": ["auth", "logon"], "fields": {"EventID": 4624}}"#,
            r#"{"ts_ms": 1700000000001, "host": "test-host", "tags": ["process"], "fields": {"Image": "cmd.exe"}}"#,
        ];
        create_test_segment(dir.path(), 1, &records);

        let ptr = EvidencePtr {
            stream_id: "test".to_string(),
            segment_id: 1,
            record_index: 0,
        };

        let result = deref_evidence(dir.path(), &ptr, 500);
        assert!(result.is_success());
        assert!(result.excerpt().unwrap().contains("ts=1700000000000"));
        assert!(result.source().unwrap().contains("auth"));
    }

    #[test]
    fn test_deref_segment_not_found() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("segments")).unwrap();

        let ptr = EvidencePtr {
            stream_id: "test".to_string(),
            segment_id: 999,
            record_index: 0,
        };

        let result = deref_evidence(dir.path(), &ptr, 500);
        assert!(matches!(result, DerefResult::SegmentNotFound { .. }));
    }

    #[test]
    fn test_deref_record_not_found() {
        let dir = TempDir::new().unwrap();
        create_test_segment(dir.path(), 1, &[r#"{"ts_ms": 1}"#]);

        let ptr = EvidencePtr {
            stream_id: "test".to_string(),
            segment_id: 1,
            record_index: 5, // Out of bounds
        };

        let result = deref_evidence(dir.path(), &ptr, 500);
        assert!(matches!(result, DerefResult::RecordNotFound { .. }));
    }
}

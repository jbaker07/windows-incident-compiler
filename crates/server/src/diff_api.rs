//! Pro Feature: Diff API endpoint for comparing signal snapshots.
//!
//! This module provides the /api/diff endpoint.
//! Access is gated by runtime license entitlement, not compile-time feature.
//! The diff code is always compiled ("one binary"), but returns 402 without valid license.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use edr_core::{
    diff_snapshots, watermark::create_watermark_from_license, DiffResult, SignalSnapshot,
    SnapshotSignal,
};

use crate::db::{Database, StoredSignal};
use crate::license_api::require_diff_mode_entitlement;

/// Query parameters for diff endpoint
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used via serde deserialization
pub struct DiffQuery {
    /// Left snapshot identifier (timestamp or run_id)
    pub left: String,
    /// Right snapshot identifier (timestamp or run_id)
    pub right: String,
}

/// Response wrapper for diff results
#[derive(Debug, Serialize)]
pub struct DiffResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<DiffResponseData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Diff response data (available with valid license)
#[derive(Debug, Serialize)]
pub struct DiffResponseData {
    pub diff: DiffResult,
    pub meta: DiffMeta,
    /// Watermark for attribution/provenance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermark: Option<WatermarkInfo>,
}

/// Watermark information embedded in exports
#[derive(Debug, Serialize)]
pub struct WatermarkInfo {
    /// Human-readable watermark string
    pub visible: String,
    /// License ID
    pub license_id: String,
    /// Truncated install hash
    pub install_hash: String,
    /// Export timestamp
    pub exported_at: i64,
}

/// Metadata about the diff operation
#[derive(Debug, Serialize)]
pub struct DiffMeta {
    pub left_snapshot_size: usize,
    pub right_snapshot_size: usize,
    pub computed_at: String,
}

/// Run information for listing available runs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunInfo {
    pub run_id: String,
    pub name: Option<String>,  // User-assigned name
    pub signal_count: usize,
    pub earliest_ts: i64,
    pub latest_ts: i64,
    pub hosts: Vec<String>,
    // Extended fields from RunRecord
    pub profile: Option<String>,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub events_total: u64,
    pub segments_count: u32,
    pub facts_extracted: u64,
    pub status: String,
}

/// Load signals from database for a given run_id
fn load_snapshot_signals(db: &Database, run_id: &str) -> Result<Vec<StoredSignal>, String> {
    db.list_signals(Some(run_id), None, None, None, 10000, 0)
        .map_err(|e| format!("Database error: {}", e))
}

/// List available runs from the database
/// First checks the runs table for persisted run records,
/// then falls back to signal-based discovery for backwards compatibility
pub fn list_runs_from_db(db: &Database) -> Result<Vec<RunInfo>, String> {
    // First, try to get runs from the runs table
    let persisted_runs = db.list_runs(100)
        .map_err(|e| format!("Database error: {}", e))?;
    
    if !persisted_runs.is_empty() {
        // Convert RunRecords to RunInfo
        let mut result: Vec<RunInfo> = persisted_runs.into_iter().map(|run| {
            // Parse started_at to get a timestamp in milliseconds (to match signal ts)
            let earliest_ts = chrono::DateTime::parse_from_rfc3339(&run.started_at)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(0);
            let latest_ts = run.stopped_at.as_ref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(earliest_ts);
            
            RunInfo {
                run_id: run.run_id,
                name: run.name,
                signal_count: run.signals_fired as usize,
                earliest_ts,
                latest_ts,
                hosts: vec![], // Could be populated from signals if needed
                profile: run.profile,
                started_at: Some(run.started_at),
                stopped_at: run.stopped_at,
                events_total: run.events_total,
                segments_count: run.segments_count,
                facts_extracted: run.facts_extracted,
                status: run.status,
            }
        }).collect();
        
        result.sort_by(|a, b| b.earliest_ts.cmp(&a.earliest_ts));
        return Ok(result);
    }
    
    // Fallback: Load all signals to discover unique run_ids (backwards compatibility)
    let signals = db
        .list_signals(None, None, None, None, 10000, 0)
        .map_err(|e| format!("Database error: {}", e))?;

    if signals.is_empty() {
        return Ok(vec![]);
    }

    // Group signals by their actual run_id field
    struct RunAccumulator<'a> {
        signals: Vec<&'a StoredSignal>,
        earliest: i64,
        latest: i64,
        hosts: std::collections::HashSet<String>,
    }

    let mut runs: HashMap<String, RunAccumulator> = HashMap::new();

    for signal in &signals {
        // Use the actual run_id from the signal
        let run_id = signal.run_id.clone();

        let entry = runs.entry(run_id).or_insert_with(|| RunAccumulator {
            signals: Vec::new(),
            earliest: i64::MAX,
            latest: i64::MIN,
            hosts: std::collections::HashSet::new(),
        });

        entry.signals.push(signal);
        entry.earliest = entry.earliest.min(signal.ts);
        entry.latest = entry.latest.max(signal.ts);
        entry.hosts.insert(signal.host.clone());
    }

    let mut result: Vec<RunInfo> = runs
        .into_iter()
        .map(|(run_id, acc)| RunInfo {
            run_id,
            name: None,
            signal_count: acc.signals.len(),
            earliest_ts: acc.earliest,
            latest_ts: acc.latest,
            hosts: acc.hosts.into_iter().collect(),
            // Backwards compat - signals-only discovery doesn't have these
            profile: None,
            started_at: None,
            stopped_at: None,
            events_total: 0,
            segments_count: 0,
            facts_extracted: 0,
            status: "unknown".to_string(),
        })
        .collect();

    result.sort_by(|a, b| b.earliest_ts.cmp(&a.earliest_ts));
    Ok(result)
}

/// Convert stored signals to a snapshot for diffing
fn signals_to_snapshot(run_id: &str, signals: Vec<StoredSignal>) -> SignalSnapshot {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut snapshot_signals = HashMap::new();

    for signal in signals {
        // Compute entity key from available keys
        let entity_key = signal
            .proc_key
            .clone()
            .or_else(|| signal.file_key.clone())
            .or_else(|| signal.identity_key.clone());

        // Compute metadata hash
        let mut hasher = DefaultHasher::new();
        signal.metadata.to_string().hash(&mut hasher);
        let metadata_hash = format!("{:016x}", hasher.finish());

        let snap_signal = SnapshotSignal {
            signal_id: signal.signal_id.clone(),
            signal_type: signal.signal_type.clone(),
            severity: signal.severity.clone(),
            host: signal.host.clone(),
            ts: signal.ts,
            entity_key,
            evidence_count: signal.evidence_ptrs.len(),
            metadata_hash,
        };

        let key = snap_signal.stable_key();
        snapshot_signals.insert(key, snap_signal);
    }

    SignalSnapshot {
        run_id: run_id.to_string(),
        captured_at: chrono::Utc::now().to_rfc3339(),
        signals: snapshot_signals,
    }
}

/// Compute diff between two snapshots (internal implementation)
pub fn compute_diff(
    db: &Database,
    left_id: &str,
    right_id: &str,
) -> Result<(DiffResult, DiffMeta), String> {
    // Load left snapshot
    let left_signals = load_snapshot_signals(db, left_id)?;

    // Load right snapshot
    let right_signals = load_snapshot_signals(db, right_id)?;

    let left_snapshot = signals_to_snapshot(left_id, left_signals);
    let right_snapshot = signals_to_snapshot(right_id, right_signals);

    let left_size = left_snapshot.signals.len();
    let right_size = right_snapshot.signals.len();

    let diff = diff_snapshots(&left_snapshot, &right_snapshot);

    Ok((
        diff,
        DiffMeta {
            left_snapshot_size: left_size,
            right_snapshot_size: right_size,
            computed_at: chrono::Utc::now().to_rfc3339(),
        },
    ))
}

/// HTTP response for diff endpoint
/// Returns 402 if diff_mode entitlement is not granted.
/// Returns 200 with diff result if licensed.
pub fn diff_response(db: &Database, params: &DiffQuery) -> impl IntoResponse {
    // Check license entitlement first (runtime gate)
    if let Err(err_response) = require_diff_mode_entitlement() {
        return err_response.into_response();
    }

    match compute_diff(db, &params.left, &params.right) {
        Ok((diff, meta)) => {
            // Generate watermark for this export
            let watermark = create_watermark_from_license("diff_report").map(|wm| WatermarkInfo {
                visible: wm.to_visible_string(),
                license_id: wm.license_id,
                install_hash: wm.install_hash,
                exported_at: wm.exported_at,
            });

            (
                StatusCode::OK,
                Json(DiffResponse {
                    success: true,
                    data: Some(DiffResponseData {
                        diff,
                        meta,
                        watermark,
                    }),
                    error: None,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(DiffResponse {
                success: false,
                data: None,
                error: Some(e),
            }),
        )
            .into_response(),
    }
}

/// HTTP response for list runs endpoint
pub fn list_runs_response(db: &Database) -> impl IntoResponse {
    match list_runs_from_db(db) {
        Ok(runs) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "data": runs
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": e
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_info_serialization() {
        let info = RunInfo {
            run_id: "run_123".to_string(),
            signal_count: 5,
            earliest_ts: 1704500000000,
            latest_ts: 1704503600000,
            hosts: vec!["HOST1".to_string()],
            profile: Some("extended".to_string()),
            started_at: Some("2024-01-06T00:00:00Z".to_string()),
            stopped_at: Some("2024-01-06T01:00:00Z".to_string()),
            events_total: 1000,
            segments_count: 50,
            facts_extracted: 100,
            status: "completed".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("run_123"));
        assert!(json.contains("extended"));
        assert!(json.contains("completed"));
    }

    #[test]
    fn test_signals_to_snapshot() {
        let signals = vec![StoredSignal {
            signal_id: "sig1".to_string(),
            run_id: "test_run".to_string(),
            signal_type: "encoded_powershell".to_string(),
            severity: "high".to_string(),
            host: "HOST1".to_string(),
            ts: 1704500000000,
            ts_start: 1704500000000,
            ts_end: 1704500001000,
            proc_key: Some("proc_123".to_string()),
            file_key: None,
            identity_key: None,
            detector_id: "playbook:test".to_string(),
            detector_version: "1.0.0".to_string(),
            source_sensor: "test".to_string(),
            metadata: serde_json::json!({"test": true}),
            evidence_ptrs: vec![serde_json::json!({"stream": "test"})],
            dropped_evidence_count: 0,
        }];

        let snapshot = signals_to_snapshot("test_run", signals);
        assert_eq!(snapshot.signals.len(), 1);
        assert_eq!(snapshot.run_id, "test_run");
    }
}

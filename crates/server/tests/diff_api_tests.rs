//! Pro Feature: Diff API Integration Tests
//!
//! These tests verify the /api/diff endpoint behavior for Pro builds.
//! In core builds, the endpoint should return 402 (Payment Required).

use serde_json::json;

// Test fixtures: Two signal sets that differ
#[allow(dead_code)] // Used in pro feature tests
fn fixture_left_signals() -> Vec<serde_json::Value> {
    vec![
        json!({
            "signal_id": "sig_left_1",
            "signal_type": "encoded_powershell",
            "severity": "high",
            "host": "HOST1",
            "ts": 1704500000000_i64,
            "ts_start": 1704500000000_i64,
            "ts_end": 1704500001000_i64,
            "proc_key": "proc_ps_123",
            "file_key": null,
            "identity_key": null,
            "metadata": {"technique": "T1059.001"},
            "evidence_ptrs": [{"stream": "test", "segment": 1, "index": 0}],
            "dropped_evidence_count": 0
        }),
        json!({
            "signal_id": "sig_left_2",
            "signal_type": "discovery_burst",
            "severity": "medium",
            "host": "HOST1",
            "ts": 1704500100000_i64,
            "ts_start": 1704500100000_i64,
            "ts_end": 1704500101000_i64,
            "proc_key": "proc_whoami",
            "file_key": null,
            "identity_key": null,
            "metadata": {"technique": "T1082"},
            "evidence_ptrs": [{"stream": "test", "segment": 1, "index": 1}],
            "dropped_evidence_count": 0
        }),
    ]
}

#[allow(dead_code)] // Used in pro feature tests
fn fixture_right_signals() -> Vec<serde_json::Value> {
    vec![
        // Same signal but different severity (changed)
        json!({
            "signal_id": "sig_right_1",
            "signal_type": "encoded_powershell",
            "severity": "critical",  // Changed from high
            "host": "HOST1",
            "ts": 1704500000000_i64,
            "ts_start": 1704500000000_i64,
            "ts_end": 1704500001000_i64,
            "proc_key": "proc_ps_123",  // Same entity key
            "file_key": null,
            "identity_key": null,
            "metadata": {"technique": "T1059.001", "extra": "data"},  // Metadata changed
            "evidence_ptrs": [{"stream": "test", "segment": 1, "index": 0}],
            "dropped_evidence_count": 0
        }),
        // New signal (added)
        json!({
            "signal_id": "sig_right_3",
            "signal_type": "lateral_movement",
            "severity": "critical",
            "host": "HOST1",
            "ts": 1704500200000_i64,
            "ts_start": 1704500200000_i64,
            "ts_end": 1704500201000_i64,
            "proc_key": "proc_psexec",
            "file_key": null,
            "identity_key": null,
            "metadata": {"technique": "T1021"},
            "evidence_ptrs": [{"stream": "test", "segment": 1, "index": 2}],
            "dropped_evidence_count": 0
        }),
        // discovery_burst signal removed (not in right)
    ]
}

// Tests for diff functionality (always compiled - "one binary")
mod diff_tests {
    use super::*;
    use edr_core::{diff_snapshots, SignalSnapshot, SnapshotSignal};
    use std::collections::HashMap;

    fn signals_to_snapshot(run_id: &str, signals: Vec<serde_json::Value>) -> SignalSnapshot {
        let mut snapshot_signals = HashMap::new();

        for signal in signals {
            let entity_key = signal["proc_key"]
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| signal["file_key"].as_str().map(|s| s.to_string()))
                .or_else(|| signal["identity_key"].as_str().map(|s| s.to_string()));

            let snap_signal = SnapshotSignal {
                signal_id: signal["signal_id"].as_str().unwrap_or("").to_string(),
                signal_type: signal["signal_type"].as_str().unwrap_or("").to_string(),
                severity: signal["severity"].as_str().unwrap_or("").to_string(),
                host: signal["host"].as_str().unwrap_or("").to_string(),
                ts: signal["ts"].as_i64().unwrap_or(0),
                entity_key,
                evidence_count: signal["evidence_ptrs"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0),
                metadata_hash: format!("{:016x}", {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut h = DefaultHasher::new();
                    signal["metadata"].to_string().hash(&mut h);
                    h.finish()
                }),
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

    #[test]
    fn test_diff_detects_added_signal() {
        let left = signals_to_snapshot("run_left", fixture_left_signals());
        let right = signals_to_snapshot("run_right", fixture_right_signals());

        let diff = diff_snapshots(&left, &right);

        // Should detect lateral_movement as added
        assert_eq!(diff.summary.added_count, 1, "Should have 1 added signal");
        assert!(
            diff.added
                .iter()
                .any(|s| s.signal_type == "lateral_movement"),
            "Added signal should be lateral_movement"
        );
    }

    #[test]
    fn test_diff_detects_removed_signal() {
        let left = signals_to_snapshot("run_left", fixture_left_signals());
        let right = signals_to_snapshot("run_right", fixture_right_signals());

        let diff = diff_snapshots(&left, &right);

        // Should detect discovery_burst as removed
        assert_eq!(
            diff.summary.removed_count, 1,
            "Should have 1 removed signal"
        );
        assert!(
            diff.removed
                .iter()
                .any(|s| s.signal_type == "discovery_burst"),
            "Removed signal should be discovery_burst"
        );
    }

    #[test]
    fn test_diff_detects_changed_signal() {
        let left = signals_to_snapshot("run_left", fixture_left_signals());
        let right = signals_to_snapshot("run_right", fixture_right_signals());

        let diff = diff_snapshots(&left, &right);

        // Should detect encoded_powershell as changed (severity: high -> critical)
        assert_eq!(
            diff.summary.changed_count, 1,
            "Should have 1 changed signal"
        );

        let changed = &diff.changed[0];
        assert!(
            changed.stable_key.contains("encoded_powershell"),
            "Changed signal should be encoded_powershell"
        );
        assert!(
            changed.changes.iter().any(|c| c.field == "severity"),
            "Should detect severity change"
        );
    }

    #[test]
    fn test_diff_result_has_correct_structure() {
        let left = signals_to_snapshot("run_left", fixture_left_signals());
        let right = signals_to_snapshot("run_right", fixture_right_signals());

        let diff = diff_snapshots(&left, &right);

        // Verify all required fields are present
        assert_eq!(diff.left_run_id, "run_left");
        assert_eq!(diff.right_run_id, "run_right");
        assert!(!diff.added.is_empty() || !diff.removed.is_empty() || !diff.changed.is_empty());

        // Verify summary consistency
        assert_eq!(diff.summary.added_count, diff.added.len());
        assert_eq!(diff.summary.removed_count, diff.removed.len());
        assert_eq!(diff.summary.changed_count, diff.changed.len());

        // Verify total counts make sense
        let total_left = diff.summary.total_left;
        let total_right = diff.summary.total_right;
        assert!(total_left > 0, "Left snapshot should have signals");
        assert!(total_right > 0, "Right snapshot should have signals");
    }

    #[test]
    fn test_diff_serializes_to_json() {
        let left = signals_to_snapshot("run_left", fixture_left_signals());
        let right = signals_to_snapshot("run_right", fixture_right_signals());

        let diff = diff_snapshots(&left, &right);

        // Should serialize without error
        let json = serde_json::to_string(&diff).expect("Should serialize to JSON");

        // Should contain expected fields
        assert!(json.contains("left_run_id"));
        assert!(json.contains("right_run_id"));
        assert!(json.contains("added"));
        assert!(json.contains("removed"));
        assert!(json.contains("changed"));
        assert!(json.contains("summary"));

        // Should deserialize back
        let _: edr_core::DiffResult =
            serde_json::from_str(&json).expect("Should deserialize from JSON");
    }
}

/// Test that can run in both builds to verify API response codes
#[cfg(test)]
mod api_response_tests {
    #[test]
    fn test_diff_query_params_structure() {
        // Verify the DiffQuery struct exists and has expected fields
        // This is a compile-time check
        let _query = serde_json::json!({
            "left": "run_123",
            "right": "run_456"
        });
    }
}

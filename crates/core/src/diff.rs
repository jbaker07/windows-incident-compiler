//! Pro Feature: Diff Engine for comparing signal snapshots between runs.
//!
//! This module is only compiled when the `pro` feature is enabled.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A snapshot of signals from a single run, keyed by stable identifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSnapshot {
    /// Run identifier (e.g., "run_20260105_143000")
    pub run_id: String,
    /// Timestamp when snapshot was taken
    pub captured_at: String,
    /// Signals keyed by their stable key (signal_type|host|entity_key)
    pub signals: HashMap<String, SnapshotSignal>,
}

/// A signal within a snapshot, with fields relevant for comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotSignal {
    pub signal_id: String,
    pub signal_type: String,
    pub severity: String,
    pub host: String,
    pub ts: i64,
    /// Stable key for matching: combines proc_key, file_key, or identity_key
    pub entity_key: Option<String>,
    /// Evidence count for quick comparison
    pub evidence_count: usize,
    /// Metadata hash for detecting content changes
    pub metadata_hash: String,
}

impl SnapshotSignal {
    /// Generate stable matching key for this signal.
    /// Format: signal_type|host|entity_key
    pub fn stable_key(&self) -> String {
        let entity = self.entity_key.as_deref().unwrap_or("_none_");
        format!("{}|{}|{}", self.signal_type, self.host, entity)
    }
}

/// Result of diffing two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Left run identifier
    pub left_run_id: String,
    /// Right run identifier  
    pub right_run_id: String,
    /// Signals only in left (removed in right)
    pub removed: Vec<DiffSignal>,
    /// Signals only in right (added in right)
    pub added: Vec<DiffSignal>,
    /// Signals in both but with changes
    pub changed: Vec<ChangedSignal>,
    /// Signals identical in both
    pub unchanged_count: usize,
    /// Summary statistics
    pub summary: DiffSummary,
}

/// A signal that exists in only one snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSignal {
    pub signal_id: String,
    pub signal_type: String,
    pub severity: String,
    pub host: String,
    pub stable_key: String,
}

/// A signal that exists in both but has changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangedSignal {
    pub stable_key: String,
    pub left: SignalDelta,
    pub right: SignalDelta,
    pub changes: Vec<FieldChange>,
}

/// Condensed signal info for delta display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalDelta {
    pub signal_id: String,
    pub severity: String,
    pub evidence_count: usize,
    pub ts: i64,
}

/// A specific field that changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub left_value: String,
    pub right_value: String,
}

/// Summary statistics for the diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_left: usize,
    pub total_right: usize,
    pub added_count: usize,
    pub removed_count: usize,
    pub changed_count: usize,
    pub unchanged_count: usize,
    /// Severity breakdown of changes
    pub severity_delta: HashMap<String, i32>,
}

/// Compute diff between two signal snapshots.
pub fn diff_snapshots(left: &SignalSnapshot, right: &SignalSnapshot) -> DiffResult {
    let left_keys: HashSet<&String> = left.signals.keys().collect();
    let right_keys: HashSet<&String> = right.signals.keys().collect();

    let only_left: Vec<&String> = left_keys.difference(&right_keys).copied().collect();
    let only_right: Vec<&String> = right_keys.difference(&left_keys).copied().collect();
    let common: Vec<&String> = left_keys.intersection(&right_keys).copied().collect();

    // Build removed signals
    let removed: Vec<DiffSignal> = only_left
        .iter()
        .filter_map(|k| left.signals.get(*k))
        .map(|s| DiffSignal {
            signal_id: s.signal_id.clone(),
            signal_type: s.signal_type.clone(),
            severity: s.severity.clone(),
            host: s.host.clone(),
            stable_key: s.stable_key(),
        })
        .collect();

    // Build added signals
    let added: Vec<DiffSignal> = only_right
        .iter()
        .filter_map(|k| right.signals.get(*k))
        .map(|s| DiffSignal {
            signal_id: s.signal_id.clone(),
            signal_type: s.signal_type.clone(),
            severity: s.severity.clone(),
            host: s.host.clone(),
            stable_key: s.stable_key(),
        })
        .collect();

    // Find changed and unchanged
    let mut changed = Vec::new();
    let mut unchanged_count = 0;

    for key in common {
        let l = left.signals.get(key).unwrap();
        let r = right.signals.get(key).unwrap();

        let mut changes = Vec::new();

        if l.severity != r.severity {
            changes.push(FieldChange {
                field: "severity".to_string(),
                left_value: l.severity.clone(),
                right_value: r.severity.clone(),
            });
        }

        if l.evidence_count != r.evidence_count {
            changes.push(FieldChange {
                field: "evidence_count".to_string(),
                left_value: l.evidence_count.to_string(),
                right_value: r.evidence_count.to_string(),
            });
        }

        if l.metadata_hash != r.metadata_hash {
            changes.push(FieldChange {
                field: "metadata".to_string(),
                left_value: "(hash differs)".to_string(),
                right_value: "(hash differs)".to_string(),
            });
        }

        if changes.is_empty() {
            unchanged_count += 1;
        } else {
            changed.push(ChangedSignal {
                stable_key: key.to_string(),
                left: SignalDelta {
                    signal_id: l.signal_id.clone(),
                    severity: l.severity.clone(),
                    evidence_count: l.evidence_count,
                    ts: l.ts,
                },
                right: SignalDelta {
                    signal_id: r.signal_id.clone(),
                    severity: r.severity.clone(),
                    evidence_count: r.evidence_count,
                    ts: r.ts,
                },
                changes,
            });
        }
    }

    // Calculate severity delta
    let mut severity_delta: HashMap<String, i32> = HashMap::new();
    for s in &added {
        *severity_delta.entry(s.severity.clone()).or_insert(0) += 1;
    }
    for s in &removed {
        *severity_delta.entry(s.severity.clone()).or_insert(0) -= 1;
    }

    let summary = DiffSummary {
        total_left: left.signals.len(),
        total_right: right.signals.len(),
        added_count: added.len(),
        removed_count: removed.len(),
        changed_count: changed.len(),
        unchanged_count,
        severity_delta,
    };

    DiffResult {
        left_run_id: left.run_id.clone(),
        right_run_id: right.run_id.clone(),
        removed,
        added,
        changed,
        unchanged_count,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signal(id: &str, sig_type: &str, severity: &str, host: &str) -> SnapshotSignal {
        SnapshotSignal {
            signal_id: id.to_string(),
            signal_type: sig_type.to_string(),
            severity: severity.to_string(),
            host: host.to_string(),
            ts: 1704500000000,
            entity_key: Some(format!("proc_{}", id)),
            evidence_count: 3,
            metadata_hash: format!("hash_{}", id),
        }
    }

    #[test]
    fn test_diff_added_signal() {
        let mut left_signals = HashMap::new();
        let s1 = make_signal("sig1", "encoded_powershell", "high", "HOST1");
        left_signals.insert(s1.stable_key(), s1);

        let mut right_signals = HashMap::new();
        let s1 = make_signal("sig1", "encoded_powershell", "high", "HOST1");
        let s2 = make_signal("sig2", "lateral_movement", "critical", "HOST1");
        right_signals.insert(s1.stable_key(), s1);
        right_signals.insert(s2.stable_key(), s2);

        let left = SignalSnapshot {
            run_id: "run_left".to_string(),
            captured_at: "2026-01-05T12:00:00Z".to_string(),
            signals: left_signals,
        };

        let right = SignalSnapshot {
            run_id: "run_right".to_string(),
            captured_at: "2026-01-05T13:00:00Z".to_string(),
            signals: right_signals,
        };

        let diff = diff_snapshots(&left, &right);

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.summary.added_count, 1);
        assert_eq!(diff.added[0].signal_type, "lateral_movement");
    }

    #[test]
    fn test_diff_removed_signal() {
        let mut left_signals = HashMap::new();
        let s1 = make_signal("sig1", "encoded_powershell", "high", "HOST1");
        let s2 = make_signal("sig2", "lateral_movement", "critical", "HOST1");
        left_signals.insert(s1.stable_key(), s1);
        left_signals.insert(s2.stable_key(), s2);

        let mut right_signals = HashMap::new();
        let s1 = make_signal("sig1", "encoded_powershell", "high", "HOST1");
        right_signals.insert(s1.stable_key(), s1);

        let left = SignalSnapshot {
            run_id: "run_left".to_string(),
            captured_at: "2026-01-05T12:00:00Z".to_string(),
            signals: left_signals,
        };

        let right = SignalSnapshot {
            run_id: "run_right".to_string(),
            captured_at: "2026-01-05T13:00:00Z".to_string(),
            signals: right_signals,
        };

        let diff = diff_snapshots(&left, &right);

        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].signal_type, "lateral_movement");
    }

    #[test]
    fn test_diff_changed_severity() {
        let mut left_signals = HashMap::new();
        let s1 = make_signal("sig1", "encoded_powershell", "medium", "HOST1");
        left_signals.insert(s1.stable_key(), s1);

        let mut right_signals = HashMap::new();
        let mut s1 = make_signal("sig1", "encoded_powershell", "high", "HOST1");
        s1.signal_id = "sig1_v2".to_string(); // ID can differ
        right_signals.insert(s1.stable_key(), s1);

        let left = SignalSnapshot {
            run_id: "run_left".to_string(),
            captured_at: "2026-01-05T12:00:00Z".to_string(),
            signals: left_signals,
        };

        let right = SignalSnapshot {
            run_id: "run_right".to_string(),
            captured_at: "2026-01-05T13:00:00Z".to_string(),
            signals: right_signals,
        };

        let diff = diff_snapshots(&left, &right);

        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].changes[0].field, "severity");
        assert_eq!(diff.changed[0].changes[0].left_value, "medium");
        assert_eq!(diff.changed[0].changes[0].right_value, "high");
    }
}

//! Episode Clustering Logic (RUN_BRIEF-1 Refactor)
//!
//! Deterministic clustering of signals into activity episodes.
//! An episode is a group of signals within a time window that share the same
//! primary entity.
//!
//! ## Algorithm
//! - Sort signals by ts_start
//! - Signals within 60s of each other with same proc_key become an episode
//! - Episode inherits labels (playbook IDs) from all its signals
//! - Evidence pointers are merged from all signals in the episode
//!
//! ## Design
//! - Pure logic, no DB access
//! - Unit testable
//! - Preserves exact behavior from original locint.rs inline code

use serde::{Deserialize, Serialize};
use crate::services::evidence_ptrs::{parse_evidence_ptrs_raw, strip_playbook_prefix};

// ============================================================================
// Episode Types
// ============================================================================

/// Input signal for episode clustering
/// 
/// Corresponds to a row from the signals table, normalized for clustering.
#[derive(Debug, Clone)]
pub struct SignalForClustering {
    /// Signal identifier
    pub signal_id: String,
    /// Signal type (e.g., "playbook:persistence")
    pub signal_type: String,
    /// Start timestamp (milliseconds)
    pub ts_start: i64,
    /// End timestamp (milliseconds)
    pub ts_end: i64,
    /// Process key (entity identifier)
    pub proc_key: Option<String>,
    /// Raw evidence_ptrs JSON string
    pub evidence_ptrs_json: Option<String>,
}

/// A clustered activity episode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Episode {
    /// Episode identifier (format: "ep_{start_ts}")
    pub episode_id: String,
    /// Start timestamp (milliseconds)
    pub start_ts: i64,
    /// End timestamp (milliseconds)
    pub end_ts: i64,
    /// Primary entity (proc_key from first signal, or "unknown")
    pub primary_entity: String,
    /// Playbook labels from all signals in this episode
    pub labels: Vec<String>,
    /// Merged evidence pointers from all signals
    pub evidence_ptrs: Vec<serde_json::Value>,
}

impl Episode {
    /// Convert to serde_json::Value
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "episode_id": self.episode_id,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "primary_entity": self.primary_entity,
            "labels": self.labels,
            "evidence_ptrs": self.evidence_ptrs
        })
    }
}

// ============================================================================
// Clustering Configuration
// ============================================================================

/// Default clustering window in milliseconds (60 seconds)
pub const DEFAULT_WINDOW_MS: i64 = 60_000;

// ============================================================================
// Clustering Algorithm
// ============================================================================

/// Cluster signals into episodes
/// 
/// This implements the exact algorithm from the original locint.rs handler:
/// - Signals are processed in order of ts_start
/// - Signals within `window_ms` of each other with same entity are grouped
/// - If entity changes or time gap exceeds window, new episode starts
/// 
/// # Arguments
/// * `signals` - Signals sorted by ts_start (caller must ensure sort order)
/// * `window_ms` - Time window for clustering (default: 60,000ms = 60s)
/// 
/// # Returns
/// Vec of clustered episodes
pub fn cluster_episodes(signals: &[SignalForClustering], window_ms: i64) -> Vec<Episode> {
    let mut episodes: Vec<Episode> = Vec::new();
    let mut current_episode: Option<EpisodeBuilder> = None;
    
    for signal in signals {
        let entity = signal.proc_key.clone().unwrap_or_else(|| "unknown".to_string());
        let playbook_id = strip_playbook_prefix(&signal.signal_type).to_string();
        let evidence: Vec<serde_json::Value> = parse_evidence_ptrs_raw(signal.evidence_ptrs_json.as_deref());
        
        if let Some(mut builder) = current_episode.take() {
            if signal.ts_start <= builder.end_ts + window_ms && entity == builder.entity {
                // Extend current episode
                builder.extend(signal.ts_end, &playbook_id, evidence);
                current_episode = Some(builder);
            } else {
                // Close current episode and start new one
                episodes.push(builder.build());
                current_episode = Some(EpisodeBuilder::new(
                    signal.ts_start,
                    signal.ts_end,
                    entity,
                    playbook_id,
                    evidence,
                ));
            }
        } else {
            // Start first episode
            current_episode = Some(EpisodeBuilder::new(
                signal.ts_start,
                signal.ts_end,
                entity,
                playbook_id,
                evidence,
            ));
        }
    }
    
    // Close final episode
    if let Some(builder) = current_episode {
        episodes.push(builder.build());
    }
    
    episodes
}

/// Cluster signals using default window (60s)
pub fn cluster_episodes_default(signals: &[SignalForClustering]) -> Vec<Episode> {
    cluster_episodes(signals, DEFAULT_WINDOW_MS)
}

// ============================================================================
// Internal Builder
// ============================================================================

/// Builder for constructing episodes incrementally
struct EpisodeBuilder {
    start_ts: i64,
    end_ts: i64,
    entity: String,
    labels: Vec<String>,
    evidence_ptrs: Vec<serde_json::Value>,
}

impl EpisodeBuilder {
    fn new(
        start_ts: i64,
        end_ts: i64,
        entity: String,
        playbook_id: String,
        evidence: Vec<serde_json::Value>,
    ) -> Self {
        Self {
            start_ts,
            end_ts,
            entity,
            labels: vec![playbook_id],
            evidence_ptrs: evidence,
        }
    }
    
    fn extend(&mut self, ts_end: i64, playbook_id: &str, evidence: Vec<serde_json::Value>) {
        self.end_ts = self.end_ts.max(ts_end);
        if !self.labels.contains(&playbook_id.to_string()) {
            self.labels.push(playbook_id.to_string());
        }
        self.evidence_ptrs.extend(evidence);
    }
    
    fn build(self) -> Episode {
        Episode {
            episode_id: format!("ep_{}", self.start_ts),
            start_ts: self.start_ts,
            end_ts: self.end_ts,
            primary_entity: self.entity,
            labels: self.labels,
            evidence_ptrs: self.evidence_ptrs,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signal(
        signal_id: &str,
        signal_type: &str,
        ts_start: i64,
        ts_end: i64,
        proc_key: Option<&str>,
    ) -> SignalForClustering {
        SignalForClustering {
            signal_id: signal_id.to_string(),
            signal_type: signal_type.to_string(),
            ts_start,
            ts_end,
            proc_key: proc_key.map(|s| s.to_string()),
            evidence_ptrs_json: None,
        }
    }

    #[test]
    fn test_empty_signals() {
        let signals: Vec<SignalForClustering> = vec![];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        assert!(episodes.is_empty());
    }

    #[test]
    fn test_single_signal_becomes_single_episode() {
        let signals = vec![
            make_signal("sig1", "playbook:persistence", 1000, 2000, Some("proc1")),
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].episode_id, "ep_1000");
        assert_eq!(episodes[0].start_ts, 1000);
        assert_eq!(episodes[0].end_ts, 2000);
        assert_eq!(episodes[0].primary_entity, "proc1");
        assert_eq!(episodes[0].labels, vec!["persistence"]);
    }

    #[test]
    fn test_signals_within_window_same_entity_merge() {
        let signals = vec![
            make_signal("sig1", "playbook:persistence", 1000, 2000, Some("proc1")),
            make_signal("sig2", "playbook:execution", 50000, 60000, Some("proc1")), // within 60s window
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].episode_id, "ep_1000");
        assert_eq!(episodes[0].start_ts, 1000);
        assert_eq!(episodes[0].end_ts, 60000); // extended
        assert_eq!(episodes[0].labels, vec!["persistence", "execution"]);
    }

    #[test]
    fn test_signals_outside_window_split() {
        let signals = vec![
            make_signal("sig1", "playbook:persistence", 1000, 2000, Some("proc1")),
            make_signal("sig2", "playbook:execution", 100000, 110000, Some("proc1")), // > 60s gap
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes.len(), 2);
        assert_eq!(episodes[0].episode_id, "ep_1000");
        assert_eq!(episodes[1].episode_id, "ep_100000");
    }

    #[test]
    fn test_different_entities_split() {
        let signals = vec![
            make_signal("sig1", "playbook:persistence", 1000, 2000, Some("proc1")),
            make_signal("sig2", "playbook:execution", 3000, 4000, Some("proc2")), // different entity
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes.len(), 2);
        assert_eq!(episodes[0].primary_entity, "proc1");
        assert_eq!(episodes[1].primary_entity, "proc2");
    }

    #[test]
    fn test_unknown_entity_fallback() {
        let signals = vec![
            make_signal("sig1", "playbook:persistence", 1000, 2000, None),
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes[0].primary_entity, "unknown");
    }

    #[test]
    fn test_duplicate_labels_deduped() {
        let signals = vec![
            make_signal("sig1", "playbook:persistence", 1000, 2000, Some("proc1")),
            make_signal("sig2", "playbook:persistence", 3000, 4000, Some("proc1")), // same playbook
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].labels, vec!["persistence"]); // not duplicated
    }

    #[test]
    fn test_playbook_prefix_stripped() {
        let signals = vec![
            make_signal("sig1", "playbook:test", 1000, 2000, Some("proc1")),
            make_signal("sig2", "custom_signal", 3000, 4000, Some("proc1")),
        ];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes[0].labels, vec!["test", "custom_signal"]);
    }

    #[test]
    fn test_evidence_ptrs_merged() {
        let mut sig1 = make_signal("sig1", "playbook:p1", 1000, 2000, Some("proc1"));
        sig1.evidence_ptrs_json = Some(r#"[{"seg": "s1", "row": 1}]"#.to_string());
        
        let mut sig2 = make_signal("sig2", "playbook:p2", 3000, 4000, Some("proc1"));
        sig2.evidence_ptrs_json = Some(r#"[{"seg": "s2", "row": 2}]"#.to_string());
        
        let signals = vec![sig1, sig2];
        let episodes = cluster_episodes(&signals, DEFAULT_WINDOW_MS);
        
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].evidence_ptrs.len(), 2);
    }
}

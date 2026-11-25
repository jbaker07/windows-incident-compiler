//! Disambiguator: Computed pivots for hypothesis clarification.
//!
//! Disambiguators guide analysts and automated systems to gather
//! additional evidence that distinguishes between competing hypotheses.

use super::hypothesis_state::HypothesisState;
use super::scope_keys::ScopeKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Pivot Actions
// ============================================================================

/// Machine-executable pivot actions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
#[derive(Default)]
pub enum PivotAction {
    /// Expand time window backward
    ExpandWindowBackward { seconds: i64 },
    /// Expand time window forward
    ExpandWindowForward { seconds: i64 },
    /// Focus on a specific entity
    FocusEntity { scope_key: ScopeKey },
    /// Fetch file hash
    FetchFileHash { path: String, inode: Option<u64> },
    /// Join socket to process
    JoinSockToProc { sock_key: String },
    /// Fetch process tree
    FetchProcTree { proc_key: String, depth: u32 },
    /// Query events with filter
    QueryEvents { filter_expression: String },
    /// Enable forensic burst capture (only if live)
    EnableForensicBurst {
        ttl_seconds: i64,
        collectors: Vec<String>,
    },
    /// Request additional stream
    RequestStream { stream_id: String, reason: String },
    /// Fetch DNS resolution
    FetchDnsResolution { ip: String },
    /// Fetch signature verification
    VerifySignature { path: String },
    /// Cannot pivot due to missing capability
    CannotPivot {
        reason: String,
        required_capability: String,
    },
    /// Focus on a process tree
    FocusProcessTree { proc_key: String },
    /// Correlate across hosts
    CrossHostCorrelation { host_ids: Vec<String> },
    /// Reconstruct timeline
    TimelineReconstruction { start_ts: i64, end_ts: i64 },
    /// Expand parent process chain
    ParentChainExpansion { proc_key: String, depth: u32 },
    /// Scan child processes
    ChildProcessScan { proc_key: String, depth: u32 },
    /// No pivot available
    #[default]
    None,
}

// ============================================================================
// Expected Outcomes
// ============================================================================

/// Expected outcomes from a pivot action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutcomes {
    /// What we expect if the hypothesis is confirmed
    pub if_yes: String,
    /// What we expect if the hypothesis is refuted
    pub if_no: String,
}

// ============================================================================
// Disambiguator
// ============================================================================

/// A computed disambiguator for a hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disambiguator {
    /// Unique ID
    pub id: String,
    /// Priority (1 = highest)
    pub priority: u32,
    /// Human-readable question
    pub question_text: String,
    /// Machine-executable pivot action (also available as `action`)
    pub pivot_action: PivotAction,
    /// Alias for pivot_action for copilot compatibility
    #[serde(skip)]
    pub action: PivotAction,
    /// Rationale for this disambiguator
    pub rationale: String,
    /// Parameters for the pivot action
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    /// Expected outcomes
    pub expected_outcomes: ExpectedOutcomes,
    /// Description of evidence needed
    pub evidence_needed: String,
    /// Whether this disambiguator is actionable given current state
    pub actionable: bool,
    /// Reason if not actionable
    pub not_actionable_reason: Option<String>,
}

impl Disambiguator {
    pub fn new(
        priority: u32,
        question: impl Into<String>,
        pivot_action: PivotAction,
        if_yes: impl Into<String>,
        if_no: impl Into<String>,
        evidence_needed: impl Into<String>,
    ) -> Self {
        let question = question.into();
        let evidence_needed = evidence_needed.into();
        let id = format!("disamb_{}_{}", priority, hash_string(&question));

        Self {
            id,
            priority,
            question_text: question.clone(),
            action: pivot_action.clone(),
            pivot_action,
            rationale: evidence_needed.clone(),
            parameters: None,
            expected_outcomes: ExpectedOutcomes {
                if_yes: if_yes.into(),
                if_no: if_no.into(),
            },
            evidence_needed,
            actionable: true,
            not_actionable_reason: None,
        }
    }

    pub fn not_actionable(mut self, reason: impl Into<String>) -> Self {
        self.actionable = false;
        self.not_actionable_reason = Some(reason.into());
        self
    }
}

fn hash_string(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(&hasher.finalize()[..4])
}

// ============================================================================
// Disambiguator Generation
// ============================================================================

/// Generate disambiguators for a hypothesis (1-3)
pub fn generate_disambiguators(hypothesis: &HypothesisState) -> Vec<Disambiguator> {
    let mut disambiguators = Vec::new();

    // Priority 1: Missing REQUIRED slots
    for slot_id in hypothesis.missing_required_slots() {
        if let Some(slot) = hypothesis.get_slot(&slot_id) {
            let disamb = generate_for_missing_slot(hypothesis, &slot.slot_id, &slot.predicate_id);
            disambiguators.push(disamb);

            if disambiguators.len() >= 3 {
                return disambiguators;
            }
        }
    }

    // Priority 2: Visibility gaps
    for stream in &hypothesis.visibility_state.streams_missing {
        let disamb = generate_for_missing_stream(hypothesis, stream);
        disambiguators.push(disamb);

        if disambiguators.len() >= 3 {
            return disambiguators;
        }
    }

    // Priority 3: Cross-domain corroboration
    if hypothesis.corroboration_vector.domain_count() < 3 {
        if let Some(disamb) = generate_for_corroboration(hypothesis) {
            disambiguators.push(disamb);
        }
    }

    // Priority 4: Time window expansion
    if disambiguators.len() < 3 {
        if let Some(disamb) = generate_for_window_expansion(hypothesis) {
            disambiguators.push(disamb);
        }
    }

    disambiguators
}

/// Generate disambiguator for a missing slot
fn generate_for_missing_slot(
    hypothesis: &HypothesisState,
    slot_id: &str,
    predicate_id: &str,
) -> Disambiguator {
    let pivot_action = match predicate_id {
        pred if pred.contains("exec") || pred.contains("process") => PivotAction::FetchProcTree {
            proc_key: hypothesis.scope_key.key().to_string(),
            depth: 3,
        },
        pred if pred.contains("network") || pred.contains("connect") => PivotAction::QueryEvents {
            filter_expression: format!(
                "event_type:socket_connect AND scope_key:{}",
                hypothesis.scope_key
            ),
        },
        pred if pred.contains("file") || pred.contains("write") => PivotAction::QueryEvents {
            filter_expression: format!(
                "event_type:file_write AND scope_key:{}",
                hypothesis.scope_key
            ),
        },
        pred if pred.contains("memory") || pred.contains("alloc") => PivotAction::QueryEvents {
            filter_expression: format!(
                "event_type:memory_* AND scope_key:{}",
                hypothesis.scope_key
            ),
        },
        _ => PivotAction::ExpandWindowBackward { seconds: 300 },
    };

    Disambiguator::new(
        1,
        format!("Is there {} evidence for slot '{}'?", predicate_id, slot_id),
        pivot_action,
        format!("Slot '{}' would be filled, increasing maturity", slot_id),
        format!("Hypothesis weakened - missing required slot '{}'", slot_id),
        format!(
            "Evidence matching predicate '{}' within hypothesis window",
            predicate_id
        ),
    )
}

/// Generate disambiguator for a missing stream
fn generate_for_missing_stream(hypothesis: &HypothesisState, stream_id: &str) -> Disambiguator {
    let can_request = !stream_id.contains("kernel") && !stream_id.contains("forensic");

    let (pivot_action, actionable, not_actionable_reason) = if can_request {
        (
            PivotAction::RequestStream {
                stream_id: stream_id.to_string(),
                reason: format!("Required for hypothesis {} evaluation", hypothesis.family),
            },
            true,
            None,
        )
    } else {
        (
            PivotAction::CannotPivot {
                reason: format!(
                    "Stream '{}' requires elevated privileges or is unavailable",
                    stream_id
                ),
                required_capability: stream_id.to_string(),
            },
            false,
            Some(format!(
                "Cannot request stream '{}' - requires elevated privileges",
                stream_id
            )),
        )
    };

    let mut disamb = Disambiguator::new(
        2,
        format!("Can we enable the '{}' stream for visibility?", stream_id),
        pivot_action,
        "Stream enabled, hypothesis evaluation can proceed with full visibility".to_string(),
        format!(
            "Hypothesis evaluation degraded - '{}' stream unavailable",
            stream_id
        ),
        format!("Telemetry from '{}' stream", stream_id),
    );

    if !actionable {
        disamb = disamb.not_actionable(not_actionable_reason.unwrap());
    }

    disamb
}

/// Generate disambiguator for corroboration gaps
fn generate_for_corroboration(hypothesis: &HypothesisState) -> Option<Disambiguator> {
    // Determine which domain we're missing
    let vec = &hypothesis.corroboration_vector;

    let (missing_domain, filter, description) = if vec.network == 0 {
        (
            "network",
            "event_type:socket_*",
            "Network activity corroboration",
        )
    } else if vec.file == 0 {
        (
            "file",
            "event_type:file_*",
            "File system activity corroboration",
        )
    } else if vec.persist == 0 {
        (
            "persistence",
            "event_type:service_* OR event_type:scheduled_task_*",
            "Persistence mechanism corroboration",
        )
    } else if vec.memory == 0 {
        (
            "memory",
            "event_type:memory_*",
            "Memory operation corroboration",
        )
    } else {
        return None;
    };

    Some(Disambiguator::new(
        3,
        format!(
            "Is there {} evidence to corroborate this hypothesis?",
            missing_domain
        ),
        PivotAction::QueryEvents {
            filter_expression: format!("{} AND scope_key:{}", filter, hypothesis.scope_key),
        },
        format!(
            "Corroboration strengthened with {} domain evidence",
            missing_domain
        ),
        "Hypothesis remains single-domain, lower confidence".to_string(),
        description.to_string(),
    ))
}

/// Generate disambiguator for window expansion
fn generate_for_window_expansion(hypothesis: &HypothesisState) -> Option<Disambiguator> {
    let window_seconds = hypothesis
        .window_end_ts
        .signed_duration_since(hypothesis.window_start_ts)
        .num_seconds();

    if window_seconds < 300 {
        // Window less than 5 minutes, suggest expansion
        Some(Disambiguator::new(
            4,
            "Should we expand the time window to find antecedent activity?",
            PivotAction::ExpandWindowBackward { seconds: 300 },
            "Additional context found - antecedent activity discovered".to_string(),
            "No additional relevant activity in expanded window".to_string(),
            "Events in the 5 minutes preceding current window start".to_string(),
        ))
    } else {
        None
    }
}

// ============================================================================
// Competing Hypothesis Disambiguation
// ============================================================================

/// Generate disambiguators that distinguish between competing hypotheses
pub fn generate_competitive_disambiguators(
    hypothesis: &HypothesisState,
    competitors: &[&HypothesisState],
) -> Vec<Disambiguator> {
    let mut disambiguators = Vec::new();

    for competitor in competitors {
        if competitor.hypothesis_id == hypothesis.hypothesis_id {
            continue;
        }

        // Find slots that are satisfied in one but not the other
        let our_slots: std::collections::HashSet<_> = hypothesis
            .slot_fills
            .iter()
            .filter(|(_, f)| f.satisfied)
            .map(|(k, _)| k.as_str())
            .collect();

        let their_slots: std::collections::HashSet<_> = competitor
            .slot_fills
            .iter()
            .filter(|(_, f)| f.satisfied)
            .map(|(k, _)| k.as_str())
            .collect();

        // Slots we have that they don't
        let _our_unique: Vec<_> = our_slots.difference(&their_slots).collect();
        // Slots they have that we don't
        let their_unique: Vec<_> = their_slots.difference(&our_slots).collect();

        if !their_unique.is_empty() {
            // They have evidence we don't - can we find it?
            let slot_id = their_unique[0];
            disambiguators.push(Disambiguator::new(
                2,
                format!(
                    "Can we find '{}' evidence to match hypothesis '{}'?",
                    slot_id, competitor.family
                ),
                PivotAction::QueryEvents {
                    filter_expression: format!(
                        "slot_predicate:{} AND scope_key:{}",
                        slot_id, hypothesis.scope_key
                    ),
                },
                format!(
                    "Evidence found - supports '{}' hypothesis",
                    competitor.family
                ),
                format!(
                    "No evidence - '{}' hypothesis less likely",
                    competitor.family
                ),
                format!("Evidence for slot '{}'", slot_id),
            ));
        }

        if disambiguators.len() >= 3 {
            break;
        }
    }

    disambiguators
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::canonical_fact::FactDomain;
    use crate::hypothesis::hypothesis_state::{HypothesisState, Slot};
    use chrono::Utc;

    #[test]
    fn test_disambiguator_generation() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = Utc::now();

        let mut hypothesis = HypothesisState::new("host1", "injection", "t1", scope, ts, 600, 3600);
        hypothesis.add_required_slot(Slot::required(
            "exec",
            "Exec",
            FactDomain::Process,
            "pred_exec",
        ));
        hypothesis.add_required_slot(Slot::required(
            "connect",
            "Connect",
            FactDomain::Network,
            "pred_network",
        ));

        let disambiguators = generate_disambiguators(&hypothesis);

        // Should have disambiguators for missing required slots
        assert!(!disambiguators.is_empty());
        assert!(disambiguators.len() <= 3);
        assert_eq!(disambiguators[0].priority, 1);
    }

    #[test]
    fn test_pivot_action_serialization() {
        let action = PivotAction::ExpandWindowBackward { seconds: 300 };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("expand_window_backward"));
        assert!(json.contains("300"));
    }
}

//! Arbitration: Rank hypotheses and determine top-3 with absorption logic.

use super::canonical_event::EvidencePtr;
use super::disambiguator::Disambiguator;
use super::hypothesis_state::{FillStrength, HypothesisState, HypothesisStatus, VisibilityState};
use super::incident::Incident;
use super::promotion::{calculate_confidence, Severity};
use super::scope_keys::ScopeKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ============================================================================
// Arbitration Configuration
// ============================================================================

/// Configuration for arbitration scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrationConfig {
    /// Weight for maturity score
    pub maturity_weight: f64,
    /// Weight for confidence score
    pub confidence_weight: f64,
    /// Weight for corroboration score
    pub corroboration_weight: f64,
    /// Weight for surprise score
    pub surprise_weight: f64,
    /// Maximum overlap penalty
    pub max_overlap_penalty: f64,
}

impl Default for ArbitrationConfig {
    fn default() -> Self {
        Self {
            maturity_weight: 0.55,
            confidence_weight: 0.20,
            corroboration_weight: 0.15,
            surprise_weight: 0.10,
            max_overlap_penalty: 0.3,
        }
    }
}

// ============================================================================
// Ranked Hypothesis
// ============================================================================

/// A hypothesis with computed ranking score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedHypothesis {
    pub hypothesis_id: String,
    pub family: String,
    pub template_id: String,
    pub scope_key: ScopeKey,
    pub maturity: f64,
    pub confidence: f64,
    pub rank_score: f64,
    /// Reasons why this hypothesis ranks well
    pub why_wins: Vec<String>,
    /// Missing required slots
    pub missing_required_slots: Vec<String>,
    /// Computed disambiguators
    pub disambiguators: Vec<Disambiguator>,
    /// Severity
    pub severity: Severity,
    /// Domain count
    pub domain_count: u32,
    /// Number of required slots satisfied
    pub required_satisfied: usize,
    /// Total number of required slots
    pub required_total: usize,
    /// Key evidence pointers supporting this hypothesis
    pub key_evidence_ptrs: Vec<EvidencePtr>,
}

// ============================================================================
// Suppression Reason
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "reason_type", rename_all = "snake_case")]
pub enum SuppressionReason {
    /// Absorbed by a superset hypothesis
    Absorbed { absorbing_hypothesis_id: String },
    /// Subsumed by a higher-ranked hypothesis with same scope
    Subsumed { higher_hypothesis_id: String },
    /// Mutually exclusive with promoted hypothesis
    MutualExclusion { conflicting_hypothesis_id: String },
    /// Below rank threshold
    BelowThreshold { rank_score: f64, threshold: f64 },
    /// Expired
    Expired,
}

/// A suppressed hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedHypothesis {
    pub hypothesis_id: String,
    pub family: String,
    pub reason: SuppressionReason,
}

// ============================================================================
// Visibility Summary
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilitySummary {
    pub streams_present: Vec<String>,
    pub streams_missing: Vec<String>,
    pub degraded: bool,
    pub degraded_reasons: Vec<String>,
}

impl From<&VisibilityState> for VisibilitySummary {
    fn from(state: &VisibilityState) -> Self {
        Self {
            streams_present: state.streams_present.iter().cloned().collect(),
            streams_missing: state.streams_missing.iter().cloned().collect(),
            degraded: state.is_degraded(),
            degraded_reasons: state.degraded_reasons.clone(),
        }
    }
}

// ============================================================================
// Arbitration Response
// ============================================================================

/// Response from arbitration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrationResponse {
    /// Top 3 ranked hypotheses
    pub top3: Vec<RankedHypothesis>,
    /// Suppressed hypotheses with reasons
    pub suppressed: Vec<SuppressedHypothesis>,
    /// Absorbed hypotheses (merged into higher-ranked ones)
    pub absorbed: Vec<String>,
    /// Visibility summary
    pub visibility: VisibilitySummary,
    /// Total candidates considered
    pub total_candidates: usize,
    /// Timestamp
    pub ts: DateTime<Utc>,
}

// ============================================================================
// Arbitration Engine
// ============================================================================

/// Engine for ranking and selecting hypotheses
pub struct ArbitrationEngine {
    config: ArbitrationConfig,
}

impl ArbitrationEngine {
    pub fn new() -> Self {
        Self {
            config: ArbitrationConfig::default(),
        }
    }

    pub fn with_config(config: ArbitrationConfig) -> Self {
        Self { config }
    }

    /// Arbitrate hypotheses given a query context
    pub fn arbitrate(
        &self,
        hypotheses: &[&HypothesisState],
        focus_window: Option<(DateTime<Utc>, DateTime<Utc>)>,
        focus_scope: Option<&ScopeKey>,
        focus_families: Option<&HashSet<String>>,
        include_expired: bool,
    ) -> ArbitrationResponse {
        // Filter candidates
        let candidates: Vec<&HypothesisState> = hypotheses
            .iter()
            .filter(|h| {
                // Filter by status
                if !include_expired && h.status == HypothesisStatus::Expired {
                    return false;
                }

                // Filter by time window
                if let Some((start, end)) = focus_window {
                    if h.window_end_ts < start || h.window_start_ts > end {
                        return false;
                    }
                }

                // Filter by scope
                if let Some(scope) = focus_scope {
                    if &h.scope_key != scope {
                        return false;
                    }
                }

                // Filter by family
                if let Some(families) = focus_families {
                    if !families.contains(&h.family) {
                        return false;
                    }
                }

                true
            })
            .copied()
            .collect();

        let total_candidates = candidates.len();

        // Score all candidates
        let mut scored: Vec<(f64, &HypothesisState)> = candidates
            .iter()
            .map(|h| (self.compute_rank_score(h, &candidates), *h))
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        // Apply absorption rules
        let (kept, absorbed) = self.apply_absorption(&scored);

        // Build top 3
        let top3: Vec<RankedHypothesis> = kept
            .iter()
            .take(3)
            .map(|(score, h)| self.build_ranked_hypothesis(h, *score))
            .collect();

        // Build suppressed list
        let mut suppressed: Vec<SuppressedHypothesis> = absorbed
            .iter()
            .map(|(h, absorber_id)| SuppressedHypothesis {
                hypothesis_id: h.hypothesis_id.clone(),
                family: h.family.clone(),
                reason: SuppressionReason::Absorbed {
                    absorbing_hypothesis_id: absorber_id.clone(),
                },
            })
            .collect();

        // Add below-threshold suppressed
        for (score, h) in kept.iter().skip(3) {
            suppressed.push(SuppressedHypothesis {
                hypothesis_id: h.hypothesis_id.clone(),
                family: h.family.clone(),
                reason: SuppressionReason::BelowThreshold {
                    rank_score: *score,
                    threshold: top3.last().map(|t| t.rank_score).unwrap_or(0.0),
                },
            });
        }

        // Aggregate visibility
        let visibility = self.aggregate_visibility(&candidates);

        ArbitrationResponse {
            top3,
            suppressed,
            absorbed: Vec::new(), // Will be populated by absorption logic
            visibility,
            total_candidates,
            ts: Utc::now(),
        }
    }

    /// Compute rank score for a hypothesis
    fn compute_rank_score(&self, hypothesis: &HypothesisState, all: &[&HypothesisState]) -> f64 {
        let maturity = hypothesis.maturity_score;
        let confidence = calculate_confidence(hypothesis);
        let corroboration = (hypothesis.corroboration_vector.domain_count() as f64 / 7.0).min(1.0);
        let surprise = hypothesis.surprise_vector.score;

        // Base score
        let base = self.config.maturity_weight * maturity
            + self.config.confidence_weight * confidence
            + self.config.corroboration_weight * corroboration
            + self.config.surprise_weight * surprise;

        // Overlap penalty: reduce score if this hypothesis is a strict subchain of a higher one
        let overlap_penalty = self.compute_overlap_penalty(hypothesis, all);

        (base - overlap_penalty).max(0.0)
    }

    /// Compute overlap penalty for subchains
    fn compute_overlap_penalty(
        &self,
        hypothesis: &HypothesisState,
        all: &[&HypothesisState],
    ) -> f64 {
        for other in all {
            if other.hypothesis_id == hypothesis.hypothesis_id {
                continue;
            }

            // Check if hypothesis is a strict subchain of other
            if self.is_subchain(hypothesis, other) {
                // Penalty based on how much higher the other scores
                let other_maturity = other.maturity_score;
                if other_maturity > hypothesis.maturity_score {
                    return self.config.max_overlap_penalty
                        * (other_maturity - hypothesis.maturity_score);
                }
            }
        }
        0.0
    }

    /// Check if hypothesis A is a subchain of hypothesis B
    fn is_subchain(&self, a: &HypothesisState, b: &HypothesisState) -> bool {
        // A is subchain of B if:
        // 1. Same family
        // 2. A's scope is contained in or equal to B's scope (simplified: same scope)
        // 3. A's window is contained within B's window
        // 4. A's satisfied slots are a subset of B's satisfied slots

        if a.family != b.family {
            return false;
        }

        // Window containment
        if a.window_start_ts < b.window_start_ts || a.window_end_ts > b.window_end_ts {
            return false;
        }

        // Slot subset check
        let a_satisfied: HashSet<_> = a
            .slot_fills
            .iter()
            .filter(|(_, f)| f.satisfied)
            .map(|(k, _)| k.as_str())
            .collect();

        let b_satisfied: HashSet<_> = b
            .slot_fills
            .iter()
            .filter(|(_, f)| f.satisfied)
            .map(|(k, _)| k.as_str())
            .collect();

        // A is subchain if all A's slots are in B and B has more
        a_satisfied.is_subset(&b_satisfied) && b_satisfied.len() > a_satisfied.len()
    }

    /// Apply absorption rules
    #[allow(clippy::type_complexity)]
    fn apply_absorption<'a>(
        &self,
        scored: &[(f64, &'a HypothesisState)],
    ) -> (
        Vec<(f64, &'a HypothesisState)>,
        Vec<(&'a HypothesisState, String)>,
    ) {
        let mut kept: Vec<(f64, &'a HypothesisState)> = Vec::new();
        let mut absorbed: Vec<(&'a HypothesisState, String)> = Vec::new();

        for (score, hypothesis) in scored {
            // Check if this hypothesis should be absorbed by any kept hypothesis
            let mut should_absorb = None;

            for (_, kept_h) in &kept {
                if self.should_absorb(hypothesis, kept_h) {
                    should_absorb = Some(kept_h.hypothesis_id.clone());
                    break;
                }
            }

            if let Some(absorber_id) = should_absorb {
                absorbed.push((*hypothesis, absorber_id));
            } else {
                kept.push((*score, *hypothesis));
            }
        }

        (kept, absorbed)
    }

    /// Check if hypothesis A should be absorbed by hypothesis B
    fn should_absorb(&self, a: &HypothesisState, b: &HypothesisState) -> bool {
        // B absorbs A if:
        // 1. B is a superset chain of A
        // 2. Same scope or joinable scopes
        // 3. Window overlap

        if a.family != b.family {
            return false;
        }

        // Check window overlap
        let overlap = a.window_start_ts <= b.window_end_ts && a.window_end_ts >= b.window_start_ts;
        if !overlap {
            return false;
        }

        // Check slot superset (B contains all of A's satisfied slots)
        let a_slots: HashSet<_> = a
            .slot_fills
            .iter()
            .filter(|(_, f)| f.satisfied && f.strength == FillStrength::Strong)
            .map(|(k, _)| k.as_str())
            .collect();

        let b_slots: HashSet<_> = b
            .slot_fills
            .iter()
            .filter(|(_, f)| f.satisfied && f.strength == FillStrength::Strong)
            .map(|(k, _)| k.as_str())
            .collect();

        // B must have all of A's slots and more
        a_slots.is_subset(&b_slots) && b_slots.len() > a_slots.len()
    }

    /// Build a RankedHypothesis from state
    fn build_ranked_hypothesis(&self, h: &HypothesisState, rank_score: f64) -> RankedHypothesis {
        let mut why_wins = Vec::new();

        // Generate "why wins" reasons
        if h.all_required_satisfied() {
            why_wins.push("All required slots satisfied".to_string());
        }

        let domain_count = h.corroboration_vector.domain_count();
        if domain_count >= 3 {
            why_wins.push(format!(
                "Strong corroboration across {} domains",
                domain_count
            ));
        }

        if h.corroboration_vector.has_high_value_domain() {
            why_wins.push("High-value domain evidence (net/persist/mem)".to_string());
        }

        if h.surprise_vector.score > 0.5 {
            why_wins.push(format!(
                "High surprise score: {:.2}",
                h.surprise_vector.score
            ));
        }

        if h.maturity_score > 0.8 {
            why_wins.push(format!("High maturity: {:.2}", h.maturity_score));
        }

        // Generate disambiguators
        let disambiguators = crate::hypothesis::disambiguator::generate_disambiguators(h);

        // Count required slots
        let required_total = h.required_slots.len();
        let required_satisfied = h
            .required_slots
            .iter()
            .filter(|s| h.slot_fills.contains_key(&s.slot_id))
            .count();

        // Gather key evidence from slot fills
        let key_evidence_ptrs = h
            .slot_fills
            .values()
            .flat_map(|f| f.evidence_ptrs.clone())
            .collect();

        RankedHypothesis {
            hypothesis_id: h.hypothesis_id.clone(),
            family: h.family.clone(),
            template_id: h.template_id.clone(),
            scope_key: h.scope_key.clone(),
            maturity: h.maturity_score,
            confidence: calculate_confidence(h),
            rank_score,
            why_wins,
            missing_required_slots: h.missing_required_slots(),
            disambiguators,
            severity: crate::hypothesis::promotion::calculate_severity(h),
            domain_count,
            required_satisfied,
            required_total,
            key_evidence_ptrs,
        }
    }

    /// Aggregate visibility from all candidates
    fn aggregate_visibility(&self, candidates: &[&HypothesisState]) -> VisibilitySummary {
        let mut present: HashSet<String> = HashSet::new();
        let mut missing: HashSet<String> = HashSet::new();
        let mut reasons: Vec<String> = Vec::new();

        for h in candidates {
            present.extend(h.visibility_state.streams_present.iter().cloned());
            missing.extend(h.visibility_state.streams_missing.iter().cloned());
            reasons.extend(h.visibility_state.degraded_reasons.iter().cloned());
        }

        // Remove from missing if present in any
        missing.retain(|s| !present.contains(s));

        VisibilitySummary {
            streams_present: present.into_iter().collect(),
            streams_missing: missing.iter().cloned().collect(),
            degraded: !missing.is_empty(),
            degraded_reasons: reasons,
        }
    }
}

impl Default for ArbitrationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Arbitration for Incidents
// ============================================================================

/// Arbitrate among incidents (for display ranking)
pub fn arbitrate_incidents<'a>(incidents: &'a [&'a Incident]) -> Vec<(&'a Incident, f64)> {
    let mut scored: Vec<_> = incidents
        .iter()
        .map(|i| {
            let score = i.confidence * 0.4
                + (i.severity.score() as f64 / 5.0) * 0.4
                + (i.entities.len().min(10) as f64 / 10.0) * 0.2;
            (*i, score)
        })
        .collect();

    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::canonical_fact::FactDomain;
    use crate::hypothesis::hypothesis_state::{HypothesisState, Slot};

    #[test]
    fn test_arbitration_empty() {
        let engine = ArbitrationEngine::new();
        let result = engine.arbitrate(&[], None, None, None, false);

        assert!(result.top3.is_empty());
        assert_eq!(result.total_candidates, 0);
    }

    #[test]
    fn test_arbitration_ranking() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = Utc::now();

        let mut h1 = HypothesisState::new("host1", "injection", "t1", scope.clone(), ts, 600, 3600);
        h1.maturity_score = 0.9;

        let mut h2 = HypothesisState::new("host1", "discovery", "t2", scope.clone(), ts, 600, 3600);
        h2.maturity_score = 0.5;

        let engine = ArbitrationEngine::new();
        let result = engine.arbitrate(&[&h1, &h2], None, None, None, false);

        assert_eq!(result.top3.len(), 2);
        assert_eq!(result.top3[0].hypothesis_id, h1.hypothesis_id);
    }

    #[test]
    fn test_subchain_detection() {
        let engine = ArbitrationEngine::new();
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = Utc::now();

        let mut h1 = HypothesisState::new("host1", "injection", "t1", scope.clone(), ts, 600, 3600);
        h1.add_required_slot(Slot::required("exec", "Exec", FactDomain::Process, "pred1"));

        let mut h2 = HypothesisState::new("host1", "injection", "t1", scope.clone(), ts, 600, 3600);
        h2.add_required_slot(Slot::required("exec", "Exec", FactDomain::Process, "pred1"));
        h2.add_required_slot(Slot::required(
            "connect",
            "Connect",
            FactDomain::Network,
            "pred2",
        ));

        // h1 is NOT a subchain of h2 yet (no fills)
        assert!(!engine.is_subchain(&h1, &h2));
    }
}

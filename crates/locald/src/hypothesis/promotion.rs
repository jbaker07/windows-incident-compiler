//! Promotion Math: Maturity, Confidence, and Severity calculations.
//!
//! All calculations are deterministic and configurable.

use super::hypothesis_state::{FillStrength, HypothesisState};
use serde::{Deserialize, Serialize};

// ============================================================================
// Promotion Configuration
// ============================================================================

/// Configuration for promotion calculations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionConfig {
    /// Weight for base score (required slots ratio)
    pub base_weight: f64,
    /// Weight for corroboration factor
    pub corroboration_weight: f64,
    /// Weight for optional slots
    pub optional_weight: f64,
    /// Maximum surprise boost
    pub max_surprise_boost: f64,
    /// Maximum precision penalty
    pub max_precision_penalty: f64,
    /// Minimum domains for max corroboration factor
    pub min_domains_for_max_corroboration: u32,
    /// Promotion threshold for non-invariants
    pub promotion_threshold: f64,
    /// Minimum domains required for promotion
    pub min_domains_for_promotion: u32,
    /// Visibility gap penalty
    pub visibility_gap_penalty: f64,
    /// Critical stream penalty
    pub critical_stream_penalty: f64,
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            base_weight: 0.7,
            corroboration_weight: 0.3,
            optional_weight: 0.1,
            max_surprise_boost: 0.2,
            max_precision_penalty: 0.3,
            min_domains_for_max_corroboration: 3,
            promotion_threshold: 0.85,
            min_domains_for_promotion: 3,
            visibility_gap_penalty: 0.2,
            critical_stream_penalty: 0.2,
        }
    }
}

/// Global config instance (in production, load from file/env)
pub fn default_config() -> PromotionConfig {
    PromotionConfig::default()
}

// ============================================================================
// Maturity Score Calculation
// ============================================================================

/// Calculate maturity score for a hypothesis.
///
/// Formula:
/// - R = required_slots_count
/// - r = required_slots_satisfied_count (strong fills only)
/// - o = optional_slots_satisfied_count (strong fills)
/// - D = domain_count_satisfied
/// - C = corroboration factor = min(1.0, D / min_domains_for_max_corroboration)
/// - S = surprise_boost in [0, max_surprise_boost]
/// - P = precision_penalty in [0, max_precision_penalty]
///
/// Base = r / R
/// Maturity = clamp(Base * (base_weight + corroboration_weight * C) + optional_weight * (o / max(1, optional_count)) + S - P, 0, 1)
pub fn calculate_maturity(hypothesis: &HypothesisState) -> f64 {
    calculate_maturity_with_config(hypothesis, &default_config())
}

pub fn calculate_maturity_with_config(
    hypothesis: &HypothesisState,
    config: &PromotionConfig,
) -> f64 {
    let required_count = hypothesis.required_slots.len() as f64;
    let required_satisfied = hypothesis.required_satisfied_count() as f64;
    let optional_count = hypothesis.optional_slots.len().max(1) as f64;
    let optional_satisfied = hypothesis.optional_satisfied_count() as f64;
    let domain_count = hypothesis.corroboration_vector.domain_count() as f64;

    // Base score from required slots
    let base = if required_count > 0.0 {
        required_satisfied / required_count
    } else {
        0.0
    };

    // Corroboration factor
    let corroboration = (domain_count / config.min_domains_for_max_corroboration as f64).min(1.0);

    // Optional contribution
    let optional_contrib = config.optional_weight * (optional_satisfied / optional_count);

    // Surprise boost
    let surprise_boost = hypothesis
        .surprise_vector
        .boost()
        .min(config.max_surprise_boost);

    // Precision penalty (based on common benign patterns)
    let precision_penalty = calculate_precision_penalty(hypothesis, config);

    // Final maturity
    let maturity = base * (config.base_weight + config.corroboration_weight * corroboration)
        + optional_contrib
        + surprise_boost
        - precision_penalty;

    maturity.clamp(0.0, 1.0)
}

/// Calculate precision penalty for common benign patterns
fn calculate_precision_penalty(hypothesis: &HypothesisState, config: &PromotionConfig) -> f64 {
    // In production, this would check:
    // - Known signed browsers/dev tools
    // - Build system patterns
    // - Interactive shell context
    // For now, return 0 (no penalty)
    let _ = (hypothesis, config);
    0.0
}

// ============================================================================
// Confidence Score Calculation
// ============================================================================

/// Calculate confidence score.
///
/// Confidence = Maturity * (1 - visibility_gap_penalty)
pub fn calculate_confidence(hypothesis: &HypothesisState) -> f64 {
    calculate_confidence_with_config(hypothesis, &default_config())
}

pub fn calculate_confidence_with_config(
    hypothesis: &HypothesisState,
    config: &PromotionConfig,
) -> f64 {
    let maturity = hypothesis.maturity_score;

    let visibility_penalty = if hypothesis.visibility_state.is_degraded() {
        // Check for critical stream missing
        let critical_missing = hypothesis
            .visibility_state
            .streams_missing
            .iter()
            .any(|s| is_critical_stream(s));

        if critical_missing {
            config.critical_stream_penalty
        } else {
            config.visibility_gap_penalty
        }
    } else {
        0.0
    };

    (maturity * (1.0 - visibility_penalty)).clamp(0.0, 1.0)
}

fn is_critical_stream(stream_id: &str) -> bool {
    // Critical streams that significantly impact analysis
    matches!(
        stream_id,
        "windows_etw_process"
            | "macos_es_exec"
            | "linux_ebpf_execve"
            | "windows_etw_network"
            | "macos_es_network"
            | "linux_ebpf_connect"
    )
}

// ============================================================================
// Severity Calculation
// ============================================================================

/// Severity level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Informational => "informational",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            Severity::Informational => 1,
            Severity::Low => 2,
            Severity::Medium => 3,
            Severity::High => 4,
            Severity::Critical => 5,
        }
    }

    pub fn from_score(score: u32) -> Self {
        match score {
            0..=1 => Severity::Informational,
            2 => Severity::Low,
            3 => Severity::Medium,
            4 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

/// Family base severity mappings
pub fn family_base_severity(family: &str) -> Severity {
    match family {
        "injection" | "code_injection" => Severity::High,
        "memory_exploit" | "memory_wx" => Severity::Critical,
        "exfiltration" | "data_theft" => Severity::High,
        "persistence" => Severity::Medium,
        "credential_access" => Severity::High,
        "lateral_movement" => Severity::High,
        "privilege_escalation" => Severity::High,
        "defense_evasion" | "tamper" => Severity::High,
        "discovery" | "reconnaissance" => Severity::Low,
        "execution" => Severity::Medium,
        "initial_access" => Severity::High,
        "command_control" | "c2" => Severity::High,
        _ => Severity::Medium,
    }
}

/// Calculate severity for a hypothesis
pub fn calculate_severity(hypothesis: &HypothesisState) -> Severity {
    let mut score = family_base_severity(&hypothesis.family).score();

    // Increment for Tier-0 invariants
    if has_tier0_invariant(hypothesis) {
        score = score.saturating_add(1);
    }

    // Increment for privilege boundary
    if has_privilege_boundary(hypothesis) {
        score = score.saturating_add(1);
    }

    // Increment for persistence
    if has_persistence(hypothesis) {
        score = score.saturating_add(1);
    }

    // Increment for tamper evidence
    if has_tamper_evidence(hypothesis) {
        score = score.saturating_add(1);
    }

    // Cap at critical
    Severity::from_score(score.min(5))
}

fn has_tier0_invariant(hypothesis: &HypothesisState) -> bool {
    // Check for Tier-0 invariant triggers:
    // - MemWX near exec or memfd_exec
    // - Injection primitive + remote thread
    // - Unsigned kernel module
    // - Log clear + suspicious chain

    // Check memory domain with high count
    hypothesis.corroboration_vector.memory > 0 && hypothesis.corroboration_vector.process > 0
}

fn has_privilege_boundary(hypothesis: &HypothesisState) -> bool {
    // Check for privilege escalation slots
    hypothesis
        .slot_fills
        .keys()
        .any(|k| k.contains("privilege") || k.contains("escalation"))
}

fn has_persistence(hypothesis: &HypothesisState) -> bool {
    hypothesis.corroboration_vector.persist > 0
}

fn has_tamper_evidence(hypothesis: &HypothesisState) -> bool {
    hypothesis.corroboration_vector.tamper > 0
}

// ============================================================================
// Promotion Decision
// ============================================================================

/// Result of promotion check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionDecision {
    pub should_promote: bool,
    pub reason: PromotionReason,
    pub maturity: f64,
    pub confidence: f64,
    pub severity: Severity,
    pub domain_count: u32,
}

/// Reason for promotion decision
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionReason {
    /// All required slots satisfied
    AllRequiredSlots,
    /// Maturity threshold met with sufficient domains
    MaturityThreshold { threshold: f64 },
    /// Tier-0 invariant triggered
    Tier0Invariant { invariant: String },
    /// Not promoted: insufficient evidence
    InsufficientEvidence,
    /// Not promoted: visibility gap
    VisibilityGap { missing_streams: Vec<String> },
    /// Not promoted: below threshold
    BelowThreshold { current: f64, required: f64 },
}

/// Check if a hypothesis should be promoted to an incident
pub fn check_promotion(hypothesis: &HypothesisState) -> PromotionDecision {
    check_promotion_with_config(hypothesis, &default_config())
}

pub fn check_promotion_with_config(
    hypothesis: &HypothesisState,
    config: &PromotionConfig,
) -> PromotionDecision {
    let maturity = hypothesis.maturity_score;
    let confidence = calculate_confidence_with_config(hypothesis, config);
    let severity = calculate_severity(hypothesis);
    let domain_count = hypothesis.corroboration_vector.domain_count();

    // Check Tier-0 invariants first (always promote if triggered)
    if let Some(invariant) = check_tier0_invariants(hypothesis) {
        return PromotionDecision {
            should_promote: true,
            reason: PromotionReason::Tier0Invariant { invariant },
            maturity,
            confidence,
            severity,
            domain_count,
        };
    }

    // Check visibility gaps for required slots
    let missing_required = hypothesis.missing_required_slots();
    if !missing_required.is_empty() {
        // Check if missing slots are due to visibility gaps
        let missing_streams: Vec<String> = hypothesis
            .visibility_state
            .streams_missing
            .iter()
            .cloned()
            .collect();

        if !missing_streams.is_empty() {
            return PromotionDecision {
                should_promote: false,
                reason: PromotionReason::VisibilityGap { missing_streams },
                maturity,
                confidence,
                severity,
                domain_count,
            };
        }
    }

    // Check if all required slots are satisfied
    // Note: must have at least one slot fill to avoid promoting empty hypotheses
    if hypothesis.all_required_satisfied() && !hypothesis.slot_fills.is_empty() {
        return PromotionDecision {
            should_promote: true,
            reason: PromotionReason::AllRequiredSlots,
            maturity,
            confidence,
            severity,
            domain_count,
        };
    }

    // Check maturity threshold with domain requirements
    let has_high_value_domain = hypothesis.corroboration_vector.has_high_value_domain();

    if maturity >= config.promotion_threshold
        && domain_count >= config.min_domains_for_promotion
        && has_high_value_domain
    {
        return PromotionDecision {
            should_promote: true,
            reason: PromotionReason::MaturityThreshold {
                threshold: config.promotion_threshold,
            },
            maturity,
            confidence,
            severity,
            domain_count,
        };
    }

    // Not promoted
    PromotionDecision {
        should_promote: false,
        reason: PromotionReason::BelowThreshold {
            current: maturity,
            required: config.promotion_threshold,
        },
        maturity,
        confidence,
        severity,
        domain_count,
    }
}

/// Check for Tier-0 invariant violations
fn check_tier0_invariants(hypothesis: &HypothesisState) -> Option<String> {
    // Tier-0 invariants that always promote:

    // 1. MemWX near exec or memfd_exec
    if hypothesis
        .slot_fills
        .keys()
        .any(|k| k.contains("memwx") || k.contains("memfd_exec"))
    {
        if let Some(fill) = hypothesis
            .slot_fills
            .values()
            .find(|f| f.satisfied && f.strength == FillStrength::Strong)
        {
            if fill.slot_id.contains("memwx") || fill.slot_id.contains("memfd_exec") {
                return Some("MemWX or memfd_exec detected".to_string());
            }
        }
    }

    // 2. Injection primitive + remote thread/ptrace
    let has_injection = hypothesis
        .slot_fills
        .keys()
        .any(|k| k.contains("injection"));
    let has_remote = hypothesis
        .slot_fills
        .keys()
        .any(|k| k.contains("remote_thread") || k.contains("ptrace"));
    if has_injection && has_remote {
        return Some("Injection with remote thread/ptrace".to_string());
    }

    // 3. Unsigned kernel module load
    if hypothesis
        .slot_fills
        .keys()
        .any(|k| k.contains("kernel_module_unsigned"))
    {
        return Some("Unsigned kernel module load".to_string());
    }

    // 4. Log clear + suspicious chain
    let has_log_clear = hypothesis.corroboration_vector.tamper > 0;
    let has_suspicious = hypothesis.corroboration_vector.domain_count() >= 2;
    if has_log_clear && has_suspicious {
        return Some("Log tampering with suspicious activity chain".to_string());
    }

    None
}

// ============================================================================
// Confidence/Severity Breakdown
// ============================================================================

/// Detailed breakdown of confidence and severity factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSeverityBreakdown {
    pub maturity_score: f64,
    pub confidence_score: f64,
    pub severity: Severity,

    // Maturity components
    pub base_score: f64,
    pub corroboration_factor: f64,
    pub optional_contribution: f64,
    pub surprise_boost: f64,
    pub precision_penalty: f64,

    // Confidence components
    pub visibility_penalty: f64,

    // Severity components
    pub family_base_severity: Severity,
    pub tier0_increment: bool,
    pub privilege_increment: bool,
    pub persistence_increment: bool,
    pub tamper_increment: bool,

    // Counts
    pub required_slots_total: usize,
    pub required_slots_satisfied: usize,
    pub optional_slots_total: usize,
    pub optional_slots_satisfied: usize,
    pub domain_count: u32,
}

/// Generate detailed breakdown
pub fn generate_breakdown(hypothesis: &HypothesisState) -> ConfidenceSeverityBreakdown {
    let config = default_config();

    let required_count = hypothesis.required_slots.len();
    let required_satisfied = hypothesis.required_satisfied_count();
    let optional_count = hypothesis.optional_slots.len();
    let optional_satisfied = hypothesis.optional_satisfied_count();
    let domain_count = hypothesis.corroboration_vector.domain_count();

    let base_score = if required_count > 0 {
        required_satisfied as f64 / required_count as f64
    } else {
        0.0
    };

    let corroboration_factor =
        (domain_count as f64 / config.min_domains_for_max_corroboration as f64).min(1.0);
    let optional_contribution =
        config.optional_weight * (optional_satisfied as f64 / optional_count.max(1) as f64);
    let surprise_boost = hypothesis.surprise_vector.boost();
    let precision_penalty = calculate_precision_penalty(hypothesis, &config);

    let visibility_penalty = if hypothesis.visibility_state.is_degraded() {
        config.visibility_gap_penalty
    } else {
        0.0
    };

    ConfidenceSeverityBreakdown {
        maturity_score: hypothesis.maturity_score,
        confidence_score: calculate_confidence(hypothesis),
        severity: calculate_severity(hypothesis),
        base_score,
        corroboration_factor,
        optional_contribution,
        surprise_boost,
        precision_penalty,
        visibility_penalty,
        family_base_severity: family_base_severity(&hypothesis.family),
        tier0_increment: has_tier0_invariant(hypothesis),
        privilege_increment: has_privilege_boundary(hypothesis),
        persistence_increment: has_persistence(hypothesis),
        tamper_increment: has_tamper_evidence(hypothesis),
        required_slots_total: required_count,
        required_slots_satisfied: required_satisfied,
        optional_slots_total: optional_count,
        optional_slots_satisfied: optional_satisfied,
        domain_count,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::canonical_fact::FactDomain;
    use crate::hypothesis::hypothesis_state::Slot;
    use crate::hypothesis::scope_keys::ScopeKey;

    #[test]
    fn test_maturity_calculation() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = chrono::Utc::now();

        let mut hypothesis = HypothesisState::new(
            "host1",
            "injection",
            "template1",
            scope.clone(),
            ts,
            600,
            3600,
        );

        // Add required slots
        hypothesis.add_required_slot(Slot::required("exec", "Exec", FactDomain::Process, "pred1"));
        hypothesis.add_required_slot(Slot::required(
            "connect",
            "Connect",
            FactDomain::Network,
            "pred2",
        ));

        // Initially maturity should be 0
        let maturity = calculate_maturity(&hypothesis);
        assert_eq!(maturity, 0.0);
    }

    #[test]
    fn test_severity_calculation() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = chrono::Utc::now();

        let hypothesis =
            HypothesisState::new("host1", "injection", "template1", scope, ts, 600, 3600);

        let severity = calculate_severity(&hypothesis);
        assert_eq!(severity, Severity::High); // injection base severity
    }

    #[test]
    fn test_promotion_decision() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = chrono::Utc::now();

        let hypothesis =
            HypothesisState::new("host1", "discovery", "template1", scope, ts, 600, 3600);

        let decision = check_promotion(&hypothesis);
        assert!(!decision.should_promote);
    }
}

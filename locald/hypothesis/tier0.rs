//! Tier-0 Invariant Protection
//!
//! Tier-0 invariants are UNSUPPRESSIBLE by any analyst assertion.
//! They represent fundamental security violations that MUST surface.
//!
//! Examples:
//! - Memory with RWX permissions
//! - Process injection into protected processes
//! - Kernel integrity violations
//! - Credential dumping patterns
//!
//! Assertions can:
//! - Add context/notes to Tier-0 alerts
//! - Adjust non-Tier-0 thresholds
//! - Suppress lower-tier hypotheses
//!
//! Assertions CANNOT:
//! - Suppress Tier-0 invariant detection
//! - Lower severity of Tier-0 incidents
//! - Hide Tier-0 evidence from reports

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ============================================================================
// Tier-0 Invariant Definitions
// ============================================================================

/// Tier-0 invariant types that cannot be suppressed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier0Invariant {
    /// Memory region with RWX (read-write-execute) permissions
    MemoryRwx,
    /// Process injection into protected process (lsass, csrss, etc.)
    ProtectedProcessInjection,
    /// Direct syscall (bypassing ntdll)
    DirectSyscall,
    /// Credential access (SAM, LSASS memory, etc.)
    CredentialAccess,
    /// Kernel object tampering
    KernelObjectTamper,
    /// Boot/UEFI persistence
    BootPersistence,
    /// Security log tampering
    SecurityLogTamper,
    /// Rootkit behavior (hiding processes, files, etc.)
    RootkitBehavior,
    /// Code signing bypass
    CodeSigningBypass,
    /// Anti-forensic activity
    AntiForensic,
}

impl Tier0Invariant {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::MemoryRwx => "Memory region with read-write-execute permissions detected",
            Self::ProtectedProcessInjection => "Code injection into protected system process",
            Self::DirectSyscall => "Direct syscall bypassing standard API",
            Self::CredentialAccess => "Access to credential storage or memory",
            Self::KernelObjectTamper => "Kernel object modification detected",
            Self::BootPersistence => "Boot or UEFI persistence mechanism",
            Self::SecurityLogTamper => "Security log modification or deletion",
            Self::RootkitBehavior => "Process, file, or network hiding behavior",
            Self::CodeSigningBypass => "Code signing enforcement bypass",
            Self::AntiForensic => "Anti-forensic artifact destruction",
        }
    }

    /// All Tier-0 invariants
    pub fn all() -> &'static [Tier0Invariant] {
        &[
            Self::MemoryRwx,
            Self::ProtectedProcessInjection,
            Self::DirectSyscall,
            Self::CredentialAccess,
            Self::KernelObjectTamper,
            Self::BootPersistence,
            Self::SecurityLogTamper,
            Self::RootkitBehavior,
            Self::CodeSigningBypass,
            Self::AntiForensic,
        ]
    }

    /// Check if a predicate ID represents a Tier-0 invariant
    pub fn from_predicate(predicate_id: &str) -> Option<Self> {
        match predicate_id {
            p if p.contains("memory_rwx") || p.contains("mem_rwx") => Some(Self::MemoryRwx),
            p if p.contains("protected_process") || p.contains("lsass_inject") => {
                Some(Self::ProtectedProcessInjection)
            }
            p if p.contains("direct_syscall") || p.contains("syscall_stub") => {
                Some(Self::DirectSyscall)
            }
            p if p.contains("cred_access")
                || p.contains("sam_read")
                || p.contains("lsass_read") =>
            {
                Some(Self::CredentialAccess)
            }
            p if p.contains("kernel_tamper") || p.contains("dkom") => {
                Some(Self::KernelObjectTamper)
            }
            p if p.contains("boot_persist") || p.contains("uefi_") => Some(Self::BootPersistence),
            p if p.contains("log_tamper") || p.contains("evtx_clear") => {
                Some(Self::SecurityLogTamper)
            }
            p if p.contains("rootkit") || p.contains("process_hide") => Some(Self::RootkitBehavior),
            p if p.contains("signing_bypass") || p.contains("authenticode_bypass") => {
                Some(Self::CodeSigningBypass)
            }
            p if p.contains("anti_forensic") || p.contains("timestomp") => Some(Self::AntiForensic),
            _ => None,
        }
    }
}

// ============================================================================
// Suppression Policy
// ============================================================================

/// Policy for what can be suppressed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionPolicy {
    /// Tier-0 invariants that are NEVER suppressible (always all of them)
    pub unsuppressible_invariants: HashSet<Tier0Invariant>,
    /// Whether to allow suppression of promoted incidents
    pub allow_incident_suppression: bool,
    /// Whether to allow suppression of hypotheses
    pub allow_hypothesis_suppression: bool,
    /// Minimum severity that cannot be suppressed (if set)
    pub min_unsuppressible_severity: Option<String>,
    /// Require reference (ticket) for any suppression
    pub require_reference: bool,
}

impl Default for SuppressionPolicy {
    fn default() -> Self {
        Self {
            unsuppressible_invariants: Tier0Invariant::all().iter().copied().collect(),
            allow_incident_suppression: true,
            allow_hypothesis_suppression: true,
            min_unsuppressible_severity: None,
            require_reference: true,
        }
    }
}

impl SuppressionPolicy {
    /// Create a strict policy (Tier-0 only unsuppressible)
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create a very strict policy (Critical severity also unsuppressible)
    pub fn very_strict() -> Self {
        Self {
            min_unsuppressible_severity: Some("critical".to_string()),
            ..Self::default()
        }
    }
}

// ============================================================================
// Suppression Request
// ============================================================================

/// Request to suppress something
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRequest {
    /// What to suppress
    pub target: SuppressionTarget,
    /// Who is requesting
    pub analyst_id: String,
    /// Why
    pub reason: String,
    /// Reference (ticket, etc.)
    pub reference: Option<String>,
    /// Duration (None = permanent until removed)
    pub duration_seconds: Option<i64>,
}

/// What can be suppressed
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionTarget {
    /// A specific hypothesis
    Hypothesis { hypothesis_id: String },
    /// A specific incident
    Incident { incident_id: String },
    /// A rule/predicate for a scope
    Rule {
        predicate_id: String,
        scope_key: Option<String>,
    },
    /// All alerts from a family
    Family {
        family: String,
        scope_key: Option<String>,
    },
}

// ============================================================================
// Suppression Checker
// ============================================================================

/// Result of checking if suppression is allowed
#[derive(Debug, Clone)]
pub enum SuppressionCheckResult {
    /// Suppression is allowed
    Allowed,
    /// Suppression is denied
    Denied { reason: SuppressionDenialReason },
}

/// Why suppression was denied
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionDenialReason {
    /// Tier-0 invariant cannot be suppressed
    Tier0Invariant { invariant: Tier0Invariant },
    /// Severity too high
    SeverityTooHigh {
        severity: String,
        min_unsuppressible: String,
    },
    /// Reference required but not provided
    ReferenceRequired,
    /// Incident suppression not allowed by policy
    IncidentSuppressionDisabled,
    /// Hypothesis suppression not allowed by policy
    HypothesisSuppressionDisabled,
}

/// Checker for suppression requests
pub struct SuppressionChecker {
    policy: SuppressionPolicy,
}

impl SuppressionChecker {
    pub fn new(policy: SuppressionPolicy) -> Self {
        Self { policy }
    }

    /// Check if a suppression request is allowed
    pub fn check(
        &self,
        request: &SuppressionRequest,
        context: &SuppressionContext,
    ) -> SuppressionCheckResult {
        // Check reference requirement
        if self.policy.require_reference && request.reference.is_none() {
            return SuppressionCheckResult::Denied {
                reason: SuppressionDenialReason::ReferenceRequired,
            };
        }

        // Check Tier-0 invariants
        for invariant in &context.tier0_invariants {
            if self.policy.unsuppressible_invariants.contains(invariant) {
                return SuppressionCheckResult::Denied {
                    reason: SuppressionDenialReason::Tier0Invariant {
                        invariant: *invariant,
                    },
                };
            }
        }

        // Check severity
        if let Some(ref min_severity) = self.policy.min_unsuppressible_severity {
            if let Some(ref current_severity) = context.severity {
                if self.severity_meets_or_exceeds(current_severity, min_severity) {
                    return SuppressionCheckResult::Denied {
                        reason: SuppressionDenialReason::SeverityTooHigh {
                            severity: current_severity.clone(),
                            min_unsuppressible: min_severity.clone(),
                        },
                    };
                }
            }
        }

        // Check target type
        match request.target {
            SuppressionTarget::Incident { .. } => {
                if !self.policy.allow_incident_suppression {
                    return SuppressionCheckResult::Denied {
                        reason: SuppressionDenialReason::IncidentSuppressionDisabled,
                    };
                }
            }
            SuppressionTarget::Hypothesis { .. } => {
                if !self.policy.allow_hypothesis_suppression {
                    return SuppressionCheckResult::Denied {
                        reason: SuppressionDenialReason::HypothesisSuppressionDisabled,
                    };
                }
            }
            _ => {}
        }

        SuppressionCheckResult::Allowed
    }

    fn severity_meets_or_exceeds(&self, current: &str, threshold: &str) -> bool {
        let severity_order = ["informational", "low", "medium", "high", "critical"];
        let current_idx = severity_order
            .iter()
            .position(|&s| s == current.to_lowercase());
        let threshold_idx = severity_order
            .iter()
            .position(|&s| s == threshold.to_lowercase());

        match (current_idx, threshold_idx) {
            (Some(c), Some(t)) => c >= t,
            _ => false,
        }
    }
}

/// Context for suppression check
#[derive(Debug, Clone, Default)]
pub struct SuppressionContext {
    /// Tier-0 invariants present in target
    pub tier0_invariants: Vec<Tier0Invariant>,
    /// Severity of target
    pub severity: Option<String>,
    /// Predicates involved
    pub predicates: Vec<String>,
}

impl SuppressionContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_predicates(mut self, predicates: Vec<String>) -> Self {
        // Auto-detect Tier-0 invariants from predicates
        for pred in &predicates {
            if let Some(invariant) = Tier0Invariant::from_predicate(pred) {
                self.tier0_invariants.push(invariant);
            }
        }
        self.predicates = predicates;
        self
    }

    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }

    pub fn with_tier0(mut self, invariant: Tier0Invariant) -> Self {
        self.tier0_invariants.push(invariant);
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier0_invariant_detection() {
        assert!(Tier0Invariant::from_predicate("memory_rwx_allocation").is_some());
        assert!(Tier0Invariant::from_predicate("lsass_inject_attempt").is_some());
        assert!(Tier0Invariant::from_predicate("process_exec").is_none());
    }

    #[test]
    fn test_suppression_denied_for_tier0() {
        let policy = SuppressionPolicy::strict();
        let checker = SuppressionChecker::new(policy);

        let request = SuppressionRequest {
            target: SuppressionTarget::Hypothesis {
                hypothesis_id: "hyp_123".to_string(),
            },
            analyst_id: "analyst@example.com".to_string(),
            reason: "False positive".to_string(),
            reference: Some("JIRA-1234".to_string()),
            duration_seconds: None,
        };

        // Context with Tier-0 invariant
        let context = SuppressionContext::new().with_tier0(Tier0Invariant::MemoryRwx);

        let result = checker.check(&request, &context);
        assert!(matches!(result, SuppressionCheckResult::Denied { .. }));
    }

    #[test]
    fn test_suppression_allowed_without_tier0() {
        let policy = SuppressionPolicy::strict();
        let checker = SuppressionChecker::new(policy);

        let request = SuppressionRequest {
            target: SuppressionTarget::Hypothesis {
                hypothesis_id: "hyp_123".to_string(),
            },
            analyst_id: "analyst@example.com".to_string(),
            reason: "False positive".to_string(),
            reference: Some("JIRA-1234".to_string()),
            duration_seconds: None,
        };

        // Context without Tier-0 invariant
        let context = SuppressionContext::new()
            .with_severity("medium")
            .with_predicates(vec!["process_exec".to_string()]);

        let result = checker.check(&request, &context);
        assert!(matches!(result, SuppressionCheckResult::Allowed));
    }

    #[test]
    fn test_reference_required() {
        let policy = SuppressionPolicy::strict();
        let checker = SuppressionChecker::new(policy);

        let request = SuppressionRequest {
            target: SuppressionTarget::Hypothesis {
                hypothesis_id: "hyp_123".to_string(),
            },
            analyst_id: "analyst@example.com".to_string(),
            reason: "False positive".to_string(),
            reference: None, // No reference!
            duration_seconds: None,
        };

        let context = SuppressionContext::new();
        let result = checker.check(&request, &context);

        assert!(matches!(
            result,
            SuppressionCheckResult::Denied {
                reason: SuppressionDenialReason::ReferenceRequired
            }
        ));
    }
}

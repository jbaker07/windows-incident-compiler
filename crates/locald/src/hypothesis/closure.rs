//! Incident Closure Semantics
//!
//! Deterministic rules for when an incident closes, reopens, or merges.
//! Prevents duplicated incidents and confusing PDFs.

use super::ordering::LateArrivalAction;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Closure Policy
// ============================================================================

/// Policy for incident lifecycle management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosurePolicy {
    /// TTL after last activity before auto-close
    pub inactivity_ttl: Duration,
    /// Maximum incident duration before forced close
    pub max_duration: Duration,
    /// Whether checkpoints can close incidents
    pub checkpoint_closes: bool,
    /// Window after close during which reopen is allowed
    pub reopen_window: Duration,
    /// Maximum times an incident can be reopened
    pub max_reopens: u32,
    /// Whether to allow analyst manual close
    pub allow_manual_close: bool,
    /// Whether to allow analyst manual reopen
    pub allow_manual_reopen: bool,
}

impl Default for ClosurePolicy {
    fn default() -> Self {
        Self {
            inactivity_ttl: Duration::hours(1),
            max_duration: Duration::hours(24),
            checkpoint_closes: false,
            reopen_window: Duration::minutes(15),
            max_reopens: 3,
            allow_manual_close: true,
            allow_manual_reopen: true,
        }
    }
}

// ============================================================================
// Incident Lifecycle State
// ============================================================================

/// Lifecycle state of an incident
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentLifecycleState {
    /// Actively receiving evidence
    Active,
    /// No recent activity, may auto-close soon
    Stale,
    /// Closed due to inactivity
    ClosedInactivity,
    /// Closed due to TTL
    ClosedTtl,
    /// Closed by analyst
    ClosedManual,
    /// Closed by checkpoint
    ClosedCheckpoint,
    /// Reopened after closure
    Reopened,
    /// Merged into another incident
    Merged,
    /// Suppressed (false positive)
    Suppressed,
}

impl IncidentLifecycleState {
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Active | Self::Stale | Self::Reopened)
    }

    pub fn is_closed(&self) -> bool {
        matches!(
            self,
            Self::ClosedInactivity
                | Self::ClosedTtl
                | Self::ClosedManual
                | Self::ClosedCheckpoint
                | Self::Merged
                | Self::Suppressed
        )
    }

    pub fn can_reopen(&self) -> bool {
        matches!(
            self,
            Self::ClosedInactivity | Self::ClosedTtl | Self::ClosedCheckpoint
        )
    }
}

// ============================================================================
// Lifecycle Tracking
// ============================================================================

/// Tracks the full lifecycle of an incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentLifecycle {
    /// Incident ID
    pub incident_id: String,
    /// Current state
    pub state: IncidentLifecycleState,
    /// When the incident was created
    pub created_at: DateTime<Utc>,
    /// When the incident was last updated
    pub last_activity: DateTime<Utc>,
    /// When the incident was closed (if closed)
    pub closed_at: Option<DateTime<Utc>>,
    /// Number of times reopened
    pub reopen_count: u32,
    /// Full state transition history
    pub transitions: Vec<StateTransition>,
    /// If merged, the target incident ID
    pub merged_into: Option<String>,
}

/// A state transition record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_state: IncidentLifecycleState,
    pub to_state: IncidentLifecycleState,
    pub ts: DateTime<Utc>,
    pub trigger: TransitionTrigger,
    pub actor: Option<String>,
    pub reason: Option<String>,
}

/// What triggered a state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    /// Initial creation
    Created,
    /// New evidence received
    NewEvidence,
    /// Inactivity timeout
    InactivityTimeout,
    /// TTL expiration
    TtlExpiration,
    /// Analyst action
    AnalystAction,
    /// Checkpoint created
    Checkpoint,
    /// Late event arrival
    LateEvent,
    /// Merge with another incident
    Merge,
    /// System decision
    System,
}

impl IncidentLifecycle {
    pub fn new(incident_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            incident_id: incident_id.into(),
            state: IncidentLifecycleState::Active,
            created_at: now,
            last_activity: now,
            closed_at: None,
            reopen_count: 0,
            transitions: vec![StateTransition {
                from_state: IncidentLifecycleState::Active,
                to_state: IncidentLifecycleState::Active,
                ts: now,
                trigger: TransitionTrigger::Created,
                actor: None,
                reason: Some("Initial creation".to_string()),
            }],
            merged_into: None,
        }
    }

    /// Transition to a new state
    pub fn transition(
        &mut self,
        new_state: IncidentLifecycleState,
        trigger: TransitionTrigger,
        actor: Option<String>,
        reason: Option<String>,
    ) -> Result<(), LifecycleError> {
        // Validate transition
        self.validate_transition(new_state)?;

        let transition = StateTransition {
            from_state: self.state,
            to_state: new_state,
            ts: Utc::now(),
            trigger,
            actor,
            reason,
        };

        self.transitions.push(transition);
        self.state = new_state;

        // Update timestamps
        if new_state.is_closed() {
            self.closed_at = Some(Utc::now());
        } else if matches!(new_state, IncidentLifecycleState::Reopened) {
            self.closed_at = None;
            self.reopen_count += 1;
        }

        Ok(())
    }

    fn validate_transition(&self, new_state: IncidentLifecycleState) -> Result<(), LifecycleError> {
        match (self.state, new_state) {
            // Can't transition from merged/suppressed
            (IncidentLifecycleState::Merged, _) => Err(LifecycleError {
                kind: LifecycleErrorKind::InvalidTransition {
                    from: self.state,
                    to: new_state,
                    reason: "Merged incidents cannot transition".to_string(),
                },
            }),
            (IncidentLifecycleState::Suppressed, new)
                if new != IncidentLifecycleState::Reopened =>
            {
                Err(LifecycleError {
                    kind: LifecycleErrorKind::InvalidTransition {
                        from: self.state,
                        to: new_state,
                        reason: "Suppressed incidents can only be reopened".to_string(),
                    },
                })
            }
            // Can't close what's already closed
            (from, to) if from.is_closed() && to.is_closed() => Err(LifecycleError {
                kind: LifecycleErrorKind::InvalidTransition {
                    from: self.state,
                    to: new_state,
                    reason: "Already closed".to_string(),
                },
            }),
            _ => Ok(()),
        }
    }

    /// Record new activity
    pub fn record_activity(&mut self) {
        self.last_activity = Utc::now();
        if matches!(self.state, IncidentLifecycleState::Stale) {
            let _ = self.transition(
                IncidentLifecycleState::Active,
                TransitionTrigger::NewEvidence,
                None,
                Some("New activity received".to_string()),
            );
        }
    }

    /// Get time since last activity
    pub fn time_since_activity(&self) -> Duration {
        Utc::now().signed_duration_since(self.last_activity)
    }

    /// Get incident duration
    pub fn duration(&self) -> Duration {
        let end = self.closed_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.created_at)
    }
}

/// Lifecycle operation error
#[derive(Debug, Clone)]
pub struct LifecycleError {
    pub kind: LifecycleErrorKind,
}

#[derive(Debug, Clone)]
pub enum LifecycleErrorKind {
    InvalidTransition {
        from: IncidentLifecycleState,
        to: IncidentLifecycleState,
        reason: String,
    },
    MaxReopensExceeded,
    ReopenWindowExpired,
    NotCloseable,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            LifecycleErrorKind::InvalidTransition { from, to, reason } => {
                write!(
                    f,
                    "Invalid transition from {:?} to {:?}: {}",
                    from, to, reason
                )
            }
            LifecycleErrorKind::MaxReopensExceeded => {
                write!(f, "Maximum number of reopens exceeded")
            }
            LifecycleErrorKind::ReopenWindowExpired => {
                write!(f, "Reopen window has expired")
            }
            LifecycleErrorKind::NotCloseable => {
                write!(f, "Incident is not in a closeable state")
            }
        }
    }
}

impl std::error::Error for LifecycleError {}

impl From<LifecycleErrorKind> for LifecycleError {
    fn from(kind: LifecycleErrorKind) -> Self {
        Self { kind }
    }
}

// ============================================================================
// Lifecycle Manager
// ============================================================================

/// Manages incident lifecycle transitions
pub struct LifecycleManager {
    policy: ClosurePolicy,
}

impl LifecycleManager {
    pub fn new(policy: ClosurePolicy) -> Self {
        Self { policy }
    }

    /// Check if an incident should auto-close
    pub fn should_auto_close(
        &self,
        lifecycle: &IncidentLifecycle,
    ) -> Option<IncidentLifecycleState> {
        if !lifecycle.state.is_open() {
            return None;
        }

        // Check max duration
        if lifecycle.duration() > self.policy.max_duration {
            return Some(IncidentLifecycleState::ClosedTtl);
        }

        // Check inactivity
        if lifecycle.time_since_activity() > self.policy.inactivity_ttl {
            return Some(IncidentLifecycleState::ClosedInactivity);
        }

        // Check if should mark as stale
        let stale_threshold = self.policy.inactivity_ttl / 2;
        if lifecycle.time_since_activity() > stale_threshold
            && matches!(lifecycle.state, IncidentLifecycleState::Active)
        {
            // Not a close, but could trigger staleness
        }

        None
    }

    /// Check if an incident can be reopened
    pub fn can_reopen(&self, lifecycle: &IncidentLifecycle) -> Result<(), LifecycleError> {
        if !lifecycle.state.can_reopen() {
            return Err(LifecycleErrorKind::InvalidTransition {
                from: lifecycle.state,
                to: IncidentLifecycleState::Reopened,
                reason: "State does not allow reopening".to_string(),
            }
            .into());
        }

        if lifecycle.reopen_count >= self.policy.max_reopens {
            return Err(LifecycleErrorKind::MaxReopensExceeded.into());
        }

        if let Some(closed_at) = lifecycle.closed_at {
            let time_since_close = Utc::now().signed_duration_since(closed_at);
            if time_since_close > self.policy.reopen_window {
                return Err(LifecycleErrorKind::ReopenWindowExpired.into());
            }
        }

        Ok(())
    }

    /// Handle a late event for an incident
    pub fn handle_late_event(
        &self,
        lifecycle: &mut IncidentLifecycle,
        late_action: LateArrivalAction,
    ) -> LateEventResult {
        match late_action {
            LateArrivalAction::ProcessNormal | LateArrivalAction::UpdateHypothesis => {
                if lifecycle.state.is_open() {
                    lifecycle.record_activity();
                    LateEventResult::Processed
                } else {
                    LateEventResult::Ignored {
                        reason: "Incident closed".to_string(),
                    }
                }
            }
            LateArrivalAction::MayReopenIncident => {
                if lifecycle.state.is_open() {
                    lifecycle.record_activity();
                    LateEventResult::Processed
                } else if self.can_reopen(lifecycle).is_ok() {
                    LateEventResult::ShouldReopen
                } else {
                    LateEventResult::LateEnrichment
                }
            }
            LateArrivalAction::LateEnrichmentOnly => LateEventResult::LateEnrichment,
            LateArrivalAction::Reject => LateEventResult::Rejected {
                reason: "Event too old".to_string(),
            },
        }
    }

    /// Close an incident manually
    pub fn close_manual(
        &self,
        lifecycle: &mut IncidentLifecycle,
        actor: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), LifecycleError> {
        if !self.policy.allow_manual_close {
            return Err(LifecycleErrorKind::NotCloseable.into());
        }

        lifecycle.transition(
            IncidentLifecycleState::ClosedManual,
            TransitionTrigger::AnalystAction,
            Some(actor.into()),
            Some(reason.into()),
        )
    }

    /// Reopen an incident manually
    pub fn reopen_manual(
        &self,
        lifecycle: &mut IncidentLifecycle,
        actor: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), LifecycleError> {
        if !self.policy.allow_manual_reopen {
            return Err(LifecycleErrorKind::InvalidTransition {
                from: lifecycle.state,
                to: IncidentLifecycleState::Reopened,
                reason: "Manual reopen not allowed".to_string(),
            }
            .into());
        }

        self.can_reopen(lifecycle)?;

        lifecycle.transition(
            IncidentLifecycleState::Reopened,
            TransitionTrigger::AnalystAction,
            Some(actor.into()),
            Some(reason.into()),
        )
    }

    /// Mark an incident as merged
    pub fn merge_into(
        &self,
        lifecycle: &mut IncidentLifecycle,
        target_incident_id: impl Into<String>,
    ) -> Result<(), LifecycleError> {
        let target = target_incident_id.into();
        lifecycle.merged_into = Some(target.clone());
        lifecycle.transition(
            IncidentLifecycleState::Merged,
            TransitionTrigger::Merge,
            None,
            Some(format!("Merged into {}", target)),
        )
    }
}

/// Result of handling a late event
#[derive(Debug, Clone)]
pub enum LateEventResult {
    /// Event was processed normally
    Processed,
    /// Incident should be reopened
    ShouldReopen,
    /// Added as late enrichment only
    LateEnrichment,
    /// Event was ignored
    Ignored { reason: String },
    /// Event was rejected
    Rejected { reason: String },
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_creation() {
        let lifecycle = IncidentLifecycle::new("inc_123");
        assert_eq!(lifecycle.state, IncidentLifecycleState::Active);
        assert!(lifecycle.state.is_open());
        assert_eq!(lifecycle.reopen_count, 0);
    }

    #[test]
    fn test_lifecycle_transitions() {
        let mut lifecycle = IncidentLifecycle::new("inc_123");

        // Close due to inactivity
        let result = lifecycle.transition(
            IncidentLifecycleState::ClosedInactivity,
            TransitionTrigger::InactivityTimeout,
            None,
            Some("No activity".to_string()),
        );
        assert!(result.is_ok());
        assert!(lifecycle.state.is_closed());

        // Reopen
        let result = lifecycle.transition(
            IncidentLifecycleState::Reopened,
            TransitionTrigger::LateEvent,
            None,
            Some("Late event".to_string()),
        );
        assert!(result.is_ok());
        assert!(lifecycle.state.is_open());
        assert_eq!(lifecycle.reopen_count, 1);
    }

    #[test]
    fn test_invalid_transition() {
        let mut lifecycle = IncidentLifecycle::new("inc_123");

        // Merge
        lifecycle.merged_into = Some("inc_456".to_string());
        let result = lifecycle.transition(
            IncidentLifecycleState::Merged,
            TransitionTrigger::Merge,
            None,
            None,
        );
        assert!(result.is_ok());

        // Try to transition from merged
        let result = lifecycle.transition(
            IncidentLifecycleState::Active,
            TransitionTrigger::NewEvidence,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_lifecycle_manager() {
        let policy = ClosurePolicy {
            max_reopens: 2,
            ..Default::default()
        };
        let manager = LifecycleManager::new(policy);
        let mut lifecycle = IncidentLifecycle::new("inc_123");

        // Close and reopen twice
        for _i in 0..2 {
            lifecycle
                .transition(
                    IncidentLifecycleState::ClosedInactivity,
                    TransitionTrigger::InactivityTimeout,
                    None,
                    None,
                )
                .unwrap();

            assert!(manager.can_reopen(&lifecycle).is_ok());
            lifecycle
                .transition(
                    IncidentLifecycleState::Reopened,
                    TransitionTrigger::LateEvent,
                    None,
                    None,
                )
                .unwrap();
        }

        // Third close
        lifecycle
            .transition(
                IncidentLifecycleState::ClosedInactivity,
                TransitionTrigger::InactivityTimeout,
                None,
                None,
            )
            .unwrap();

        // Should not be able to reopen a third time
        assert!(manager.can_reopen(&lifecycle).is_err());
    }
}

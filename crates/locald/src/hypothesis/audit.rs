//! Trust and Suppression Audit Trail
//!
//! Every trust/suppression change is treated like a code change:
//! - Who made it
//! - When
//! - Why (link to ticket/policy)
//! - Reversible/rollback support

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ============================================================================
// Audit Entry Types
// ============================================================================

/// An auditable action in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique ID for this entry (hash of content)
    pub id: String,
    /// When the action occurred
    pub timestamp: DateTime<Utc>,
    /// Type of action
    pub action: AuditAction,
    /// Who performed the action
    pub actor: Actor,
    /// Target of the action
    pub target: AuditTarget,
    /// Previous state (for rollback)
    pub previous_state: Option<serde_json::Value>,
    /// New state
    pub new_state: serde_json::Value,
    /// Reason/justification
    pub reason: String,
    /// Link to ticket/policy
    pub reference: Option<AuditReference>,
    /// Whether this action can be rolled back
    pub reversible: bool,
    /// If this was a rollback, the entry being rolled back
    pub rollback_of: Option<String>,
}

impl AuditEntry {
    pub fn compute_id(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", self.action).as_bytes());
        hasher.update(format!("{:?}", self.actor).as_bytes());
        hasher.update(format!("{:?}", self.target).as_bytes());
        hasher.update(serde_json::to_vec(&self.new_state).unwrap_or_default());
        self.id = hex::encode(&hasher.finalize()[..16]);
    }
}

/// Type of auditable action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Trust level changed
    TrustChange,
    /// Rule suppressed
    RuleSuppressed,
    /// Rule unsuppressed
    RuleUnsuppressed,
    /// Incident suppressed (false positive)
    IncidentSuppressed,
    /// Incident unsuppressed
    IncidentUnsuppressed,
    /// Evidence excluded
    EvidenceExcluded,
    /// Evidence re-included
    EvidenceIncluded,
    /// Threshold modified
    ThresholdModified,
    /// Allowlist entry added
    AllowlistAdded,
    /// Allowlist entry removed
    AllowlistRemoved,
    /// Policy changed
    PolicyChanged,
    /// Configuration changed
    ConfigChanged,
    /// Manual score override
    ScoreOverride,
    /// Rollback of previous action
    Rollback,
    /// Event rejected due to late arrival
    EventRejectedLate,
    /// Event accepted as late enrichment only
    EventLateEnrichment,
}

/// Who performed an action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    /// Actor type
    pub actor_type: ActorType,
    /// Unique identifier (username, service name, etc.)
    pub id: String,
    /// Human-readable name
    pub name: Option<String>,
    /// Session/request context
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// Human analyst
    Analyst,
    /// Automated system/service
    System,
    /// API integration
    Api,
    /// Policy engine
    Policy,
    /// Scheduled job
    Scheduler,
}

/// Target of an auditable action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTarget {
    /// A specific rule
    Rule {
        rule_id: String,
        rule_name: Option<String>,
    },
    /// An incident
    Incident { incident_id: String },
    /// An evidence item
    Evidence {
        evidence_id: String,
        incident_id: Option<String>,
    },
    /// A hypothesis
    Hypothesis { hypothesis_id: String },
    /// A trust configuration
    TrustConfig { config_key: String },
    /// A threshold
    Threshold { threshold_name: String },
    /// An allowlist
    Allowlist {
        list_name: String,
        entry: Option<String>,
    },
    /// Global policy
    GlobalPolicy { policy_name: String },
    /// Session configuration
    SessionConfig { session_id: String },
}

/// Reference to external justification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReference {
    /// Type of reference
    pub ref_type: ReferenceType,
    /// Reference ID (ticket number, policy ID, etc.)
    pub id: String,
    /// URL if available
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    /// Ticket/issue
    Ticket,
    /// Policy document
    Policy,
    /// Change request
    ChangeRequest,
    /// Runbook
    Runbook,
    /// Manual override (no external reference)
    Manual,
}

// ============================================================================
// Audit Log
// ============================================================================

/// Append-only audit log with rollback support
pub struct AuditLog {
    /// All entries in order
    entries: Vec<AuditEntry>,
    /// Index by target for fast lookup
    by_target: HashMap<String, Vec<usize>>,
    /// Index by action type
    by_action: HashMap<AuditAction, Vec<usize>>,
    /// Whether to require references for certain actions
    require_references: bool,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            by_target: HashMap::new(),
            by_action: HashMap::new(),
            require_references: false,
        }
    }

    pub fn with_required_references(mut self) -> Self {
        self.require_references = true;
        self
    }

    /// Record an audit entry
    pub fn record(&mut self, mut entry: AuditEntry) -> Result<String, AuditError> {
        // Validate
        self.validate(&entry)?;

        // Compute ID
        entry.compute_id();
        let id = entry.id.clone();
        let idx = self.entries.len();

        // Index by target
        let target_key = self.target_key(&entry.target);
        self.by_target.entry(target_key).or_default().push(idx);

        // Index by action
        self.by_action
            .entry(entry.action.clone())
            .or_default()
            .push(idx);

        self.entries.push(entry);
        Ok(id)
    }

    fn validate(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        // Check for required reference
        if self.require_references && entry.reference.is_none() {
            match entry.action {
                AuditAction::RuleSuppressed
                | AuditAction::IncidentSuppressed
                | AuditAction::PolicyChanged
                | AuditAction::ThresholdModified => {
                    return Err(AuditError::ReferenceRequired {
                        action: entry.action.clone(),
                    });
                }
                _ => {}
            }
        }

        // Validate rollback target exists
        if let Some(ref rollback_of) = entry.rollback_of {
            if !self.entries.iter().any(|e| e.id == *rollback_of) {
                return Err(AuditError::RollbackTargetNotFound {
                    id: rollback_of.clone(),
                });
            }
        }

        Ok(())
    }

    fn target_key(&self, target: &AuditTarget) -> String {
        match target {
            AuditTarget::Rule { rule_id, .. } => format!("rule:{}", rule_id),
            AuditTarget::Incident { incident_id } => format!("incident:{}", incident_id),
            AuditTarget::Evidence { evidence_id, .. } => format!("evidence:{}", evidence_id),
            AuditTarget::Hypothesis { hypothesis_id } => format!("hypothesis:{}", hypothesis_id),
            AuditTarget::TrustConfig { config_key } => format!("trust:{}", config_key),
            AuditTarget::Threshold { threshold_name } => format!("threshold:{}", threshold_name),
            AuditTarget::Allowlist { list_name, .. } => format!("allowlist:{}", list_name),
            AuditTarget::GlobalPolicy { policy_name } => format!("policy:{}", policy_name),
            AuditTarget::SessionConfig { session_id } => format!("session:{}", session_id),
        }
    }

    /// Get all entries for a target
    pub fn get_for_target(&self, target: &AuditTarget) -> Vec<&AuditEntry> {
        let key = self.target_key(target);
        self.by_target
            .get(&key)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Get all entries of a specific action type
    pub fn get_by_action(&self, action: &AuditAction) -> Vec<&AuditEntry> {
        self.by_action
            .get(action)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }

    /// Get an entry by ID
    pub fn get(&self, id: &str) -> Option<&AuditEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Check if an action can be rolled back
    pub fn can_rollback(&self, id: &str) -> RollbackCheck {
        let Some(entry) = self.get(id) else {
            return RollbackCheck::NotFound;
        };

        if !entry.reversible {
            return RollbackCheck::NotReversible;
        }

        if entry.previous_state.is_none() {
            return RollbackCheck::NoPreviousState;
        }

        // Check if already rolled back
        let already_rolled_back = self
            .entries
            .iter()
            .any(|e| e.rollback_of.as_ref() == Some(&entry.id));

        if already_rolled_back {
            return RollbackCheck::AlreadyRolledBack;
        }

        RollbackCheck::CanRollback {
            previous_state: entry.previous_state.clone().unwrap(),
        }
    }

    /// Create a rollback entry
    pub fn create_rollback(
        &self,
        id: &str,
        actor: Actor,
        reason: String,
    ) -> Result<AuditEntry, AuditError> {
        let check = self.can_rollback(id);
        let previous_state = match check {
            RollbackCheck::CanRollback { previous_state } => previous_state,
            RollbackCheck::NotFound => {
                return Err(AuditError::EntryNotFound { id: id.to_string() });
            }
            RollbackCheck::NotReversible => {
                return Err(AuditError::NotReversible { id: id.to_string() });
            }
            RollbackCheck::NoPreviousState => {
                return Err(AuditError::NoPreviousState { id: id.to_string() });
            }
            RollbackCheck::AlreadyRolledBack => {
                return Err(AuditError::AlreadyRolledBack { id: id.to_string() });
            }
        };

        let original = self.get(id).unwrap();

        Ok(AuditEntry {
            id: String::new(), // Will be computed
            timestamp: Utc::now(),
            action: AuditAction::Rollback,
            actor,
            target: original.target.clone(),
            previous_state: Some(original.new_state.clone()),
            new_state: previous_state,
            reason,
            reference: None,
            reversible: true,
            rollback_of: Some(id.to_string()),
        })
    }

    /// Get all entries
    pub fn all_entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get entries in a time range
    pub fn entries_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Get recent entries
    pub fn recent(&self, count: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(count).collect()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of checking if an entry can be rolled back
#[derive(Debug, Clone)]
pub enum RollbackCheck {
    NotFound,
    NotReversible,
    NoPreviousState,
    AlreadyRolledBack,
    CanRollback { previous_state: serde_json::Value },
}

// ============================================================================
// Audit Errors
// ============================================================================

#[derive(Debug, Clone)]
pub enum AuditError {
    ReferenceRequired { action: AuditAction },
    RollbackTargetNotFound { id: String },
    EntryNotFound { id: String },
    NotReversible { id: String },
    NoPreviousState { id: String },
    AlreadyRolledBack { id: String },
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReferenceRequired { action } => {
                write!(f, "Reference required for action {:?}", action)
            }
            Self::RollbackTargetNotFound { id } => {
                write!(f, "Rollback target not found: {}", id)
            }
            Self::EntryNotFound { id } => write!(f, "Entry not found: {}", id),
            Self::NotReversible { id } => write!(f, "Entry not reversible: {}", id),
            Self::NoPreviousState { id } => {
                write!(f, "Entry has no previous state: {}", id)
            }
            Self::AlreadyRolledBack { id } => {
                write!(f, "Entry already rolled back: {}", id)
            }
        }
    }
}

impl std::error::Error for AuditError {}

// ============================================================================
// Builder Helpers
// ============================================================================

/// Builder for creating audit entries
pub struct AuditEntryBuilder {
    action: Option<AuditAction>,
    actor: Option<Actor>,
    target: Option<AuditTarget>,
    previous_state: Option<serde_json::Value>,
    new_state: Option<serde_json::Value>,
    reason: String,
    reference: Option<AuditReference>,
    reversible: bool,
}

impl AuditEntryBuilder {
    pub fn new() -> Self {
        Self {
            action: None,
            actor: None,
            target: None,
            previous_state: None,
            new_state: None,
            reason: String::new(),
            reference: None,
            reversible: true,
        }
    }

    pub fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn actor(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn analyst(mut self, id: impl Into<String>, name: Option<String>) -> Self {
        self.actor = Some(Actor {
            actor_type: ActorType::Analyst,
            id: id.into(),
            name,
            session_id: None,
        });
        self
    }

    pub fn system(mut self, id: impl Into<String>) -> Self {
        self.actor = Some(Actor {
            actor_type: ActorType::System,
            id: id.into(),
            name: None,
            session_id: None,
        });
        self
    }

    pub fn target(mut self, target: AuditTarget) -> Self {
        self.target = Some(target);
        self
    }

    pub fn rule(mut self, rule_id: impl Into<String>) -> Self {
        self.target = Some(AuditTarget::Rule {
            rule_id: rule_id.into(),
            rule_name: None,
        });
        self
    }

    pub fn incident(mut self, incident_id: impl Into<String>) -> Self {
        self.target = Some(AuditTarget::Incident {
            incident_id: incident_id.into(),
        });
        self
    }

    pub fn previous_state<T: Serialize>(mut self, state: &T) -> Self {
        self.previous_state = serde_json::to_value(state).ok();
        self
    }

    pub fn new_state<T: Serialize>(mut self, state: &T) -> Self {
        self.new_state = serde_json::to_value(state).ok();
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn ticket(mut self, ticket_id: impl Into<String>, url: Option<String>) -> Self {
        self.reference = Some(AuditReference {
            ref_type: ReferenceType::Ticket,
            id: ticket_id.into(),
            url,
        });
        self
    }

    pub fn policy(mut self, policy_id: impl Into<String>) -> Self {
        self.reference = Some(AuditReference {
            ref_type: ReferenceType::Policy,
            id: policy_id.into(),
            url: None,
        });
        self
    }

    pub fn not_reversible(mut self) -> Self {
        self.reversible = false;
        self
    }

    pub fn build(self) -> Result<AuditEntry, &'static str> {
        Ok(AuditEntry {
            id: String::new(),
            timestamp: Utc::now(),
            action: self.action.ok_or("action required")?,
            actor: self.actor.ok_or("actor required")?,
            target: self.target.ok_or("target required")?,
            previous_state: self.previous_state,
            new_state: self.new_state.unwrap_or(serde_json::Value::Null),
            reason: self.reason,
            reference: self.reference,
            reversible: self.reversible,
            rollback_of: None,
        })
    }
}

impl Default for AuditEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_actor() -> Actor {
        Actor {
            actor_type: ActorType::Analyst,
            id: "analyst@example.com".to_string(),
            name: Some("Test Analyst".to_string()),
            session_id: None,
        }
    }

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditEntryBuilder::new()
            .action(AuditAction::RuleSuppressed)
            .analyst("analyst@example.com", Some("Test".to_string()))
            .rule("RULE_001")
            .reason("False positive in dev environment")
            .ticket("JIRA-1234", None)
            .previous_state(&true)
            .new_state(&false)
            .build()
            .unwrap();

        assert_eq!(entry.action, AuditAction::RuleSuppressed);
        assert!(entry.reversible);
    }

    #[test]
    fn test_audit_log_record_and_lookup() {
        let mut log = AuditLog::new();

        let entry = AuditEntryBuilder::new()
            .action(AuditAction::RuleSuppressed)
            .actor(make_actor())
            .rule("RULE_001")
            .reason("Test")
            .previous_state(&true)
            .new_state(&false)
            .build()
            .unwrap();

        let id = log.record(entry).unwrap();
        assert!(!id.is_empty());

        let retrieved = log.get(&id).unwrap();
        assert_eq!(retrieved.action, AuditAction::RuleSuppressed);

        let by_target = log.get_for_target(&AuditTarget::Rule {
            rule_id: "RULE_001".to_string(),
            rule_name: None,
        });
        assert_eq!(by_target.len(), 1);

        let by_action = log.get_by_action(&AuditAction::RuleSuppressed);
        assert_eq!(by_action.len(), 1);
    }

    #[test]
    fn test_rollback() {
        let mut log = AuditLog::new();

        let entry = AuditEntryBuilder::new()
            .action(AuditAction::RuleSuppressed)
            .actor(make_actor())
            .rule("RULE_001")
            .reason("Test suppression")
            .previous_state(&true)
            .new_state(&false)
            .build()
            .unwrap();

        let id = log.record(entry).unwrap();

        // Check can rollback
        let check = log.can_rollback(&id);
        assert!(matches!(check, RollbackCheck::CanRollback { .. }));

        // Create and record rollback
        let rollback = log
            .create_rollback(&id, make_actor(), "Reverting".to_string())
            .unwrap();
        let rollback_id = log.record(rollback).unwrap();

        // Original should now show as already rolled back
        let check = log.can_rollback(&id);
        assert!(matches!(check, RollbackCheck::AlreadyRolledBack));

        // Rollback entry should exist
        let rollback_entry = log.get(&rollback_id).unwrap();
        assert_eq!(rollback_entry.action, AuditAction::Rollback);
        assert_eq!(rollback_entry.rollback_of, Some(id));
    }

    #[test]
    fn test_required_references() {
        let mut log = AuditLog::new().with_required_references();

        // Without reference should fail
        let entry = AuditEntryBuilder::new()
            .action(AuditAction::RuleSuppressed)
            .actor(make_actor())
            .rule("RULE_001")
            .reason("Test")
            .new_state(&false)
            .build()
            .unwrap();

        let result = log.record(entry);
        assert!(matches!(result, Err(AuditError::ReferenceRequired { .. })));

        // With reference should succeed
        let entry = AuditEntryBuilder::new()
            .action(AuditAction::RuleSuppressed)
            .actor(make_actor())
            .rule("RULE_001")
            .reason("Test")
            .ticket("JIRA-1234", None)
            .new_state(&false)
            .build()
            .unwrap();

        let result = log.record(entry);
        assert!(result.is_ok());
    }
}

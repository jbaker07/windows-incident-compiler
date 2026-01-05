//! Session Model: Discovery and Mission modes with checkpoints and focus windows.

use super::scope_keys::ScopeKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

// ============================================================================
// Session Mode
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// Discovery mode: broad monitoring, all families enabled
    Discovery,
    /// Mission mode: focused on specific objective
    Mission,
}

// ============================================================================
// Platform Context
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformContext {
    /// Atomic Red Team testing
    AtomicRedTeam,
    /// Caldera adversary emulation
    Caldera,
    /// Hack The Box lab
    HackTheBox,
    /// TryHackMe lab
    TryHackMe,
    /// Production environment
    Production,
    /// Development/test environment
    Development,
    /// Unknown context
    Unknown,
}

// ============================================================================
// Capture Profile
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProfile {
    /// Core telemetry only (process, basic file, basic network)
    Core,
    /// Extended telemetry (+ memory, detailed file, detailed network)
    Extended,
    /// Full forensic capture (+ raw packets, full command lines, etc.)
    Forensic,
}

// ============================================================================
// Focus Window
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusWindow {
    /// Minimum timestamp
    pub t_min: DateTime<Utc>,
    /// Maximum timestamp
    pub t_max: DateTime<Utc>,
    /// Optional anchor evidence pointer
    pub anchor_ptr: Option<String>,
    /// Auto-expand policy
    pub auto_expand_policy: AutoExpandPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoExpandPolicy {
    /// No auto-expansion
    None,
    /// Expand until first antecedent cause found
    ExpandToAntecedent { max_backtrack_seconds: i64 },
    /// Expand until disambiguator evidence found
    ExpandToDisambiguator { max_expand_seconds: i64 },
}

impl FocusWindow {
    pub fn new(t_min: DateTime<Utc>, t_max: DateTime<Utc>) -> Self {
        Self {
            t_min,
            t_max,
            anchor_ptr: None,
            auto_expand_policy: AutoExpandPolicy::None,
        }
    }

    pub fn with_anchor(mut self, ptr: impl Into<String>) -> Self {
        self.anchor_ptr = Some(ptr.into());
        self
    }

    pub fn with_policy(mut self, policy: AutoExpandPolicy) -> Self {
        self.auto_expand_policy = policy;
        self
    }

    /// Check if window is too narrow (< 1 minute)
    pub fn is_too_narrow(&self) -> bool {
        self.duration_seconds() < 60
    }

    /// Get window duration in seconds
    pub fn duration_seconds(&self) -> i64 {
        self.t_max.signed_duration_since(self.t_min).num_seconds()
    }

    /// Propose expanded window
    pub fn propose_expansion(&self) -> Option<FocusWindow> {
        if self.is_too_narrow() {
            let new_t_min = self.t_min - chrono::Duration::minutes(5);
            let new_t_max = self.t_max + chrono::Duration::minutes(5);
            Some(FocusWindow {
                t_min: new_t_min,
                t_max: new_t_max,
                anchor_ptr: self.anchor_ptr.clone(),
                auto_expand_policy: self.auto_expand_policy,
            })
        } else {
            None
        }
    }
}

// ============================================================================
// Checkpoint
// ============================================================================

/// Baseline references at checkpoint time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineRefs {
    /// Baseline process set (proc_keys)
    pub process_set: Vec<String>,
    /// Baseline open sockets summary
    pub open_sockets_summary: String,
    /// Known files changed watermark pointer
    pub files_changed_watermark: Option<String>,
    /// Active incidents/hypotheses snapshot reference
    pub active_snapshot_ref: Option<String>,
}

/// A checkpoint in the session timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Unique checkpoint ID
    pub checkpoint_id: String,
    /// Timestamp
    pub ts: DateTime<Utc>,
    /// Human-readable label
    pub label: String,
    /// Baseline references
    pub baseline_refs: BaselineRefs,
    /// Session state at checkpoint
    pub enabled_families: HashSet<String>,
    /// Notes
    pub notes: Option<String>,
}

impl Checkpoint {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            checkpoint_id: format!(
                "ckpt_{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            ),
            ts: Utc::now(),
            label: label.into(),
            baseline_refs: BaselineRefs {
                process_set: Vec::new(),
                open_sockets_summary: String::new(),
                files_changed_watermark: None,
                active_snapshot_ref: None,
            },
            enabled_families: HashSet::new(),
            notes: None,
        }
    }
}

// ============================================================================
// Expected Observable
// ============================================================================

/// Expected observable for mission mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedObservable {
    /// Type of observable (process_exec, network_connect, file_write, etc.)
    pub observable_type: String,
    /// Scope hint (which entity to watch)
    pub scope_hint: Option<ScopeKey>,
    /// Expected time window
    pub time_expectation: Option<TimeExpectation>,
    /// Query hint for evidence retrieval
    pub evidence_query_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeExpectation {
    /// Minimum expected time (relative to session start)
    pub min_offset_seconds: Option<i64>,
    /// Maximum expected time
    pub max_offset_seconds: Option<i64>,
}

// ============================================================================
// Session Config (Mission output)
// ============================================================================

/// Configuration produced from mission intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Enabled security families
    pub enabled_families: HashSet<String>,
    /// Specific enabled playbooks (optional subset)
    pub enabled_playbooks: Option<HashSet<String>>,
    /// Session TTL in seconds
    pub ttl_seconds: i64,
    /// Expected observables from mission
    pub expected_observables: Vec<ExpectedObservable>,
    /// Capture profile adjustments
    pub capture_profile_adjustments: Vec<CaptureAdjustment>,
    /// Noise policies to ignore
    pub ignore_noise_policies: Vec<NoisePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureAdjustment {
    pub stream_id: String,
    pub enabled: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoisePolicy {
    pub policy_id: String,
    pub predicate: String,
    pub scope: Option<ScopeKey>,
    pub reason: String,
}

impl SessionConfig {
    /// Create default discovery config
    pub fn discovery_default() -> Self {
        let mut families = HashSet::new();
        families.insert("execution".to_string());
        families.insert("persistence".to_string());
        families.insert("privilege_escalation".to_string());
        families.insert("defense_evasion".to_string());
        families.insert("credential_access".to_string());
        families.insert("discovery".to_string());
        families.insert("lateral_movement".to_string());
        families.insert("collection".to_string());
        families.insert("exfiltration".to_string());
        families.insert("command_control".to_string());

        Self {
            enabled_families: families,
            enabled_playbooks: None,
            ttl_seconds: 3600,
            expected_observables: Vec::new(),
            capture_profile_adjustments: Vec::new(),
            ignore_noise_policies: Vec::new(),
        }
    }

    /// Create minimal core config
    pub fn core_minimal() -> Self {
        let mut families = HashSet::new();
        families.insert("injection".to_string());
        families.insert("memory_exploit".to_string());
        families.insert("privilege_escalation".to_string());
        families.insert("persistence".to_string());
        families.insert("tamper".to_string());

        Self {
            enabled_families: families,
            enabled_playbooks: None,
            ttl_seconds: 3600,
            expected_observables: Vec::new(),
            capture_profile_adjustments: Vec::new(),
            ignore_noise_policies: Vec::new(),
        }
    }
}

// ============================================================================
// Analyst Assertion
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AssertionType {
    /// Lab mode on/off
    LabMode { enabled: bool },
    /// Known good binary
    KnownGoodBinary {
        exe_hash: Option<String>,
        path: Option<String>,
        signature: Option<String>,
    },
    /// Known good parent-child relationship
    KnownGoodParentChild {
        parent_hash: String,
        child_hash: String,
    },
    /// Ignore noise pattern
    IgnoreNoisePattern {
        predicate_id: String,
        scope_key: Option<ScopeKey>,
    },
    /// Suspected family hint
    SuspectedFamily { family: String },
    /// Role hint for user
    RoleHint { user_key: String, role: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub assertion_id: String,
    pub ts: DateTime<Utc>,
    pub assertion_type: AssertionType,
    pub reason: String,
    pub analyst_id: Option<String>,
}

impl Assertion {
    pub fn new(assertion_type: AssertionType, reason: impl Into<String>) -> Self {
        Self {
            assertion_id: format!(
                "assert_{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            ),
            ts: Utc::now(),
            assertion_type,
            reason: reason.into(),
            analyst_id: None,
        }
    }
}

// ============================================================================
// Analyst Action
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Action was observed in telemetry
    Observed,
    /// Action was not observed
    NotObserved,
    /// Cannot verify due to visibility gap
    VisibilityGap,
    /// Ambiguous evidence
    Ambiguous,
    /// Not yet checked
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    RanCommand {
        command: String,
    },
    StartedListener {
        port: u16,
        protocol: String,
    },
    DownloadedFile {
        url: String,
        destination: Option<String>,
    },
    ModifiedFile {
        path: String,
    },
    CreatedUser {
        username: String,
    },
    EscalatedPrivilege {
        method: String,
    },
    CustomAction {
        description: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystAction {
    pub action_id: String,
    pub ts: DateTime<Utc>,
    pub text: String,
    pub action_type: Option<ActionType>,
    pub scope_hint: Option<ScopeKey>,
    pub verification_status: VerificationStatus,
    pub verification_evidence: Vec<String>,
    pub analyst_id: Option<String>,
}

impl AnalystAction {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            action_id: format!(
                "action_{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            ),
            ts: Utc::now(),
            text: text.into(),
            action_type: None,
            scope_hint: None,
            verification_status: VerificationStatus::Pending,
            verification_evidence: Vec::new(),
            analyst_id: None,
        }
    }

    pub fn with_type(mut self, action_type: ActionType) -> Self {
        self.action_type = Some(action_type);
        self
    }

    pub fn with_scope(mut self, scope: ScopeKey) -> Self {
        self.scope_hint = Some(scope);
        self
    }
}

// ============================================================================
// Session
// ============================================================================

/// A detection session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub session_id: String,
    /// Session mode
    pub mode: SessionMode,
    /// Start timestamp
    pub start_ts: DateTime<Utc>,
    /// End timestamp (None if active)
    pub end_ts: Option<DateTime<Utc>>,
    /// TTL in seconds
    pub ttl_seconds: i64,
    /// Platform context
    pub platform_context: PlatformContext,
    /// Capture profile
    pub capture_profile: CaptureProfile,
    /// Current focus window
    pub focus_window: Option<FocusWindow>,
    /// Focus entities
    pub focus_entities: Vec<ScopeKey>,
    /// Enabled families
    pub enabled_families: HashSet<String>,
    /// Enabled playbooks (optional subset)
    pub enabled_playbooks: Option<HashSet<String>>,
    /// Checkpoints
    pub checkpoints: Vec<Checkpoint>,
    /// Analyst assertions
    pub analyst_assertions: Vec<Assertion>,
    /// Analyst actions
    pub analyst_actions: Vec<AnalystAction>,
    /// Session configuration
    pub config: SessionConfig,
    /// Host ID
    pub host_id: String,
    /// Notes
    pub notes: Vec<String>,
}

impl Session {
    /// Create a new discovery session
    pub fn new_discovery(host_id: impl Into<String>) -> Self {
        let config = SessionConfig::discovery_default();
        let families = config.enabled_families.clone();

        Self {
            session_id: format!("sess_{}", Uuid::new_v4()),
            mode: SessionMode::Discovery,
            start_ts: Utc::now(),
            end_ts: None,
            ttl_seconds: config.ttl_seconds,
            platform_context: PlatformContext::Unknown,
            capture_profile: CaptureProfile::Core,
            focus_window: None,
            focus_entities: Vec::new(),
            enabled_families: families,
            enabled_playbooks: None,
            checkpoints: Vec::new(),
            analyst_assertions: Vec::new(),
            analyst_actions: Vec::new(),
            config,
            host_id: host_id.into(),
            notes: Vec::new(),
        }
    }

    /// Create a new mission session
    pub fn new_mission(host_id: impl Into<String>, config: SessionConfig) -> Self {
        let families = config.enabled_families.clone();
        let playbooks = config.enabled_playbooks.clone();
        let ttl = config.ttl_seconds;

        Self {
            session_id: format!("sess_{}", Uuid::new_v4()),
            mode: SessionMode::Mission,
            start_ts: Utc::now(),
            end_ts: None,
            ttl_seconds: ttl,
            platform_context: PlatformContext::Unknown,
            capture_profile: CaptureProfile::Extended,
            focus_window: None,
            focus_entities: Vec::new(),
            enabled_families: families,
            enabled_playbooks: playbooks,
            checkpoints: Vec::new(),
            analyst_assertions: Vec::new(),
            analyst_actions: Vec::new(),
            config,
            host_id: host_id.into(),
            notes: Vec::new(),
        }
    }

    /// Set platform context
    pub fn with_platform(mut self, context: PlatformContext) -> Self {
        self.platform_context = context;
        self
    }

    /// Set capture profile
    pub fn with_capture_profile(mut self, profile: CaptureProfile) -> Self {
        self.capture_profile = profile;
        self
    }

    /// Set focus window
    pub fn set_focus(&mut self, window: FocusWindow) {
        self.focus_window = Some(window);
    }

    /// Add focus entity
    pub fn add_focus_entity(&mut self, entity: ScopeKey) {
        if !self.focus_entities.contains(&entity) {
            self.focus_entities.push(entity);
        }
    }

    /// Create a checkpoint
    pub fn checkpoint(&mut self, label: impl Into<String>) -> &Checkpoint {
        let mut ckpt = Checkpoint::new(label);
        ckpt.enabled_families = self.enabled_families.clone();
        self.checkpoints.push(ckpt);
        self.checkpoints.last().unwrap()
    }

    /// Add assertion
    pub fn add_assertion(&mut self, assertion: Assertion) {
        self.analyst_assertions.push(assertion);
    }

    /// Add action
    pub fn add_action(&mut self, action: AnalystAction) {
        self.analyst_actions.push(action);
    }

    /// End the session
    pub fn end(&mut self) {
        self.end_ts = Some(Utc::now());
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.end_ts.is_none()
    }

    /// Get session duration
    pub fn duration_seconds(&self) -> i64 {
        let end = self.end_ts.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.start_ts).num_seconds()
    }

    /// Diff between two checkpoints
    pub fn diff_checkpoints(&self, ckpt1_id: &str, ckpt2_id: &str) -> Option<CheckpointDiff> {
        let ckpt1 = self
            .checkpoints
            .iter()
            .find(|c| c.checkpoint_id == ckpt1_id)?;
        let ckpt2 = self
            .checkpoints
            .iter()
            .find(|c| c.checkpoint_id == ckpt2_id)?;

        Some(CheckpointDiff {
            from_checkpoint: ckpt1_id.to_string(),
            to_checkpoint: ckpt2_id.to_string(),
            time_delta_seconds: ckpt2.ts.signed_duration_since(ckpt1.ts).num_seconds(),
            processes_added: Vec::new(), // Would compute from baseline refs
            processes_removed: Vec::new(),
            families_changed: ckpt1
                .enabled_families
                .symmetric_difference(&ckpt2.enabled_families)
                .cloned()
                .collect(),
        })
    }
}

/// Diff between two checkpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointDiff {
    pub from_checkpoint: String,
    pub to_checkpoint: String,
    pub time_delta_seconds: i64,
    pub processes_added: Vec<String>,
    pub processes_removed: Vec<String>,
    pub families_changed: Vec<String>,
}

// ============================================================================
// Session Store
// ============================================================================

/// In-memory session store
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: std::collections::HashMap<String, Session>,
    active_by_host: std::collections::HashMap<String, String>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, session: Session) {
        let id = session.session_id.clone();
        let host = session.host_id.clone();

        if session.is_active() {
            self.active_by_host.insert(host, id.clone());
        }

        self.sessions.insert(id, session);
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    pub fn active_for_host(&self, host_id: &str) -> Option<&Session> {
        self.active_by_host
            .get(host_id)
            .and_then(|id| self.sessions.get(id))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new_discovery("host1");
        assert!(session.is_active());
        assert_eq!(session.mode, SessionMode::Discovery);
        assert!(!session.enabled_families.is_empty());
    }

    #[test]
    fn test_checkpoint() {
        let mut session = Session::new_discovery("host1");
        session.checkpoint("Before test");
        session.checkpoint("After test");

        assert_eq!(session.checkpoints.len(), 2);
    }

    #[test]
    fn test_focus_window() {
        let now = Utc::now();
        let window = FocusWindow::new(now - chrono::Duration::seconds(30), now);

        assert!(window.is_too_narrow());

        let expanded = window.propose_expansion().unwrap();
        assert!(!expanded.is_too_narrow());
    }
}

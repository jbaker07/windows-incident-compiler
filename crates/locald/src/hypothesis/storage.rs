//! Storage layer for hypothesis/incident system
//!
//! SQLite schema and queries for persistent storage.

use super::canonical_event::CanonicalEvent;
use super::canonical_fact::Fact;
use super::hypothesis_state::HypothesisState;
use super::incident::Incident;
use super::scope_keys::ScopeKey;
use super::session::Session;
use std::collections::HashMap;

// ============================================================================
// Schema Definitions
// ============================================================================

/// SQL statements for schema creation
pub const CREATE_SCHEMA: &str = r#"
-- ============================================================================
-- Evidence Storage
-- ============================================================================

-- Segment metadata (ring-buffer segment files)
CREATE TABLE IF NOT EXISTS segments (
    segment_id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    record_count INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(stream_id, segment_id)
);

CREATE INDEX IF NOT EXISTS idx_segments_stream ON segments(stream_id);
CREATE INDEX IF NOT EXISTS idx_segments_time ON segments(start_ts, end_ts);

-- Canonical events (denormalized for fast queries)
CREATE TABLE IF NOT EXISTS canonical_events (
    event_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    
    -- Evidence pointer
    stream_id TEXT NOT NULL,
    segment_id TEXT NOT NULL,
    record_index INTEGER NOT NULL,
    record_sha256 TEXT NOT NULL,
    
    -- Scope keys (nullable, depend on event type)
    proc_scope_key TEXT,
    user_scope_key TEXT,
    exe_scope_key TEXT,
    sock_scope_key TEXT,
    file_scope_key TEXT,
    
    -- Denormalized for fast filtering
    pid INTEGER,
    exe_path TEXT,
    exe_hash TEXT,
    user_id TEXT,
    remote_ip TEXT,
    remote_port INTEGER,
    file_path TEXT,
    
    -- Full event as JSON
    event_json TEXT NOT NULL,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_events_host_time ON canonical_events(host_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_proc ON canonical_events(proc_scope_key);
CREATE INDEX IF NOT EXISTS idx_events_user ON canonical_events(user_scope_key);
CREATE INDEX IF NOT EXISTS idx_events_exe ON canonical_events(exe_scope_key);
CREATE INDEX IF NOT EXISTS idx_events_sock ON canonical_events(sock_scope_key);
CREATE INDEX IF NOT EXISTS idx_events_file ON canonical_events(file_scope_key);
CREATE INDEX IF NOT EXISTS idx_events_type ON canonical_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_pid ON canonical_events(pid);
CREATE INDEX IF NOT EXISTS idx_events_exe_path ON canonical_events(exe_path);

-- ============================================================================
-- Facts Storage
-- ============================================================================

CREATE TABLE IF NOT EXISTS facts (
    fact_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    fact_type TEXT NOT NULL,
    domain TEXT NOT NULL,
    
    -- Scope keys
    proc_scope_key TEXT,
    user_scope_key TEXT,
    exe_scope_key TEXT,
    sock_scope_key TEXT,
    file_scope_key TEXT,
    
    -- Evidence pointers (JSON array of EvidencePtr)
    evidence_ptrs TEXT NOT NULL,
    
    -- Conflict handling
    conflict_set_id TEXT,
    superseded_by TEXT,
    
    -- Full fact as JSON
    fact_json TEXT NOT NULL,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_facts_host_time ON facts(host_id, ts);
CREATE INDEX IF NOT EXISTS idx_facts_type ON facts(fact_type);
CREATE INDEX IF NOT EXISTS idx_facts_domain ON facts(domain);
CREATE INDEX IF NOT EXISTS idx_facts_proc ON facts(proc_scope_key);
CREATE INDEX IF NOT EXISTS idx_facts_conflict ON facts(conflict_set_id);

-- ============================================================================
-- Hypotheses Storage
-- ============================================================================

CREATE TABLE IF NOT EXISTS hypotheses (
    hypothesis_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    family TEXT NOT NULL,
    template_id TEXT NOT NULL,
    variant TEXT,
    
    -- Scope keys (determines identity)
    proc_scope_key TEXT NOT NULL,
    user_scope_key TEXT,
    exe_scope_key TEXT,
    
    -- Status
    status TEXT NOT NULL,
    
    -- Scoring
    maturity REAL NOT NULL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.0,
    severity TEXT NOT NULL DEFAULT 'unknown',
    
    -- Corroboration/Surprise
    corroboration_ratio REAL NOT NULL DEFAULT 0.0,
    surprise_score REAL NOT NULL DEFAULT 0.0,
    
    -- Slot status
    required_slots_count INTEGER NOT NULL DEFAULT 0,
    required_satisfied INTEGER NOT NULL DEFAULT 0,
    optional_slots_count INTEGER NOT NULL DEFAULT 0,
    optional_satisfied INTEGER NOT NULL DEFAULT 0,
    
    -- Timing
    first_ts INTEGER NOT NULL,
    last_ts INTEGER NOT NULL,
    
    -- Full state as JSON
    state_json TEXT NOT NULL,
    
    -- Incident reference (if promoted)
    incident_id TEXT,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_hyp_host ON hypotheses(host_id);
CREATE INDEX IF NOT EXISTS idx_hyp_family ON hypotheses(family);
CREATE INDEX IF NOT EXISTS idx_hyp_status ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_hyp_proc ON hypotheses(proc_scope_key);
CREATE INDEX IF NOT EXISTS idx_hyp_maturity ON hypotheses(maturity DESC);
CREATE INDEX IF NOT EXISTS idx_hyp_incident ON hypotheses(incident_id);

-- Hypothesis slot fills (for detailed queries)
CREATE TABLE IF NOT EXISTS hypothesis_slot_fills (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    satisfied INTEGER NOT NULL DEFAULT 0,
    strength TEXT,
    count INTEGER NOT NULL DEFAULT 0,
    first_ts INTEGER,
    last_ts INTEGER,
    
    -- Evidence pointers (JSON array)
    evidence_ptrs TEXT,
    
    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(hypothesis_id) ON DELETE CASCADE,
    UNIQUE(hypothesis_id, slot_id)
);

CREATE INDEX IF NOT EXISTS idx_slot_fills_hyp ON hypothesis_slot_fills(hypothesis_id);

-- ============================================================================
-- Incidents Storage
-- ============================================================================

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    family TEXT NOT NULL,
    template_id TEXT NOT NULL,
    
    -- Status
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    
    -- Scoring (at promotion time)
    maturity_at_promotion REAL NOT NULL,
    confidence_at_promotion REAL NOT NULL,
    current_maturity REAL NOT NULL,
    current_confidence REAL NOT NULL,
    
    -- Timing
    first_ts INTEGER NOT NULL,
    last_ts INTEGER NOT NULL,
    promoted_ts INTEGER NOT NULL,
    
    -- Full state as JSON
    incident_json TEXT NOT NULL,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_inc_host ON incidents(host_id);
CREATE INDEX IF NOT EXISTS idx_inc_family ON incidents(family);
CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_inc_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_inc_time ON incidents(first_ts, last_ts);

-- Incident timeline entries
CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    entry_type TEXT NOT NULL,
    summary TEXT NOT NULL,
    
    -- Evidence pointer
    evidence_ptr TEXT,
    
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_timeline_inc ON incident_timeline(incident_id);
CREATE INDEX IF NOT EXISTS idx_timeline_ts ON incident_timeline(ts);

-- Incident entity references
CREATE TABLE IF NOT EXISTS incident_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    role TEXT,
    
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    UNIQUE(incident_id, entity_type, scope_key)
);

CREATE INDEX IF NOT EXISTS idx_entities_inc ON incident_entities(incident_id);
CREATE INDEX IF NOT EXISTS idx_entities_scope ON incident_entities(scope_key);

-- ============================================================================
-- Sessions Storage
-- ============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    
    -- Focus window
    focus_start_ts INTEGER,
    focus_end_ts INTEGER,
    
    -- Status
    status TEXT NOT NULL,
    
    -- Full state as JSON
    session_json TEXT NOT NULL,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_sess_host ON sessions(host_id);
CREATE INDEX IF NOT EXISTS idx_sess_status ON sessions(status);

-- Session checkpoints
CREATE TABLE IF NOT EXISTS session_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    checkpoint_ts INTEGER NOT NULL,
    label TEXT,
    
    -- Snapshot as JSON
    snapshot_json TEXT NOT NULL,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ckpt_session ON session_checkpoints(session_id);

-- Session assertions
CREATE TABLE IF NOT EXISTS session_assertions (
    assertion_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    assertion_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason TEXT,
    
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assert_session ON session_assertions(session_id);
CREATE INDEX IF NOT EXISTS idx_assert_target ON session_assertions(target_id);

-- Session analyst actions
CREATE TABLE IF NOT EXISTS session_analyst_actions (
    action_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    action_text TEXT NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'pending',
    
    -- Verification evidence (JSON array)
    verification_evidence TEXT,
    
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_action_session ON session_analyst_actions(session_id);

-- ============================================================================
-- Arbitration History
-- ============================================================================

CREATE TABLE IF NOT EXISTS arbitration_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    ts INTEGER NOT NULL,
    
    -- Top 3 hypothesis IDs
    rank1_hypothesis_id TEXT,
    rank2_hypothesis_id TEXT,
    rank3_hypothesis_id TEXT,
    
    -- Scores
    rank1_score REAL,
    rank2_score REAL,
    rank3_score REAL,
    
    -- Full response as JSON
    response_json TEXT NOT NULL,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_arb_session ON arbitration_history(session_id);
CREATE INDEX IF NOT EXISTS idx_arb_ts ON arbitration_history(ts);

-- ============================================================================
-- Visibility Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS visibility_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    
    -- Stream presence (JSON object)
    streams_present TEXT NOT NULL,
    streams_missing TEXT NOT NULL,
    
    degraded INTEGER NOT NULL DEFAULT 0,
    degraded_reasons TEXT,
    
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_vis_host ON visibility_state(host_id);
CREATE INDEX IF NOT EXISTS idx_vis_ts ON visibility_state(ts);
"#;

// ============================================================================
// Query Builders
// ============================================================================

/// Query for retrieving events by time range and scope
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub host_id: Option<String>,
    pub start_ts: Option<i64>,
    pub end_ts: Option<i64>,
    pub proc_scope_key: Option<String>,
    pub user_scope_key: Option<String>,
    pub exe_scope_key: Option<String>,
    pub event_types: Vec<String>,
    pub limit: Option<u32>,
}

impl EventQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn host(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = Some(host_id.into());
        self
    }

    pub fn time_range(mut self, start_ts: i64, end_ts: i64) -> Self {
        self.start_ts = Some(start_ts);
        self.end_ts = Some(end_ts);
        self
    }

    pub fn proc(mut self, proc_scope_key: impl Into<String>) -> Self {
        self.proc_scope_key = Some(proc_scope_key.into());
        self
    }

    pub fn user(mut self, user_scope_key: impl Into<String>) -> Self {
        self.user_scope_key = Some(user_scope_key.into());
        self
    }

    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_types.push(event_type.into());
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn to_sql(&self) -> (String, Vec<SqlParam>) {
        let mut conditions: Vec<String> = Vec::new();
        let mut params = Vec::new();

        if let Some(ref host_id) = self.host_id {
            conditions.push("host_id = ?".to_string());
            params.push(SqlParam::Text(host_id.clone()));
        }

        if let Some(start_ts) = self.start_ts {
            conditions.push("ts >= ?".to_string());
            params.push(SqlParam::Int(start_ts));
        }

        if let Some(end_ts) = self.end_ts {
            conditions.push("ts <= ?".to_string());
            params.push(SqlParam::Int(end_ts));
        }

        if let Some(ref key) = self.proc_scope_key {
            conditions.push("proc_scope_key = ?".to_string());
            params.push(SqlParam::Text(key.clone()));
        }

        if let Some(ref key) = self.user_scope_key {
            conditions.push("user_scope_key = ?".to_string());
            params.push(SqlParam::Text(key.clone()));
        }

        if let Some(ref key) = self.exe_scope_key {
            conditions.push("exe_scope_key = ?".to_string());
            params.push(SqlParam::Text(key.clone()));
        }

        if !self.event_types.is_empty() {
            let placeholders: Vec<&str> = self.event_types.iter().map(|_| "?").collect();
            conditions.push(format!("event_type IN ({})", placeholders.join(", ")));
            for t in &self.event_types {
                params.push(SqlParam::Text(t.clone()));
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit_clause = self
            .limit
            .map(|l| format!("LIMIT {}", l))
            .unwrap_or_default();

        let sql = format!(
            "SELECT event_id, event_json FROM canonical_events {} ORDER BY ts ASC {}",
            where_clause, limit_clause
        );

        (sql, params)
    }
}

/// Query for retrieving hypotheses
#[derive(Debug, Clone, Default)]
pub struct HypothesisQuery {
    pub host_id: Option<String>,
    pub family: Option<String>,
    pub status: Option<String>,
    pub min_maturity: Option<f64>,
    pub proc_scope_key: Option<String>,
    pub limit: Option<u32>,
}

impl HypothesisQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn host(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = Some(host_id.into());
        self
    }

    pub fn family(mut self, family: impl Into<String>) -> Self {
        self.family = Some(family.into());
        self
    }

    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }

    pub fn min_maturity(mut self, min: f64) -> Self {
        self.min_maturity = Some(min);
        self
    }

    pub fn proc(mut self, proc_scope_key: impl Into<String>) -> Self {
        self.proc_scope_key = Some(proc_scope_key.into());
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn to_sql(&self) -> (String, Vec<SqlParam>) {
        let mut conditions = Vec::new();
        let mut params = Vec::new();

        if let Some(ref host_id) = self.host_id {
            conditions.push("host_id = ?");
            params.push(SqlParam::Text(host_id.clone()));
        }

        if let Some(ref family) = self.family {
            conditions.push("family = ?");
            params.push(SqlParam::Text(family.clone()));
        }

        if let Some(ref status) = self.status {
            conditions.push("status = ?");
            params.push(SqlParam::Text(status.clone()));
        }

        if let Some(min) = self.min_maturity {
            conditions.push("maturity >= ?");
            params.push(SqlParam::Real(min));
        }

        if let Some(ref key) = self.proc_scope_key {
            conditions.push("proc_scope_key = ?");
            params.push(SqlParam::Text(key.clone()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit_clause = self
            .limit
            .map(|l| format!("LIMIT {}", l))
            .unwrap_or_default();

        let sql = format!(
            "SELECT hypothesis_id, state_json FROM hypotheses {} ORDER BY maturity DESC {}",
            where_clause, limit_clause
        );

        (sql, params)
    }
}

/// Query for retrieving incidents
#[derive(Debug, Clone, Default)]
pub struct IncidentQuery {
    pub host_id: Option<String>,
    pub family: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub start_ts: Option<i64>,
    pub end_ts: Option<i64>,
    pub limit: Option<u32>,
}

impl IncidentQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn host(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = Some(host_id.into());
        self
    }

    pub fn family(mut self, family: impl Into<String>) -> Self {
        self.family = Some(family.into());
        self
    }

    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }

    pub fn severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }

    pub fn time_range(mut self, start_ts: i64, end_ts: i64) -> Self {
        self.start_ts = Some(start_ts);
        self.end_ts = Some(end_ts);
        self
    }

    pub fn limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn to_sql(&self) -> (String, Vec<SqlParam>) {
        let mut conditions = Vec::new();
        let mut params = Vec::new();

        if let Some(ref host_id) = self.host_id {
            conditions.push("host_id = ?");
            params.push(SqlParam::Text(host_id.clone()));
        }

        if let Some(ref family) = self.family {
            conditions.push("family = ?");
            params.push(SqlParam::Text(family.clone()));
        }

        if let Some(ref status) = self.status {
            conditions.push("status = ?");
            params.push(SqlParam::Text(status.clone()));
        }

        if let Some(ref severity) = self.severity {
            conditions.push("severity = ?");
            params.push(SqlParam::Text(severity.clone()));
        }

        if let Some(start_ts) = self.start_ts {
            conditions.push("first_ts >= ?");
            params.push(SqlParam::Int(start_ts));
        }

        if let Some(end_ts) = self.end_ts {
            conditions.push("last_ts <= ?");
            params.push(SqlParam::Int(end_ts));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit_clause = self
            .limit
            .map(|l| format!("LIMIT {}", l))
            .unwrap_or_default();

        let sql = format!(
            "SELECT incident_id, incident_json FROM incidents {} ORDER BY first_ts DESC {}",
            where_clause, limit_clause
        );

        (sql, params)
    }
}

/// SQL parameter types
#[derive(Debug, Clone)]
pub enum SqlParam {
    Text(String),
    Int(i64),
    Real(f64),
    Null,
}

// ============================================================================
// Storage Abstraction
// ============================================================================

/// Storage trait for hypothesis system persistence
pub trait HypothesisStorage {
    type Error;

    // Events
    fn store_event(&mut self, event: &CanonicalEvent) -> Result<(), Self::Error>;
    fn query_events(&self, query: &EventQuery) -> Result<Vec<CanonicalEvent>, Self::Error>;
    fn get_event(&self, event_id: &str) -> Result<Option<CanonicalEvent>, Self::Error>;

    // Facts
    fn store_fact(&mut self, fact: &Fact) -> Result<(), Self::Error>;
    fn get_facts_for_proc(&self, proc_scope_key: &str) -> Result<Vec<Fact>, Self::Error>;

    // Hypotheses
    fn store_hypothesis(&mut self, hypothesis: &HypothesisState) -> Result<(), Self::Error>;
    fn update_hypothesis(&mut self, hypothesis: &HypothesisState) -> Result<(), Self::Error>;
    fn query_hypotheses(
        &self,
        query: &HypothesisQuery,
    ) -> Result<Vec<HypothesisState>, Self::Error>;
    fn get_hypothesis(&self, hypothesis_id: &str) -> Result<Option<HypothesisState>, Self::Error>;

    // Incidents
    fn store_incident(&mut self, incident: &Incident) -> Result<(), Self::Error>;
    fn update_incident(&mut self, incident: &Incident) -> Result<(), Self::Error>;
    fn query_incidents(&self, query: &IncidentQuery) -> Result<Vec<Incident>, Self::Error>;
    fn get_incident(&self, incident_id: &str) -> Result<Option<Incident>, Self::Error>;

    // Sessions
    fn store_session(&mut self, session: &Session) -> Result<(), Self::Error>;
    fn update_session(&mut self, session: &Session) -> Result<(), Self::Error>;
    fn get_session(&self, session_id: &str) -> Result<Option<Session>, Self::Error>;
}

// ============================================================================
// In-Memory Storage Implementation
// ============================================================================

/// In-memory storage for testing and development
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    events: HashMap<String, String>,
    facts: HashMap<String, String>,
    hypotheses: HashMap<String, String>,
    incidents: HashMap<String, String>,
    sessions: HashMap<String, String>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct InMemoryStorageError(pub String);

impl std::fmt::Display for InMemoryStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryStorageError: {}", self.0)
    }
}

impl std::error::Error for InMemoryStorageError {}

impl HypothesisStorage for InMemoryStorage {
    type Error = InMemoryStorageError;

    fn store_event(&mut self, event: &CanonicalEvent) -> Result<(), Self::Error> {
        let json = serde_json::to_string(event).map_err(|e| InMemoryStorageError(e.to_string()))?;
        self.events.insert(event.evidence_ptr.canonical_key(), json);
        Ok(())
    }

    fn query_events(&self, _query: &EventQuery) -> Result<Vec<CanonicalEvent>, Self::Error> {
        // Simplified: return all events
        let mut events = Vec::new();
        for json in self.events.values() {
            let event: CanonicalEvent =
                serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    fn get_event(&self, event_id: &str) -> Result<Option<CanonicalEvent>, Self::Error> {
        match self.events.get(event_id) {
            Some(json) => {
                let event: CanonicalEvent =
                    serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    fn store_fact(&mut self, fact: &Fact) -> Result<(), Self::Error> {
        let json = serde_json::to_string(fact).map_err(|e| InMemoryStorageError(e.to_string()))?;
        self.facts.insert(fact.fact_id.clone(), json);
        Ok(())
    }

    fn get_facts_for_proc(&self, proc_scope_key: &str) -> Result<Vec<Fact>, Self::Error> {
        let mut facts = Vec::new();
        for json in self.facts.values() {
            let fact: Fact =
                serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
            // Check if the scope_key is a Process with matching key
            if let ScopeKey::Process { key, .. } = &fact.scope_key {
                if key == proc_scope_key {
                    facts.push(fact);
                }
            }
        }
        Ok(facts)
    }

    fn store_hypothesis(&mut self, hypothesis: &HypothesisState) -> Result<(), Self::Error> {
        let json =
            serde_json::to_string(hypothesis).map_err(|e| InMemoryStorageError(e.to_string()))?;
        self.hypotheses
            .insert(hypothesis.hypothesis_id.clone(), json);
        Ok(())
    }

    fn update_hypothesis(&mut self, hypothesis: &HypothesisState) -> Result<(), Self::Error> {
        self.store_hypothesis(hypothesis)
    }

    fn query_hypotheses(
        &self,
        _query: &HypothesisQuery,
    ) -> Result<Vec<HypothesisState>, Self::Error> {
        let mut hypotheses = Vec::new();
        for json in self.hypotheses.values() {
            let hypothesis: HypothesisState =
                serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
            hypotheses.push(hypothesis);
        }
        Ok(hypotheses)
    }

    fn get_hypothesis(&self, hypothesis_id: &str) -> Result<Option<HypothesisState>, Self::Error> {
        match self.hypotheses.get(hypothesis_id) {
            Some(json) => {
                let hypothesis: HypothesisState =
                    serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
                Ok(Some(hypothesis))
            }
            None => Ok(None),
        }
    }

    fn store_incident(&mut self, incident: &Incident) -> Result<(), Self::Error> {
        let json =
            serde_json::to_string(incident).map_err(|e| InMemoryStorageError(e.to_string()))?;
        self.incidents.insert(incident.incident_id.clone(), json);
        Ok(())
    }

    fn update_incident(&mut self, incident: &Incident) -> Result<(), Self::Error> {
        self.store_incident(incident)
    }

    fn query_incidents(&self, _query: &IncidentQuery) -> Result<Vec<Incident>, Self::Error> {
        let mut incidents = Vec::new();
        for json in self.incidents.values() {
            let incident: Incident =
                serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
            incidents.push(incident);
        }
        Ok(incidents)
    }

    fn get_incident(&self, incident_id: &str) -> Result<Option<Incident>, Self::Error> {
        match self.incidents.get(incident_id) {
            Some(json) => {
                let incident: Incident =
                    serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
                Ok(Some(incident))
            }
            None => Ok(None),
        }
    }

    fn store_session(&mut self, session: &Session) -> Result<(), Self::Error> {
        let json =
            serde_json::to_string(session).map_err(|e| InMemoryStorageError(e.to_string()))?;
        self.sessions.insert(session.session_id.clone(), json);
        Ok(())
    }

    fn update_session(&mut self, session: &Session) -> Result<(), Self::Error> {
        self.store_session(session)
    }

    fn get_session(&self, session_id: &str) -> Result<Option<Session>, Self::Error> {
        match self.sessions.get(session_id) {
            Some(json) => {
                let session: Session =
                    serde_json::from_str(json).map_err(|e| InMemoryStorageError(e.to_string()))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_query_builder() {
        let query = EventQuery::new()
            .host("host1")
            .time_range(1000, 2000)
            .proc("proc_key")
            .event_type("ProcessExec")
            .limit(100);

        let (sql, params) = query.to_sql();
        assert!(sql.contains("host_id = ?"));
        assert!(sql.contains("ts >= ?"));
        assert!(sql.contains("ts <= ?"));
        assert!(sql.contains("proc_scope_key = ?"));
        assert!(sql.contains("LIMIT 100"));
        assert_eq!(params.len(), 5);
    }

    #[test]
    fn test_hypothesis_query_builder() {
        let query = HypothesisQuery::new()
            .host("host1")
            .family("credential_access")
            .min_maturity(0.5)
            .limit(10);

        let (sql, params) = query.to_sql();
        assert!(sql.contains("host_id = ?"));
        assert!(sql.contains("family = ?"));
        assert!(sql.contains("maturity >= ?"));
        assert!(sql.contains("ORDER BY maturity DESC"));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn test_incident_query_builder() {
        let query = IncidentQuery::new()
            .host("host1")
            .severity("high")
            .status("active")
            .time_range(1000, 2000);

        let (sql, params) = query.to_sql();
        assert!(sql.contains("host_id = ?"));
        assert!(sql.contains("severity = ?"));
        assert!(sql.contains("status = ?"));
        assert!(sql.contains("first_ts >= ?"));
        assert_eq!(params.len(), 5);
    }

    #[test]
    fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();

        // Just test that it compiles and basic operations work
        assert!(storage.events.is_empty());
        assert!(storage.hypotheses.is_empty());
        assert!(storage.incidents.is_empty());
    }
}

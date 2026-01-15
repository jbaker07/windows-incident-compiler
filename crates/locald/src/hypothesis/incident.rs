//! Incident Model: Promoted hypotheses with timeline and entity tracking.

use super::canonical_event::EvidencePtr;
use super::hypothesis_state::HypothesisState;
use super::ordering::EventOrderKey;
use super::promotion::Severity;
use super::scope_keys::ScopeKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Incident Status
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Active incident, may receive updates
    Active,
    /// Closed by analyst or system
    Closed,
    /// Suppressed (false positive, lab mode, etc.)
    Suppressed,
    /// Merged into another incident
    Merged,
}

// ============================================================================
// Timeline Entry
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEntryKind {
    /// Process spawn/exec
    ProcessEvent,
    /// File operation
    FileEvent,
    /// Network activity
    NetworkEvent,
    /// Memory operation
    MemoryEvent,
    /// Authentication/privilege
    AuthEvent,
    /// Persistence mechanism
    PersistenceEvent,
    /// Tampering activity
    TamperEvent,
    /// Analyst annotation
    AnalystNote,
    /// System event
    SystemEvent,
}

/// A single entry in the incident timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Timestamp of the entry
    pub ts: DateTime<Utc>,
    /// Kind of entry
    pub kind: TimelineEntryKind,
    /// Human-readable summary
    pub summary: String,
    /// Evidence pointers for this entry
    pub evidence_ptrs: Vec<EvidencePtr>,
    /// Related entity scope keys
    pub related_entities: Vec<ScopeKey>,
    /// Sequence number for ordering
    pub sequence: u64,
    /// Whether this entry was added via late-arriving event
    #[serde(default)]
    pub is_late_arrival: bool,
}

impl TimelineEntry {
    pub fn new(ts: DateTime<Utc>, kind: TimelineEntryKind, summary: impl Into<String>) -> Self {
        Self {
            ts,
            kind,
            summary: summary.into(),
            evidence_ptrs: Vec::new(),
            related_entities: Vec::new(),
            sequence: 0,
            is_late_arrival: false,
        }
    }

    /// Mark this entry as derived from a late-arriving event
    pub fn with_late_arrival(mut self, is_late: bool) -> Self {
        self.is_late_arrival = is_late;
        self
    }

    pub fn with_evidence(mut self, ptrs: Vec<EvidencePtr>) -> Self {
        self.evidence_ptrs = ptrs;
        self
    }

    pub fn with_entities(mut self, entities: Vec<ScopeKey>) -> Self {
        self.related_entities = entities;
        self
    }

    /// Get canonical order key for deterministic sorting.
    /// Uses the full 4-tuple: (ts, stream_id, segment_id, record_index)
    /// Falls back to (ts, sequence, "", 0) if no evidence pointers.
    pub fn canonical_order_key(&self) -> EventOrderKey {
        // Use first evidence pointer for the canonical key
        if let Some(ptr) = self.evidence_ptrs.first() {
            EventOrderKey::from_evidence_ptr(ptr)
        } else {
            // No evidence pointer, use ts and sequence as fallback
            EventOrderKey::new(self.ts, format!("_seq_{}", self.sequence), "", 0)
        }
    }
}

// ============================================================================
// Entity Reference
// ============================================================================

/// Reference to an entity involved in the incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRef {
    /// Scope key for the entity
    pub scope_key: ScopeKey,
    /// Role in the incident (actor, target, artifact, etc.)
    pub role: EntityRole,
    /// First seen timestamp
    pub first_seen: DateTime<Utc>,
    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
    /// Evidence count
    pub evidence_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityRole {
    /// Primary actor (attacker process)
    Actor,
    /// Target of the activity
    Target,
    /// Artifact created/modified
    Artifact,
    /// Network endpoint
    NetworkEndpoint,
    /// User account
    UserAccount,
    /// Related but secondary
    Related,
}

// ============================================================================
// Incident
// ============================================================================

/// A promoted security incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    /// Deterministic incident ID
    pub incident_id: String,
    /// Security family
    pub family: String,
    /// Primary scope key
    pub primary_scope_key: ScopeKey,
    /// Related scope keys
    pub related_scope_keys: Vec<ScopeKey>,
    /// First event timestamp
    pub first_ts: DateTime<Utc>,
    /// Last event timestamp
    pub last_ts: DateTime<Utc>,
    /// Current severity
    pub severity: Severity,
    /// Current confidence (0.0 to 1.0)
    pub confidence: f64,
    /// Current status
    pub status: IncidentStatus,
    /// Timeline entries
    pub timeline_entries: Vec<TimelineEntry>,
    /// Involved entities
    pub entities: Vec<EntityRef>,
    /// Hypothesis IDs that promoted to this incident
    pub promoted_from_hypothesis_ids: Vec<String>,
    /// Hypothesis IDs absorbed into this incident
    pub absorbed_hypothesis_ids: Vec<String>,
    /// Candidate hypotheses that were suppressed
    pub suppressed_candidate_hypothesis_ids: Vec<String>,
    /// Reference to explanation bundle
    pub explanation_bundle_ref: Option<String>,
    /// Summary of evidence pointers (bounded)
    pub evidence_ptrs_summary: Vec<EvidencePtr>,
    /// Host ID where incident originated
    pub host_id: String,
    /// Bucket seconds used for ID computation
    pub time_bucket_seconds: i64,
    /// Creation timestamp
    pub created_ts: DateTime<Utc>,
    /// Last update timestamp
    pub updated_ts: DateTime<Utc>,
    /// Closure timestamp
    pub closed_ts: Option<DateTime<Utc>>,
    /// Closure reason
    pub closure_reason: Option<String>,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Tags
    pub tags: HashSet<String>,
}

impl Incident {
    /// Create a new incident from a promoted hypothesis
    pub fn from_hypothesis(hypothesis: &HypothesisState, host_id: &str) -> Self {
        let now = Utc::now();
        let time_bucket_seconds = 3600; // 60 minute buckets for incidents

        let incident_id = Self::compute_incident_id(
            host_id,
            &hypothesis.family,
            &hypothesis.scope_key,
            hypothesis.window_start_ts,
            time_bucket_seconds,
        );

        let mut incident = Self {
            incident_id,
            family: hypothesis.family.clone(),
            primary_scope_key: hypothesis.scope_key.clone(),
            related_scope_keys: Vec::new(),
            first_ts: hypothesis.window_start_ts,
            last_ts: hypothesis.window_end_ts,
            severity: crate::hypothesis::promotion::calculate_severity(hypothesis),
            confidence: crate::hypothesis::promotion::calculate_confidence(hypothesis),
            status: IncidentStatus::Active,
            timeline_entries: Vec::new(),
            entities: Vec::new(),
            promoted_from_hypothesis_ids: vec![hypothesis.hypothesis_id.clone()],
            absorbed_hypothesis_ids: Vec::new(),
            suppressed_candidate_hypothesis_ids: Vec::new(),
            explanation_bundle_ref: None,
            evidence_ptrs_summary: Vec::new(),
            host_id: host_id.to_string(),
            time_bucket_seconds,
            created_ts: now,
            updated_ts: now,
            closed_ts: None,
            closure_reason: None,
            mitre_techniques: Vec::new(),
            tags: HashSet::new(),
        };

        // Build timeline from hypothesis slot fills
        incident.build_timeline_from_hypothesis(hypothesis);

        // Collect evidence pointers
        incident.collect_evidence_summary(hypothesis);

        incident
    }

    /// Compute deterministic incident ID
    /// IncidentId = hash(host_id + family + primary_scope_key + time_bucket_big)
    pub fn compute_incident_id(
        host_id: &str,
        family: &str,
        scope_key: &ScopeKey,
        window_start_ts: DateTime<Utc>,
        time_bucket_seconds: i64,
    ) -> String {
        let time_bucket = window_start_ts.timestamp() / time_bucket_seconds;

        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(family.as_bytes());
        hasher.update(scope_key.to_string().as_bytes());
        hasher.update(time_bucket.to_le_bytes());

        format!("inc_{}", hex::encode(&hasher.finalize()[..16]))
    }

    fn build_timeline_from_hypothesis(&mut self, hypothesis: &HypothesisState) {
        let mut sequence = 0u64;

        for (slot_id, fill) in &hypothesis.slot_fills {
            if fill.satisfied {
                let kind = self.slot_to_timeline_kind(slot_id);
                let summary = format!(
                    "Slot '{}' satisfied with {} evidence(s)",
                    slot_id, fill.count
                );

                let mut entry = TimelineEntry::new(fill.first_ts, kind, summary);
                entry.evidence_ptrs = fill.evidence_ptrs.clone();
                entry.sequence = sequence;
                sequence += 1;

                self.timeline_entries.push(entry);
            }
        }

        // Sort by canonical 4-tuple (ts, stream_id, segment_id, record_index) for determinism
        self.timeline_entries
            .sort_by_key(|a| a.canonical_order_key());
    }

    fn slot_to_timeline_kind(&self, slot_id: &str) -> TimelineEntryKind {
        if slot_id.contains("exec") || slot_id.contains("proc") || slot_id.contains("spawn") {
            TimelineEntryKind::ProcessEvent
        } else if slot_id.contains("file") || slot_id.contains("write") || slot_id.contains("read")
        {
            TimelineEntryKind::FileEvent
        } else if slot_id.contains("net") || slot_id.contains("connect") || slot_id.contains("sock")
        {
            TimelineEntryKind::NetworkEvent
        } else if slot_id.contains("mem") || slot_id.contains("alloc") {
            TimelineEntryKind::MemoryEvent
        } else if slot_id.contains("auth") || slot_id.contains("priv") || slot_id.contains("login")
        {
            TimelineEntryKind::AuthEvent
        } else if slot_id.contains("persist")
            || slot_id.contains("service")
            || slot_id.contains("cron")
        {
            TimelineEntryKind::PersistenceEvent
        } else if slot_id.contains("tamper") || slot_id.contains("log") || slot_id.contains("clear")
        {
            TimelineEntryKind::TamperEvent
        } else {
            TimelineEntryKind::SystemEvent
        }
    }

    fn collect_evidence_summary(&mut self, hypothesis: &HypothesisState) {
        // Collect up to 100 evidence pointers
        let max_ptrs = 100;

        for fill in hypothesis.slot_fills.values() {
            for ptr in &fill.evidence_ptrs {
                if self.evidence_ptrs_summary.len() >= max_ptrs {
                    break;
                }
                if !self.evidence_ptrs_summary.contains(ptr) {
                    self.evidence_ptrs_summary.push(ptr.clone());
                }
            }
        }
    }

    /// Upsert: merge new hypothesis data into existing incident
    pub fn upsert(&mut self, hypothesis: &HypothesisState) {
        self.last_ts = self.last_ts.max(hypothesis.window_end_ts);
        self.updated_ts = Utc::now();

        // Update confidence/severity
        let new_confidence = crate::hypothesis::promotion::calculate_confidence(hypothesis);
        let new_severity = crate::hypothesis::promotion::calculate_severity(hypothesis);

        self.confidence = self.confidence.max(new_confidence);
        if new_severity > self.severity {
            self.severity = new_severity;
        }

        // Add to promoted list if not already there
        if !self
            .promoted_from_hypothesis_ids
            .contains(&hypothesis.hypothesis_id)
        {
            self.promoted_from_hypothesis_ids
                .push(hypothesis.hypothesis_id.clone());
        }

        // Merge timeline entries (dedup by evidence ptr)
        self.build_timeline_from_hypothesis(hypothesis);
        self.dedup_timeline();

        // Merge evidence
        self.collect_evidence_summary(hypothesis);
    }

    fn dedup_timeline(&mut self) {
        let mut seen: HashSet<String> = HashSet::new();
        self.timeline_entries.retain(|e| {
            let key = format!("{:?}_{}", e.ts, e.summary);
            if seen.contains(&key) {
                false
            } else {
                seen.insert(key);
                true
            }
        });
    }

    /// Absorb another hypothesis into this incident
    pub fn absorb_hypothesis(&mut self, hypothesis_id: &str) {
        if !self
            .absorbed_hypothesis_ids
            .contains(&hypothesis_id.to_string())
        {
            self.absorbed_hypothesis_ids.push(hypothesis_id.to_string());
        }
        self.updated_ts = Utc::now();
    }

    /// Add a suppressed candidate
    pub fn add_suppressed_candidate(&mut self, hypothesis_id: &str) {
        if !self
            .suppressed_candidate_hypothesis_ids
            .contains(&hypothesis_id.to_string())
        {
            self.suppressed_candidate_hypothesis_ids
                .push(hypothesis_id.to_string());
        }
    }

    /// Add an entity reference
    pub fn add_entity(&mut self, scope_key: ScopeKey, role: EntityRole, ts: DateTime<Utc>) {
        if let Some(entity) = self.entities.iter_mut().find(|e| e.scope_key == scope_key) {
            entity.last_seen = entity.last_seen.max(ts);
            entity.first_seen = entity.first_seen.min(ts);
            entity.evidence_count += 1;
        } else {
            self.entities.push(EntityRef {
                scope_key,
                role,
                first_seen: ts,
                last_seen: ts,
                evidence_count: 1,
            });
        }
    }

    /// Add a timeline entry
    pub fn add_timeline_entry(&mut self, entry: TimelineEntry) {
        self.timeline_entries.push(entry);
        // Sort by canonical 4-tuple for determinism
        self.timeline_entries
            .sort_by_key(|a| a.canonical_order_key());
    }

    /// Close the incident
    pub fn close(&mut self, reason: &str) {
        self.status = IncidentStatus::Closed;
        self.closed_ts = Some(Utc::now());
        self.closure_reason = Some(reason.to_string());
        self.updated_ts = Utc::now();
    }

    /// Reopen a closed incident (late-arriving events)
    pub fn reopen(&mut self) {
        if self.status == IncidentStatus::Closed {
            self.status = IncidentStatus::Active;
            self.closed_ts = None;
            self.closure_reason = None;
            self.updated_ts = Utc::now();
        }
    }

    /// Suppress the incident
    pub fn suppress(&mut self, reason: &str) {
        self.status = IncidentStatus::Suppressed;
        self.closure_reason = Some(reason.to_string());
        self.updated_ts = Utc::now();
    }

    /// Check if incident can be merged with another
    pub fn can_merge_with(&self, other: &Incident, merge_gap_seconds: i64) -> bool {
        // Same family and scope
        if self.family != other.family {
            return false;
        }

        if self.primary_scope_key != other.primary_scope_key {
            return false;
        }

        // Not closed
        if self.status == IncidentStatus::Closed || other.status == IncidentStatus::Closed {
            return false;
        }

        // Time gap within threshold
        let gap = if self.last_ts < other.first_ts {
            other
                .first_ts
                .signed_duration_since(self.last_ts)
                .num_seconds()
        } else if other.last_ts < self.first_ts {
            self.first_ts
                .signed_duration_since(other.last_ts)
                .num_seconds()
        } else {
            0 // Overlapping
        };

        gap <= merge_gap_seconds
    }

    /// Merge another incident into this one
    pub fn merge(&mut self, other: &Incident) {
        self.first_ts = self.first_ts.min(other.first_ts);
        self.last_ts = self.last_ts.max(other.last_ts);

        // Merge related scope keys
        for key in &other.related_scope_keys {
            if !self.related_scope_keys.contains(key) {
                self.related_scope_keys.push(key.clone());
            }
        }

        // Update confidence/severity
        self.confidence = self.confidence.max(other.confidence);
        if other.severity > self.severity {
            self.severity = other.severity;
        }

        // Merge hypothesis references
        for id in &other.promoted_from_hypothesis_ids {
            if !self.promoted_from_hypothesis_ids.contains(id) {
                self.promoted_from_hypothesis_ids.push(id.clone());
            }
        }

        for id in &other.absorbed_hypothesis_ids {
            if !self.absorbed_hypothesis_ids.contains(id) {
                self.absorbed_hypothesis_ids.push(id.clone());
            }
        }

        // Merge timeline
        for entry in &other.timeline_entries {
            self.timeline_entries.push(entry.clone());
        }
        // Sort by canonical 4-tuple for determinism
        self.timeline_entries
            .sort_by_key(|a| a.canonical_order_key());
        self.dedup_timeline();

        // Merge entities
        for entity in &other.entities {
            self.add_entity(entity.scope_key.clone(), entity.role, entity.last_seen);
        }

        // Merge evidence
        for ptr in &other.evidence_ptrs_summary {
            if self.evidence_ptrs_summary.len() < 100 && !self.evidence_ptrs_summary.contains(ptr) {
                self.evidence_ptrs_summary.push(ptr.clone());
            }
        }

        // Merge tags and techniques
        self.tags.extend(other.tags.iter().cloned());
        for technique in &other.mitre_techniques {
            if !self.mitre_techniques.contains(technique) {
                self.mitre_techniques.push(technique.clone());
            }
        }

        self.updated_ts = Utc::now();
    }
}

// ============================================================================
// Incident Store
// ============================================================================

/// In-memory incident store
#[derive(Debug, Default)]
pub struct IncidentStore {
    incidents: HashMap<String, Incident>,
    by_scope: HashMap<String, HashSet<String>>,
    by_family: HashMap<String, HashSet<String>>,
    by_host: HashMap<String, HashSet<String>>,
}

impl IncidentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update an incident
    pub fn upsert(&mut self, incident: Incident) {
        let id = incident.incident_id.clone();
        let scope = incident.primary_scope_key.to_string();
        let family = incident.family.clone();
        let host_id = incident.host_id.clone();

        self.by_scope.entry(scope).or_default().insert(id.clone());
        self.by_family.entry(family).or_default().insert(id.clone());
        self.by_host.entry(host_id).or_default().insert(id.clone());
        self.incidents.insert(id, incident);
    }

    /// Get incident by ID
    pub fn get(&self, id: &str) -> Option<&Incident> {
        self.incidents.get(id)
    }

    /// Get mutable incident by ID
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Incident> {
        self.incidents.get_mut(id)
    }

    /// Get active incidents by host
    pub fn active_by_host(&self, host_id: &str) -> Vec<&Incident> {
        self.by_host
            .get(host_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.incidents.get(id))
                    .filter(|i| i.status == IncidentStatus::Active)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find incident for upsert based on deterministic ID
    pub fn find_for_upsert(
        &mut self,
        host_id: &str,
        family: &str,
        scope_key: &ScopeKey,
        window_start_ts: DateTime<Utc>,
    ) -> Option<&mut Incident> {
        let incident_id = Incident::compute_incident_id(
            host_id,
            family,
            scope_key,
            window_start_ts,
            3600, // Default bucket
        );

        self.incidents.get_mut(&incident_id)
    }

    /// Find mergeable incidents
    pub fn find_mergeable(&self, incident: &Incident, merge_gap_seconds: i64) -> Vec<String> {
        self.incidents
            .values()
            .filter(|i| {
                i.incident_id != incident.incident_id
                    && incident.can_merge_with(i, merge_gap_seconds)
            })
            .map(|i| i.incident_id.clone())
            .collect()
    }
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
    fn test_incident_id_determinism() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let id1 = Incident::compute_incident_id("host1", "injection", &scope, ts, 3600);
        let id2 = Incident::compute_incident_id("host1", "injection", &scope, ts, 3600);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_incident_from_hypothesis() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = Utc::now();

        let mut hypothesis = HypothesisState::new(
            "host1",
            "injection",
            "template1",
            scope.clone(),
            ts,
            600,
            3600,
        );
        hypothesis.add_required_slot(Slot::required("exec", "Exec", FactDomain::Process, "pred1"));

        let incident = Incident::from_hypothesis(&hypothesis, "host1");

        assert!(incident.incident_id.starts_with("inc_"));
        assert_eq!(incident.family, "injection");
        assert_eq!(incident.status, IncidentStatus::Active);
    }

    #[test]
    fn test_incident_merge() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts1 = Utc::now();
        let ts2 = ts1 + chrono::Duration::minutes(30);

        let hyp1 = HypothesisState::new("host1", "injection", "t1", scope.clone(), ts1, 600, 3600);
        let hyp2 = HypothesisState::new("host1", "injection", "t1", scope.clone(), ts2, 600, 3600);

        let incident1 = Incident::from_hypothesis(&hyp1, "host1");
        let incident2 = Incident::from_hypothesis(&hyp2, "host1");

        assert!(incident1.can_merge_with(&incident2, 3600));
    }
}

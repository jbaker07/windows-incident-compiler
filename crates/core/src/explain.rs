//! ExplanationBundle: Compact, verifiable explanation for a signal.
//!
//! This module provides the ExplanationBundle struct that contains everything
//! needed to understand WHY a signal fired:
//! - Which playbook matched
//! - Which slots were filled (or not)
//! - Which facts filled each slot
//! - Evidence pointers back to raw segment records
//! - Explicit limitations (missing telemetry, etc.)

use crate::EvidencePtr;
use serde::{Deserialize, Serialize};

// ============================================================================
// ExplanationBundle - Top-Level Schema
// ============================================================================

/// Compact explanation bundle for a signal, supporting full audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplanationBundle {
    /// Signal ID this explanation is for
    pub signal_id: String,

    /// Playbook ID that generated this signal
    pub playbook_id: String,

    /// Playbook title (human-readable)
    pub playbook_title: String,

    /// Security family (e.g., "persistence", "defense_evasion")
    pub family: String,

    /// Timestamp when the playbook matched (all required slots filled)
    pub matched_at_ms: i64,

    /// Human-readable summary (1-3 sentences)
    pub summary: String,

    /// Slot fill details
    pub slots: Vec<SlotExplanation>,

    /// Entity keys involved in this signal
    pub entities: EntityBundle,

    /// Evidence excerpts with dereferenced content
    pub evidence: Vec<EvidenceExcerpt>,

    /// Counters for telemetry coverage
    pub counters: ExplanationCounters,

    /// Explicit limitations/uncertainties
    pub limitations: Vec<String>,

    /// Generated timestamp
    pub generated_at_ms: i64,
}

// ============================================================================
// SlotExplanation
// ============================================================================

/// Explanation for a single slot in the playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotExplanation {
    /// Slot identifier
    pub slot_id: String,

    /// Human-readable slot name
    pub name: String,

    /// Whether this slot is required
    pub required: bool,

    /// TTL in seconds for this slot
    pub ttl_seconds: u64,

    /// Current status
    pub status: SlotStatus,

    /// Human-readable description of what this slot matches
    pub predicate_desc: String,

    /// Facts that filled this slot
    pub matched_facts: Vec<MatchedFact>,
}

/// Status of a slot fill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    /// Slot is filled and satisfied
    Filled,
    /// Slot has partial fills but not fully satisfied
    Partial,
    /// Slot is empty (no matching facts)
    Empty,
    /// Slot expired (TTL exceeded before fill)
    Expired,
}

// ============================================================================
// MatchedFact
// ============================================================================

/// A fact that matched and filled a slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedFact {
    /// Fact ID
    pub fact_id: String,

    /// Fact type discriminant (e.g., "LogTamper", "PersistArtifact")
    pub fact_type: String,

    /// Timestamp of the fact
    pub ts_ms: i64,

    /// Entity keys extracted from the fact
    pub entity_keys: FactEntityKeys,

    /// Evidence pointers from this fact
    pub evidence_ptrs: Vec<EvidencePtr>,
}

/// Entity keys extracted from a fact
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FactEntityKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_key: Option<String>,
}

// ============================================================================
// EntityBundle
// ============================================================================

/// Bundle of all entity keys involved in the signal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityBundle {
    /// Process keys (proc_guid, exe path)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proc_keys: Vec<String>,

    /// File paths
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_keys: Vec<String>,

    /// Identity/user keys
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_keys: Vec<String>,

    /// Network keys (ip:port)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net_keys: Vec<String>,

    /// Registry keys
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry_keys: Vec<String>,
}

// ============================================================================
// EvidenceExcerpt
// ============================================================================

/// Evidence pointer with dereferenced excerpt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExcerpt {
    /// The evidence pointer
    pub ptr: EvidencePtr,

    /// Dereferenced excerpt (first 200-500 chars of raw record)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,

    /// Timestamp of the record
    pub ts_ms: i64,

    /// Source description (e.g., "Security/4624", "Sysmon/1")
    pub source: String,
}

// ============================================================================
// ExplanationCounters
// ============================================================================

/// Telemetry coverage counters for the explanation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplanationCounters {
    /// Total events seen in the time window
    pub events_seen: u64,

    /// Facts extracted from those events
    pub facts_emitted: u64,

    /// Required slots filled
    pub required_slots_filled: u32,

    /// Required slots total
    pub required_slots_total: u32,

    /// Optional slots filled
    pub optional_slots_filled: u32,

    /// Optional slots total
    pub optional_slots_total: u32,
}

// ============================================================================
// Builder for ExplanationBundle
// ============================================================================

impl ExplanationBundle {
    /// Create a new explanation bundle builder
    pub fn builder(
        signal_id: impl Into<String>,
        playbook_id: impl Into<String>,
    ) -> ExplanationBundleBuilder {
        ExplanationBundleBuilder {
            signal_id: signal_id.into(),
            playbook_id: playbook_id.into(),
            playbook_title: String::new(),
            family: String::new(),
            matched_at_ms: 0,
            summary: String::new(),
            slots: Vec::new(),
            entities: EntityBundle::default(),
            evidence: Vec::new(),
            counters: ExplanationCounters::default(),
            limitations: Vec::new(),
        }
    }
}

/// Builder for constructing ExplanationBundle
pub struct ExplanationBundleBuilder {
    signal_id: String,
    playbook_id: String,
    playbook_title: String,
    family: String,
    matched_at_ms: i64,
    summary: String,
    slots: Vec<SlotExplanation>,
    entities: EntityBundle,
    evidence: Vec<EvidenceExcerpt>,
    counters: ExplanationCounters,
    limitations: Vec<String>,
}

impl ExplanationBundleBuilder {
    pub fn playbook_title(mut self, title: impl Into<String>) -> Self {
        self.playbook_title = title.into();
        self
    }

    pub fn family(mut self, family: impl Into<String>) -> Self {
        self.family = family.into();
        self
    }

    pub fn matched_at_ms(mut self, ts: i64) -> Self {
        self.matched_at_ms = ts;
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn add_slot(mut self, slot: SlotExplanation) -> Self {
        self.slots.push(slot);
        self
    }

    pub fn slots(mut self, slots: Vec<SlotExplanation>) -> Self {
        self.slots = slots;
        self
    }

    pub fn entities(mut self, entities: EntityBundle) -> Self {
        self.entities = entities;
        self
    }

    pub fn add_evidence(mut self, evidence: EvidenceExcerpt) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn evidence(mut self, evidence: Vec<EvidenceExcerpt>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn counters(mut self, counters: ExplanationCounters) -> Self {
        self.counters = counters;
        self
    }

    pub fn add_limitation(mut self, limitation: impl Into<String>) -> Self {
        self.limitations.push(limitation.into());
        self
    }

    pub fn limitations(mut self, limitations: Vec<String>) -> Self {
        self.limitations = limitations;
        self
    }

    pub fn build(self) -> ExplanationBundle {
        let now = chrono::Utc::now().timestamp_millis();
        ExplanationBundle {
            signal_id: self.signal_id,
            playbook_id: self.playbook_id,
            playbook_title: self.playbook_title,
            family: self.family,
            matched_at_ms: self.matched_at_ms,
            summary: self.summary,
            slots: self.slots,
            entities: self.entities,
            evidence: self.evidence,
            counters: self.counters,
            limitations: self.limitations,
            generated_at_ms: now,
        }
    }
}

// ============================================================================
// SlotExplanation Builder
// ============================================================================

impl SlotExplanation {
    /// Create a new slot explanation
    pub fn new(
        slot_id: impl Into<String>,
        name: impl Into<String>,
        required: bool,
        ttl_seconds: u64,
    ) -> Self {
        Self {
            slot_id: slot_id.into(),
            name: name.into(),
            required,
            ttl_seconds,
            status: SlotStatus::Empty,
            predicate_desc: String::new(),
            matched_facts: Vec::new(),
        }
    }

    pub fn with_status(mut self, status: SlotStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_predicate_desc(mut self, desc: impl Into<String>) -> Self {
        self.predicate_desc = desc.into();
        self
    }

    pub fn with_matched_facts(mut self, facts: Vec<MatchedFact>) -> Self {
        self.matched_facts = facts;
        self
    }

    pub fn add_matched_fact(mut self, fact: MatchedFact) -> Self {
        self.matched_facts.push(fact);
        self
    }
}

// ============================================================================
// MatchedFact Builder
// ============================================================================

impl MatchedFact {
    pub fn new(fact_id: impl Into<String>, fact_type: impl Into<String>, ts_ms: i64) -> Self {
        Self {
            fact_id: fact_id.into(),
            fact_type: fact_type.into(),
            ts_ms,
            entity_keys: FactEntityKeys::default(),
            evidence_ptrs: Vec::new(),
        }
    }

    pub fn with_entity_keys(mut self, keys: FactEntityKeys) -> Self {
        self.entity_keys = keys;
        self
    }

    pub fn with_evidence_ptrs(mut self, ptrs: Vec<EvidencePtr>) -> Self {
        self.evidence_ptrs = ptrs;
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
    fn test_explanation_bundle_builder() {
        let bundle = ExplanationBundle::builder("sig_001", "windows_log_tamper_clear")
            .playbook_title("Windows Log Tamper: Clear")
            .family("defense_evasion")
            .matched_at_ms(1700000000000)
            .summary("Security event log was cleared by a non-system process.")
            .add_slot(
                SlotExplanation::new("slot_log_clear", "Log Clear Event", true, 300)
                    .with_status(SlotStatus::Filled)
                    .with_predicate_desc("LogTamper where subtype=clear")
                    .add_matched_fact(
                        MatchedFact::new("fact_001", "LogTamper", 1700000000000)
                            .with_evidence_ptrs(vec![EvidencePtr {
                                stream_id: "evtx".to_string(),
                                segment_id: 1,
                                record_index: 42,
                            }]),
                    ),
            )
            .add_limitation("DNS resolution telemetry not available")
            .build();

        assert_eq!(bundle.signal_id, "sig_001");
        assert_eq!(bundle.playbook_id, "windows_log_tamper_clear");
        assert_eq!(bundle.slots.len(), 1);
        assert_eq!(bundle.slots[0].status, SlotStatus::Filled);
        assert_eq!(bundle.slots[0].matched_facts.len(), 1);
        assert_eq!(bundle.limitations.len(), 1);
    }

    #[test]
    fn test_slot_status_serialization() {
        let filled = SlotStatus::Filled;
        let json = serde_json::to_string(&filled).unwrap();
        assert_eq!(json, "\"filled\"");

        let empty = SlotStatus::Empty;
        let json = serde_json::to_string(&empty).unwrap();
        assert_eq!(json, "\"empty\"");
    }
}

//! HypothesisState: State machine for tracking security hypotheses.
//!
//! Hypotheses track partially-filled playbook slots and progress toward incident promotion.

use super::canonical_event::EvidencePtr;
use super::canonical_fact::FactDomain;
use super::scope_keys::ScopeKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// ============================================================================
// Slot Definitions
// ============================================================================

/// Requirement level for a slot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotRequirement {
    Required,
    Optional,
}

/// Ordering constraint between slots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderingConstraint {
    /// Slot that must come first
    pub before_slot: String,
    /// Slot that must come after
    pub after_slot: String,
    /// Maximum time gap allowed (seconds)
    pub max_gap_seconds: Option<i64>,
}

/// Definition of a hypothesis slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    /// Unique slot identifier within template
    pub slot_id: String,
    /// Human-readable name
    pub name: String,
    /// Domain this slot belongs to
    pub domain: FactDomain,
    /// Whether slot is required or optional
    pub requirement: SlotRequirement,
    /// Predicate ID for matching facts
    pub predicate_id: String,
    /// Minimum number of fills required (usually 1)
    pub min_count: u32,
    /// Maximum fills to track (for burst compression)
    pub max_count: u32,
    /// Time window for fills (seconds from hypothesis start)
    pub within_seconds: Option<i64>,
    /// Ordering constraints relative to other slots
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ordering_constraints: Vec<OrderingConstraint>,
}

impl Slot {
    pub fn required(
        slot_id: impl Into<String>,
        name: impl Into<String>,
        domain: FactDomain,
        predicate_id: impl Into<String>,
    ) -> Self {
        Self {
            slot_id: slot_id.into(),
            name: name.into(),
            domain,
            requirement: SlotRequirement::Required,
            predicate_id: predicate_id.into(),
            min_count: 1,
            max_count: 100,
            within_seconds: None,
            ordering_constraints: Vec::new(),
        }
    }

    pub fn optional(
        slot_id: impl Into<String>,
        name: impl Into<String>,
        domain: FactDomain,
        predicate_id: impl Into<String>,
    ) -> Self {
        Self {
            slot_id: slot_id.into(),
            name: name.into(),
            domain,
            requirement: SlotRequirement::Optional,
            predicate_id: predicate_id.into(),
            min_count: 1,
            max_count: 100,
            within_seconds: None,
            ordering_constraints: Vec::new(),
        }
    }

    pub fn with_count(mut self, min: u32, max: u32) -> Self {
        self.min_count = min;
        self.max_count = max;
        self
    }

    pub fn within(mut self, seconds: i64) -> Self {
        self.within_seconds = Some(seconds);
        self
    }

    pub fn must_follow(mut self, before_slot: impl Into<String>) -> Self {
        self.ordering_constraints.push(OrderingConstraint {
            before_slot: before_slot.into(),
            after_slot: self.slot_id.clone(),
            max_gap_seconds: None,
        });
        self
    }
}

// ============================================================================
// Slot Fill
// ============================================================================

/// Strength of a slot fill
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillStrength {
    /// Strong evidence, high confidence
    Strong,
    /// Weak evidence, lower confidence (e.g., partial match)
    Weak,
}

/// A fill for a hypothesis slot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotFill {
    /// ID of the slot being filled
    pub slot_id: String,
    /// Whether the slot is satisfied
    pub satisfied: bool,
    /// Strength of the fill
    pub strength: FillStrength,
    /// Evidence pointers for this fill
    pub evidence_ptrs: Vec<EvidencePtr>,
    /// Fact references (fact_ids)
    pub fact_refs: Vec<String>,
    /// First fill timestamp
    pub first_ts: DateTime<Utc>,
    /// Last fill timestamp
    pub last_ts: DateTime<Utc>,
    /// Number of fills (for burst compression)
    pub count: u32,
    /// Sample evidence ptrs if count > max_count
    pub sample_ptrs: Vec<EvidencePtr>,
    /// Optional notes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl SlotFill {
    pub fn new(slot_id: impl Into<String>, ts: DateTime<Utc>) -> Self {
        Self {
            slot_id: slot_id.into(),
            satisfied: false,
            strength: FillStrength::Weak,
            evidence_ptrs: Vec::new(),
            fact_refs: Vec::new(),
            first_ts: ts,
            last_ts: ts,
            count: 0,
            sample_ptrs: Vec::new(),
            notes: None,
        }
    }

    /// Add evidence to this fill
    pub fn add_evidence(
        &mut self,
        ptr: EvidencePtr,
        fact_id: String,
        ts: DateTime<Utc>,
        max_ptrs: usize,
    ) {
        self.count += 1;
        self.last_ts = ts.max(self.last_ts);
        self.first_ts = ts.min(self.first_ts);

        if !self.fact_refs.contains(&fact_id) {
            self.fact_refs.push(fact_id);
        }

        // Compress: keep first N ptrs, then sample
        if self.evidence_ptrs.len() < max_ptrs {
            self.evidence_ptrs.push(ptr);
        } else if self.sample_ptrs.len() < 10 {
            // Keep a sample of later evidence
            self.sample_ptrs.push(ptr);
        }
    }

    /// Mark as satisfied with given strength
    pub fn satisfy(&mut self, strength: FillStrength) {
        self.satisfied = true;
        self.strength = strength;
    }
}

// ============================================================================
// Visibility State
// ============================================================================

/// Tracks what streams/sensors are available vs missing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VisibilityState {
    /// Streams that have provided data
    pub streams_present: HashSet<String>,
    /// Streams that are expected but missing
    pub streams_missing: HashSet<String>,
    /// Reasons for degraded visibility
    pub degraded_reasons: Vec<String>,
    /// Last seen evidence ptr per stream
    pub last_seen_ptr_per_stream: HashMap<String, EvidencePtr>,
}

impl VisibilityState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_stream(&mut self, stream_id: &str, ptr: EvidencePtr) {
        self.streams_present.insert(stream_id.to_string());
        self.streams_missing.remove(stream_id);
        self.last_seen_ptr_per_stream
            .insert(stream_id.to_string(), ptr);
    }

    pub fn mark_missing(&mut self, stream_id: &str, reason: &str) {
        if !self.streams_present.contains(stream_id) {
            self.streams_missing.insert(stream_id.to_string());
            self.degraded_reasons
                .push(format!("{}: {}", stream_id, reason));
        }
    }

    pub fn is_degraded(&self) -> bool {
        !self.streams_missing.is_empty()
    }

    /// Calculate visibility penalty (0.0 to 1.0)
    pub fn penalty(&self) -> f64 {
        if self.streams_missing.is_empty() {
            0.0
        } else {
            // Each missing critical stream adds 0.2 penalty (max 0.4)
            (self.streams_missing.len() as f64 * 0.2).min(0.4)
        }
    }
}

// ============================================================================
// Hypothesis Status
// ============================================================================

/// Status of a hypothesis in the lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    /// Active hypothesis, gathering evidence
    Hypothesis,
    /// Promoted to incident
    Promoted,
    /// Absorbed into another hypothesis/incident
    Absorbed,
    /// Expired due to TTL
    Expired,
    /// Suppressed by analyst or rule
    Suppressed,
}

// ============================================================================
// Corroboration Vector
// ============================================================================

/// Counts of evidence per domain
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorroborationVector {
    pub process: u32,
    pub file: u32,
    pub network: u32,
    pub auth: u32,
    pub memory: u32,
    pub persist: u32,
    pub tamper: u32,
}

impl CorroborationVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&mut self, domain: FactDomain) {
        match domain {
            FactDomain::Process | FactDomain::Execution => self.process += 1,
            FactDomain::File => self.file += 1,
            FactDomain::Network => self.network += 1,
            FactDomain::Auth => self.auth += 1,
            FactDomain::Memory => self.memory += 1,
            FactDomain::Persist => self.persist += 1,
            FactDomain::Tamper => self.tamper += 1,
            FactDomain::Module => self.process += 1,
            FactDomain::Unknown => {}
        }
    }

    /// Count of domains with at least one observation
    pub fn domain_count(&self) -> u32 {
        let mut count = 0;
        if self.process > 0 {
            count += 1;
        }
        if self.file > 0 {
            count += 1;
        }
        if self.network > 0 {
            count += 1;
        }
        if self.auth > 0 {
            count += 1;
        }
        if self.memory > 0 {
            count += 1;
        }
        if self.persist > 0 {
            count += 1;
        }
        if self.tamper > 0 {
            count += 1;
        }
        count
    }

    /// Check if specific high-value domains are present
    pub fn has_high_value_domain(&self) -> bool {
        self.network > 0 || self.persist > 0 || self.memory > 0
    }
}

// ============================================================================
// Surprise Vector (from fingerprints/baselines)
// ============================================================================

/// Measures how unusual the observed behavior is
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SurpriseVector {
    /// Overall surprise score (0.0 to 1.0)
    pub score: f64,
    /// Per-domain surprise
    pub by_domain: HashMap<FactDomain, f64>,
    /// Specific surprises observed
    pub surprises: Vec<String>,
}

impl SurpriseVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_surprise(&mut self, domain: FactDomain, amount: f64, description: &str) {
        let entry = self.by_domain.entry(domain).or_insert(0.0);
        *entry = (*entry + amount).min(1.0);
        self.surprises.push(description.to_string());
        self.recalculate_score();
    }

    fn recalculate_score(&mut self) {
        if self.by_domain.is_empty() {
            self.score = 0.0;
        } else {
            self.score = self.by_domain.values().sum::<f64>() / self.by_domain.len() as f64;
        }
    }

    /// Get boost value for maturity calculation (0.0 to 0.2)
    pub fn boost(&self) -> f64 {
        (self.score * 0.2).min(0.2)
    }
}

// ============================================================================
// HypothesisState
// ============================================================================

/// Complete state for a hypothesis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisState {
    /// Deterministic hypothesis ID
    pub hypothesis_id: String,
    /// Security family (e.g., "injection", "exfiltration", "persistence")
    pub family: String,
    /// Template ID within family
    pub template_id: String,
    /// Primary scope key for this hypothesis
    pub scope_key: ScopeKey,
    /// Time window start
    pub window_start_ts: DateTime<Utc>,
    /// Time window end
    pub window_end_ts: DateTime<Utc>,
    /// Creation timestamp
    pub created_ts: DateTime<Utc>,
    /// Last update timestamp
    pub updated_ts: DateTime<Utc>,

    /// Required slot definitions
    pub required_slots: Vec<Slot>,
    /// Optional slot definitions
    pub optional_slots: Vec<Slot>,
    /// Current slot fills
    pub slot_fills: HashMap<String, SlotFill>,

    /// Calculated maturity score (0.0 to 1.0)
    pub maturity_score: f64,
    /// Corroboration vector (domain counts)
    pub corroboration_vector: CorroborationVector,
    /// Surprise vector from baselines
    pub surprise_vector: SurpriseVector,

    /// Computed disambiguators
    pub disambiguators: Vec<String>,
    /// Visibility state
    pub visibility_state: VisibilityState,

    /// Current status
    pub status: HypothesisStatus,
    /// If absorbed, the incident ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absorbed_into_incident_id: Option<String>,
    /// If suppressed, the suppressing hypothesis ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_by_hypothesis_id: Option<String>,

    /// TTL expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Bucket seconds used for ID computation
    pub bucket_seconds: i64,
}

impl HypothesisState {
    /// Create a new hypothesis with deterministic ID
    pub fn new(
        host_id: &str,
        family: impl Into<String>,
        template_id: impl Into<String>,
        scope_key: ScopeKey,
        window_start_ts: DateTime<Utc>,
        bucket_seconds: i64,
        ttl_seconds: i64,
    ) -> Self {
        let family = family.into();
        let template_id = template_id.into();
        let now = Utc::now();

        // Compute deterministic hypothesis ID
        let hypothesis_id = Self::compute_hypothesis_id(
            host_id,
            &family,
            &scope_key,
            window_start_ts,
            bucket_seconds,
            &template_id,
        );

        Self {
            hypothesis_id,
            family,
            template_id,
            scope_key,
            window_start_ts,
            window_end_ts: window_start_ts,
            created_ts: now,
            updated_ts: now,
            required_slots: Vec::new(),
            optional_slots: Vec::new(),
            slot_fills: HashMap::new(),
            maturity_score: 0.0,
            corroboration_vector: CorroborationVector::new(),
            surprise_vector: SurpriseVector::new(),
            disambiguators: Vec::new(),
            visibility_state: VisibilityState::new(),
            status: HypothesisStatus::Hypothesis,
            absorbed_into_incident_id: None,
            suppressed_by_hypothesis_id: None,
            expires_at: now + chrono::Duration::seconds(ttl_seconds),
            bucket_seconds,
        }
    }

    /// Compute deterministic hypothesis ID
    /// HypothesisId = hash(host_id + family + scope_key + window_bucket + template_id)
    pub fn compute_hypothesis_id(
        host_id: &str,
        family: &str,
        scope_key: &ScopeKey,
        window_start_ts: DateTime<Utc>,
        bucket_seconds: i64,
        template_id: &str,
    ) -> String {
        let window_bucket = window_start_ts.timestamp() / bucket_seconds;

        let mut hasher = Sha256::new();
        hasher.update(host_id.as_bytes());
        hasher.update(family.as_bytes());
        hasher.update(scope_key.to_string().as_bytes());
        hasher.update(window_bucket.to_le_bytes());
        hasher.update(template_id.as_bytes());

        format!("hyp_{}", hex::encode(&hasher.finalize()[..16]))
    }

    /// Add a required slot
    pub fn add_required_slot(&mut self, slot: Slot) {
        self.required_slots.push(slot);
    }

    /// Add an optional slot
    pub fn add_optional_slot(&mut self, slot: Slot) {
        self.optional_slots.push(slot);
    }

    /// Fill a slot with evidence
    pub fn fill_slot(
        &mut self,
        slot_id: &str,
        evidence_ptr: EvidencePtr,
        fact_id: String,
        fact_domain: FactDomain,
        ts: DateTime<Utc>,
    ) {
        let max_ptrs = self
            .get_slot(slot_id)
            .map(|s| s.max_count as usize)
            .unwrap_or(100);

        let fill = self
            .slot_fills
            .entry(slot_id.to_string())
            .or_insert_with(|| SlotFill::new(slot_id, ts));

        fill.add_evidence(evidence_ptr.clone(), fact_id, ts, max_ptrs);

        // Update corroboration
        self.corroboration_vector.increment(fact_domain);

        // Update visibility
        let stream_id = evidence_ptr.stream_id.clone();
        self.visibility_state.add_stream(&stream_id, evidence_ptr);

        // Extend window
        self.window_end_ts = self.window_end_ts.max(ts);
        self.updated_ts = Utc::now();

        // Check if slot is now satisfied
        self.evaluate_slot_satisfaction(slot_id);
    }

    /// Get slot definition by ID
    pub fn get_slot(&self, slot_id: &str) -> Option<&Slot> {
        self.required_slots
            .iter()
            .chain(self.optional_slots.iter())
            .find(|s| s.slot_id == slot_id)
    }

    /// Evaluate if a specific slot is satisfied
    fn evaluate_slot_satisfaction(&mut self, slot_id: &str) {
        let slot = match self.get_slot(slot_id) {
            Some(s) => s.clone(),
            None => return,
        };

        // Get fill info first, then release the borrow
        let (should_update, _fill_count, fill_first_ts, fill_last_ts, time_ok) = {
            let fill = match self.slot_fills.get(slot_id) {
                Some(f) => f,
                None => return,
            };

            // Check min_count
            if fill.count < slot.min_count {
                return;
            }

            // Check time constraint
            let time_ok = slot
                .within_seconds
                .map(|w| {
                    let duration = fill.last_ts.signed_duration_since(self.window_start_ts);
                    duration.num_seconds() <= w
                })
                .unwrap_or(true);

            (true, fill.count, fill.first_ts, fill.last_ts, time_ok)
        };

        if should_update {
            // Check ordering constraints (now we don't have mutable borrow)
            let order_ok =
                self.check_ordering_constraints_internal(&slot, fill_first_ts, fill_last_ts);

            if let Some(fill) = self.slot_fills.get_mut(slot_id) {
                if time_ok && order_ok {
                    fill.satisfy(FillStrength::Strong);
                } else if time_ok {
                    fill.satisfy(FillStrength::Weak);
                }
            }
        }

        // Recalculate maturity after any fill change
        self.recalculate_maturity();
    }

    /// Check ordering constraints for a slot (internal helper)
    fn check_ordering_constraints_internal(
        &self,
        slot: &Slot,
        fill_first_ts: DateTime<Utc>,
        _fill_last_ts: DateTime<Utc>,
    ) -> bool {
        for constraint in &slot.ordering_constraints {
            if constraint.after_slot == slot.slot_id {
                // This slot must come after before_slot
                if let Some(before_fill) = self.slot_fills.get(&constraint.before_slot) {
                    if fill_first_ts < before_fill.last_ts {
                        return false;
                    }
                    if let Some(max_gap) = constraint.max_gap_seconds {
                        let gap = fill_first_ts.signed_duration_since(before_fill.last_ts);
                        if gap.num_seconds() > max_gap {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Check ordering constraints for a slot
    #[allow(dead_code)]
    fn check_ordering_constraints(&self, slot: &Slot, fill: &SlotFill) -> bool {
        self.check_ordering_constraints_internal(slot, fill.first_ts, fill.last_ts)
    }

    /// Recalculate maturity score
    fn recalculate_maturity(&mut self) {
        self.maturity_score = crate::hypothesis::promotion::calculate_maturity(self);
    }

    /// Get count of satisfied required slots (strong fills only)
    pub fn required_satisfied_count(&self) -> usize {
        self.required_slots
            .iter()
            .filter(|s| {
                self.slot_fills
                    .get(&s.slot_id)
                    .map(|f| f.satisfied && f.strength == FillStrength::Strong)
                    .unwrap_or(false)
            })
            .count()
    }

    /// Get count of satisfied optional slots (strong fills only)
    pub fn optional_satisfied_count(&self) -> usize {
        self.optional_slots
            .iter()
            .filter(|s| {
                self.slot_fills
                    .get(&s.slot_id)
                    .map(|f| f.satisfied && f.strength == FillStrength::Strong)
                    .unwrap_or(false)
            })
            .count()
    }

    /// Check if all required slots are satisfied
    pub fn all_required_satisfied(&self) -> bool {
        self.required_satisfied_count() == self.required_slots.len()
    }

    /// Get missing required slot IDs
    pub fn missing_required_slots(&self) -> Vec<String> {
        self.required_slots
            .iter()
            .filter(|s| {
                !self
                    .slot_fills
                    .get(&s.slot_id)
                    .map(|f| f.satisfied)
                    .unwrap_or(false)
            })
            .map(|s| s.slot_id.clone())
            .collect()
    }

    /// Mark as promoted
    pub fn promote(&mut self, incident_id: &str) {
        self.status = HypothesisStatus::Promoted;
        self.absorbed_into_incident_id = Some(incident_id.to_string());
        self.updated_ts = Utc::now();
    }

    /// Mark as absorbed
    pub fn absorb(&mut self, absorbing_hypothesis_id: &str) {
        self.status = HypothesisStatus::Absorbed;
        self.suppressed_by_hypothesis_id = Some(absorbing_hypothesis_id.to_string());
        self.updated_ts = Utc::now();
    }

    /// Mark as expired
    pub fn expire(&mut self) {
        self.status = HypothesisStatus::Expired;
        self.updated_ts = Utc::now();
    }

    /// Check if hypothesis is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if hypothesis is still active
    pub fn is_active(&self) -> bool {
        self.status == HypothesisStatus::Hypothesis && !self.is_expired()
    }
}

// ============================================================================
// Hypothesis Store
// ============================================================================

/// In-memory store for hypotheses
#[derive(Debug, Default)]
pub struct HypothesisStore {
    hypotheses: HashMap<String, HypothesisState>,
    by_scope: HashMap<String, HashSet<String>>,
    by_family: HashMap<String, HashSet<String>>,
    by_host: HashMap<String, HashSet<String>>,
}

impl HypothesisStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a hypothesis
    pub fn upsert(&mut self, hypothesis: HypothesisState) {
        let id = hypothesis.hypothesis_id.clone();
        let scope = hypothesis.scope_key.to_string();
        let family = hypothesis.family.clone();

        // Extract host_id from scope_key (first segment before ':')
        let host_id = scope.split(':').next().unwrap_or("").to_string();

        self.by_scope.entry(scope).or_default().insert(id.clone());
        self.by_family.entry(family).or_default().insert(id.clone());
        self.by_host.entry(host_id).or_default().insert(id.clone());
        self.hypotheses.insert(id, hypothesis);
    }

    /// Get hypothesis by ID
    pub fn get(&self, id: &str) -> Option<&HypothesisState> {
        self.hypotheses.get(id)
    }

    /// Get mutable hypothesis by ID
    pub fn get_mut(&mut self, id: &str) -> Option<&mut HypothesisState> {
        self.hypotheses.get_mut(id)
    }

    /// Get hypotheses by scope
    pub fn by_scope(&self, scope_key: &ScopeKey) -> Vec<&HypothesisState> {
        self.by_scope
            .get(&scope_key.to_string())
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.hypotheses.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get active hypotheses by family
    pub fn by_family(&self, family: &str) -> Vec<&HypothesisState> {
        self.by_family
            .get(family)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.hypotheses.get(id))
                    .filter(|h| h.is_active())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get hypotheses overlapping a time window
    pub fn overlapping_window(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&HypothesisState> {
        self.hypotheses
            .values()
            .filter(|h| h.window_start_ts <= end && h.window_end_ts >= start)
            .collect()
    }

    /// Expire old hypotheses
    pub fn expire_old(&mut self) {
        let now = Utc::now();
        for hypothesis in self.hypotheses.values_mut() {
            if hypothesis.is_active() && hypothesis.expires_at < now {
                hypothesis.expire();
            }
        }
    }

    /// Remove expired hypotheses (garbage collection)
    pub fn gc_expired(&mut self, max_age_seconds: i64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_seconds);
        self.hypotheses.retain(|_, h| h.updated_ts > cutoff);
        // Note: Should also clean up indexes, simplified here
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

impl HypothesisState {
    /// Create a hypothesis for testing purposes with minimal setup
    pub fn new_for_testing(
        hypothesis_id: &str,
        _host_id: &str,
        scope_key: ScopeKey,
        family: &str,
        maturity_score: f64,
    ) -> Self {
        let now = Utc::now();
        Self {
            hypothesis_id: hypothesis_id.to_string(),
            family: family.to_string(),
            template_id: "test_template".to_string(),
            scope_key,
            window_start_ts: now - chrono::Duration::hours(1),
            window_end_ts: now,
            created_ts: now,
            updated_ts: now,
            required_slots: Vec::new(),
            optional_slots: Vec::new(),
            slot_fills: HashMap::new(),
            maturity_score,
            corroboration_vector: CorroborationVector::new(),
            surprise_vector: SurpriseVector::new(),
            disambiguators: Vec::new(),
            visibility_state: VisibilityState::new(),
            status: HypothesisStatus::Hypothesis,
            absorbed_into_incident_id: None,
            suppressed_by_hypothesis_id: None,
            expires_at: now + chrono::Duration::hours(24),
            bucket_seconds: 600,
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
    fn test_hypothesis_id_determinism() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let id1 = HypothesisState::compute_hypothesis_id(
            "host1",
            "injection",
            &scope,
            ts,
            600,
            "template1",
        );
        let id2 = HypothesisState::compute_hypothesis_id(
            "host1",
            "injection",
            &scope,
            ts,
            600,
            "template1",
        );

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_hypothesis_slot_fill() {
        let scope = ScopeKey::Process {
            key: "proc123".to_string(),
        };
        let ts = Utc::now();

        let mut hypothesis =
            HypothesisState::new("host1", "injection", "remote_thread", scope, ts, 600, 3600);

        hypothesis.add_required_slot(Slot::required(
            "exec",
            "Process Execution",
            FactDomain::Process,
            "pred_exec",
        ));

        let ptr = EvidencePtr::new("stream", "seg", 0).with_timestamp(ts);
        hypothesis.fill_slot("exec", ptr, "fact1".to_string(), FactDomain::Process, ts);

        assert!(hypothesis.slot_fills.contains_key("exec"));
        assert_eq!(hypothesis.slot_fills["exec"].count, 1);
    }

    #[test]
    fn test_corroboration_vector() {
        let mut vec = CorroborationVector::new();
        vec.increment(FactDomain::Process);
        vec.increment(FactDomain::Network);
        vec.increment(FactDomain::File);

        assert_eq!(vec.domain_count(), 3);
        assert!(vec.has_high_value_domain());
    }
}

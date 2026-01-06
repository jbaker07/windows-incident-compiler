//! HypothesisController: Runtime wiring for the incident compiler.
//!
//! This module connects the hypothesis/incident system to the running binary.
//! It provides the entry point for:
//! - Ingesting facts from the signal pipeline
//! - Running arbitration to rank hypotheses
//! - Building explanations for the API
//! - Playbook slot matching (ground-truth incident compiler)

use crate::hypothesis::{
    ArbitrationEngine, ArbitrationResponse, CanonicalEvent, ExplanationBuilder,
    ExplanationResponse, ExplanationVisibilityState, Fact, FactDomain, FactType, FocusWindow,
    GlobalWatermark, HypothesisState, HypothesisStatus, HypothesisStorage, InMemoryStorage,
    IncidentStore, LateArrivalAction, LateArrivalPolicy, QueryContext, ScopeKey, SessionMode, Slot,
    SlotRequirement, StreamWatermark,
};
use crate::integrations::config::ExportSinkConfig;
use crate::integrations::export::IncidentExporter;
use crate::slot_matcher::{
    CapabilityRegistry, FillStrength, HypothesisKey, PlaybookDef, PlaybookIndex, SlotMatcher,
};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// HypothesisController owns the hypothesis system runtime state
pub struct HypothesisController {
    /// In-memory storage for hypotheses, incidents, and events
    storage: Arc<RwLock<InMemoryStorage>>,
    /// Arbitration engine for ranking hypotheses
    arbitration_engine: ArbitrationEngine,
    /// Active hypotheses by ID
    hypotheses: HashMap<String, HypothesisState>,
    /// Incident store for promoted hypotheses
    incident_store: IncidentStore,
    /// Host ID for this controller
    host_id: String,
    /// Late arrival policy for event ingestion
    late_arrival_policy: LateArrivalPolicy,
    /// Global watermark tracking per-stream watermarks
    global_watermark: GlobalWatermark,
    /// Optional incident exporter for SIEM integration
    exporter: Option<IncidentExporter>,
    /// Export namespace for multi-tenant support
    export_namespace: Option<String>,
    /// Playbook index for fast fact→playbook matching
    playbook_index: PlaybookIndex,
    /// Slot matcher with capability awareness
    slot_matcher: SlotMatcher,
    /// Time bucket size in seconds (for hypothesis ID stability)
    bucket_seconds: i64,
    /// Cooldown tracker: (playbook_id, entity_key) → last_fire_ts
    cooldowns: HashMap<String, DateTime<Utc>>,
}

impl HypothesisController {
    /// Create a new HypothesisController
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            storage: Arc::new(RwLock::new(InMemoryStorage::new())),
            arbitration_engine: ArbitrationEngine::new(),
            hypotheses: HashMap::new(),
            incident_store: IncidentStore::new(),
            host_id: host_id.into(),
            late_arrival_policy: LateArrivalPolicy::default(),
            global_watermark: GlobalWatermark::new(),
            exporter: None,
            export_namespace: None,
            playbook_index: PlaybookIndex::new(),
            slot_matcher: SlotMatcher::new(),
            bucket_seconds: 600, // 10-minute buckets
            cooldowns: HashMap::new(),
        }
    }

    /// Create with custom late arrival policy
    pub fn with_late_arrival_policy(host_id: impl Into<String>, policy: LateArrivalPolicy) -> Self {
        Self {
            storage: Arc::new(RwLock::new(InMemoryStorage::new())),
            arbitration_engine: ArbitrationEngine::new(),
            hypotheses: HashMap::new(),
            incident_store: IncidentStore::new(),
            host_id: host_id.into(),
            late_arrival_policy: policy,
            global_watermark: GlobalWatermark::new(),
            exporter: None,
            export_namespace: None,
            playbook_index: PlaybookIndex::new(),
            slot_matcher: SlotMatcher::new(),
            bucket_seconds: 600,
            cooldowns: HashMap::new(),
        }
    }

    /// Create with export configuration
    pub fn with_exporter(
        host_id: impl Into<String>,
        export_config: ExportSinkConfig,
        namespace: Option<String>,
    ) -> Result<Self, String> {
        let exporter = IncidentExporter::new(export_config)?;
        Ok(Self {
            storage: Arc::new(RwLock::new(InMemoryStorage::new())),
            arbitration_engine: ArbitrationEngine::new(),
            hypotheses: HashMap::new(),
            incident_store: IncidentStore::new(),
            host_id: host_id.into(),
            late_arrival_policy: LateArrivalPolicy::default(),
            global_watermark: GlobalWatermark::new(),
            exporter: Some(exporter),
            export_namespace: namespace,
            playbook_index: PlaybookIndex::new(),
            slot_matcher: SlotMatcher::new(),
            bucket_seconds: 600,
            cooldowns: HashMap::new(),
        })
    }

    /// Register a playbook for slot matching
    pub fn register_playbook(&mut self, playbook: PlaybookDef) {
        self.playbook_index.add_playbook(playbook);
    }

    /// Set capability registry for fact gating
    pub fn set_capability_registry(&mut self, registry: CapabilityRegistry) {
        self.slot_matcher = SlotMatcher::with_capabilities(registry);
    }

    /// Set time bucket size for hypothesis ID stability
    pub fn set_bucket_seconds(&mut self, seconds: i64) {
        self.bucket_seconds = seconds;
    }

    /// Ingest a canonical event with late arrival checking
    pub fn ingest_event(&mut self, event: CanonicalEvent) -> Result<LateArrivalAction, String> {
        // Check late arrival policy BEFORE updating watermark
        let result = self
            .late_arrival_policy
            .check_event(event.timestamp, &self.global_watermark);

        match result.action {
            LateArrivalAction::ProcessNormal | LateArrivalAction::UpdateHypothesis => {
                // Update watermark and store the event
                self.update_watermark_for_event(&event);
                let mut storage = self.storage.write().map_err(|e| e.to_string())?;
                storage.store_event(&event).map_err(|e| e.to_string())?;
                Ok(result.action)
            }
            LateArrivalAction::MayReopenIncident => {
                // Late but within reopen window - store and let caller handle reopen logic
                // Don't update watermark for late events
                let mut storage = self.storage.write().map_err(|e| e.to_string())?;
                storage.store_event(&event).map_err(|e| e.to_string())?;
                Ok(result.action)
            }
            LateArrivalAction::LateEnrichmentOnly => {
                // Too late to mutate, but can still enrich
                // Don't update watermark
                let mut storage = self.storage.write().map_err(|e| e.to_string())?;
                storage.store_event(&event).map_err(|e| e.to_string())?;
                Ok(result.action)
            }
            LateArrivalAction::Reject => {
                // Event is too old, don't store it
                Ok(LateArrivalAction::Reject)
            }
        }
    }

    /// Update watermark for an accepted event
    fn update_watermark_for_event(&mut self, event: &CanonicalEvent) {
        let stream_id = event.evidence_ptr.stream_id.clone();

        // Get existing watermark or create new
        let watermark = if let Some(existing) = self.global_watermark.streams.get(&stream_id) {
            StreamWatermark {
                stream_id: stream_id.clone(),
                high_watermark: existing.high_watermark.max(event.timestamp),
                low_watermark: existing.low_watermark.min(event.timestamp),
                events_in_flight: existing.events_in_flight,
                updated_at: chrono::Utc::now(),
            }
        } else {
            StreamWatermark {
                stream_id: stream_id.clone(),
                high_watermark: event.timestamp,
                low_watermark: event.timestamp,
                events_in_flight: 0,
                updated_at: chrono::Utc::now(),
            }
        };

        self.global_watermark.update_stream(watermark);
    }

    /// Ingest a fact derived from events
    /// This is the main entry point for the signal pipeline to feed the hypothesis system
    pub fn ingest_fact(&mut self, fact: Fact) -> Result<Vec<String>, String> {
        // Store the fact
        {
            let mut storage = self.storage.write().map_err(|e| e.to_string())?;
            storage.store_fact(&fact).map_err(|e| e.to_string())?;
        }

        // Find or create hypotheses that match this fact
        let affected_hypothesis_ids = self.update_hypotheses_for_fact(&fact)?;

        Ok(affected_hypothesis_ids)
    }

    /// Ingest multiple facts (batch operation for third-party integration)
    pub fn ingest_facts(&mut self, facts: Vec<Fact>) -> Result<Vec<String>, String> {
        let mut all_affected = Vec::new();
        for fact in facts {
            match self.ingest_fact(fact) {
                Ok(affected) => all_affected.extend(affected),
                Err(e) => eprintln!("[hypothesis] Error ingesting fact: {}", e),
            }
        }
        Ok(all_affected)
    }

    /// Update hypotheses based on a new fact.
    ///
    /// This is the core of the ground-truth slot engine:
    /// 1. Match fact against playbook slot predicates (via PlaybookIndex)
    /// 2. Create/update hypotheses keyed by (playbook_id, scope_key, time_bucket)
    /// 3. Fill slots respecting TTL and capability gating
    /// 4. Fire incidents when all REQUIRED slots are satisfied
    fn update_hypotheses_for_fact(&mut self, fact: &Fact) -> Result<Vec<String>, String> {
        let fact_type = Self::fact_type_discriminant(fact);
        let mut affected_ids = Vec::new();
        let mut incidents_to_fire = Vec::new();
        let now = Utc::now();

        // Get candidate playbooks for this fact type (O(1) lookup)
        let candidates = self.playbook_index.candidates_for_fact_type(fact_type);

        if candidates.is_empty() {
            return Ok(affected_ids);
        }

        // Process each candidate in deterministic order (BTreeMap ensures sorted keys)
        // Sort by (playbook_id, slot_id) for stable ordering
        let mut sorted_candidates: Vec<_> = candidates;
        sorted_candidates.sort_by(|a, b| {
            a.0.playbook_id
                .cmp(&b.0.playbook_id)
                .then_with(|| a.1.cmp(b.1))
        });

        for (playbook, slot_id) in sorted_candidates {
            // Find the slot definition
            let slot = match playbook.slots.iter().find(|s| s.slot_id == slot_id) {
                Some(s) => s,
                None => continue,
            };

            // Check if fact matches this slot's predicate
            let fill_strength = match self.slot_matcher.matches_slot(fact, slot) {
                Some(s) => s,
                None => continue,
            };

            // Check cooldown
            let entity_key = self.compute_entity_key(&playbook.entity_scope, fact);
            let cooldown_key = format!("{}:{}", playbook.playbook_id, entity_key);
            if let Some(last_fire) = self.cooldowns.get(&cooldown_key) {
                let cooldown_duration = chrono::Duration::seconds(playbook.cooldown_seconds as i64);
                if now < *last_fire + cooldown_duration {
                    continue; // Still in cooldown
                }
            }

            // Get or create hypothesis for this (playbook, entity, time_bucket)
            let hyp_key = HypothesisKey::new(
                &playbook.playbook_id,
                &fact.host_id,
                &fact.scope_key,
                fact.ts,
                self.bucket_seconds,
            );
            let hypothesis_id = hyp_key.to_hypothesis_id();

            // Create hypothesis if not exists (avoid borrow issue)
            if !self.hypotheses.contains_key(&hypothesis_id) {
                let new_hypothesis = Self::create_hypothesis_from_playbook_static(
                    &hypothesis_id,
                    playbook,
                    &fact.host_id,
                    fact.scope_key.clone(),
                    fact.ts,
                    self.bucket_seconds,
                );
                self.hypotheses
                    .insert(hypothesis_id.clone(), new_hypothesis);
            }

            // Now get mutable reference to the hypothesis
            let hypothesis = match self.hypotheses.get_mut(&hypothesis_id) {
                Some(h) => h,
                None => continue, // Should never happen
            };

            // Check if hypothesis is still active (not expired, not promoted)
            if hypothesis.status != HypothesisStatus::Hypothesis {
                continue;
            }
            if hypothesis.is_expired() {
                hypothesis.expire();
                continue;
            }

            // Check slot TTL
            let slot_ttl = chrono::Duration::seconds(slot.ttl_seconds as i64);
            let slot_deadline = hypothesis.window_start_ts + slot_ttl;
            if fact.ts > slot_deadline {
                continue; // Fact is outside slot's TTL window
            }

            // Fill the slot
            let evidence_ptr =
                fact.evidence_ptrs.first().cloned().unwrap_or_else(|| {
                    crate::hypothesis::EvidencePtr::new("unknown", "unknown", 0)
                });

            let fact_domain = fact.domain();
            hypothesis.fill_slot(
                &slot.slot_id,
                evidence_ptr,
                fact.fact_id.clone(),
                fact_domain,
                fact.ts,
            );

            // Mark slot as satisfied based on fill strength
            if let Some(fill) = hypothesis.slot_fills.get_mut(&slot.slot_id) {
                let strength = match fill_strength {
                    FillStrength::Strong => {
                        crate::hypothesis::hypothesis_state::FillStrength::Strong
                    }
                    FillStrength::Weak => crate::hypothesis::hypothesis_state::FillStrength::Weak,
                };
                fill.satisfy(strength);
            }

            affected_ids.push(hypothesis_id.clone());

            // Check if all required slots are now satisfied
            if hypothesis.all_required_satisfied() {
                incidents_to_fire.push((
                    hypothesis_id.clone(),
                    playbook.playbook_id.clone(),
                    playbook.severity.clone(),
                    cooldown_key.clone(),
                ));
            }
        }

        // Fire incidents (separate loop to avoid borrow issues)
        for (hypothesis_id, _playbook_id, _severity, cooldown_key) in incidents_to_fire {
            match self.promote_to_incident(&hypothesis_id) {
                Ok(incident_id) => {
                    // Record cooldown
                    self.cooldowns.insert(cooldown_key, now);
                    eprintln!(
                        "[hypothesis] Playbook fired: hypothesis {} → incident {}",
                        hypothesis_id, incident_id
                    );
                }
                Err(e) => {
                    eprintln!("[hypothesis] Failed to promote {}: {}", hypothesis_id, e);
                }
            }
        }

        // Deduplicate affected IDs while preserving order
        let mut seen = HashSet::new();
        affected_ids.retain(|id| seen.insert(id.clone()));

        Ok(affected_ids)
    }

    /// Create a new hypothesis from a playbook definition (static version)
    fn create_hypothesis_from_playbook_static(
        hypothesis_id: &str,
        playbook: &PlaybookDef,
        host_id: &str,
        scope_key: ScopeKey,
        window_start: DateTime<Utc>,
        bucket_seconds: i64,
    ) -> HypothesisState {
        let mut hypothesis = HypothesisState::new(
            host_id,
            &playbook.family,
            &playbook.playbook_id,
            scope_key,
            window_start,
            bucket_seconds,
            playbook.ttl_seconds as i64,
        );

        // Override the computed ID with our deterministic one
        hypothesis.hypothesis_id = hypothesis_id.to_string();

        // Add slots from playbook
        for slot in &playbook.slots {
            let domain = Self::infer_domain_from_fact_type_static(&slot.predicate.fact_type);
            let requirement = if slot.required {
                SlotRequirement::Required
            } else {
                SlotRequirement::Optional
            };

            let hypothesis_slot = Slot {
                slot_id: slot.slot_id.clone(),
                name: slot.name.clone(),
                domain,
                requirement,
                predicate_id: slot.predicate.fact_type.clone(),
                min_count: 1,
                max_count: 100,
                within_seconds: Some(slot.ttl_seconds as i64),
                ordering_constraints: Vec::new(),
            };

            if slot.required {
                hypothesis.add_required_slot(hypothesis_slot);
            } else {
                hypothesis.add_optional_slot(hypothesis_slot);
            }
        }

        hypothesis
    }

    /// Compute entity key for cooldown and grouping
    fn compute_entity_key(&self, scope_pattern: &str, fact: &Fact) -> String {
        let mut parts = Vec::new();

        for component in scope_pattern.split('|') {
            match component.trim() {
                "host" => parts.push(fact.host_id.clone()),
                "user" => {
                    // Extract user from scope_key if available
                    if let ScopeKey::User { key } = &fact.scope_key {
                        parts.push(key.clone());
                    }
                }
                "exe" => {
                    // Extract exe path from fact type if available
                    if let Some(exe) = self.extract_exe_from_fact(fact) {
                        parts.push(exe);
                    }
                }
                "process" => {
                    if let ScopeKey::Process { key } = &fact.scope_key {
                        parts.push(key.clone());
                    }
                }
                _ => {}
            }
        }

        if parts.is_empty() {
            parts.push(fact.host_id.clone());
        }

        parts.join("|")
    }

    /// Extract exe path from fact for entity key
    fn extract_exe_from_fact(&self, fact: &Fact) -> Option<String> {
        match &fact.fact_type {
            FactType::Exec { path, .. } => Some(path.clone()),
            FactType::ShellCommand { shell, .. } => Some(shell.clone()),
            FactType::ScriptExec { interpreter, .. } => Some(interpreter.clone()),
            _ => None,
        }
    }

    /// Get fact type discriminant string
    fn fact_type_discriminant(fact: &Fact) -> &'static str {
        match &fact.fact_type {
            FactType::ProcSpawn { .. } => "ProcSpawn",
            FactType::Exec { .. } => "Exec",
            FactType::OutboundConnect { .. } => "OutboundConnect",
            FactType::InboundConnect { .. } => "InboundConnect",
            FactType::DnsResolve { .. } => "DnsResolve",
            FactType::WritePath { .. } => "WritePath",
            FactType::ReadPath { .. } => "ReadPath",
            FactType::CreatePath { .. } => "CreatePath",
            FactType::DeletePath { .. } => "DeletePath",
            FactType::RenamePath { .. } => "RenamePath",
            FactType::PersistArtifact { .. } => "PersistArtifact",
            FactType::PrivilegeBoundary { .. } => "PrivilegeBoundary",
            FactType::MemWX { .. } => "MemWX",
            FactType::MemAlloc { .. } => "MemAlloc",
            FactType::ModuleLoad { .. } => "ModuleLoad",
            FactType::Injection { .. } => "Injection",
            FactType::RegistryMod { .. } => "RegistryMod",
            FactType::AuthEvent { .. } => "AuthEvent",
            FactType::LogTamper { .. } => "LogTamper",
            FactType::SecurityToolDisable { .. } => "SecurityToolDisable",
            FactType::ShellCommand { .. } => "ShellCommand",
            FactType::ScriptExec { .. } => "ScriptExec",
            FactType::Unknown { .. } => "Unknown",
        }
    }

    /// Infer fact domain from fact type string (static version)
    fn infer_domain_from_fact_type_static(fact_type: &str) -> FactDomain {
        match fact_type {
            "ProcSpawn" | "Exec" => FactDomain::Process,
            "OutboundConnect" | "InboundConnect" | "DnsResolve" => FactDomain::Network,
            "WritePath" | "ReadPath" | "CreatePath" | "DeletePath" | "RenamePath" => {
                FactDomain::File
            }
            "PersistArtifact" | "RegistryMod" => FactDomain::Persist,
            "PrivilegeBoundary" | "AuthEvent" => FactDomain::Auth,
            "MemWX" | "MemAlloc" | "Injection" => FactDomain::Memory,
            "LogTamper" | "SecurityToolDisable" => FactDomain::Tamper,
            "ModuleLoad" => FactDomain::Module,
            "ShellCommand" | "ScriptExec" => FactDomain::Execution,
            _ => FactDomain::Unknown,
        }
    }

    /// Expire old hypotheses and clean up stale state
    pub fn expire_hypotheses(&mut self) {
        let now = Utc::now();
        for hypothesis in self.hypotheses.values_mut() {
            if hypothesis.is_active() && hypothesis.is_expired() {
                hypothesis.expire();
            }
        }

        // Clean up old cooldowns (keep for 2x cooldown period)
        let max_cooldown_age = chrono::Duration::hours(2);
        self.cooldowns.retain(|_, ts| now - *ts < max_cooldown_age);
    }

    /// Upsert a hypothesis (create or update)
    pub fn upsert_hypothesis(&mut self, hypothesis: HypothesisState) -> Result<(), String> {
        let id = hypothesis.hypothesis_id.clone();

        // Store in storage
        {
            let mut storage = self.storage.write().map_err(|e| e.to_string())?;
            storage
                .store_hypothesis(&hypothesis)
                .map_err(|e| e.to_string())?;
        }

        // Update local cache
        self.hypotheses.insert(id, hypothesis);

        Ok(())
    }

    /// Run arbitration on all active hypotheses
    pub fn arbitrate(&self) -> ArbitrationResponse {
        let candidates: Vec<&HypothesisState> =
            self.hypotheses.values().filter(|h| h.is_active()).collect();

        self.arbitration_engine.arbitrate(
            &candidates,
            None,  // focus_window
            None,  // focus_scope
            None,  // focus_families
            false, // include_expired
        )
    }

    /// Build query context from hypothesis
    fn build_query_context(&self, hypothesis: &HypothesisState) -> QueryContext {
        QueryContext {
            mode: SessionMode::Discovery,
            focus_window: Some(FocusWindow::new(
                hypothesis.window_start_ts,
                hypothesis.window_end_ts,
            )),
            focus_entities: vec![hypothesis.scope_key.clone()],
            families_enabled: vec![hypothesis.family.clone()],
            checkpoint_ref: None,
            host_id: self.host_id.clone(),
            query_ts: Utc::now(),
        }
    }

    /// Build explanation for a hypothesis
    pub fn explain(&self, hypothesis_id: &str) -> Option<ExplanationResponse> {
        let hypothesis = self.hypotheses.get(hypothesis_id)?;

        // Build query context from hypothesis
        let ctx = self.build_query_context(hypothesis);

        // Build explanation
        let visibility_state = ExplanationVisibilityState {
            streams_present: hypothesis
                .visibility_state
                .streams_present
                .iter()
                .cloned()
                .collect(),
            streams_missing: hypothesis
                .visibility_state
                .streams_missing
                .iter()
                .cloned()
                .collect(),
            degraded: !hypothesis.visibility_state.streams_missing.is_empty(),
            degraded_reasons: Vec::new(),
        };

        let response = ExplanationBuilder::new(ctx)
            .visibility(visibility_state)
            .slot_status(hypothesis)
            .build();

        Some(response)
    }

    /// Build explanation for an incident
    pub fn explain_incident(&self, incident_id: &str) -> Option<ExplanationResponse> {
        let incident = self.incident_store.get(incident_id)?;

        // Build query context from incident
        let ctx = QueryContext {
            mode: SessionMode::Discovery,
            focus_window: Some(FocusWindow::new(incident.first_ts, incident.last_ts)),
            focus_entities: vec![incident.primary_scope_key.clone()],
            families_enabled: vec![incident.family.clone()],
            checkpoint_ref: None,
            host_id: incident.host_id.clone(),
            query_ts: Utc::now(),
        };

        // Build explanation
        let visibility_state = ExplanationVisibilityState {
            streams_present: Vec::new(),
            streams_missing: Vec::new(),
            degraded: false,
            degraded_reasons: Vec::new(),
        };

        let response = ExplanationBuilder::new(ctx)
            .visibility(visibility_state)
            .build();

        Some(response)
    }

    /// Get storage for direct queries
    pub fn storage(&self) -> Arc<RwLock<InMemoryStorage>> {
        self.storage.clone()
    }

    /// Get all active hypotheses
    pub fn active_hypotheses(&self) -> Vec<&HypothesisState> {
        self.hypotheses.values().filter(|h| h.is_active()).collect()
    }

    /// Get hypothesis by ID
    pub fn get_hypothesis(&self, id: &str) -> Option<&HypothesisState> {
        self.hypotheses.get(id)
    }

    /// Get incident by ID
    pub fn get_incident(&self, id: &str) -> Option<&crate::hypothesis::Incident> {
        self.incident_store.get(id)
    }

    /// Get all incidents from the incident store
    pub fn all_incidents(&self) -> Vec<&crate::hypothesis::Incident> {
        // Get all incidents by iterating the by_host index
        // This is a bit inefficient but works for the current use case
        let mut incidents = Vec::new();
        if let Some(host_ids) = self
            .incident_store
            .active_by_host(&self.host_id)
            .into_iter()
            .next()
        {
            incidents.push(host_ids);
        }
        // Actually we need a better way - let's add a method to IncidentStore
        // For now, return active by host since that's what we have
        self.incident_store.active_by_host(&self.host_id)
    }

    /// Promote a hypothesis to an incident
    pub fn promote_to_incident(&mut self, hypothesis_id: &str) -> Result<String, String> {
        let hypothesis = self
            .hypotheses
            .get_mut(hypothesis_id)
            .ok_or_else(|| format!("Hypothesis not found: {}", hypothesis_id))?;

        // Create incident from hypothesis
        let incident = crate::hypothesis::Incident::from_hypothesis(hypothesis, &self.host_id);
        let incident_id = incident.incident_id.clone();

        // Mark hypothesis as promoted
        hypothesis.promote(&incident_id);

        // Store incident
        self.incident_store.upsert(incident.clone());

        // Update hypothesis in storage
        {
            let mut storage = self.storage.write().map_err(|e| e.to_string())?;
            storage
                .update_hypothesis(hypothesis)
                .map_err(|e| e.to_string())?;
        }

        // Export incident if exporter is configured
        if let Some(exporter) = &mut self.exporter {
            exporter
                .export_batch(&[&incident], self.export_namespace.as_deref())
                .map_err(|e| format!("Failed to export incident: {}", e))?;
        }

        Ok(incident_id)
    }
}

impl Default for HypothesisController {
    fn default() -> Self {
        Self::new("default_host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::{EvidencePtr, FactType};

    #[test]
    fn test_controller_creation() {
        let controller = HypothesisController::new("test_host");
        assert!(controller.active_hypotheses().is_empty());
    }

    #[test]
    fn test_fact_ingestion() {
        let mut controller = HypothesisController::new("test_host");

        let fact = Fact::new(
            "host1",
            ScopeKey::Process {
                key: "proc_key_1".to_string(),
            },
            FactType::Exec {
                exe_hash: Some("abc123".to_string()),
                path: "/usr/bin/test".to_string(),
                signer: None,
                cmdline: Some("test --arg".to_string()),
            },
            vec![EvidencePtr::new("test_stream", "seg_001", 0)],
        );

        let result = controller.ingest_fact(fact);
        assert!(result.is_ok());
    }

    #[test]
    fn test_arbitration_empty() {
        let controller = HypothesisController::new("test_host");
        let response = controller.arbitrate();
        assert!(response.top3.is_empty());
    }
}

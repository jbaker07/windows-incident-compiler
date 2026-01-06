//! Explanation Builder: Construct ExplanationBundle from hypothesis/incident data.
//!
//! This module bridges the hypothesis_controller's internal state to the
//! edr_core::ExplanationBundle format for API responses.

use crate::evidence_deref::{deref_evidence, DerefResult};
use crate::hypothesis::{EvidencePtr as HypEvidencePtr, Fact, FactType, HypothesisState, Incident};
use crate::slot_matcher::PlaybookDef;
use edr_core::{
    EntityBundle, EvidenceExcerpt, EvidencePtr, ExplanationBundle, ExplanationCounters,
    FactEntityKeys, MatchedFact, SlotExplanation, SlotStatus,
};
use std::collections::HashSet;
use std::path::Path;

/// Build an ExplanationBundle for a signal that was promoted from a hypothesis.
pub fn build_explanation_from_hypothesis(
    hypothesis: &HypothesisState,
    incident: &Incident,
    playbook: &PlaybookDef,
    telemetry_root: &Path,
    facts_store: &[Fact],
) -> ExplanationBundle {
    let signal_id = incident.incident_id.clone();
    let playbook_id = playbook.playbook_id.clone();

    // Build slot explanations
    let slots = build_slot_explanations(hypothesis, playbook, facts_store);

    // Build entity bundle
    let entities = build_entity_bundle(hypothesis, facts_store);

    // Build evidence excerpts with dereference
    let evidence = build_evidence_excerpts(incident, telemetry_root, 10);

    // Build counters
    let counters = build_counters(hypothesis, &slots);

    // Build limitations
    let limitations = build_limitations(hypothesis, &slots);

    // Build summary
    let summary = build_summary(playbook, &slots);

    ExplanationBundle::builder(signal_id, playbook_id)
        .playbook_title(&playbook.title)
        .family(&playbook.family)
        .matched_at_ms(incident.created_ts.timestamp_millis())
        .summary(summary)
        .slots(slots)
        .entities(entities)
        .evidence(evidence)
        .counters(counters)
        .limitations(limitations)
        .build()
}

/// Build slot explanations from hypothesis state
fn build_slot_explanations(
    hypothesis: &HypothesisState,
    playbook: &PlaybookDef,
    facts_store: &[Fact],
) -> Vec<SlotExplanation> {
    let mut slot_explanations = Vec::new();

    for pb_slot in &playbook.slots {
        let slot_id = &pb_slot.slot_id;
        let fill = hypothesis.slot_fills.get(slot_id);

        // Determine status
        let status = match fill {
            Some(f) if f.satisfied => SlotStatus::Filled,
            Some(f) if f.count > 0 => SlotStatus::Partial,
            None => SlotStatus::Empty,
            _ => SlotStatus::Empty,
        };

        // Build predicate description
        let predicate_desc = build_predicate_desc(&pb_slot.predicate);

        // Build matched facts
        let matched_facts = match fill {
            Some(f) => build_matched_facts(f, facts_store),
            None => Vec::new(),
        };

        let explanation = SlotExplanation::new(
            slot_id,
            &pb_slot.name,
            pb_slot.required,
            pb_slot.ttl_seconds,
        )
        .with_status(status)
        .with_predicate_desc(predicate_desc)
        .with_matched_facts(matched_facts);

        slot_explanations.push(explanation);
    }

    slot_explanations
}

/// Build a human-readable predicate description
fn build_predicate_desc(predicate: &crate::slot_matcher::SlotPredicate) -> String {
    let mut parts = vec![predicate.fact_type.clone()];

    if let Some(ref path) = predicate.path_glob {
        parts.push(format!("path glob {}", path));
    }
    if let Some(ref regex) = predicate.path_regex {
        parts.push(format!("path matches /{}/", regex));
    }
    if let Some(ref exe) = predicate.exe_filter {
        parts.push(format!("exe contains {}", exe));
    }
    if let Some(port) = predicate.dst_port {
        parts.push(format!("port={}", port));
    }
    if predicate.soft_required {
        parts.push("(soft)".to_string());
    }

    parts.join(" where ")
}

/// Build matched facts from slot fill
fn build_matched_facts(
    fill: &crate::hypothesis::hypothesis_state::SlotFill,
    facts_store: &[Fact],
) -> Vec<MatchedFact> {
    let mut matched = Vec::new();

    for fact_ref in &fill.fact_refs {
        // Find fact in store
        let fact = facts_store.iter().find(|f| &f.fact_id == fact_ref);

        if let Some(fact) = fact {
            let fact_type = fact_type_name(&fact.fact_type);
            let entity_keys = extract_entity_keys(fact);
            let evidence_ptrs = fact
                .evidence_ptrs
                .iter()
                .map(convert_evidence_ptr)
                .collect();

            matched.push(
                MatchedFact::new(&fact.fact_id, fact_type, fact.ts.timestamp_millis())
                    .with_entity_keys(entity_keys)
                    .with_evidence_ptrs(evidence_ptrs),
            );
        } else {
            // Fact not in store, use fill evidence pointers
            let evidence_ptrs: Vec<EvidencePtr> = fill
                .evidence_ptrs
                .iter()
                .map(convert_evidence_ptr)
                .collect();

            matched.push(
                MatchedFact::new(fact_ref, "Unknown", fill.first_ts.timestamp_millis())
                    .with_evidence_ptrs(evidence_ptrs),
            );
        }
    }

    matched
}

/// Get fact type name as string
fn fact_type_name(fact_type: &FactType) -> &'static str {
    match fact_type {
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

/// Extract entity keys from a fact
fn extract_entity_keys(fact: &Fact) -> FactEntityKeys {
    let mut keys = FactEntityKeys::default();

    match &fact.scope_key {
        crate::hypothesis::ScopeKey::Process { key } => {
            keys.proc_key = Some(key.clone());
        }
        crate::hypothesis::ScopeKey::File { key } => {
            keys.file_key = Some(key.clone());
        }
        crate::hypothesis::ScopeKey::User { key } => {
            keys.user_key = Some(key.clone());
        }
        crate::hypothesis::ScopeKey::Socket { key } => {
            keys.net_key = Some(key.clone());
        }
        crate::hypothesis::ScopeKey::Executable { key } => {
            // Executable scope - use as process key
            keys.proc_key = Some(key.clone());
        }
        crate::hypothesis::ScopeKey::Campaign { key: _ }
        | crate::hypothesis::ScopeKey::Session { key: _ } => {
            // These don't map directly to entity keys
        }
    }

    // Extract additional keys from fact type
    match &fact.fact_type {
        FactType::Exec { path, .. } | FactType::ModuleLoad { path, .. } => {
            if keys.file_key.is_none() {
                keys.file_key = Some(path.clone());
            }
        }
        FactType::WritePath { path, .. }
        | FactType::ReadPath { path, .. }
        | FactType::CreatePath { path, .. }
        | FactType::DeletePath { path, .. } => {
            if keys.file_key.is_none() {
                keys.file_key = Some(path.clone());
            }
        }
        FactType::OutboundConnect {
            dst_ip, dst_port, ..
        } => {
            keys.net_key = Some(format!("{}:{}", dst_ip, dst_port));
        }
        FactType::RegistryMod { key, .. } => {
            keys.registry_key = Some(key.clone());
        }
        FactType::AuthEvent { user, .. } => {
            if keys.user_key.is_none() {
                keys.user_key = Some(user.clone());
            }
        }
        _ => {}
    }

    keys
}

/// Convert hypothesis EvidencePtr to core EvidencePtr
fn convert_evidence_ptr(ptr: &HypEvidencePtr) -> EvidencePtr {
    EvidencePtr {
        stream_id: ptr.stream_id.clone(),
        segment_id: ptr.segment_id.parse().unwrap_or(0),
        record_index: ptr.record_index as u32,
    }
}

/// Build entity bundle from hypothesis and facts
fn build_entity_bundle(hypothesis: &HypothesisState, facts_store: &[Fact]) -> EntityBundle {
    let mut bundle = EntityBundle::default();
    let mut proc_keys = HashSet::new();
    let mut file_keys = HashSet::new();
    let mut identity_keys = HashSet::new();
    let mut net_keys = HashSet::new();
    let mut registry_keys = HashSet::new();

    // Add scope key
    match &hypothesis.scope_key {
        crate::hypothesis::ScopeKey::Process { key } => {
            proc_keys.insert(key.clone());
        }
        crate::hypothesis::ScopeKey::File { key } => {
            file_keys.insert(key.clone());
        }
        crate::hypothesis::ScopeKey::User { key } => {
            identity_keys.insert(key.clone());
        }
        crate::hypothesis::ScopeKey::Socket { key } => {
            net_keys.insert(key.clone());
        }
        crate::hypothesis::ScopeKey::Executable { key } => {
            proc_keys.insert(key.clone());
        }
        crate::hypothesis::ScopeKey::Campaign { .. }
        | crate::hypothesis::ScopeKey::Session { .. } => {
            // These don't map directly to entity bundles
        }
    }

    // Extract from all matched facts
    for fill in hypothesis.slot_fills.values() {
        for fact_ref in &fill.fact_refs {
            if let Some(fact) = facts_store.iter().find(|f| &f.fact_id == fact_ref) {
                let keys = extract_entity_keys(fact);
                if let Some(k) = keys.proc_key {
                    proc_keys.insert(k);
                }
                if let Some(k) = keys.file_key {
                    file_keys.insert(k);
                }
                if let Some(k) = keys.user_key {
                    identity_keys.insert(k);
                }
                if let Some(k) = keys.net_key {
                    net_keys.insert(k);
                }
                if let Some(k) = keys.registry_key {
                    registry_keys.insert(k);
                }
            }
        }
    }

    bundle.proc_keys = proc_keys.into_iter().collect();
    bundle.file_keys = file_keys.into_iter().collect();
    bundle.identity_keys = identity_keys.into_iter().collect();
    bundle.net_keys = net_keys.into_iter().collect();
    bundle.registry_keys = registry_keys.into_iter().collect();

    bundle
}

/// Build evidence excerpts with dereference
fn build_evidence_excerpts(
    incident: &Incident,
    telemetry_root: &Path,
    max_excerpts: usize,
) -> Vec<EvidenceExcerpt> {
    let mut excerpts = Vec::new();

    for ptr in incident.evidence_ptrs_summary.iter().take(max_excerpts) {
        let core_ptr = convert_evidence_ptr(ptr);

        // Try to dereference
        let result = deref_evidence(telemetry_root, &core_ptr, 500);

        let (excerpt, ts_ms, source) = match result {
            DerefResult::Success {
                excerpt,
                ts_ms,
                source,
                ..
            } => (Some(excerpt), ts_ms.unwrap_or(0), source),
            _ => {
                // Fallback if deref fails
                (
                    None,
                    ptr.ts.map(|t| t.timestamp_millis()).unwrap_or(0),
                    "deref_failed".to_string(),
                )
            }
        };

        excerpts.push(EvidenceExcerpt {
            ptr: core_ptr,
            excerpt,
            ts_ms,
            source,
        });
    }

    excerpts
}

/// Build counters from hypothesis state
fn build_counters(hypothesis: &HypothesisState, slots: &[SlotExplanation]) -> ExplanationCounters {
    let required_total = slots.iter().filter(|s| s.required).count() as u32;
    let required_filled = slots
        .iter()
        .filter(|s| s.required && s.status == SlotStatus::Filled)
        .count() as u32;
    let optional_total = slots.iter().filter(|s| !s.required).count() as u32;
    let optional_filled = slots
        .iter()
        .filter(|s| !s.required && s.status == SlotStatus::Filled)
        .count() as u32;

    // Sum evidence counts
    let facts_emitted: u64 = hypothesis
        .slot_fills
        .values()
        .map(|f| f.fact_refs.len() as u64)
        .sum();

    ExplanationCounters {
        events_seen: 0, // Would need event tracking to populate
        facts_emitted,
        required_slots_filled: required_filled,
        required_slots_total: required_total,
        optional_slots_filled: optional_filled,
        optional_slots_total: optional_total,
    }
}

/// Build limitations list from hypothesis state
fn build_limitations(hypothesis: &HypothesisState, slots: &[SlotExplanation]) -> Vec<String> {
    let mut limitations = Vec::new();

    // Check for missing streams
    if !hypothesis.visibility_state.streams_missing.is_empty() {
        let missing: Vec<_> = hypothesis
            .visibility_state
            .streams_missing
            .iter()
            .cloned()
            .collect();
        limitations.push(format!("Missing telemetry streams: {}", missing.join(", ")));
    }

    // Check for unfilled optional slots
    let unfilled_optional: Vec<_> = slots
        .iter()
        .filter(|s| !s.required && s.status == SlotStatus::Empty)
        .map(|s| s.name.clone())
        .collect();
    if !unfilled_optional.is_empty() {
        limitations.push(format!(
            "Optional slots not filled (may indicate incomplete visibility): {}",
            unfilled_optional.join(", ")
        ));
    }

    // Check for partial fills
    let partial_fills: Vec<_> = slots
        .iter()
        .filter(|s| s.status == SlotStatus::Partial)
        .map(|s| s.name.clone())
        .collect();
    if !partial_fills.is_empty() {
        limitations.push(format!(
            "Slots with partial evidence: {}",
            partial_fills.join(", ")
        ));
    }

    // Note if visibility is degraded
    if !hypothesis.visibility_state.degraded_reasons.is_empty() {
        for reason in &hypothesis.visibility_state.degraded_reasons {
            limitations.push(format!("Visibility degraded: {}", reason));
        }
    }

    limitations
}

/// Build summary from playbook and slots
fn build_summary(playbook: &PlaybookDef, slots: &[SlotExplanation]) -> String {
    let filled_count = slots
        .iter()
        .filter(|s| s.status == SlotStatus::Filled)
        .count();
    let total_required = slots.iter().filter(|s| s.required).count();

    if let Some(ref narrative) = playbook.narrative {
        // Use playbook narrative if available
        narrative.clone()
    } else {
        // Generate summary
        format!(
            "Playbook '{}' ({}) fired with {}/{} required slots filled.",
            playbook.title, playbook.family, filled_count, total_required
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predicate_desc() {
        let pred = crate::slot_matcher::SlotPredicate::for_fact_type("LogTamper")
            .with_path_glob("*Security*");
        let desc = build_predicate_desc(&pred);
        assert!(desc.contains("LogTamper"));
        assert!(desc.contains("Security"));
    }

    #[test]
    fn test_fact_type_name() {
        assert_eq!(
            fact_type_name(&FactType::LogTamper {
                log_type: "Security".to_string(),
                action: crate::hypothesis::canonical_fact::TamperAction::Clear,
            }),
            "LogTamper"
        );
    }
}

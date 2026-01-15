//! Explanation Builder: Construct ExplanationBundle from hypothesis/incident data.
//!
//! This module bridges the hypothesis_controller's internal state to the
//! edr_core::ExplanationBundle format for API responses.
//!
//! ## Phase 2: Template-based "Why Fired" Explanations
//! For core playbooks (encoded_powershell, schtasks, service, registry, credential_access),
//! we use canonical templates to generate:
//! - Stable reason codes (DetectionReasonCode enums)
//! - Key fields extracted from matched facts
//! - Deterministic narratives (2-4 sentences)

use crate::evidence_deref::{deref_evidence, DerefResult};
use crate::explanation_reason::{
    get_playbook_template, key_field, DetectionReason, DetectionReasonCode, PlaybookExplainTemplate,
};
use crate::hypothesis::{EvidencePtr as HypEvidencePtr, Fact, FactType, HypothesisState, Incident};
use crate::slot_matcher::PlaybookDef;
use edr_core::{
    DetectionReasonEntry, EntityBundle, EvidenceExcerpt, EvidencePtr, ExplanationBundle,
    ExplanationCounters, FactEntityKeys, MatchedFact, SlotExplanation, SlotStatus,
};
use std::collections::{HashMap, HashSet};
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

    // Build summary (fallback for playbooks without templates)
    let summary = build_summary(playbook, &slots);

    // Phase 2: Build template-based explanation if available
    let template = get_playbook_template(&playbook_id);
    let (reasons, key_fields, why_fired) = if let Some(tmpl) = template {
        build_template_explanation(tmpl, &slots, hypothesis, facts_store)
    } else {
        // Fallback: no template, use generic explanation
        (Vec::new(), HashMap::new(), None)
    };

    // Convert reasons to DetectionReasonEntry for core types
    let reason_entries: Vec<DetectionReasonEntry> = reasons
        .into_iter()
        .map(|r| DetectionReasonEntry {
            code: r.code,
            label: r.label,
            detail: r.detail,
            backed_by_slot: r.backed_by_slot,
        })
        .collect();

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
        .reasons(reason_entries)
        .key_fields(key_fields)
        .why_fired(why_fired.unwrap_or_default())
        .detector_version(playbook.version.clone())
        .build()
}

/// Build template-based explanation for core playbooks.
/// Returns (reasons, key_fields, why_fired_narrative)
fn build_template_explanation(
    template: &PlaybookExplainTemplate,
    slots: &[SlotExplanation],
    hypothesis: &HypothesisState,
    facts_store: &[Fact],
) -> (Vec<DetectionReason>, HashMap<String, String>, Option<String>) {
    let mut reasons = Vec::new();
    let mut key_fields = HashMap::new();

    // Step 1: Extract key fields from matched facts
    for fill in hypothesis.slot_fills.values() {
        for fact_ref in &fill.fact_refs {
            if let Some(fact) = facts_store.iter().find(|f| &f.fact_id == fact_ref) {
                extract_key_fields_from_fact(fact, template, &mut key_fields);
            }
        }
    }

    // Also extract from scope key if it's a process
    match &hypothesis.scope_key {
        crate::hypothesis::ScopeKey::Process { key } => {
            key_fields.entry(key_field::PROC_KEY.to_string())
                .or_insert_with(|| key.clone());
        }
        crate::hypothesis::ScopeKey::Executable { key } => {
            key_fields.entry(key_field::PROC_KEY.to_string())
                .or_insert_with(|| key.clone());
        }
        _ => {}
    }

    // Step 2: Determine reason codes from filled slots
    let filled_slots: Vec<&SlotExplanation> = slots
        .iter()
        .filter(|s| s.status == SlotStatus::Filled)
        .collect();

    for slot in &filled_slots {
        // Find matching reason code from template
        let reason_code = find_reason_for_slot(&slot.slot_id, &slot.name, template);
        
        // Build detail from slot's matched facts
        let detail = build_reason_detail(slot);
        
        let reason = DetectionReason::new(reason_code)
            .with_slot(&slot.slot_id);
        
        let reason = if let Some(d) = detail {
            reason.with_detail(d)
        } else {
            reason
        };
        
        reasons.push(reason);
    }

    // If no specific reasons matched, add the default
    if reasons.is_empty() && !filled_slots.is_empty() {
        reasons.push(DetectionReason::new(template.default_reason));
    }

    // Step 3: Generate why_fired narrative from template
    let why_fired = if !filled_slots.is_empty() {
        Some(render_narrative_template(template.narrative_template, &key_fields))
    } else {
        None
    };

    (reasons, key_fields, why_fired)
}

/// Extract key fields from a fact based on template requirements.
fn extract_key_fields_from_fact(
    fact: &Fact,
    template: &PlaybookExplainTemplate,
    key_fields: &mut HashMap<String, String>,
) {
    // Extract based on fact type
    match &fact.fact_type {
        FactType::Exec { path, cmdline, .. } => {
            if template.key_fields.contains(&key_field::CMDLINE) && cmdline.is_some() {
                key_fields.entry(key_field::CMDLINE.to_string())
                    .or_insert_with(|| truncate_cmdline(cmdline.as_ref().unwrap()));
            }
            if template.key_fields.contains(&key_field::PROC_KEY) {
                key_fields.entry(key_field::PROC_KEY.to_string())
                    .or_insert_with(|| path.clone());
            }
        }
        FactType::ProcSpawn { parent_proc_key, child_proc_key } => {
            if template.key_fields.contains(&key_field::PROC_KEY) {
                key_fields.entry(key_field::PROC_KEY.to_string())
                    .or_insert_with(|| child_proc_key.clone());
            }
            if template.key_fields.contains(&key_field::PARENT_PROC) {
                key_fields.entry(key_field::PARENT_PROC.to_string())
                    .or_insert_with(|| parent_proc_key.clone());
            }
        }
        FactType::ProcessAccess { source_proc_key, target_proc_key: _, target_image, granted_access, call_trace } => {
            if template.key_fields.contains(&key_field::SOURCE_PROC) {
                key_fields.entry(key_field::SOURCE_PROC.to_string())
                    .or_insert_with(|| source_proc_key.clone());
            }
            if template.key_fields.contains(&key_field::TARGET_IMAGE) {
                key_fields.entry(key_field::TARGET_IMAGE.to_string())
                    .or_insert_with(|| target_image.clone());
            }
            if template.key_fields.contains(&key_field::GRANTED_ACCESS) {
                key_fields.entry(key_field::GRANTED_ACCESS.to_string())
                    .or_insert_with(|| granted_access.clone());
            }
            if template.key_fields.contains(&key_field::CALL_TRACE) && call_trace.is_some() {
                key_fields.entry(key_field::CALL_TRACE.to_string())
                    .or_insert_with(|| call_trace.clone().unwrap());
            }
        }
        FactType::RegistryMod { key, value_name, operation: _ } => {
            if template.key_fields.contains(&key_field::REGISTRY_KEY) {
                key_fields.entry(key_field::REGISTRY_KEY.to_string())
                    .or_insert_with(|| key.clone());
            }
            if template.key_fields.contains(&key_field::REGISTRY_VALUE) {
                let val = value_name.clone().unwrap_or_default();
                key_fields.entry(key_field::REGISTRY_VALUE.to_string())
                    .or_insert_with(|| truncate_value(&val, 200));
            }
        }
        FactType::PersistArtifact { artifact_type, path_or_key, enable_action: _ } => {
            // For service/task persistence
            if template.key_fields.contains(&key_field::SERVICE_NAME) {
                if matches!(artifact_type, crate::hypothesis::canonical_fact::PersistenceType::Service) {
                    key_fields.entry(key_field::SERVICE_NAME.to_string())
                        .or_insert_with(|| path_or_key.clone());
                }
            }
            if template.key_fields.contains(&key_field::TASK_NAME) {
                if matches!(artifact_type, crate::hypothesis::canonical_fact::PersistenceType::ScheduledTask) {
                    key_fields.entry(key_field::TASK_NAME.to_string())
                        .or_insert_with(|| path_or_key.clone());
                }
            }
            if template.key_fields.contains(&key_field::BINARY_PATH) {
                key_fields.entry(key_field::BINARY_PATH.to_string())
                    .or_insert_with(|| path_or_key.clone());
            }
        }
        _ => {
            // Other fact types: extract proc_key from scope if available
        }
    }

    // Extract host from fact scope if we can derive it (not from evidence ptr)
    // Note: EvidencePtr doesn't have host/event_id fields in this codebase
    // Host info would need to come from incident or hypothesis scope
}

/// Find the appropriate reason code for a filled slot.
fn find_reason_for_slot(
    slot_id: &str,
    slot_name: &str,
    template: &PlaybookExplainTemplate,
) -> DetectionReasonCode {
    let slot_lower = slot_id.to_lowercase();
    let name_lower = slot_name.to_lowercase();
    
    for (pattern, reason_code) in template.slot_reason_map {
        if slot_lower.contains(pattern) || name_lower.contains(pattern) {
            return *reason_code;
        }
    }
    
    template.default_reason
}

/// Build detail string from slot's matched facts.
fn build_reason_detail(slot: &SlotExplanation) -> Option<String> {
    // Take first matched fact's entity keys as detail
    if let Some(fact) = slot.matched_facts.first() {
        let mut parts = Vec::new();
        
        if let Some(ref pk) = fact.entity_keys.proc_key {
            parts.push(format!("process={}", truncate_value(pk, 60)));
        }
        if let Some(ref fk) = fact.entity_keys.file_key {
            parts.push(format!("file={}", truncate_value(fk, 60)));
        }
        if let Some(ref rk) = fact.entity_keys.registry_key {
            parts.push(format!("key={}", truncate_value(rk, 80)));
        }
        
        if !parts.is_empty() {
            return Some(parts.join(", "));
        }
    }
    None
}

/// Render a narrative template with key field substitutions.
fn render_narrative_template(template: &str, key_fields: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    
    for (key, value) in key_fields {
        let placeholder = format!("{{{}}}", key);
        result = result.replace(&placeholder, value);
    }
    
    // Remove any unsubstituted placeholders (missing fields)
    // Replace {field_name} with "[unknown]" or empty
    let re = regex::Regex::new(r"\{[a-z_]+\}").unwrap();
    result = re.replace_all(&result, "[not available]").to_string();
    
    result
}

/// Truncate command line for display (keep first N chars).
fn truncate_cmdline(cmdline: &str) -> String {
    truncate_value(cmdline, 300)
}

/// Truncate any value to max length with ellipsis.
fn truncate_value(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        value.to_string()
    } else {
        format!("{}...", &value[..max_len.saturating_sub(3)])
    }
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
        FactType::ProcessAccess { .. } => "ProcessAccess",
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
/// Generates a 2-4 sentence deterministic narrative
/// INVARIANT: Only generates narrative when there is real proven data (filled slots)
fn build_summary(playbook: &PlaybookDef, slots: &[SlotExplanation]) -> String {
    let filled_count = slots
        .iter()
        .filter(|s| s.status == SlotStatus::Filled)
        .count();
    let total_required = slots.iter().filter(|s| s.required).count();

    // INVARIANT: Must have at least one filled slot to generate a narrative
    // Never invent explanations without evidence
    if filled_count == 0 {
        return String::from("Detection triggered but slot evidence not available for narrative generation.");
    }

    if let Some(ref narrative) = playbook.narrative {
        // Use playbook narrative if available (playbook author's own text)
        narrative.clone()
    } else {
        // Generate 2-4 sentence narrative from REAL filled slots
        generate_why_fired_narrative(playbook, slots, filled_count, total_required)
    }
}

/// Generate deterministic "why fired" narrative (2-4 sentences)
/// Template-based with slot fill-ins from actual evidence
fn generate_why_fired_narrative(
    playbook: &PlaybookDef,
    slots: &[SlotExplanation],
    filled_count: usize,
    total_required: usize,
) -> String {
    let mut sentences = Vec::new();
    
    // Sentence 1: What was detected (required)
    let category_desc = match playbook.family.as_str() {
        "persistence" => "persistence mechanism",
        "defense_evasion" => "security evasion technique",
        "credential_access" => "credential access attempt",
        "execution" => "suspicious execution",
        "discovery" => "reconnaissance activity",
        "lateral_movement" => "lateral movement indicator",
        "collection" => "data collection activity",
        "exfiltration" => "data exfiltration attempt",
        "command_and_control" => "C2 communication pattern",
        "initial_access" => "initial access vector",
        "privilege_escalation" => "privilege escalation attempt",
        "impact" => "destructive activity",
        _ => "suspicious activity"
    };
    
    sentences.push(format!(
        "The '{}' detector identified a {} pattern.",
        playbook.title, category_desc
    ));
    
    // Sentence 2: Which slots matched (if any have names to show)
    let filled_slots: Vec<&SlotExplanation> = slots.iter()
        .filter(|s| s.status == SlotStatus::Filled)
        .collect();
    
    if !filled_slots.is_empty() {
        let slot_names: Vec<&str> = filled_slots.iter()
            .take(3)
            .map(|s| s.name.as_str())
            .collect();
        
        let slots_desc = if slot_names.len() == 1 {
            format!("Evidence matched the '{}' criteria", slot_names[0])
        } else if slot_names.len() == 2 {
            format!("Evidence matched '{}' and '{}' criteria", slot_names[0], slot_names[1])
        } else {
            let remaining = filled_slots.len().saturating_sub(2);
            format!("Evidence matched '{}', '{}' and {} other criteria", 
                    slot_names[0], slot_names[1], remaining)
        };
        sentences.push(format!("{}.", slots_desc));
    }
    
    // Sentence 3: Slot completion status
    if total_required > 0 {
        if filled_count == total_required {
            sentences.push(format!(
                "All {} required detection slots were satisfied.",
                total_required
            ));
        } else {
            sentences.push(format!(
                "{} of {} required slots matched, triggering the detection.",
                filled_count, total_required
            ));
        }
    }
    
    // Sentence 4: Family/category context
    if !playbook.family.is_empty() && playbook.family != "unknown" {
        sentences.push(format!(
            "This activity falls under the '{}' threat category.",
            playbook.family
        ));
    }
    
    // Join sentences (2-4 sentences)
    sentences.join(" ")
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

    // ========================================================================
    // Phase 2: Template-based explanation unit tests
    // ========================================================================

    #[test]
    fn test_truncate_cmdline() {
        let short = "powershell.exe -enc abc";
        assert_eq!(truncate_cmdline(short), short);

        let long = "a".repeat(400);
        let truncated = truncate_cmdline(&long);
        assert!(truncated.len() <= 300);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_truncate_value() {
        assert_eq!(truncate_value("short", 100), "short");
        
        let long = "x".repeat(50);
        let truncated = truncate_value(&long, 20);
        assert!(truncated.len() <= 20);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_render_narrative_template_basic() {
        let template = "Process {proc_key} executed with {cmdline}";
        let mut key_fields = HashMap::new();
        key_fields.insert("proc_key".to_string(), "powershell.exe".to_string());
        key_fields.insert("cmdline".to_string(), "-enc abc".to_string());

        let result = render_narrative_template(template, &key_fields);
        assert_eq!(result, "Process powershell.exe executed with -enc abc");
    }

    #[test]
    fn test_render_narrative_template_missing_field() {
        let template = "Process {proc_key} accessed {target_image}";
        let mut key_fields = HashMap::new();
        key_fields.insert("proc_key".to_string(), "test.exe".to_string());
        // target_image is missing

        let result = render_narrative_template(template, &key_fields);
        assert!(result.contains("test.exe"));
        assert!(result.contains("[not available]")); // Missing field replaced
    }

    #[test]
    fn test_find_reason_for_slot_encoded_flag() {
        use crate::explanation_reason::{DetectionReasonCode, ENCODED_POWERSHELL_TEMPLATE};

        let code = find_reason_for_slot("encoded_flag", "Encoded Flag", &ENCODED_POWERSHELL_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::PowershellEncodedCommand);
    }

    #[test]
    fn test_find_reason_for_slot_bypass_flag() {
        use crate::explanation_reason::{DetectionReasonCode, ENCODED_POWERSHELL_TEMPLATE};

        let code = find_reason_for_slot("bypass_flag", "Bypass Policy", &ENCODED_POWERSHELL_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::PowershellBypassPolicy);
    }

    #[test]
    fn test_find_reason_for_slot_unknown_returns_default() {
        use crate::explanation_reason::{DetectionReasonCode, ENCODED_POWERSHELL_TEMPLATE};

        let code = find_reason_for_slot("unknown_slot", "Unknown", &ENCODED_POWERSHELL_TEMPLATE);
        assert_eq!(code, ENCODED_POWERSHELL_TEMPLATE.default_reason);
    }

    #[test]
    fn test_find_reason_for_slot_credential_access() {
        use crate::explanation_reason::{DetectionReasonCode, CREDENTIAL_ACCESS_TEMPLATE};

        let code = find_reason_for_slot("lsass_access", "LSASS Access", &CREDENTIAL_ACCESS_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::ProcessAccessLsass);

        let code = find_reason_for_slot("mimikatz_exec", "Mimikatz", &CREDENTIAL_ACCESS_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::CredentialDumpTool);
    }

    #[test]
    fn test_find_reason_for_slot_schtasks() {
        use crate::explanation_reason::{DetectionReasonCode, SCHTASKS_ABUSE_TEMPLATE};

        let code = find_reason_for_slot("run_as_system", "Run as SYSTEM", &SCHTASKS_ABUSE_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::TaskCreatedSystem);

        let code = find_reason_for_slot("remote_target", "Remote", &SCHTASKS_ABUSE_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::TaskCreatedRemote);
    }

    #[test]
    fn test_find_reason_for_slot_registry() {
        use crate::explanation_reason::{DetectionReasonCode, REGISTRY_PERSISTENCE_TEMPLATE};

        let code = find_reason_for_slot("run_key_mod", "Run Key", &REGISTRY_PERSISTENCE_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::RegistryRunKeyModified);

        let code = find_reason_for_slot("ifeo_debugger", "IFEO", &REGISTRY_PERSISTENCE_TEMPLATE);
        assert_eq!(code, DetectionReasonCode::RegistryIfeoDebugger);
    }

    #[test]
    fn test_all_templates_produce_valid_narrative() {
        use crate::explanation_reason::PLAYBOOK_TEMPLATES;

        for (_id, template) in PLAYBOOK_TEMPLATES.iter() {
            // Test with empty key_fields - should produce narrative with "[not available]"
            let empty_fields: HashMap<String, String> = HashMap::new();
            let narrative = render_narrative_template(template.narrative_template, &empty_fields);
            
            // Narrative should not be empty
            assert!(!narrative.is_empty(), "Template {} produced empty narrative", template.playbook_id);
            
            // Narrative should have substituted missing fields
            // (it's okay if it has "[not available]" for missing fields)
            assert!(
                !narrative.contains('{') || narrative.contains("[not available]"),
                "Template {} has unsubstituted placeholders: {}",
                template.playbook_id, narrative
            );
        }
    }

    #[test]
    fn test_detection_reason_creation() {
        use crate::explanation_reason::{DetectionReason, DetectionReasonCode};

        let reason = DetectionReason::new(DetectionReasonCode::PowershellEncodedCommand)
            .with_detail("-enc SQBFAFgA...")
            .with_slot("encoded_flag");

        assert_eq!(reason.code, "POWERSHELL_ENCODED_COMMAND");
        assert_eq!(reason.label, "Encoded PowerShell Command");
        assert_eq!(reason.detail, Some("-enc SQBFAFgA...".to_string()));
        assert_eq!(reason.backed_by_slot, Some("encoded_flag".to_string()));
    }

    #[test]
    fn test_build_reason_detail_with_proc_key() {
        // Create a mock SlotExplanation with matched facts
        let entity_keys = FactEntityKeys {
            proc_key: Some("C:\\Windows\\System32\\powershell.exe".to_string()),
            ..Default::default()
        };
        let matched_fact = MatchedFact::new("fact_001", "Exec", 1234567890)
            .with_entity_keys(entity_keys);

        let slot = SlotExplanation::new("test_slot", "Test Slot", true, 60)
            .with_status(SlotStatus::Filled)
            .with_matched_facts(vec![matched_fact]);

        let detail = build_reason_detail(&slot);
        assert!(detail.is_some());
        let detail = detail.unwrap();
        assert!(detail.contains("process="));
        assert!(detail.contains("powershell"));
    }

    #[test]
    fn test_build_reason_detail_empty_slot() {
        let slot = SlotExplanation::new("empty_slot", "Empty", true, 60)
            .with_status(SlotStatus::Empty);

        let detail = build_reason_detail(&slot);
        assert!(detail.is_none());
    }
}


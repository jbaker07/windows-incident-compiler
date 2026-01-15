//! Explain Response Normalizer
//!
//! Normalizes ExplanationBundle and legacy signal data into the canonical
//! ExplainResponse format for consistent API output.

use edr_core::{
    build_scoring_from_signal, normalize_entities, normalize_evidence_array, EvidencePointer,
    ExplainResponse, ScoringBreakdown, SignalEntities,
};

use crate::db::StoredSignal;

/// Normalize an ExplanationBundle JSON (from DB) + StoredSignal into canonical ExplainResponse
pub fn normalize_explain_response(
    signal: &StoredSignal,
    explanation_json: Option<&serde_json::Value>,
) -> ExplainResponse {
    let now_ms = chrono::Utc::now().timestamp_millis();

    // Base signal data
    let signal_id = signal.signal_id.clone();
    let signal_type = signal.signal_type.clone();
    let ts = signal.ts;
    let severity = signal.severity.clone();
    let host = signal.host.clone();

    // Extract playbook_id: prefer explanation's playbook_id, then extract from detector_id, then metadata
    let playbook_id = explanation_json
        .and_then(|e| e.get("playbook_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            // Try to extract from signal's metadata
            signal.metadata.get("playbook_id").and_then(|v| v.as_str()).map(|s| s.to_string())
        })
        .or_else(|| {
            // Fallback: derive from detector_id by stripping "playbook:" prefix if present
            if !signal.detector_id.is_empty() && signal.detector_id != "unknown" {
                Some(signal.detector_id.strip_prefix("playbook:").unwrap_or(&signal.detector_id).to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Extract hypothesis_name
    let hypothesis_name = explanation_json
        .and_then(|e| e.get("hypothesis_name"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            explanation_json
                .and_then(|e| e.get("playbook_title"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());

    // Extract detector_version: prefer signal field, fallback to explanation/metadata
    let detector_version = if !signal.detector_version.is_empty() && signal.detector_version != "0.0.0" {
        Some(signal.detector_version.clone())
    } else {
        explanation_json
            .and_then(|e| e.get("detector_version"))
            .and_then(|v| v.as_str())
            .or_else(|| signal.metadata.get("detector_version").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
    };

    // Build entities from signal + explanation
    let mut entities = normalize_entities(
        &host,
        signal.proc_key.as_deref(),
        signal.file_key.as_deref(),
        signal.identity_key.as_deref(),
    );

    // Merge entities from explanation if available
    if let Some(exp) = explanation_json {
        if let Some(exp_entities) = exp.get("entities") {
            merge_entities(&mut entities, exp_entities);
        }
    }

    // Build evidence pointers from signal + explanation
    let mut evidence: Vec<EvidencePointer> = normalize_evidence_array(&signal.evidence_ptrs);

    // Merge evidence from explanation if available
    if let Some(exp) = explanation_json {
        if let Some(exp_evidence) = exp.get("evidence").and_then(|e| e.as_array()) {
            for ev in exp_evidence {
                if let Some(ptr) = normalize_evidence_from_exp(ev) {
                    // Avoid duplicates
                    if !evidence.iter().any(|e| e.reference == ptr.reference) {
                        evidence.push(ptr);
                    }
                }
            }
        }
    }

    // Build scoring breakdown
    let scoring = build_scoring(signal, explanation_json);

    // Extract optional enrichment fields
    let summary = explanation_json
        .and_then(|e| e.get("summary"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let family = explanation_json
        .and_then(|e| e.get("family"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let slots = explanation_json
        .and_then(|e| e.get("slots"))
        .cloned();

    let matched_facts = explanation_json
        .and_then(|e| e.get("matched_facts"))
        .cloned()
        .or_else(|| {
            // Try to extract from slots
            explanation_json.and_then(|e| {
                e.get("slots").and_then(|slots| {
                    slots.as_array().map(|arr| {
                        let facts: Vec<serde_json::Value> = arr
                            .iter()
                            .filter_map(|s| s.get("matched_facts"))
                            .filter_map(|mf| mf.as_array())
                            .flatten()
                            .cloned()
                            .collect();
                        serde_json::Value::Array(facts)
                    })
                })
            })
        });

    let limitations = explanation_json
        .and_then(|e| e.get("limitations"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let generated_at = explanation_json
        .and_then(|e| e.get("generated_at_ms"))
        .and_then(|v| v.as_i64())
        .unwrap_or(now_ms);

    ExplainResponse {
        signal_id,
        signal_type,
        ts,
        severity,
        playbook_id,
        hypothesis_name,
        detector_version,
        entities,
        evidence,
        scoring,
        summary,
        family,
        slots,
        matched_facts,
        limitations,
        generated_at,
    }
}

/// Build scoring breakdown from signal and explanation
fn build_scoring(
    signal: &StoredSignal,
    explanation_json: Option<&serde_json::Value>,
) -> ScoringBreakdown {
    // Check if scoring is in metadata
    let risk_score = signal
        .metadata
        .get("risk_score")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            explanation_json
                .and_then(|e| e.get("scoring"))
                .and_then(|s| s.get("risk_score"))
                .and_then(|v| v.as_f64())
        });

    // Check for scoring_reasons in explanation
    if let Some(exp) = explanation_json {
        if let Some(scoring_obj) = exp.get("scoring") {
            if let Some(reasons) = scoring_obj.get("scoring_reasons").and_then(|r| r.as_array()) {
                // Use existing scoring from explanation
                let parsed_reasons: Vec<edr_core::ScoringReason> = reasons
                    .iter()
                    .filter_map(|r| {
                        let code = r.get("code")?.as_str()?;
                        let label = r.get("label")?.as_str()?;
                        let weight = r.get("weight")?.as_f64()?;
                        let detail = r.get("detail").and_then(|d| d.as_str()).map(|s| s.to_string());
                        
                        let mut reason = edr_core::ScoringReason::new(code, label, weight);
                        if let Some(d) = detail {
                            reason = reason.with_detail(d);
                        }
                        Some(reason)
                    })
                    .collect();

                if !parsed_reasons.is_empty() {
                    return ScoringBreakdown::new(
                        risk_score.unwrap_or(0.5),
                        parsed_reasons,
                    );
                }
            }
        }
    }

    // Fall back to building from signal severity + metadata
    build_scoring_from_signal(&signal.severity, risk_score, &signal.metadata)
}

/// Merge entities from explanation JSON into SignalEntities
fn merge_entities(entities: &mut SignalEntities, exp_entities: &serde_json::Value) {
    // EntityBundle format from ExplanationBundle
    if let Some(proc_keys) = exp_entities.get("proc_keys").and_then(|v| v.as_array()) {
        if entities.proc_key.is_none() {
            entities.proc_key = proc_keys.first().and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
    if let Some(file_keys) = exp_entities.get("file_keys").and_then(|v| v.as_array()) {
        if entities.file_key.is_none() {
            entities.file_key = file_keys.first().and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
    if let Some(identity_keys) = exp_entities.get("identity_keys").and_then(|v| v.as_array()) {
        if entities.user.is_none() {
            entities.user = identity_keys.first().and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
    if let Some(net_keys) = exp_entities.get("net_keys").and_then(|v| v.as_array()) {
        if entities.ip.is_none() {
            entities.ip = net_keys.first().and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
    if let Some(registry_keys) = exp_entities.get("registry_keys").and_then(|v| v.as_array()) {
        if entities.registry_key.is_none() {
            entities.registry_key = registry_keys.first().and_then(|v| v.as_str()).map(|s| s.to_string());
        }
    }
}

/// Normalize evidence from explanation JSON
fn normalize_evidence_from_exp(ev: &serde_json::Value) -> Option<EvidencePointer> {
    // EvidenceExcerpt format from ExplanationBundle
    if let Some(ptr) = ev.get("ptr") {
        let stream_id = ptr.get("stream_id")?.as_str()?;
        let segment_id = ptr.get("segment_id")?.as_u64()?;
        let record_index = ptr.get("record_index")?.as_u64()? as u32;

        let mut evidence_ptr = EvidencePointer::from_segment(stream_id, segment_id, record_index);

        // Add timestamp if available
        if let Some(ts) = ev.get("ts_ms").and_then(|v| v.as_i64()) {
            evidence_ptr = evidence_ptr.with_ts(ts);
        }

        // Add source as summary if available
        if let Some(source) = ev.get("source").and_then(|v| v.as_str()) {
            evidence_ptr = evidence_ptr.with_summary(source);
        }

        return Some(evidence_ptr);
    }

    // Legacy format: direct EvidencePtr
    let stream_id = ev.get("stream_id")?.as_str()?;
    let segment_id = ev.get("segment_id")?.as_u64()?;
    let record_index = ev.get("record_index")?.as_u64()? as u32;

    Some(EvidencePointer::from_segment(stream_id, segment_id, record_index))
}

/// Convert StoredSignal to SignalSummary for list endpoints
pub fn signal_to_summary(signal: &StoredSignal) -> edr_core::SignalSummary {
    // Use detector fields directly from signal, fallback to metadata for backwards compat
    let playbook_id = if !signal.detector_id.is_empty() {
        Some(signal.detector_id.clone())
    } else {
        signal
            .metadata
            .get("playbook_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    let detector_version = if !signal.detector_version.is_empty() {
        Some(signal.detector_version.clone())
    } else {
        signal
            .metadata
            .get("detector_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    let risk_score = signal.metadata.get("risk_score").and_then(|v| v.as_f64());

    let entities = if signal.proc_key.is_some()
        || signal.file_key.is_some()
        || signal.identity_key.is_some()
    {
        Some(normalize_entities(
            &signal.host,
            signal.proc_key.as_deref(),
            signal.file_key.as_deref(),
            signal.identity_key.as_deref(),
        ))
    } else {
        None
    };

    edr_core::SignalSummary {
        signal_id: signal.signal_id.clone(),
        signal_type: signal.signal_type.clone(),
        ts: signal.ts,
        severity: signal.severity.clone(),
        playbook_id,
        detector_version,
        host: signal.host.clone(),
        risk_score,
        entities,
        evidence_count: signal.evidence_ptrs.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_signal() -> StoredSignal {
        StoredSignal {
            signal_id: "sig_test_123".to_string(),
            run_id: "run_20241201_100000".to_string(),
            signal_type: "LogEvasion".to_string(),
            severity: "high".to_string(),
            host: "TEST-HOST".to_string(),
            ts: 1700000000000,
            ts_start: 1699999900000,
            ts_end: 1700000000000,
            proc_key: Some("proc_abc".to_string()),
            file_key: None,
            identity_key: Some("user@domain".to_string()),
            detector_id: "playbook:windows_log_tamper".to_string(),
            detector_version: "1.0.0".to_string(),
            source_sensor: "etw:kernel".to_string(),
            metadata: serde_json::json!({"playbook_id": "windows_log_tamper"}),
            evidence_ptrs: vec![serde_json::json!({
                "stream_id": "evtx",
                "segment_id": 1,
                "record_index": 42
            })],
            dropped_evidence_count: 0,
        }
    }

    #[test]
    fn test_normalize_without_explanation() {
        let signal = make_test_signal();
        let response = normalize_explain_response(&signal, None);

        assert_eq!(response.signal_id, "sig_test_123");
        assert_eq!(response.signal_type, "LogEvasion");
        assert_eq!(response.severity, "high");
        assert_eq!(response.playbook_id, "windows_log_tamper");
        assert_eq!(response.entities.host, Some("TEST-HOST".to_string()));
        assert_eq!(response.entities.proc_key, Some("proc_abc".to_string()));
        assert!(!response.scoring.scoring_unavailable);
    }

    #[test]
    fn test_normalize_with_explanation() {
        let signal = make_test_signal();
        let explanation = serde_json::json!({
            "playbook_id": "windows_log_tamper_clear",
            "playbook_title": "Log Clear Detection",
            "family": "defense_evasion",
            "summary": "Security log was cleared",
            "slots": [],
            "entities": {
                "proc_keys": ["proc_xyz"],
                "file_keys": ["/var/log/security"]
            },
            "evidence": [{
                "ptr": {
                    "stream_id": "sysmon",
                    "segment_id": 5,
                    "record_index": 100
                },
                "ts_ms": 1700000000000_i64,
                "source": "Security/1102"
            }],
            "limitations": ["DNS telemetry not available"],
            "generated_at_ms": 1700000001000_i64
        });

        let response = normalize_explain_response(&signal, Some(&explanation));

        assert_eq!(response.playbook_id, "windows_log_tamper_clear");
        assert_eq!(response.hypothesis_name, Some("Log Clear Detection".to_string()));
        assert_eq!(response.family, Some("defense_evasion".to_string()));
        assert_eq!(response.summary, Some("Security log was cleared".to_string()));
        // Original proc_key from signal preserved
        assert_eq!(response.entities.proc_key, Some("proc_abc".to_string()));
        // Evidence merged (should have 2: one from signal, one from explanation)
        assert_eq!(response.evidence.len(), 2);
        assert_eq!(response.limitations.len(), 1);
    }
}

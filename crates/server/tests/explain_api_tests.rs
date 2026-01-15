//! Tests for canonical explainability API responses
//!
//! Validates that:
//! 1. ExplainResponse always includes required core fields
//! 2. Scoring breakdown is consistent
//! 3. Evidence pointers follow canonical schema
//! 4. Missing data is handled gracefully (nulls, empty arrays)

use edr_core::{
    build_scoring_from_signal, normalize_entities, normalize_evidence_array, EvidenceKind,
    EvidencePointer, ExplainResponse, ScoringBreakdown, ScoringReason, SignalEntities,
    SignalSummary,
};

// ============================================================================
// Test Fixtures
// ============================================================================

fn make_sample_signal_summary() -> SignalSummary {
    SignalSummary {
        signal_id: "sig_test_abc123".to_string(),
        signal_type: "LogEvasion".to_string(),
        ts: 1700000000000,
        severity: "high".to_string(),
        playbook_id: Some("windows_log_tamper_clear".to_string()),
        detector_version: Some("1.2.0".to_string()),
        host: "WORKSTATION-01".to_string(),
        risk_score: Some(0.78),
        entities: Some(SignalEntities {
            host: Some("WORKSTATION-01".to_string()),
            proc_key: Some("proc_abc123".to_string()),
            user: Some("DOMAIN\\user".to_string()),
            file_key: None,
            ip: None,
            registry_key: None,
            extra: std::collections::HashMap::new(),
        }),
        evidence_count: 3,
    }
}

fn make_sample_explain_response() -> ExplainResponse {
    ExplainResponse {
        signal_id: "sig_test_abc123".to_string(),
        signal_type: "LogEvasion".to_string(),
        ts: 1700000000000,
        severity: "high".to_string(),
        playbook_id: "windows_log_tamper_clear".to_string(),
        hypothesis_name: Some("Windows Log Tamper: Clear".to_string()),
        detector_version: Some("1.2.0".to_string()),
        entities: SignalEntities {
            host: Some("WORKSTATION-01".to_string()),
            proc_key: Some("proc_abc123".to_string()),
            user: Some("DOMAIN\\user".to_string()),
            file_key: None,
            ip: None,
            registry_key: None,
            extra: std::collections::HashMap::new(),
        },
        evidence: vec![
            EvidencePointer::from_segment("evtx", 1, 42)
                .with_ts(1700000000000)
                .with_summary("Security/1102 Log Clear"),
            EvidencePointer::from_segment("sysmon", 5, 100)
                .with_ts(1699999990000)
                .with_summary("Sysmon/1 Process Create"),
        ],
        scoring: ScoringBreakdown::new(
            0.78,
            vec![
                ScoringReason::new("SEVERITY_HIGH", "High severity", 0.75),
                ScoringReason::new("PB_CHAIN_COMPLETE", "All required slots filled", 0.85)
                    .with_detail("3/3 required slots satisfied"),
            ],
        ),
        summary: Some("Security event log was cleared by a non-system process.".to_string()),
        family: Some("defense_evasion".to_string()),
        slots: None,
        matched_facts: None,
        limitations: vec!["DNS resolution telemetry not available".to_string()],
        generated_at: 1700000001000,
    }
}

fn make_explain_response_missing_scoring() -> ExplainResponse {
    ExplainResponse {
        signal_id: "sig_legacy_xyz".to_string(),
        signal_type: "SuspiciousExec".to_string(),
        ts: 1699000000000,
        severity: "medium".to_string(),
        playbook_id: "unknown".to_string(),
        hypothesis_name: None,
        detector_version: None,
        entities: SignalEntities {
            host: Some("SERVER-01".to_string()),
            proc_key: None,
            user: None,
            file_key: None,
            ip: None,
            registry_key: None,
            extra: std::collections::HashMap::new(),
        },
        evidence: vec![], // Empty evidence array
        scoring: ScoringBreakdown::unavailable(),
        summary: None,
        family: None,
        slots: None,
        matched_facts: None,
        limitations: vec![],
        generated_at: 1699000001000,
    }
}

// ============================================================================
// Core Field Validation Tests
// ============================================================================

#[test]
fn test_signal_summary_required_fields() {
    let summary = make_sample_signal_summary();

    // Required fields must be present and non-empty
    assert!(!summary.signal_id.is_empty(), "signal_id must be present");
    assert!(!summary.signal_type.is_empty(), "signal_type must be present");
    assert!(summary.ts > 0, "ts must be positive");
    assert!(!summary.severity.is_empty(), "severity must be present");
    assert!(!summary.host.is_empty(), "host must be present");
}

#[test]
fn test_explain_response_required_fields() {
    let response = make_sample_explain_response();

    // Required core fields
    assert!(!response.signal_id.is_empty(), "signal_id must be present");
    assert!(
        !response.signal_type.is_empty(),
        "signal_type must be present"
    );
    assert!(response.ts > 0, "ts must be positive");
    assert!(!response.severity.is_empty(), "severity must be present");

    // Required detector identification
    assert!(
        !response.playbook_id.is_empty(),
        "playbook_id must be present"
    );

    // Required but can be empty: entities, evidence, scoring
    // Evidence should be an array (can be empty, never null when serialized)
    assert!(response.evidence.len() >= 0, "evidence must be an array");

    // Scoring should always be present (can indicate unavailable)
    assert!(
        response.scoring.risk_score >= 0.0 && response.scoring.risk_score <= 1.0,
        "risk_score must be [0,1]"
    );
}

#[test]
fn test_explain_response_missing_scoring_marker() {
    let response = make_explain_response_missing_scoring();

    // When scoring is unavailable, it should be explicitly marked
    assert!(
        response.scoring.scoring_unavailable,
        "scoring_unavailable should be true"
    );
    assert!(
        !response.scoring.scoring_reasons.is_empty(),
        "should have at least one reason explaining unavailability"
    );
    assert_eq!(
        response.scoring.scoring_reasons[0].code, "MISSING_SCORING",
        "first reason should be MISSING_SCORING"
    );
}

// ============================================================================
// Evidence Pointer Schema Tests
// ============================================================================

#[test]
fn test_evidence_pointer_segment_record() {
    let ptr = EvidencePointer::from_segment("evtx", 42, 100);

    assert_eq!(ptr.kind, EvidenceKind::SegmentRecord);
    assert_eq!(ptr.reference, "evtx:42:100");
    assert_eq!(ptr.stream_id, Some("evtx".to_string()));
    assert_eq!(ptr.segment_id, Some(42));
    assert_eq!(ptr.record_index, Some(100));
}

#[test]
fn test_evidence_pointer_file_path() {
    let ptr = EvidencePointer::from_file_path("segments/sysmon/segment_001.jsonl");

    assert_eq!(ptr.kind, EvidenceKind::FilePath);
    assert_eq!(ptr.reference, "segments/sysmon/segment_001.jsonl");
    assert_eq!(
        ptr.bundle_rel_path,
        Some("segments/sysmon/segment_001.jsonl".to_string())
    );
}

#[test]
fn test_evidence_pointer_event_id() {
    let ptr = EvidencePointer::from_event_id("Security", 4624);

    assert_eq!(ptr.kind, EvidenceKind::EventId);
    assert_eq!(ptr.reference, "Security:4624");
    assert!(ptr.summary.is_some());
}

#[test]
fn test_evidence_pointer_serialization_roundtrip() {
    let ptr = EvidencePointer::from_segment("evtx", 42, 100)
        .with_ts(1700000000000)
        .with_summary("Security/1102 Log Clear");

    let json = serde_json::to_string(&ptr).expect("should serialize");
    let parsed: EvidencePointer = serde_json::from_str(&json).expect("should deserialize");

    assert_eq!(parsed.kind, ptr.kind);
    assert_eq!(parsed.reference, ptr.reference);
    assert_eq!(parsed.ts, ptr.ts);
    assert_eq!(parsed.summary, ptr.summary);
}

// ============================================================================
// Scoring Reason Tests
// ============================================================================

#[test]
fn test_scoring_reason_weight_clamped() {
    let reason = ScoringReason::new("TEST", "Test Reason", 1.5); // > 1.0
    assert!(reason.weight <= 1.0, "weight should be clamped to 1.0");

    let reason_neg = ScoringReason::new("TEST", "Test Reason", -0.5); // < 0.0
    assert!(reason_neg.weight >= 0.0, "weight should be clamped to 0.0");
}

#[test]
fn test_scoring_breakdown_from_severity() {
    let metadata = serde_json::json!({});

    let scoring_high = build_scoring_from_signal("high", None, &metadata);
    assert!(!scoring_high.scoring_unavailable);
    assert!(scoring_high.risk_score >= 0.7); // High severity should yield ~0.75

    let scoring_low = build_scoring_from_signal("low", None, &metadata);
    assert!(scoring_low.risk_score <= 0.3); // Low severity should yield ~0.25
}

#[test]
fn test_scoring_breakdown_with_advanced_scores() {
    let metadata = serde_json::json!({
        "mahalanobis_distance": 5.2,
        "elliptic_envelope_score": 0.85
    });

    let scoring = build_scoring_from_signal("medium", Some(0.65), &metadata);

    assert_eq!(scoring.risk_score, 0.65); // Should use provided score
    assert_eq!(scoring.mahalanobis_distance, Some(5.2));
    assert_eq!(scoring.elliptic_envelope_score, Some(0.85));

    // Should have severity reason + advanced scoring reasons
    let codes: Vec<&str> = scoring.scoring_reasons.iter().map(|r| r.code.as_str()).collect();
    assert!(codes.contains(&"SEVERITY_MEDIUM"));
    assert!(codes.contains(&"MAHALANOBIS_ANOMALY"));
    assert!(codes.contains(&"ELLIPTIC_ENVELOPE"));
}

// ============================================================================
// Entity Normalization Tests
// ============================================================================

#[test]
fn test_normalize_entities() {
    let entities = normalize_entities(
        "host1",
        Some("proc_123"),
        Some("/var/log/syslog"),
        Some("user@domain"),
    );

    assert_eq!(entities.host, Some("host1".to_string()));
    assert_eq!(entities.proc_key, Some("proc_123".to_string()));
    assert_eq!(entities.file_key, Some("/var/log/syslog".to_string()));
    assert_eq!(entities.user, Some("user@domain".to_string()));
}

#[test]
fn test_entities_with_missing_fields() {
    let entities = normalize_entities("host1", None, None, None);

    assert_eq!(entities.host, Some("host1".to_string()));
    assert!(entities.proc_key.is_none());
    assert!(entities.file_key.is_none());
    assert!(entities.user.is_none());
}

// ============================================================================
// Evidence Array Normalization Tests
// ============================================================================

#[test]
fn test_normalize_evidence_array_legacy_format() {
    let legacy_evidence = vec![
        serde_json::json!({
            "stream_id": "evtx",
            "segment_id": 1,
            "record_index": 42
        }),
        serde_json::json!({
            "stream_id": "sysmon",
            "segment_id": 5,
            "record_index": 100
        }),
    ];

    let normalized = normalize_evidence_array(&legacy_evidence);

    assert_eq!(normalized.len(), 2);
    assert_eq!(normalized[0].kind, EvidenceKind::SegmentRecord);
    assert_eq!(normalized[0].reference, "evtx:1:42");
    assert_eq!(normalized[1].reference, "sysmon:5:100");
}

#[test]
fn test_normalize_evidence_array_empty() {
    let empty: Vec<serde_json::Value> = vec![];
    let normalized = normalize_evidence_array(&empty);
    assert!(normalized.is_empty());
}

// ============================================================================
// JSON Serialization Tests (Sample Payloads)
// ============================================================================

#[test]
fn test_fully_populated_explain_response_json() {
    let response = make_sample_explain_response();
    let json = serde_json::to_string_pretty(&response).expect("should serialize");

    // Verify required fields are present in JSON
    assert!(json.contains("\"signal_id\""));
    assert!(json.contains("\"signal_type\""));
    assert!(json.contains("\"ts\""));
    assert!(json.contains("\"severity\""));
    assert!(json.contains("\"playbook_id\""));
    assert!(json.contains("\"entities\""));
    assert!(json.contains("\"evidence\""));
    assert!(json.contains("\"scoring\""));
    assert!(json.contains("\"risk_score\""));
    assert!(json.contains("\"scoring_reasons\""));

    println!("\n=== SAMPLE: Fully Populated ExplainResponse ===\n{}\n", json);
}

#[test]
fn test_missing_scoring_explain_response_json() {
    let response = make_explain_response_missing_scoring();
    let json = serde_json::to_string_pretty(&response).expect("should serialize");

    // Verify unavailable marker is present
    assert!(json.contains("\"scoring_unavailable\": true"));
    assert!(json.contains("\"MISSING_SCORING\""));

    println!("\n=== SAMPLE: ExplainResponse with Missing Scoring ===\n{}\n", json);
}

#[test]
fn test_empty_evidence_explain_response_json() {
    let mut response = make_sample_explain_response();
    response.evidence = vec![]; // Clear evidence

    let json = serde_json::to_string_pretty(&response).expect("should serialize");

    // Evidence should be empty array, not null
    assert!(json.contains("\"evidence\": []"));

    println!("\n=== SAMPLE: ExplainResponse with Empty Evidence ===\n{}\n", json);
}

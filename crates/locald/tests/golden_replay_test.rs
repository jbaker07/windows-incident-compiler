//! Golden Replay Test: Verifies deterministic incident compilation.
//!
//! This test verifies the canonical 4-tuple ordering is deterministic.

use chrono::{TimeZone, Utc};
use edr_locald::hypothesis::{
    EventOrderKey, EvidencePtr, ExplanationBuilder, ExplanationVisibilityState, FocusWindow,
    QueryContext, SessionMode,
};

/// Test that EventOrderKey produces deterministic ordering
#[test]
fn test_event_order_key_determinism() {
    let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 1).unwrap();

    // Create keys in random order
    let keys = vec![
        EventOrderKey::new(t2, "stream_a", "seg_001", 0),
        EventOrderKey::new(t1, "stream_b", "seg_001", 0),
        EventOrderKey::new(t1, "stream_a", "seg_001", 1),
        EventOrderKey::new(t1, "stream_a", "seg_001", 0),
    ];

    let mut sorted1 = keys.clone();
    sorted1.sort();

    let mut sorted2 = keys.clone();
    sorted2.sort();

    // Two sorts of the same data must produce identical order
    assert_eq!(
        sorted1, sorted2,
        "EventOrderKey sorting must be deterministic"
    );

    // Verify the expected order: (ts, stream_id, segment_id, record_index)
    assert_eq!(sorted1[0].stream_id, "stream_a");
    assert_eq!(sorted1[0].record_index, 0);
    assert_eq!(sorted1[1].stream_id, "stream_a");
    assert_eq!(sorted1[1].record_index, 1);
    assert_eq!(sorted1[2].stream_id, "stream_b");
    assert!(sorted1[3].ts_nanos > sorted1[0].ts_nanos);
}

/// Test that the same input produces identical JSON output (excluding timestamps)
#[test]
fn test_explanation_json_determinism() {
    let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

    let ctx = QueryContext {
        mode: SessionMode::Discovery,
        focus_window: Some(FocusWindow::new(t1, t1 + chrono::Duration::hours(1))),
        focus_entities: vec![],
        families_enabled: vec![],
        checkpoint_ref: None,
        host_id: "test_host".to_string(),
        query_ts: t1,
    };

    let visibility = ExplanationVisibilityState {
        streams_present: vec!["process_events".to_string()],
        streams_missing: vec!["network_events".to_string()],
        degraded: true,
        degraded_reasons: vec!["network_events unavailable".to_string()],
    };

    // Build twice with same inputs
    let response1 = ExplanationBuilder::new(ctx.clone())
        .visibility(visibility.clone())
        .build();

    let response2 = ExplanationBuilder::new(ctx).visibility(visibility).build();

    // Convert to JSON values and remove generated_ts for comparison
    let mut json1: serde_json::Value = serde_json::to_value(&response1).unwrap();
    let mut json2: serde_json::Value = serde_json::to_value(&response2).unwrap();

    // Remove generated_ts which will differ between runs
    json1.as_object_mut().unwrap().remove("generated_ts");
    json2.as_object_mut().unwrap().remove("generated_ts");

    // JSON (excluding timestamps) must be identical
    assert_eq!(
        json1, json2,
        "Explanation JSON must be deterministic (excluding generated_ts)"
    );
}

/// Test that ExplanationResponse includes visibility_state
#[test]
fn test_visibility_state_in_explanation() {
    let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

    let ctx = QueryContext {
        mode: SessionMode::Discovery,
        focus_window: Some(FocusWindow::new(t1, t1 + chrono::Duration::hours(1))),
        focus_entities: vec![],
        families_enabled: vec![],
        checkpoint_ref: None,
        host_id: "test_host".to_string(),
        query_ts: t1,
    };

    let visibility = ExplanationVisibilityState {
        streams_present: vec!["process_events".to_string(), "file_events".to_string()],
        streams_missing: vec!["network_events".to_string()],
        degraded: true,
        degraded_reasons: vec!["network_events stream not available".to_string()],
    };

    let response = ExplanationBuilder::new(ctx).visibility(visibility).build();

    // Verify visibility_state is populated
    assert!(response.visibility_state.degraded);
    assert_eq!(
        response.visibility_state.streams_missing,
        vec!["network_events"]
    );

    // Verify it serializes correctly
    let json = serde_json::to_value(&response).unwrap();
    assert!(json.get("visibility_state").is_some());
    assert!(json["visibility_state"]["degraded"].as_bool().unwrap());
}

/// Test timeline sorting uses canonical 4-tuple
#[test]
fn test_timeline_canonical_sort() {
    use edr_locald::hypothesis::explanation::ExplanationTimelineEntry;

    let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

    // Create entries with same timestamp but different evidence pointers
    let entry1 = ExplanationTimelineEntry {
        ts: t1,
        summary: "Event B".to_string(),
        claim_refs: vec![],
        evidence_ptrs: vec![EvidencePtr::new("stream_b", "seg_001", 0).with_timestamp(t1)],
        category: "test".to_string(),
        is_late_arrival: false,
    };

    let entry2 = ExplanationTimelineEntry {
        ts: t1,
        summary: "Event A".to_string(),
        claim_refs: vec![],
        evidence_ptrs: vec![EvidencePtr::new("stream_a", "seg_001", 0).with_timestamp(t1)],
        category: "test".to_string(),
        is_late_arrival: false,
    };

    // Entry2 (stream_a) should come before entry1 (stream_b) in canonical order
    let key1 = entry1.canonical_order_key();
    let key2 = entry2.canonical_order_key();

    assert!(key2 < key1, "stream_a should sort before stream_b");
}

/// COMPREHENSIVE TEST: Verify ExplanationResponse JSON contains ALL required keys
#[test]
fn test_explanation_response_json_structure() {
    let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

    let ctx = QueryContext {
        mode: SessionMode::Discovery,
        focus_window: Some(FocusWindow::new(t1, t1 + chrono::Duration::hours(1))),
        focus_entities: vec![],
        families_enabled: vec![],
        checkpoint_ref: None,
        host_id: "test_host".to_string(),
        query_ts: t1,
    };

    let visibility = ExplanationVisibilityState {
        streams_present: vec!["process_events".to_string(), "file_events".to_string()],
        streams_missing: vec!["network_events".to_string()],
        degraded: true,
        degraded_reasons: vec!["network_events not available".to_string()],
    };

    let response = ExplanationBuilder::new(ctx).visibility(visibility).build();

    // Serialize to JSON
    let json = serde_json::to_value(&response).expect("Serialization failed");

    // =====================================================================
    // VERIFY ALL REQUIRED KEYS EXIST
    // =====================================================================

    // Core structure keys
    assert!(
        json.get("query_context").is_some(),
        "Missing: query_context"
    );
    assert!(
        json.get("observed_claims").is_some(),
        "Missing: observed_claims"
    );
    assert!(json.get("timeline").is_some(), "Missing: timeline");

    // Hypothesis/arbitration keys
    assert!(
        json.get("top3_hypotheses").is_some(),
        "Missing: top3_hypotheses"
    );
    assert!(
        json.get("slot_status_summary").is_some(),
        "Missing: slot_status_summary"
    );

    // Evidence and reasoning keys
    assert!(
        json.get("missing_evidence").is_some(),
        "Missing: missing_evidence"
    );
    assert!(
        json.get("disambiguators").is_some(),
        "Missing: disambiguators"
    );

    // VISIBILITY STATE (critical for verification failure C)
    assert!(
        json.get("visibility_state").is_some(),
        "Missing: visibility_state"
    );
    let vis = json.get("visibility_state").unwrap();
    assert!(
        vis.get("streams_present").is_some(),
        "Missing: visibility_state.streams_present"
    );
    assert!(
        vis.get("streams_missing").is_some(),
        "Missing: visibility_state.streams_missing"
    );
    assert!(
        vis.get("degraded").is_some(),
        "Missing: visibility_state.degraded"
    );
    assert!(
        vis.get("degraded_reasons").is_some(),
        "Missing: visibility_state.degraded_reasons"
    );

    // Analyst inputs and integrity
    assert!(
        json.get("analyst_inputs").is_some(),
        "Missing: analyst_inputs"
    );
    assert!(
        json.get("integrity_notes").is_some(),
        "Missing: integrity_notes"
    );
    assert!(
        json.get("confidence_severity_breakdown").is_some(),
        "Missing: confidence_severity_breakdown"
    );

    // Summary and metadata
    assert!(json.get("summary").is_some(), "Missing: summary");
    assert!(json.get("generated_ts").is_some(), "Missing: generated_ts");

    // =====================================================================
    // VERIFY VISIBILITY VALUES ARE CORRECT
    // =====================================================================
    assert_eq!(vis["degraded"].as_bool(), Some(true));
    assert!(vis["streams_present"].as_array().unwrap().len() == 2);
    assert!(vis["streams_missing"].as_array().unwrap().len() == 1);
    assert_eq!(vis["streams_missing"][0].as_str(), Some("network_events"));

    println!("✓ ExplanationResponse JSON structure verified - all required keys present");
    println!("  Keys verified:");
    println!("    - query_context");
    println!("    - observed_claims");
    println!("    - timeline");
    println!("    - top3_hypotheses");
    println!("    - slot_status_summary");
    println!("    - missing_evidence");
    println!("    - disambiguators");
    println!(
        "    - visibility_state (with streams_present/streams_missing/degraded/degraded_reasons)"
    );
    println!("    - analyst_inputs");
    println!("    - integrity_notes");
    println!("    - confidence_severity_breakdown");
    println!("    - summary");
    println!("    - generated_ts");
}

/// Test determinism: same inputs produce same timeline order even with timestamp collisions
#[test]
fn test_determinism_with_timestamp_collision() {
    let t1 = Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap();

    // Create multiple evidence pointers with SAME timestamp (collision scenario)
    let ptrs = [
        EvidencePtr::new("stream_c", "seg_001", 5).with_timestamp(t1),
        EvidencePtr::new("stream_a", "seg_001", 0).with_timestamp(t1),
        EvidencePtr::new("stream_b", "seg_002", 10).with_timestamp(t1),
        EvidencePtr::new("stream_a", "seg_001", 1).with_timestamp(t1),
        EvidencePtr::new("stream_b", "seg_001", 0).with_timestamp(t1),
    ];

    // Sort using EventOrderKey multiple times
    let mut run1: Vec<_> = ptrs.iter().map(EventOrderKey::from_evidence_ptr).collect();
    let mut run2: Vec<_> = ptrs.iter().map(EventOrderKey::from_evidence_ptr).collect();
    let mut run3: Vec<_> = ptrs.iter().map(EventOrderKey::from_evidence_ptr).collect();

    run1.sort();
    run2.sort();
    run3.sort();

    // All runs must produce identical order
    assert_eq!(run1, run2, "Determinism failure: run1 != run2");
    assert_eq!(run2, run3, "Determinism failure: run2 != run3");

    // Verify the canonical order: (ts, stream_id, segment_id, record_index)
    // All have same ts, so sort by stream_id first
    assert_eq!(run1[0].stream_id, "stream_a");
    assert_eq!(run1[0].record_index, 0);
    assert_eq!(run1[1].stream_id, "stream_a");
    assert_eq!(run1[1].record_index, 1);
    assert_eq!(run1[2].stream_id, "stream_b");
    assert_eq!(run1[2].segment_id, "seg_001");
    assert_eq!(run1[3].stream_id, "stream_b");
    assert_eq!(run1[3].segment_id, "seg_002");
    assert_eq!(run1[4].stream_id, "stream_c");

    println!("✓ Determinism verified: timeline ordering stable with timestamp collisions");
    println!("  Order: stream_a:seg_001:0 → stream_a:seg_001:1 → stream_b:seg_001:0 → stream_b:seg_002:10 → stream_c:seg_001:5");
}

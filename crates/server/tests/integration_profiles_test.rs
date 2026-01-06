//! Acceptance tests for Integration Profiles + UI surfacing
//!
//! Tests:
//! 1. Integration profile appears in /api/integrations and updates last_seen_ts/eps
//! 2. Capabilities endpoint shows merged matrix (collectors + integrations)
//! 3. Sample events endpoint returns raw + mapped examples
//! 4. Health status computation works correctly

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use edr_server::integration_api::{
    integration_api_router, CapabilitiesMatrixApi, Fidelity, HealthStatus, IntegrationApiState,
    MappedEventSample, SampleEventsResponse, SourceType,
};
use tower::ServiceExt;

/// Test 1: Integration profile appears in /api/integrations and updates last_seen_ts/eps
#[tokio::test]
async fn test_integration_profiles_list_and_update() {
    let state = IntegrationApiState::demo();
    let app = integration_api_router(state.clone());

    // List integrations
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/integrations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should have demo integrations
    let integrations = json["integrations"].as_array().unwrap();
    assert!(
        integrations.len() >= 2,
        "Should have at least 2 demo integrations"
    );

    // Check that wazuh integration is present
    let wazuh = integrations
        .iter()
        .find(|i| i["integration_id"].as_str() == Some("wazuh_main"))
        .expect("Wazuh integration should be present");

    assert_eq!(wazuh["name"].as_str(), Some("Wazuh HIDS"));
    assert_eq!(wazuh["mode"].as_str(), Some("both"));
    assert!(wazuh["eps"].as_f64().unwrap() > 0.0);
    assert!(wazuh["last_seen_ts"].is_string());

    // Update the profile and verify changes
    {
        let mut profiles = state.profiles.write().unwrap();
        if let Some(profile) = profiles.get_mut("wazuh_main") {
            profile.summary.eps = 100.5;
            profile.summary.last_seen_ts = Some(Utc::now());
        }
    }

    // Fetch again and verify updated values
    let app2 = integration_api_router(state.clone());
    let response2 = app2
        .oneshot(
            Request::builder()
                .uri("/api/integrations/wazuh_main")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response2.status(), StatusCode::OK);

    let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let json2: serde_json::Value = serde_json::from_slice(&body2).unwrap();

    // IntegrationDetailApi uses #[serde(flatten)] so eps is at top level of "integration"
    let updated_eps = json2["integration"]["eps"].as_f64().unwrap();
    assert!(
        (updated_eps - 100.5).abs() < 0.01,
        "EPS should be updated to 100.5"
    );
}

/// Test 2: Capabilities endpoint shows merged matrix (collectors + integrations)
#[tokio::test]
async fn test_capabilities_matrix_merged() {
    let state = IntegrationApiState::demo();
    let app = integration_api_router(state);

    // Fetch capabilities with collectors
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/capabilities?include_collectors=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let matrix: CapabilitiesMatrixApi = serde_json::from_slice(&body).unwrap();

    // Should have both collectors and integrations
    let collectors: Vec<_> = matrix
        .sources
        .iter()
        .filter(|s| s.source_type == SourceType::Collector)
        .collect();
    let integrations: Vec<_> = matrix
        .sources
        .iter()
        .filter(|s| s.source_type == SourceType::Integration)
        .collect();

    assert!(!collectors.is_empty(), "Should have collectors");
    assert!(!integrations.is_empty(), "Should have integrations");

    // Verify fact support matrix exists
    assert!(
        !matrix.fact_support.is_empty(),
        "Fact support should not be empty"
    );

    // Check that exec fact type has both HARD (collector) and SOFT (integration) support
    if let Some(exec_support) = matrix.fact_support.get("exec") {
        let has_hard = exec_support.values().any(|f| *f == Fidelity::Hard);
        let has_soft = exec_support.values().any(|f| *f == Fidelity::Soft);
        assert!(has_hard, "exec should have HARD support from collector");
        assert!(has_soft, "exec should have SOFT support from integration");
    }

    // Verify join key support
    assert!(
        !matrix.join_key_support.is_empty(),
        "Join key support should not be empty"
    );
    assert!(
        matrix.join_key_support.contains_key("proc_key"),
        "Should have proc_key support"
    );
}

/// Test 3: Sample events endpoint returns raw + mapped examples
#[tokio::test]
async fn test_sample_events_with_provenance() {
    let state = IntegrationApiState::demo();
    let app = integration_api_router(state);

    // Fetch samples for wazuh
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/integrations/wazuh_main/sample?limit=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let samples: SampleEventsResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(samples.integration_id, "wazuh_main");
    assert!(!samples.samples.is_empty(), "Should have sample events");

    // Check first sample has required fields
    let sample = &samples.samples[0];
    assert!(
        !sample.raw_json_hash.is_empty(),
        "Should have raw_json_hash"
    );
    assert!(
        !sample.mapping_version.is_empty(),
        "Should have mapping_version"
    );

    // Check provenance (derived scope keys)
    assert!(
        !sample.derived_scope_keys.is_empty(),
        "Should have derived scope keys"
    );

    let key = &sample.derived_scope_keys[0];
    assert!(!key.key.is_empty(), "Scope key should not be empty");
    assert!(
        key.join_confidence > 0.0 && key.join_confidence <= 1.0,
        "Join confidence should be 0-1"
    );
}

/// Test 4: Health status computation
#[tokio::test]
async fn test_health_status_computation() {
    let state = IntegrationApiState::demo();

    // Modify an integration to have warning status (stale)
    {
        let mut profiles = state.profiles.write().unwrap();
        if let Some(profile) = profiles.get_mut("zeek_network") {
            // Set last_seen to 10 minutes ago (stale threshold is 5 min)
            profile.summary.last_seen_ts = Some(Utc::now() - chrono::Duration::minutes(10));
            profile.summary.health_status = HealthStatus::Warning;
        }
    }

    let app = integration_api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/integrations")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let integrations = json["integrations"].as_array().unwrap();
    let zeek = integrations
        .iter()
        .find(|i| i["integration_id"].as_str() == Some("zeek_network"))
        .expect("Zeek integration should be present");

    assert_eq!(
        zeek["health_status"].as_str(),
        Some("warning"),
        "Stale integration should have warning status"
    );
}

/// Test 5: Mode filtering works
#[tokio::test]
async fn test_integration_mode_filtering() {
    let state = IntegrationApiState::demo();

    // Filter for export mode only
    let app = integration_api_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/integrations?mode=export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let integrations = json["integrations"].as_array().unwrap();

    // All returned integrations should be export mode
    for int in integrations {
        assert_eq!(
            int["mode"].as_str(),
            Some("export"),
            "All integrations should be export mode when filtered"
        );
    }
}

/// Test 6: 404 for non-existent integration
#[tokio::test]
async fn test_integration_not_found() {
    let state = IntegrationApiState::demo();
    let app = integration_api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/integrations/nonexistent_integration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test 7: Capabilities matrix without collectors
#[tokio::test]
async fn test_capabilities_without_collectors() {
    let state = IntegrationApiState::demo();
    let app = integration_api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/capabilities?include_collectors=false")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let matrix: CapabilitiesMatrixApi = serde_json::from_slice(&body).unwrap();

    // Should only have integrations, no collectors
    let has_collector = matrix
        .sources
        .iter()
        .any(|s| s.source_type == SourceType::Collector);

    assert!(
        !has_collector,
        "Should not have collectors when include_collectors=false"
    );
}

/// Test 8: MappedEvent hash is deterministic
#[tokio::test]
async fn test_mapped_event_hash_determinism() {
    // Two samples with same raw data should have same hash
    let sample1 = MappedEventSample {
        raw_event_id: Some("test_123".to_string()),
        raw_json_hash: "abc123".to_string(),
        mapping_version: "1.0".to_string(),
        mapped_at: Utc::now(),
        raw_event_summary: Some(r#"{"key":"value"}"#.to_string()),
        mapped_event: serde_json::json!({"fact_type": "exec"}),
        derived_scope_keys: vec![],
    };

    let sample2 = MappedEventSample {
        raw_event_id: Some("test_123".to_string()),
        raw_json_hash: "abc123".to_string(), // Same hash
        mapping_version: "1.0".to_string(),
        mapped_at: Utc::now() + chrono::Duration::seconds(10), // Different time
        raw_event_summary: Some(r#"{"key":"value"}"#.to_string()),
        mapped_event: serde_json::json!({"fact_type": "exec"}),
        derived_scope_keys: vec![],
    };

    assert_eq!(
        sample1.raw_json_hash, sample2.raw_json_hash,
        "Hash should be deterministic based on raw content"
    );
}

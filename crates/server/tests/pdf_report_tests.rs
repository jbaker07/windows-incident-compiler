//! In-Process Integration Tests for PDF Report Generation
//!
//! These tests run WITHOUT a live server - they instantiate the router in-process
//! and make HTTP requests directly using axum-test.
//!
//! Tests cover:
//! - POST /api/report/pdf returns application/pdf content-type
//! - Response size is reasonable (> 5KB for valid PDF with content)
//! - PDF bytes start with "%PDF-" magic header
//! - Deterministic fixture with required elements
//! - Stable output ordering

use axum_test::TestServer;
use edr_server::{
    build_test_bundle, build_test_router, PdfRenderer, ReportBundleBuilder, ReportRequest,
};
use serde_json::json;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Create the deterministic fixture as specified:
/// - 1 hypothesis
/// - 2 timeline entries (one is_late_arrival=true)
/// - 1 claim with evidence pointer
/// - visibility_state with missing stream
/// - 1 disambiguator
fn create_test_request() -> ReportRequest {
    ReportRequest {
        session_id: Some("test-session-001".to_string()),
        incident_id: Some("test-incident-001".to_string()),
        focus_window: None,
        include_excerpts: true,
        include_visibility: true,
        include_disambiguators: true,
    }
}

// ============================================================================
// In-Process HTTP Tests (no server required)
// ============================================================================

/// Test: POST /api/report/pdf returns status 200
#[tokio::test]
async fn test_pdf_endpoint_returns_200() {
    let server = TestServer::new(build_test_router()).unwrap();

    let response = server
        .post("/api/report/pdf")
        .json(&create_test_request())
        .await;

    response.assert_status_ok();
}

/// Test: POST /api/report/pdf returns content-type application/pdf
#[tokio::test]
async fn test_pdf_endpoint_content_type() {
    let server = TestServer::new(build_test_router()).unwrap();

    let response = server
        .post("/api/report/pdf")
        .json(&create_test_request())
        .await;

    response.assert_status_ok();

    let content_type = response
        .headers()
        .get("content-type")
        .expect("Missing content-type header");

    assert_eq!(content_type, "application/pdf");
}

/// Test: PDF body length > 5KB threshold
#[tokio::test]
async fn test_pdf_body_size_threshold() {
    let server = TestServer::new(build_test_router()).unwrap();

    let response = server
        .post("/api/report/pdf")
        .json(&create_test_request())
        .await;

    response.assert_status_ok();

    let bytes = response.into_bytes();
    let min_size = 5 * 1024; // 5KB minimum

    assert!(
        bytes.len() > min_size,
        "PDF too small: {} bytes (expected > {} bytes)",
        bytes.len(),
        min_size
    );
}

/// Test: PDF bytes start with "%PDF-" magic header
#[tokio::test]
async fn test_pdf_magic_header() {
    let server = TestServer::new(build_test_router()).unwrap();

    let response = server
        .post("/api/report/pdf")
        .json(&create_test_request())
        .await;

    response.assert_status_ok();

    let bytes = response.into_bytes();

    assert!(
        bytes.len() >= 5,
        "PDF too short to have magic header: {} bytes",
        bytes.len()
    );

    assert_eq!(
        &bytes[0..5],
        b"%PDF-",
        "Invalid PDF: missing %PDF- magic header. Got: {:?}",
        &bytes[0..5.min(bytes.len())]
    );
}

/// Test: Content-Disposition header contains filename
#[tokio::test]
async fn test_pdf_content_disposition() {
    let server = TestServer::new(build_test_router()).unwrap();

    let response = server
        .post("/api/report/pdf")
        .json(&create_test_request())
        .await;

    response.assert_status_ok();

    let disposition = response
        .headers()
        .get("content-disposition")
        .expect("Missing content-disposition header")
        .to_str()
        .expect("Invalid content-disposition");

    assert!(
        disposition.starts_with("attachment; filename="),
        "Expected attachment disposition, got: {}",
        disposition
    );
    assert!(
        disposition.contains("edr_report_"),
        "Expected edr_report_ in filename, got: {}",
        disposition
    );
    assert!(
        disposition.contains(".pdf"),
        "Expected .pdf extension, got: {}",
        disposition
    );
}

/// Test: Minimal request (empty JSON) still produces valid PDF
#[tokio::test]
async fn test_pdf_minimal_request() {
    let server = TestServer::new(build_test_router()).unwrap();

    let response = server.post("/api/report/pdf").json(&json!({})).await;

    response.assert_status_ok();

    let bytes = response.into_bytes();
    assert_eq!(
        &bytes[0..5],
        b"%PDF-",
        "Minimal request should produce valid PDF"
    );
}

/// Test: Stable ordering - same input produces similar size output
#[tokio::test]
async fn test_pdf_stable_output() {
    let server = TestServer::new(build_test_router()).unwrap();
    let req = create_test_request();

    // Generate PDF twice
    let response1 = server.post("/api/report/pdf").json(&req).await;
    response1.assert_status_ok();
    let bytes1 = response1.into_bytes();

    let response2 = server.post("/api/report/pdf").json(&req).await;
    response2.assert_status_ok();
    let bytes2 = response2.into_bytes();

    // Both should be valid PDFs
    assert_eq!(&bytes1[0..5], b"%PDF-");
    assert_eq!(&bytes2[0..5], b"%PDF-");

    // Size should be within 10% tolerance (timestamps may differ slightly)
    let size_diff = (bytes1.len() as i64 - bytes2.len() as i64).abs();
    let tolerance = (bytes1.len() / 10) as i64;

    assert!(
        size_diff <= tolerance,
        "PDF sizes too different: {} vs {} (diff: {}, tolerance: {})",
        bytes1.len(),
        bytes2.len(),
        size_diff,
        tolerance
    );
}

// ============================================================================
// Fixture Verification Tests
// ============================================================================

/// Test: Fixture bundle has exactly 1 hypothesis
#[test]
fn test_fixture_has_one_hypothesis() {
    let req = create_test_request();
    let bundle = build_test_bundle(&req, "test-report".to_string(), "test-host".to_string());

    assert_eq!(
        bundle.hypotheses.len(),
        1,
        "Fixture should have exactly 1 hypothesis"
    );
    assert_eq!(bundle.hypotheses[0].hypothesis_id, "H-TEST-001");
}

/// Test: Fixture bundle has 2 timeline entries, one with is_late_arrival=true
#[test]
fn test_fixture_has_timeline_with_late_arrival() {
    let req = create_test_request();
    let bundle = build_test_bundle(&req, "test-report".to_string(), "test-host".to_string());

    assert_eq!(
        bundle.timeline.len(),
        2,
        "Fixture should have exactly 2 timeline entries"
    );

    let late_arrivals: Vec<_> = bundle
        .timeline
        .iter()
        .filter(|t| t.is_late_arrival)
        .collect();
    assert_eq!(
        late_arrivals.len(),
        1,
        "Fixture should have exactly 1 late arrival timeline entry"
    );
}

/// Test: Fixture bundle has claim with evidence pointer
#[test]
fn test_fixture_has_claim_with_evidence() {
    let req = create_test_request();
    let bundle = build_test_bundle(&req, "test-report".to_string(), "test-host".to_string());

    assert!(
        !bundle.claims.is_empty(),
        "Fixture should have at least 1 claim"
    );

    let claim = &bundle.claims[0];
    assert!(
        !claim.evidence_ptrs.is_empty(),
        "Fixture claim should have evidence pointer"
    );
    assert_eq!(claim.evidence_ptrs[0], "seg_001:evt_0");
}

/// Test: Fixture bundle has visibility with missing stream
#[test]
fn test_fixture_has_missing_stream() {
    let req = create_test_request();
    let bundle = build_test_bundle(&req, "test-report".to_string(), "test-host".to_string());

    assert!(
        !bundle.visibility.streams_missing.is_empty(),
        "Fixture visibility should have missing streams"
    );
    assert!(
        bundle
            .visibility
            .streams_missing
            .contains(&"network_events".to_string()),
        "Fixture should be missing network_events stream"
    );
}

/// Test: Fixture bundle has exactly 1 disambiguator
#[test]
fn test_fixture_has_disambiguator() {
    let req = create_test_request();
    let bundle = build_test_bundle(&req, "test-report".to_string(), "test-host".to_string());

    assert_eq!(
        bundle.disambiguators.len(),
        1,
        "Fixture should have exactly 1 disambiguator"
    );
    assert_eq!(bundle.disambiguators[0].id, "D-TEST-001");
}

// ============================================================================
// Direct Renderer Tests (no HTTP, unit-level)
// ============================================================================

/// Test: PdfRenderer can render the fixture bundle
#[test]
fn test_renderer_produces_valid_pdf() {
    let req = create_test_request();
    let bundle = build_test_bundle(&req, "render-test".to_string(), "test-host".to_string());

    let renderer = PdfRenderer::new().expect("Failed to create renderer");
    let pdf_bytes = renderer.render(&bundle).expect("Failed to render PDF");

    assert!(pdf_bytes.len() > 5000, "Rendered PDF should be > 5KB");
    assert_eq!(&pdf_bytes[0..5], b"%PDF-", "Should have PDF magic header");
}

/// Test: Renderer handles empty bundle gracefully
#[test]
fn test_renderer_handles_minimal_bundle() {
    let bundle = ReportBundleBuilder::new("minimal".to_string(), "host".to_string()).build();

    let renderer = PdfRenderer::new().expect("Failed to create renderer");
    let pdf_bytes = renderer
        .render(&bundle)
        .expect("Failed to render minimal PDF");

    assert!(
        !pdf_bytes.is_empty(),
        "Even minimal bundle should produce output"
    );
    assert_eq!(&pdf_bytes[0..5], b"%PDF-");
}

// ============================================================================
// Optional E2E Test (requires running server - keep ignored)
// ============================================================================

/// Optional E2E test against live server
/// This is the ONLY ignored test - all others run in-process
#[tokio::test]
#[ignore = "Optional: requires running server at localhost:3000"]
async fn test_e2e_live_server() {
    let client = reqwest::Client::new();

    let response = client
        .post("http://localhost:3000/api/report/pdf")
        .json(&create_test_request())
        .send()
        .await;

    match response {
        Ok(resp) => {
            assert!(resp.status().is_success(), "Live server should return 200");
            let bytes = resp.bytes().await.expect("Failed to read body");
            assert_eq!(
                &bytes[0..5],
                b"%PDF-",
                "Live server should return valid PDF"
            );
        }
        Err(e) => {
            eprintln!("⚠️  Live server not available: {}", e);
        }
    }
}

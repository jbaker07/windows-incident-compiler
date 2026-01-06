//! EDR Server Library
//!
//! Exposes report generation and test utilities for in-process testing.
//! Ship Hardening: Includes health checks, path safety, and write isolation.

pub mod bundle_exchange;
pub mod golden_bundle;
pub mod health;
pub mod integration_api;
pub mod query_isolation;
pub mod report;
pub mod support_bundle;
pub mod write_isolation;

// Re-export key types for tests
pub use report::{
    ClaimEntry, DisambiguatorEntry, HypothesisSummary, IntegrityNoteEntry, PdfRenderer,
    ReportBundle, ReportBundleBuilder, ReportRequest, TimelineEntry, VisibilitySection,
};

pub use golden_bundle::{
    generate_all_golden_bundles, generate_golden_bundle, get_predefined_scenarios,
    verify_all_bundles, verify_bundle_in_process, BundleVerifyResult, GoldenFeatures,
    GoldenScenario, Verdict, VerificationReport, VerifyMode,
};

// Ship Hardening: Health and isolation types
pub use health::{
    check_health, validate_startup, BlockingIssue, BuildInfo, CaptureStatus, HealthCheckConfig,
    HealthResponse, HealthVerdict, ImportedStatus, StartupValidation, StorageHealth, StreamHealth,
};

pub use write_isolation::{
    extract_bundle_id_from_path, is_imported_path, WriteIsolationContext, WriteIsolationError,
};

pub use query_isolation::{
    extract_bundle_id, is_imported_namespace, make_imported_namespace, IsolatedQueryResult,
    NamespaceFilter, QuerySource,
};

// Integration Profile API
pub use integration_api::{
    integration_api_router, CapabilitiesMatrixApi, CapabilitySource, CollectorInfo,
    DerivedScopeKey, Fidelity, HealthStatus, IntegrationApiState, IntegrationDetailApi,
    IntegrationMode, IntegrationProfileApi, JoinKeySupport, MappedEventSample,
    SampleEventsResponse, SourceType,
};

/// Build a minimal router for testing the PDF report endpoint.
/// This does not require database or full app state.
#[cfg(any(test, feature = "test-utils"))]
pub fn build_test_router() -> axum::Router {
    use axum::{routing::post, Router};

    Router::new().route("/api/report/pdf", post(generate_pdf_report_handler))
}

/// Standalone PDF report handler for testing
/// Does not require SharedState - uses the request data directly
#[cfg(any(test, feature = "test-utils"))]
async fn generate_pdf_report_handler(
    axum::extract::Json(req): axum::extract::Json<ReportRequest>,
) -> impl axum::response::IntoResponse {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    use axum::Json;

    // Build the report bundle from the request
    let report_id = uuid::Uuid::new_v4().to_string();
    let host_id = "test-host-001".to_string();

    let bundle = build_test_bundle(&req, report_id, host_id);

    // Render to PDF
    let renderer = PdfRenderer::new().unwrap_or_default();

    match renderer.render(&bundle) {
        Ok(pdf_bytes) => {
            let incident = bundle.metadata.incident_id.as_deref().unwrap_or("unknown");
            let filename = format!(
                "edr_report_{}_{}.pdf",
                incident,
                chrono::Utc::now().format("%Y%m%d_%H%M%S")
            );
            let content_disposition = format!("attachment; filename=\"{}\"", filename);

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/pdf"),
                    (header::CONTENT_DISPOSITION, content_disposition.as_str()),
                ],
                pdf_bytes,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("PDF generation failed: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Build a deterministic test bundle with required fixture data:
/// - 1 hypothesis
/// - 2 timeline entries (one is_late_arrival=true)
/// - 1 claim with evidence pointer
/// - visibility_state with missing stream
/// - 1 disambiguator
#[cfg(any(test, feature = "test-utils"))]
pub fn build_test_bundle(req: &ReportRequest, report_id: String, host_id: String) -> ReportBundle {
    use chrono::{TimeZone, Utc};

    // Use fixed timestamps for deterministic output
    let base_ts = Utc.with_ymd_and_hms(2025, 12, 27, 10, 0, 0).unwrap();
    let late_ts = Utc.with_ymd_and_hms(2025, 12, 27, 10, 5, 30).unwrap();

    ReportBundleBuilder::new(report_id, host_id)
        .with_incident_id(
            req.incident_id
                .clone()
                .unwrap_or_else(|| "test-incident-fixture".to_string()),
        )
        .with_session_id(
            req.session_id
                .clone()
                .unwrap_or_else(|| "test-session-fixture".to_string()),
        )
        .with_family("credential_access".to_string())
        .with_summary(
            "Test fixture: Credential theft detection with LSASS access pattern.".to_string(),
        )
        // 1 hypothesis (required by fixture spec)
        .add_hypothesis(HypothesisSummary {
            rank: 1,
            hypothesis_id: "H-TEST-001".to_string(),
            family: "credential_access".to_string(),
            template_id: "T1003.001".to_string(),
            confidence: 0.92,
            severity: "High".to_string(),
            suppressed: false,
            suppression_reason: None,
            slots_satisfied: "4/5 slots filled".to_string(),
        })
        // 2 timeline entries (one with is_late_arrival=true)
        .add_timeline_entry(TimelineEntry {
            ts: base_ts,
            summary: "Initial LSASS memory access detected".to_string(),
            category: "process".to_string(),
            evidence_ptr: Some("seg_001:evt_0".to_string()),
            is_late_arrival: false,
        })
        .add_timeline_entry(TimelineEntry {
            ts: late_ts,
            summary: "Secondary credential dump attempt (late arrival)".to_string(),
            category: "process".to_string(),
            evidence_ptr: Some("seg_002:evt_0".to_string()),
            is_late_arrival: true, // Required by fixture spec
        })
        // 1 claim with evidence pointer
        .add_claim(ClaimEntry {
            claim_id: "C-TEST-001".to_string(),
            text: "LSASS process memory was accessed by mimikatz.exe".to_string(),
            certainty: "observed".to_string(),
            claim_type: "MemoryAccess".to_string(),
            evidence_ptrs: vec!["seg_001:evt_0".to_string()], // Evidence pointer required
            has_conflict: false,
        })
        // Visibility with missing stream
        .with_visibility(VisibilitySection {
            overall_health: "degraded".to_string(),
            streams_present: vec!["process_events".to_string(), "file_events".to_string()],
            streams_missing: vec!["network_events".to_string()], // Missing stream required
            degraded: true,
            degraded_reasons: vec!["Network sensor offline".to_string()],
            late_arrival_count: 1,
            watermark_notes: vec!["Fixture test watermark".to_string()],
        })
        // 1 disambiguator
        .add_disambiguator(DisambiguatorEntry {
            id: "D-TEST-001".to_string(),
            priority: 1,
            question: "Is the LSASS access from a known security tool?".to_string(),
            pivot_action: "Check process hash against allowlist".to_string(),
            if_yes: "Benign - update allowlist documentation".to_string(),
            if_no: "Malicious - escalate to IR team".to_string(),
            actionable: true,
        })
        // Add evidence excerpt for the claim
        .add_evidence_excerpt(
            "seg_001:evt_0".to_string(),
            "Process: mimikatz.exe (PID: 1234) -> OpenProcess(PROCESS_VM_READ) on lsass.exe"
                .to_string(),
        )
        .build()
}

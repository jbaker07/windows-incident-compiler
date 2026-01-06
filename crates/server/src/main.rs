// edr-server main.rs
// HTTP API for the Attack Documentation Workbench

mod bundle_exchange;
mod capture_control;
mod db;
mod diagnostics;
mod diff_api;
mod integration_api;
mod license_api;
mod probe;
mod report;
mod support_bundle;
mod verification_pack;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use bundle_exchange::{
    build_incident_bundle, create_imported_namespace, export_to_zip, import_bundle,
    mark_as_imported, validate_bundle, ExportBundleRequest, ExportBundleResponse,
    ImportBundleResponse, RecomputeRequest, RecomputeResult,
};
use capture_control::{CaptureProfile, ProfileConfig, ThrottleController, ThrottleDecision};
use db::Database;
use diagnostics::DiagnosticEngine;
use probe::{ProbeRunner, ProbeSpec};
use report::{PdfRenderer, ReportRequest};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use verification_pack::{
    AppStateResponse, SelfCheckRequest, SelfCheckResponse as LegacySelfCheckResponse, SessionInfo,
    SetupCompleteRequest, SetupCompleteResponse, VerificationState, VerifyLoadRequest,
    VerifyLoadResponse,
};
use workbench::{
    get_technique, search_techniques, CaptureSession, Document, ExportFormat, ExportOptions,
    Exporter,
};

// ============================================================================
// Application State
// ============================================================================

struct AppState {
    db: Database,
    sessions: RwLock<std::collections::HashMap<String, CaptureSession>>,
    active_session: RwLock<Option<String>>,
    data_dir: PathBuf,
    verification_state: RwLock<VerificationState>,
    current_mode: RwLock<Option<String>>,
    current_preset: RwLock<Option<String>>,
    focus_minutes: RwLock<u32>,
    /// Capture profile (core/extended/forensic)
    capture_profile: RwLock<CaptureProfile>,
    /// Central throttle controller
    throttle_controller: Arc<ThrottleController>,
    /// Diagnostic engine
    diagnostic_engine: DiagnosticEngine,
    /// Probe runner for live telemetry verification
    probe_runner: ProbeRunner,
    /// Server start time (used for uptime reporting)
    #[allow(dead_code)]
    start_time: chrono::DateTime<chrono::Utc>,
}

type SharedState = Arc<AppState>;

// ============================================================================
// API Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }

    fn err(msg: &str) -> Json<Self> {
        Json(Self {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        })
    }
}

#[derive(Debug, Deserialize)]
struct CreateDocumentRequest {
    title: String,
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateSectionRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
struct SessionControlRequest {
    action: String, // "start", "stop", "pause", "resume"
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AddMarkerRequest {
    marker_type: String, // "important", "phase_start", "phase_end", "note"
    #[allow(dead_code)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportRequest {
    format: String,        // "html", "markdown", "json"
    theme: Option<String>, // "professional", "dark", "minimal", "technical"
}

#[derive(Debug, Deserialize)]
struct TechniqueSearchRequest {
    query: String,
}

#[derive(Debug, Deserialize)]
struct SignalIngestRequest {
    signals: Vec<db::StoredSignal>,
}

#[derive(Debug, Deserialize)]
struct SignalQueryParams {
    host: Option<String>,
    signal_type: Option<String>,
    severity: Option<String>,
    limit: Option<usize>,
}

// ============================================================================
// Narrative & Mission Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct CreateMissionRequest {
    name: String,
    objective: String,
    allowed_technique_families: Option<Vec<String>>,
    allowed_playbooks: Option<Vec<String>>,
    expected_observables: Option<Vec<String>>,
    scope_constraints: Option<serde_json::Value>,
    success_criteria: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct NarrativeActionRequest {
    sentence_id: Option<String>,
    evidence_ptr: Option<serde_json::Value>,
    action_type: String, // "pin", "hide", "verify", "annotate", "merge", "split"
    notes: Option<String>,
}

// ============================================================================
// Document Endpoints
// ============================================================================

async fn list_documents(State(state): State<SharedState>) -> impl IntoResponse {
    match state.db.list_documents() {
        Ok(docs) => {
            let list: Vec<_> = docs
                .iter()
                .map(|doc| {
                    serde_json::json!({
                        "id": doc.id,
                        "title": doc.title,
                        "created_at": doc.created_at,
                        "updated_at": doc.updated_at,
                    })
                })
                .collect();
            ApiResponse::ok(list)
        }
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

async fn create_document(
    State(state): State<SharedState>,
    Json(req): Json<CreateDocumentRequest>,
) -> impl IntoResponse {
    let doc = Document::new(
        &req.title,
        req.author.as_deref().unwrap_or("Detection Engineer"),
    );
    let id = doc.id.clone();

    match state.db.save_document(&doc) {
        Ok(_) => ApiResponse::ok(serde_json::json!({ "id": id })),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

async fn get_document(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_document(&id) {
        Ok(Some(doc)) => (StatusCode::OK, ApiResponse::ok(doc)),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            ApiResponse::err("Document not found"),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Database error: {}", e)),
        ),
    }
}

async fn update_document_section(
    State(state): State<SharedState>,
    Path((id, section)): Path<(String, String)>,
    Json(req): Json<UpdateSectionRequest>,
) -> impl IntoResponse {
    match state.db.get_document(&id) {
        Ok(Some(mut doc)) => {
            match section.as_str() {
                "summary" => doc.summary.edit(&req.content),
                "impact" => doc.impact.edit(&req.content),
                _ => return (StatusCode::BAD_REQUEST, ApiResponse::err("Invalid section")),
            }
            doc.updated_at = chrono::Utc::now();
            match state.db.save_document(&doc) {
                Ok(_) => (
                    StatusCode::OK,
                    ApiResponse::ok(serde_json::json!({ "updated": true })),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ApiResponse::err(&format!("Database error: {}", e)),
                ),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            ApiResponse::err("Document not found"),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Database error: {}", e)),
        ),
    }
}

async fn delete_document(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_document(&id) {
        Ok(true) => ApiResponse::ok(serde_json::json!({ "deleted": true })),
        Ok(false) => ApiResponse::err("Document not found"),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

// ============================================================================
// Session Endpoints
// ============================================================================

async fn get_session_status(State(state): State<SharedState>) -> impl IntoResponse {
    let active = state.active_session.read().await;
    let sessions = state.sessions.read().await;

    match &*active {
        Some(id) => {
            if let Some(session) = sessions.get(id) {
                ApiResponse::ok(serde_json::json!({
                    "active": true,
                    "session_id": id,
                    "state": format!("{:?}", session.state),
                    "started_at": session.started_at,
                    "markers_count": session.markers.len(),
                }))
            } else {
                ApiResponse::ok(serde_json::json!({ "active": false }))
            }
        }
        None => ApiResponse::ok(serde_json::json!({ "active": false })),
    }
}

async fn control_session(
    State(state): State<SharedState>,
    Json(req): Json<SessionControlRequest>,
) -> impl IntoResponse {
    match req.action.as_str() {
        "start" => {
            let mut session = CaptureSession::new();
            session.start();
            let id = uuid::Uuid::new_v4().to_string();

            state.sessions.write().await.insert(id.clone(), session);
            *state.active_session.write().await = Some(id.clone());

            ApiResponse::ok(serde_json::json!({ "session_id": id, "state": "Capturing" }))
        }
        "stop" => {
            let active = state.active_session.read().await.clone();
            if let Some(id) = active {
                if let Some(session) = state.sessions.write().await.get_mut(&id) {
                    session.stop();
                }
                *state.active_session.write().await = None;
                ApiResponse::ok(serde_json::json!({ "state": "Stopped" }))
            } else {
                ApiResponse::err("No active session")
            }
        }
        "pause" => {
            let active = state.active_session.read().await.clone();
            if let Some(id) = active {
                if let Some(session) = state.sessions.write().await.get_mut(&id) {
                    session.pause();
                }
                ApiResponse::ok(serde_json::json!({ "state": "Paused" }))
            } else {
                ApiResponse::err("No active session")
            }
        }
        "resume" => {
            let active = state.active_session.read().await.clone();
            if let Some(id) = active {
                if let Some(session) = state.sessions.write().await.get_mut(&id) {
                    session.resume();
                }
                ApiResponse::ok(serde_json::json!({ "state": "Capturing" }))
            } else {
                ApiResponse::err("No active session")
            }
        }
        _ => ApiResponse::err("Invalid action. Use: start, stop, pause, resume"),
    }
}

async fn add_marker(
    State(state): State<SharedState>,
    Json(req): Json<AddMarkerRequest>,
) -> impl IntoResponse {
    use workbench::session::MarkerType;

    let active = state.active_session.read().await.clone();
    if let Some(id) = active {
        let marker_type = match req.marker_type.as_str() {
            "important" => MarkerType::Important,
            "phase_start" => MarkerType::PhaseStart,
            "phase_end" => MarkerType::PhaseEnd,
            "note" => MarkerType::Note,
            "attack_start" => MarkerType::AttackStart,
            "attack_end" => MarkerType::AttackEnd,
            _ => return ApiResponse::err("Invalid marker type"),
        };

        if let Some(session) = state.sessions.write().await.get_mut(&id) {
            session.add_marker(marker_type, req.note);
            ApiResponse::ok(serde_json::json!({ "added": true }))
        } else {
            ApiResponse::err("Session not found")
        }
    } else {
        ApiResponse::err("No active session")
    }
}

// ============================================================================
// Export Endpoints
// ============================================================================

async fn export_document(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(req): Json<ExportRequest>,
) -> impl IntoResponse {
    use workbench::export::ExportTheme;

    match state.db.get_document(&id) {
        Ok(Some(doc)) => {
            let theme = match req.theme.as_deref() {
                Some("dark") => ExportTheme::Dark,
                Some("minimal") => ExportTheme::Minimal,
                Some("technical") => ExportTheme::Technical,
                _ => ExportTheme::Professional,
            };

            let format = match req.format.as_str() {
                "html" => ExportFormat::Html,
                "markdown" => ExportFormat::Markdown,
                "json" => ExportFormat::Json,
                _ => return (StatusCode::BAD_REQUEST, "Invalid format".into_response()),
            };

            let options = ExportOptions {
                format,
                theme,
                include_summary: true,
                include_timeline: true,
                include_technique: true,
                include_impact: true,
                include_evidence: true,
                include_raw_events: false,
                include_custom_sections: true,
            };

            match req.format.as_str() {
                "html" => {
                    let html = Exporter::to_html(&doc, &options);
                    (StatusCode::OK, Html(html).into_response())
                }
                "markdown" => {
                    let md = Exporter::to_markdown(&doc, &options);
                    (StatusCode::OK, md.into_response())
                }
                "json" => (StatusCode::OK, Json(doc).into_response()),
                _ => (StatusCode::BAD_REQUEST, "Invalid format".into_response()),
            }
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Document not found".into_response()),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e).into_response(),
        ),
    }
}

// ============================================================================
// MITRE ATT&CK Endpoints
// ============================================================================

async fn search_mitre_techniques(Json(req): Json<TechniqueSearchRequest>) -> impl IntoResponse {
    let results = search_techniques(&req.query);
    let techniques: Vec<_> = results
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "tactic": t.tactic,
                "description": t.description,
            })
        })
        .collect();
    ApiResponse::ok(techniques)
}

async fn get_mitre_technique(Path(id): Path<String>) -> impl IntoResponse {
    match get_technique(&id) {
        Some(t) => ApiResponse::ok(serde_json::json!({
            "id": t.id,
            "name": t.name,
            "tactic": t.tactic,
            "description": t.description,
        })),
        None => ApiResponse::err("Technique not found"),
    }
}

// ============================================================================
// Signal Endpoints
// ============================================================================

async fn ingest_signals(
    State(state): State<SharedState>,
    Json(req): Json<SignalIngestRequest>,
) -> impl IntoResponse {
    match state.db.save_signals(&req.signals) {
        Ok(count) => ApiResponse::ok(serde_json::json!({
            "ingested": count,
            "success": true
        })),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

async fn list_signals(
    State(state): State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<SignalQueryParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(1000);

    match state.db.list_signals(
        params.host.as_deref(),
        params.signal_type.as_deref(),
        params.severity.as_deref(),
        limit,
    ) {
        Ok(signals) => ApiResponse::ok(signals),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

async fn get_signal(State(state): State<SharedState>, Path(id): Path<String>) -> impl IntoResponse {
    match state.db.get_signal(&id) {
        Ok(Some(signal)) => (StatusCode::OK, ApiResponse::ok(signal)),
        Ok(None) => (StatusCode::NOT_FOUND, ApiResponse::err("Signal not found")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Database error: {}", e)),
        ),
    }
}

/// Get explanation bundle for a signal
async fn get_signal_explanation(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // First check if signal exists
    match state.db.get_signal(&id) {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                ApiResponse::err(&format!("Signal '{}' not found", id)),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::err(&format!("Database error: {}", e)),
            );
        }
        Ok(Some(_)) => {} // Signal exists, continue
    }

    // Get explanation from signal_explanations table
    match state.db.get_signal_explanation(&id) {
        Ok(Some(explanation)) => (StatusCode::OK, ApiResponse::ok(explanation)),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            ApiResponse::err(&format!("Explanation not found for signal '{}'. The signal may have been created before explainability was enabled.", id)),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Database error: {}", e)),
        ),
    }
}

async fn signal_stats(State(state): State<SharedState>) -> impl IntoResponse {
    match state.db.signal_stats() {
        Ok(stats) => ApiResponse::ok(stats),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

// ============================================================================
// License API Endpoints
// ============================================================================

/// GET /api/license/status - Get current license status
async fn license_status_endpoint() -> impl IntoResponse {
    license_api::license_status_handler().await
}

/// POST /api/license/install - Install a license
async fn license_install_endpoint(
    Json(request): Json<license_api::InstallLicenseRequest>,
) -> impl IntoResponse {
    license_api::install_license_handler(Json(request)).await
}

/// POST /api/license/reload - Force reload license from disk
async fn license_reload_endpoint() -> impl IntoResponse {
    license_api::reload_license_handler().await
}

// ============================================================================
// Pro: Diff API Endpoints
// ============================================================================

/// GET /api/diff - Compare two runs (requires diff_mode entitlement)
async fn diff_endpoint(
    State(state): State<SharedState>,
    Query(params): Query<diff_api::DiffQuery>,
) -> impl IntoResponse {
    diff_api::diff_response(&state.db, &params)
}

/// GET /api/runs - List available runs for diff selection
async fn list_runs_endpoint(State(state): State<SharedState>) -> impl IntoResponse {
    diff_api::list_runs_response(&state.db)
}

// ============================================================================
// Narrative Endpoints
// ============================================================================

/// Get narrative for a signal. Generates from ExplanationBundle + arbitration if not cached.
async fn get_signal_narrative(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Check if narrative is already cached
    match state.db.get_narrative(&id) {
        Ok(Some(narrative)) => {
            return (StatusCode::OK, ApiResponse::ok(narrative));
        }
        Ok(None) => {} // Not cached, generate below
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::err(&format!("Database error: {}", e)),
            );
        }
    }

    // Get explanation bundle to generate narrative
    let explanation = match state.db.get_signal_explanation(&id) {
        Ok(Some(exp)) => exp,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                ApiResponse::err(&format!(
                    "No explanation available for signal '{}'. Cannot generate narrative.",
                    id
                )),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::err(&format!("Database error: {}", e)),
            );
        }
    };

    // Get active mission spec (if any) to determine mode
    let mission_spec = state.db.get_active_mission_spec().ok().flatten();
    let mode = if mission_spec.is_some() {
        "Mission"
    } else {
        "Discovery"
    };

    // Build narrative from explanation bundle
    let narrative_id = format!("narr_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    // Extract data from explanation
    let matched_facts = explanation
        .get("matched_facts")
        .cloned()
        .unwrap_or(serde_json::json!([]));
    let slots = explanation
        .get("slots")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let hypothesis = explanation
        .get("hypothesis_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    // Build sentences from matched facts (observations) and slot explanations (inferences)
    let mut sentences = Vec::new();
    let mut sentence_idx = 0;

    // Add observation sentences from matched facts
    if let Some(facts) = matched_facts.as_array() {
        for fact in facts {
            let fact_type = fact
                .get("fact_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let summary = fact.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            let evidence_ptrs = fact
                .get("evidence_pointers")
                .cloned()
                .unwrap_or(serde_json::json!([]));
            let excerpts = fact
                .get("excerpts")
                .cloned()
                .unwrap_or(serde_json::json!([]));

            sentence_idx += 1;
            sentences.push(serde_json::json!({
                "sentence_id": format!("s_{}", sentence_idx),
                "sentence_type": "Observation",
                "text": summary,
                "receipts": {
                    "evidence_ptrs": evidence_ptrs,
                    "excerpts": excerpts,
                    "supporting_facts": [],
                    "supporting_slots": []
                },
                "confidence": 1.0,
                "tags": [fact_type]
            }));
        }
    }

    // Add inference sentences from slot explanations
    if let Some(slots_obj) = slots.as_object() {
        for (slot_name, slot_data) in slots_obj {
            if let Some(explanation_text) = slot_data.get("explanation").and_then(|v| v.as_str()) {
                let evidence_ptrs = slot_data
                    .get("evidence_pointers")
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                let supporting_facts = slot_data
                    .get("supporting_facts")
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                let is_filled = slot_data
                    .get("filled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if is_filled {
                    sentence_idx += 1;
                    sentences.push(serde_json::json!({
                        "sentence_id": format!("s_{}", sentence_idx),
                        "sentence_type": "Inference",
                        "inference_label": slot_name,
                        "text": explanation_text,
                        "receipts": {
                            "evidence_ptrs": evidence_ptrs,
                            "excerpts": [],
                            "supporting_facts": supporting_facts,
                            "supporting_slots": [slot_name]
                        },
                        "confidence": slot_data.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.8),
                        "tags": ["slot_fill"]
                    }));
                }
            }
        }
    }

    // Build arbitration doc from explanation
    let arbitration = if let Some(arb) = explanation.get("arbitration") {
        build_arbitration_doc(arb)
    } else {
        serde_json::json!({
            "winner": {
                "hypothesis_name": hypothesis,
                "rank": 1,
                "score": 1.0,
                "slot_status": {"filled_count": 0, "total_count": 0, "missing": []},
                "key_evidence": [],
                "missing_observables": [],
                "capability_gaps": []
            },
            "runner_up": null,
            "third": null,
            "win_reasons": ["Only hypothesis evaluated"],
            "runner_up_loss_reasons": [],
            "third_loss_reasons": []
        })
    };

    // Build disambiguation from missing slots/capability gaps
    let disambiguation = build_disambiguation_doc(&explanation);

    // Construct full narrative document
    let narrative = serde_json::json!({
        "narrative_id": narrative_id,
        "signal_id": id,
        "version": 1,
        "generated_at": now,
        "sentences": sentences,
        "arbitration": arbitration,
        "disambiguation": disambiguation,
        "mode_context": {
            "mode": mode,
            "mission_spec": mission_spec,
            "pivot_suggestions": [],
            "user_actions": []
        },
        "input_hash": format!("{:x}", md5::compute(serde_json::to_string(&explanation).unwrap_or_default()))
    });

    // Cache the narrative
    if let Err(e) = state.db.save_narrative(&narrative) {
        tracing::warn!("Failed to cache narrative: {}", e);
    }

    (StatusCode::OK, ApiResponse::ok(narrative))
}

/// Build arbitration doc from raw arbitration response
fn build_arbitration_doc(arb: &serde_json::Value) -> serde_json::Value {
    let candidates = arb.get("candidates").and_then(|v| v.as_array());

    let build_ranked = |candidate: Option<&serde_json::Value>, rank: u32| -> serde_json::Value {
        match candidate {
            Some(c) => serde_json::json!({
                "hypothesis_name": c.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                "rank": rank,
                "score": c.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0),
                "slot_status": c.get("slot_status").cloned().unwrap_or(serde_json::json!({
                    "filled_count": 0,
                    "total_count": 0,
                    "missing": []
                })),
                "key_evidence": c.get("key_evidence").cloned().unwrap_or(serde_json::json!([])),
                "missing_observables": c.get("missing_observables").cloned().unwrap_or(serde_json::json!([])),
                "capability_gaps": c.get("capability_gaps").cloned().unwrap_or(serde_json::json!([]))
            }),
            None => serde_json::json!(null),
        }
    };

    let (winner, runner_up, third) = if let Some(cands) = candidates {
        (
            build_ranked(cands.first(), 1),
            build_ranked(cands.get(1), 2),
            build_ranked(cands.get(2), 3),
        )
    } else {
        (
            serde_json::json!(null),
            serde_json::json!(null),
            serde_json::json!(null),
        )
    };

    // Extract win/loss reasons
    let win_reasons = arb
        .get("win_reasons")
        .cloned()
        .unwrap_or_else(|| serde_json::json!(["Higher slot fill ratio"]));
    let runner_up_loss = arb
        .get("runner_up_loss_reasons")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let third_loss = arb
        .get("third_loss_reasons")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    serde_json::json!({
        "winner": winner,
        "runner_up": runner_up,
        "third": third,
        "win_reasons": win_reasons,
        "runner_up_loss_reasons": runner_up_loss,
        "third_loss_reasons": third_loss
    })
}

/// Build disambiguation doc from explanation gaps
fn build_disambiguation_doc(explanation: &serde_json::Value) -> serde_json::Value {
    let mut questions = Vec::new();
    let mut pivot_actions = Vec::new();
    let mut capability_suggestions = Vec::new();

    // Extract missing slots
    if let Some(slots) = explanation.get("slots").and_then(|v| v.as_object()) {
        for (slot_name, slot_data) in slots {
            let is_filled = slot_data
                .get("filled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !is_filled {
                let description = slot_data
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Additional evidence needed");

                questions.push(serde_json::json!({
                    "question_id": format!("q_{}", slot_name),
                    "text": format!("What would satisfy the '{}' slot?", slot_name),
                    "reason": format!("Slot '{}' is unfilled: {}", slot_name, description),
                    "expected_answer_type": "evidence",
                    "related_facts": [],
                    "priority": "high"
                }));

                // Suggest pivot action to fill this slot
                pivot_actions.push(serde_json::json!({
                    "action_id": format!("piv_{}", slot_name),
                    "action_type": "evidence_search",
                    "description": format!("Search for evidence to fill '{}' slot", slot_name),
                    "target_slot": slot_name,
                    "estimated_impact": "high"
                }));
            }
        }
    }

    // Extract capability gaps
    if let Some(gaps) = explanation
        .get("capability_gaps")
        .and_then(|v| v.as_array())
    {
        for gap in gaps {
            let integration = gap
                .get("integration")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");
            let missing_type = gap
                .get("missing_type")
                .and_then(|v| v.as_str())
                .unwrap_or("telemetry");

            capability_suggestions.push(serde_json::json!({
                "suggestion_id": format!("cap_{}", integration),
                "capability_name": integration,
                "reason": format!("Missing {} from {}", missing_type, integration),
                "expected_benefit": "Would provide additional visibility",
                "integration_link": null,
                "priority": "medium"
            }));
        }
    }

    // Calculate ambiguity score based on questions and gaps
    let ambiguity_score = if questions.is_empty() && capability_suggestions.is_empty() {
        0.0
    } else {
        let question_weight = questions.len() as f64 * 0.15;
        let gap_weight = capability_suggestions.len() as f64 * 0.1;
        (question_weight + gap_weight).min(1.0)
    };

    serde_json::json!({
        "questions": questions,
        "pivot_actions": pivot_actions,
        "capability_suggestions": capability_suggestions,
        "ambiguity_score": ambiguity_score
    })
}

/// Record a user action on a narrative
async fn create_narrative_action(
    State(state): State<SharedState>,
    Path(narrative_id): Path<String>,
    Json(request): Json<NarrativeActionRequest>,
) -> impl IntoResponse {
    // Verify narrative exists
    match state.db.get_narrative_by_id(&narrative_id) {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                ApiResponse::err(&format!("Narrative '{}' not found", narrative_id)),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::err(&format!("Database error: {}", e)),
            );
        }
        Ok(Some(_)) => {}
    }

    match state.db.save_narrative_action(
        &narrative_id,
        request.sentence_id.as_deref(),
        request.evidence_ptr.as_ref(),
        &request.action_type,
        request.notes.as_deref(),
    ) {
        Ok(action_id) => (
            StatusCode::CREATED,
            ApiResponse::ok(serde_json::json!({
                "action_id": action_id,
                "narrative_id": narrative_id,
                "action_type": request.action_type
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Failed to save action: {}", e)),
        ),
    }
}

/// Get actions for a narrative
async fn get_narrative_actions(
    State(state): State<SharedState>,
    Path(narrative_id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_narrative_actions(&narrative_id) {
        Ok(actions) => ApiResponse::ok(actions),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

// ============================================================================
// Mission Endpoints
// ============================================================================

/// Get current mission mode (discovery vs mission)
async fn get_mission_mode(State(state): State<SharedState>) -> impl IntoResponse {
    match state.db.get_active_mission_spec() {
        Ok(Some(spec)) => ApiResponse::ok(serde_json::json!({
            "mode": "Mission",
            "mission_spec": spec
        })),
        Ok(None) => ApiResponse::ok(serde_json::json!({
            "mode": "Discovery",
            "mission_spec": null
        })),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

/// Create a new mission spec
async fn create_mission(
    State(state): State<SharedState>,
    Json(request): Json<CreateMissionRequest>,
) -> impl IntoResponse {
    let mission_id = format!("mission_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    let spec = serde_json::json!({
        "mission_id": mission_id,
        "name": request.name,
        "objective": request.objective,
        "allowed_technique_families": request.allowed_technique_families.unwrap_or_default(),
        "allowed_playbooks": request.allowed_playbooks.unwrap_or_default(),
        "expected_observables": request.expected_observables.unwrap_or_default(),
        "scope_constraints": request.scope_constraints,
        "success_criteria": request.success_criteria,
        "created_at": now
    });

    match state.db.save_mission_spec(&spec) {
        Ok(()) => (
            StatusCode::CREATED,
            ApiResponse::ok(serde_json::json!({
                "mission_id": mission_id,
                "message": "Mission spec created. Use PUT /api/mission/active to activate."
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Failed to create mission: {}", e)),
        ),
    }
}

/// List all mission specs
async fn list_missions(State(state): State<SharedState>) -> impl IntoResponse {
    match state.db.list_mission_specs() {
        Ok(specs) => ApiResponse::ok(specs),
        Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
    }
}

/// Get a specific mission spec
async fn get_mission(
    State(state): State<SharedState>,
    Path(mission_id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_mission_spec(&mission_id) {
        Ok(Some(spec)) => (StatusCode::OK, ApiResponse::ok(spec)),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            ApiResponse::err(&format!("Mission '{}' not found", mission_id)),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Database error: {}", e)),
        ),
    }
}

/// Set active mission
async fn set_active_mission(
    State(state): State<SharedState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mission_id = body.get("mission_id").and_then(|v| v.as_str());

    match mission_id {
        Some(id) => match state.db.set_active_mission(id) {
            Ok(true) => ApiResponse::ok(serde_json::json!({
                "mode": "Mission",
                "mission_id": id,
                "message": "Mission mode activated"
            })),
            Ok(false) => ApiResponse::err(&format!("Mission '{}' not found", id)),
            Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
        },
        None => {
            // Clear active mission (switch to discovery mode)
            match state.db.clear_active_mission() {
                Ok(()) => ApiResponse::ok(serde_json::json!({
                    "mode": "Discovery",
                    "message": "Switched to Discovery mode"
                })),
                Err(e) => ApiResponse::err(&format!("Database error: {}", e)),
            }
        }
    }
}

/// Delete a mission spec
async fn delete_mission(
    State(state): State<SharedState>,
    Path(mission_id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_mission_spec(&mission_id) {
        Ok(true) => (
            StatusCode::OK,
            ApiResponse::ok(serde_json::json!({
                "deleted": true,
                "mission_id": mission_id
            })),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            ApiResponse::err(&format!("Mission '{}' not found", mission_id)),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::err(&format!("Database error: {}", e)),
        ),
    }
}

// ============================================================================
// Eval Metrics Endpoint
// ============================================================================

/// Fetch the latest eval metrics from the metrics directory
async fn get_eval_metrics(State(state): State<SharedState>) -> impl IntoResponse {
    // Look for metrics files in $EDR_TELEMETRY_ROOT/metrics/
    let metrics_dir = state.data_dir.join("metrics");

    if !metrics_dir.exists() {
        return ApiResponse::err("No metrics directory found. Run eval_windows.ps1 first.");
    }

    // Find the most recent metrics file
    let mut latest_file: Option<(std::path::PathBuf, std::time::SystemTime)> = None;

    if let Ok(entries) = std::fs::read_dir(&metrics_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false)
                && path
                    .file_name()
                    .map(|n| n.to_string_lossy().contains("metrics"))
                    .unwrap_or(false)
            {
                if let Ok(metadata) = path.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if latest_file.is_none() || modified > latest_file.as_ref().unwrap().1 {
                            latest_file = Some((path, modified));
                        }
                    }
                }
            }
        }
    }

    match latest_file {
        Some((path, _)) => match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(data) => ApiResponse::ok(data),
                Err(e) => ApiResponse::err(&format!("Failed to parse metrics: {}", e)),
            },
            Err(e) => ApiResponse::err(&format!("Failed to read metrics file: {}", e)),
        },
        None => ApiResponse::err("No metrics files found. Run eval_windows.ps1 first."),
    }
}

// ============================================================================
// PDF Report Generation
// ============================================================================

/// Generate a PDF report from the current hypothesis/explanation response
async fn generate_pdf_report(
    State(_state): State<SharedState>,
    Json(req): Json<ReportRequest>,
) -> impl IntoResponse {
    use axum::http::header;
    use report::{
        ClaimEntry, DisambiguatorEntry, HypothesisSummary, IntegrityNoteEntry, ReportBundleBuilder,
        VisibilitySection,
    };

    // Build the report bundle from the request
    // In production, this would pull from the explanation response in state
    // For now, we create a demo bundle with the provided parameters
    let report_id = uuid::Uuid::new_v4().to_string();
    let host_id = "edr-host-001".to_string();

    let bundle = ReportBundleBuilder::new(report_id.clone(), host_id)
        .with_incident_id(req.incident_id.clone().unwrap_or_else(|| "incident-001".to_string()))
        .with_session_id(req.session_id.clone().unwrap_or_else(|| "session-001".to_string()))
        .with_family("credential_access".to_string())
        .with_summary("Detected potential credential theft activity via LSASS memory access patterns consistent with Mimikatz. High confidence based on multiple correlated signals.".to_string())
        .add_hypothesis(HypothesisSummary {
            rank: 1,
            hypothesis_id: "H001".to_string(),
            family: "credential_access".to_string(),
            template_id: "T1003.001".to_string(),
            confidence: 0.85,
            severity: "High".to_string(),
            suppressed: false,
            suppression_reason: None,
            slots_satisfied: "5/6 slots filled".to_string(),
        })
        .add_hypothesis(HypothesisSummary {
            rank: 2,
            hypothesis_id: "H002".to_string(),
            family: "defense_evasion".to_string(),
            template_id: "T1055.001".to_string(),
            confidence: 0.62,
            severity: "Medium".to_string(),
            suppressed: false,
            suppression_reason: None,
            slots_satisfied: "3/5 slots filled".to_string(),
        })
        .add_claim(ClaimEntry {
            claim_id: "C001".to_string(),
            text: "Memory access to LSASS process detected".to_string(),
            certainty: "observed".to_string(),
            claim_type: "MemoryAccess".to_string(),
            evidence_ptrs: vec!["seg_001:evt_0".to_string(), "seg_001:evt_1".to_string()],
            has_conflict: false,
        })
        .add_claim(ClaimEntry {
            claim_id: "C002".to_string(),
            text: "Credential extraction capability present".to_string(),
            certainty: "inferred".to_string(),
            claim_type: "Capability".to_string(),
            evidence_ptrs: vec!["seg_002:evt_0".to_string()],
            has_conflict: false,
        })
        .add_claim(ClaimEntry {
            claim_id: "C003".to_string(),
            text: "Lateral movement intent".to_string(),
            certainty: "unknown".to_string(),
            claim_type: "Intent".to_string(),
            evidence_ptrs: vec![],
            has_conflict: false,
        })
        .with_visibility(VisibilitySection {
            overall_health: "degraded".to_string(),
            streams_present: vec!["process_events".to_string(), "file_events".to_string()],
            streams_missing: vec!["network_events".to_string()],
            degraded: true,
            degraded_reasons: vec!["Network collector offline during incident window".to_string()],
            late_arrival_count: 2,
            watermark_notes: vec!["Watermark lag: 3.2s observed".to_string()],
        })
        .add_disambiguator(DisambiguatorEntry {
            id: "D001".to_string(),
            priority: 1,
            question: "Was the LSASS access malicious or legitimate?".to_string(),
            pivot_action: "Check for sekurlsa module load".to_string(),
            if_yes: "Likely credential theft, escalate immediately".to_string(),
            if_no: "Possible AV scan, verify with endpoint team".to_string(),
            actionable: true,
        })
        .add_integrity_note(IntegrityNoteEntry {
            note_type: "timestamp_verification".to_string(),
            severity: "info".to_string(),
            description: "All evidence timestamps verified against NTP source".to_string(),
            affected_evidence: vec![],
        })
        .add_integrity_note(IntegrityNoteEntry {
            note_type: "sensor_gap".to_string(),
            severity: "warning".to_string(),
            description: "Network collector was offline for 45s during incident window".to_string(),
            affected_evidence: vec!["network_events".to_string()],
        })
        .add_evidence_excerpt(
            "seg_001:evt_0".to_string(), 
            "Process: mimikatz.exe, PID: 4512, Action: OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) on lsass.exe".to_string()
        )
        .add_evidence_excerpt(
            "seg_001:evt_1".to_string(),
            "Memory Read: 0x7FFE0000-0x7FFE1000, Target: lsass.exe (PID: 656)".to_string()
        )
        .build();

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
        Err(e) => {
            tracing::error!("PDF generation failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("PDF generation failed: {}", e)
                })),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Bundle Export/Import Endpoints
// ============================================================================

/// POST /api/export/bundle - Export an incident bundle for sharing
async fn export_bundle(
    State(state): State<SharedState>,
    Json(req): Json<ExportBundleRequest>,
) -> impl IntoResponse {
    use axum::http::header;
    use report::{
        ClaimEntry, DisambiguatorEntry, HypothesisSummary, ReportBundleBuilder, VisibilitySection,
    };

    // Get session metadata
    let current_mode = state.current_mode.read().await.clone();
    let current_preset = state.current_preset.read().await.clone();
    let focus_minutes = *state.focus_minutes.read().await;

    // Build the report bundle (same structure as PDF generation)
    // In production, this would pull from the actual incident data
    let report_id = uuid::Uuid::new_v4().to_string();
    let host_id = "edr-host-001".to_string();

    let mut builder = ReportBundleBuilder::new(report_id.clone(), host_id)
        .with_incident_id(req.incident_id.clone().unwrap_or_else(|| "incident-001".to_string()))
        .with_family("credential_access".to_string())
        .with_summary("Detected potential credential theft activity via LSASS memory access patterns consistent with Mimikatz.".to_string())
        .add_hypothesis(HypothesisSummary {
            rank: 1,
            hypothesis_id: "H001".to_string(),
            family: "credential_access".to_string(),
            template_id: "T1003.001".to_string(),
            confidence: 0.85,
            severity: "High".to_string(),
            suppressed: false,
            suppression_reason: None,
            slots_satisfied: "5/6 slots filled".to_string(),
        })
        .add_claim(ClaimEntry {
            claim_id: "C001".to_string(),
            text: "Memory access to LSASS process detected".to_string(),
            certainty: "observed".to_string(),
            claim_type: "MemoryAccess".to_string(),
            evidence_ptrs: vec!["seg_001:evt_0".to_string()],
            has_conflict: false,
        })
        .with_visibility(VisibilitySection {
            overall_health: "degraded".to_string(),
            streams_present: vec!["process_events".to_string(), "file_events".to_string()],
            streams_missing: vec!["network_events".to_string()],
            degraded: true,
            degraded_reasons: vec!["Network collector offline during incident window".to_string()],
            late_arrival_count: 2,
            watermark_notes: vec!["Watermark lag: 3.2s observed".to_string()],
        })
        .add_disambiguator(DisambiguatorEntry {
            id: "D001".to_string(),
            priority: 1,
            question: "Was the LSASS access malicious or legitimate?".to_string(),
            pivot_action: "Check for sekurlsa module load".to_string(),
            if_yes: "Likely credential theft, escalate immediately".to_string(),
            if_no: "Possible AV scan, verify with endpoint team".to_string(),
            actionable: true,
        });

    // Add evidence excerpts if requested
    if req.include_evidence_excerpts {
        builder = builder.add_evidence_excerpt(
            "seg_001:evt_0".to_string(),
            "Process: mimikatz.exe, PID: 4512, Action: OpenProcess(PROCESS_VM_READ) on lsass.exe"
                .to_string(),
        );
    }

    let report_bundle = builder.build();

    // Build the incident bundle with optional sanitization
    let incident_bundle = build_incident_bundle(
        report_bundle,
        current_mode,
        current_preset,
        focus_minutes,
        req.redact,
        req.include_recompute,
    );

    // Export to ZIP format
    match export_to_zip(&incident_bundle) {
        Ok(zip_bytes) => {
            let filename = format!("{}.zip", incident_bundle.bundle_meta.bundle_id);
            let content_disposition = format!("attachment; filename=\"{}\"", filename);

            let response = ExportBundleResponse {
                success: true,
                bundle_id: incident_bundle.bundle_meta.bundle_id.clone(),
                format: "zip".to_string(),
                size_bytes: zip_bytes.len(),
                incident_count: 1,
                redacted: req.redact,
                includes_recompute: req.include_recompute,
                message: format!(
                    "Bundle exported successfully{}{}",
                    if req.redact { " (redacted)" } else { "" },
                    if req.include_recompute {
                        " (with recompute)"
                    } else {
                        ""
                    }
                ),
            };

            tracing::info!(
                "Bundle exported: {} ({} bytes)",
                response.bundle_id,
                response.size_bytes
            );

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/zip"),
                    (header::CONTENT_DISPOSITION, content_disposition.as_str()),
                ],
                zip_bytes,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Bundle export failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Export failed: {}", e)
                })),
            )
                .into_response()
        }
    }
}

/// POST /api/import/bundle - Import an incident bundle
async fn import_bundle_endpoint(
    State(state): State<SharedState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Parse the bundle
    let mut incident_bundle = match import_bundle(&body) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Bundle import parse failed: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to parse bundle: {}", e)
                })),
            )
                .into_response();
        }
    };

    // Validate bundle integrity
    if let Err(e) = validate_bundle(&incident_bundle) {
        tracing::warn!("Bundle validation warning: {}", e);
        // Continue anyway, but log the warning
    }

    // Mark as imported (adds namespace isolation)
    mark_as_imported(&mut incident_bundle);

    // Create namespace for this import
    let namespace = create_imported_namespace(&incident_bundle.bundle_meta.bundle_id);

    // Check if recompute section is present
    let has_recompute = incident_bundle.recompute.is_some();

    // Store session metadata from the bundle
    {
        let mut mode = state.current_mode.write().await;
        *mode = incident_bundle.session_meta.mode.clone();
    }
    {
        let mut preset = state.current_preset.write().await;
        *preset = incident_bundle.session_meta.preset.clone();
    }

    let response = ImportBundleResponse {
        success: true,
        bundle_id: incident_bundle.bundle_meta.bundle_id.clone(),
        incident_count: 1,
        hypothesis_count: incident_bundle.replay.report_bundle.hypotheses.len(),
        timeline_entry_count: incident_bundle.replay.report_bundle.timeline.len(),
        imported_at: chrono::Utc::now(),
        namespace: namespace.clone(),
        has_recompute,
        report_bundle: incident_bundle.replay.report_bundle.clone(),
        message: format!(
            "Bundle imported successfully into namespace {}. Source: {}{}",
            namespace,
            incident_bundle.bundle_meta.exported_at,
            if has_recompute {
                " [Recompute available]"
            } else {
                ""
            }
        ),
    };

    tracing::info!(
        "Bundle imported: {} into {} ({} hypotheses, {} timeline entries, recompute: {})",
        response.bundle_id,
        namespace,
        response.hypothesis_count,
        response.timeline_entry_count,
        has_recompute
    );

    (StatusCode::OK, Json(response)).into_response()
}

/// POST /api/import/bundle/recompute - Recompute explanation from bundle inputs
async fn recompute_bundle_endpoint(
    State(_state): State<SharedState>,
    Json(req): Json<RecomputeRequest>,
) -> impl IntoResponse {
    // For now, return an error since we need the bundle stored
    // In production, this would fetch the bundle from ImportedBundleStore
    let result = RecomputeResult {
        success: false,
        bundle_id: req.bundle_id.clone(),
        recompute_explanation: None,
        determinism_verdict: "NOT_AVAILABLE".to_string(),
        verdict_reasons: vec!["Bundle not found in store. Import the bundle first.".to_string()],
        diff_vs_replay: Default::default(),
        message: "Recompute requires a stored imported bundle. Please import the bundle again."
            .to_string(),
    };

    tracing::warn!(
        "Recompute requested for bundle {} but not found in store",
        req.bundle_id
    );

    (StatusCode::NOT_FOUND, Json(result)).into_response()
}

// ============================================================================
// Support Bundle Endpoint (One-click Redacted Support Pack)
// ============================================================================

/// POST /api/support/bundle - Generate redacted support bundle ZIP
async fn generate_support_bundle(
    State(state): State<SharedState>,
    Json(req): Json<support_bundle::SupportBundleRequest>,
) -> impl IntoResponse {
    use axum::http::header;
    use support_bundle::{SupportBundleBuilder, SupportBundleResponse};

    // Get selfcheck response
    let is_first_run = verification_pack::is_first_run(&state.data_dir);
    let stream_stats = state.db.get_stream_stats().unwrap_or_default();
    let db_ok = state.db.health_check().is_ok();
    let selfcheck = state.diagnostic_engine.run_diagnostics(
        is_first_run,
        &state.throttle_controller,
        &stream_stats,
        db_ok,
    );
    let selfcheck_json = serde_json::to_string_pretty(&selfcheck).unwrap_or_default();

    // Build support bundle
    let builder = SupportBundleBuilder::new(
        req.clone(),
        state.data_dir.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        selfcheck_json,
    );

    // Include latest incident if requested
    let builder = if req.include_latest_incident {
        // For now, we don't have the latest incident from this context
        // In production, would query the database
        builder
    } else {
        builder
    };

    // Build ZIP
    match builder.build_zip() {
        Ok(zip_data) => {
            let bundle_id = format!("support_{}", uuid::Uuid::new_v4());
            let filename = format!("{}.zip", bundle_id);
            let size_bytes = zip_data.len();

            tracing::info!(
                "Support bundle generated: {} ({} bytes, redacted={})",
                bundle_id,
                size_bytes,
                req.redact
            );

            let _response = SupportBundleResponse {
                success: true,
                bundle_id: bundle_id.clone(),
                filename: filename.clone(),
                size_bytes,
                created_at: chrono::Utc::now(),
                redacted: req.redact,
                error: None,
            };

            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/zip".to_string()),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                zip_data,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to generate support bundle: {}", e);
            let response = SupportBundleResponse {
                success: false,
                bundle_id: "".to_string(),
                filename: "".to_string(),
                size_bytes: 0,
                created_at: chrono::Utc::now(),
                redacted: false,
                error: Some(format!("Bundle generation failed: {}", e)),
            };

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(response).into_response(),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Verification Pack & App State Endpoints
// ============================================================================

/// GET /api/app/state - Get application state including first-run status
async fn get_app_state(State(state): State<SharedState>) -> impl IntoResponse {
    let verification_state = state.verification_state.read().await;
    let current_mode = state.current_mode.read().await;
    let current_preset = state.current_preset.read().await;
    let focus_minutes = *state.focus_minutes.read().await;

    let session_info = if current_mode.is_some() {
        Some(SessionInfo {
            mode: current_mode.clone().unwrap_or_default(),
            focus_minutes,
            preset: current_preset.clone(),
        })
    } else {
        None
    };

    let response = AppStateResponse {
        is_first_run: verification_pack::is_first_run(&state.data_dir),
        telemetry_root: state.data_dir.display().to_string(),
        current_session: session_info,
        verification_loaded: verification_state.loaded,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    Json(response)
}

/// POST /api/verify/load - Load verification pack for installation testing
async fn load_verification(
    State(state): State<SharedState>,
    Json(req): Json<VerifyLoadRequest>,
) -> impl IntoResponse {
    let bundle_name = req.bundle_name;

    // Check if bundle exists
    let available = verification_pack::list_verification_bundles();
    if !available.contains(&bundle_name.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            Json(VerifyLoadResponse {
                success: false,
                bundle_name: bundle_name.clone(),
                incident_count: 0,
                hypothesis_count: 0,
                timeline_entry_count: 0,
                report_bundle: verification_pack::build_verification_bundle("verify_001"),
                synthetic: true,
                message: format!(
                    "Bundle '{}' not found. Available: {:?}",
                    bundle_name, available
                ),
            }),
        );
    }

    // Build the verification bundle
    let bundle = verification_pack::build_verification_bundle(&bundle_name);

    // Mark verification as loaded
    {
        let mut verification_state = state.verification_state.write().await;
        verification_state.mark_loaded(&bundle_name);
    }

    tracing::info!("Verification pack '{}' loaded successfully", bundle_name);

    (
        StatusCode::OK,
        Json(VerifyLoadResponse {
            success: true,
            bundle_name: bundle_name.clone(),
            incident_count: 1,
            hypothesis_count: bundle.hypotheses.len(),
            timeline_entry_count: bundle.timeline.len(),
            report_bundle: bundle,
            synthetic: true,
            message: "Verification pack loaded. This is SYNTHETIC data for installation verification and workflow learning.".to_string(),
        }),
    )
}

/// POST /api/app/setup - Complete first-run setup
async fn complete_setup(
    State(state): State<SharedState>,
    Json(req): Json<SetupCompleteRequest>,
) -> impl IntoResponse {
    // Validate mode
    let mode = req.mode.to_lowercase();
    if mode != "discovery" && mode != "mission" {
        return (
            StatusCode::BAD_REQUEST,
            Json(SetupCompleteResponse {
                success: false,
                mode: req.mode,
                preset: req.preset,
                focus_minutes: req.focus_minutes,
                verification_loaded: false,
                message: "Invalid mode. Must be 'discovery' or 'mission'.".to_string(),
            }),
        );
    }

    // Validate preset
    let preset = req.preset.to_lowercase();
    let valid_presets = ["htb", "atomic", "tryhackme", "generic"];
    if !valid_presets.contains(&preset.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(SetupCompleteResponse {
                success: false,
                mode: req.mode,
                preset: req.preset,
                focus_minutes: req.focus_minutes,
                verification_loaded: false,
                message: format!("Invalid preset. Must be one of: {:?}", valid_presets),
            }),
        );
    }

    // Update state
    {
        let mut current_mode = state.current_mode.write().await;
        *current_mode = Some(mode.clone());
    }
    {
        let mut current_preset = state.current_preset.write().await;
        *current_preset = Some(preset.clone());
    }
    {
        let mut focus = state.focus_minutes.write().await;
        *focus = req.focus_minutes.clamp(1, 1440); // 1 min to 24 hours
    }

    // Load verification pack if requested (opt-in)
    let mut verification_loaded = false;
    if req.load_verification {
        let _bundle = verification_pack::build_verification_bundle("verify_001");
        {
            let mut verification_state = state.verification_state.write().await;
            verification_state.mark_loaded("verify_001");
        }
        verification_loaded = true;
        tracing::info!("Verification pack loaded as part of setup");
    }

    // Mark first run complete
    if let Err(e) = verification_pack::mark_first_run_complete(&state.data_dir) {
        tracing::warn!("Failed to mark first run complete: {}", e);
    }

    tracing::info!(
        "Setup complete: mode={}, preset={}, focus={}min, verification={}",
        mode,
        preset,
        req.focus_minutes,
        verification_loaded
    );

    (
        StatusCode::OK,
        Json(SetupCompleteResponse {
            success: true,
            mode,
            preset,
            focus_minutes: req.focus_minutes,
            verification_loaded,
            message: "Setup complete! Welcome to EDR Desktop.".to_string(),
        }),
    )
}

/// POST /api/verify/reset - Reset verification state (for re-onboarding)
async fn reset_verification(State(state): State<SharedState>) -> impl IntoResponse {
    // Reset verification state
    {
        let mut verification_state = state.verification_state.write().await;
        verification_state.reset();
    }

    // Reset first-run marker
    if let Err(e) = verification_pack::reset_first_run(&state.data_dir) {
        tracing::warn!("Failed to reset first run marker: {}", e);
    }

    // Reset session state
    {
        let mut current_mode = state.current_mode.write().await;
        *current_mode = None;
    }
    {
        let mut current_preset = state.current_preset.write().await;
        *current_preset = None;
    }
    {
        let mut focus = state.focus_minutes.write().await;
        *focus = 15; // Default
    }

    tracing::info!("Verification pack and first-run state reset");

    Json(serde_json::json!({
        "success": true,
        "message": "Verification pack cleared. Restart the app to see the wizard."
    }))
}

/// POST /api/selfcheck (legacy) - Run lightweight self-check to detect real telemetry
async fn run_self_check_legacy(
    State(state): State<SharedState>,
    Json(req): Json<SelfCheckRequest>,
) -> impl IntoResponse {
    let timeout_secs = req.timeout_seconds.clamp(1, 30);

    // For now, a simple check: look for any signals in the database
    let events_received = match state.db.count_recent_signals(timeout_secs as i64) {
        Ok(count) => count as u32,
        Err(_) => 0,
    };

    // Check if sensors appear to be running (basic heuristic)
    let sensors_detected = events_received > 0;
    let permissions_ok = true; // Would check OS-specific permissions here

    // Recommend verification pack only if no real telemetry
    let recommend_verification = !sensors_detected;

    let message = if sensors_detected {
        format!("Self-check passed. {} events received. Real telemetry detected - verification pack not needed.", events_received)
    } else {
        "No telemetry detected. Verification pack recommended to learn the workflow.".to_string()
    };

    Json(LegacySelfCheckResponse {
        success: true,
        sensors_detected,
        events_received,
        permissions_ok,
        recommend_verification,
        message,
    })
}

// ============================================================================
// Self-Check v2 API (Live Success Diagnostics)
// ============================================================================

/// GET /api/selfcheck - Comprehensive self-check diagnostics (v2)
async fn run_self_check_v2(State(state): State<SharedState>) -> impl IntoResponse {
    // Check if first run
    let is_first_run = verification_pack::is_first_run(&state.data_dir);

    // Build stream stats from database
    let stream_stats = state.db.get_stream_stats().unwrap_or_default();

    // Check database health
    let db_ok = state.db.health_check().is_ok();

    // Run diagnostics
    let response = state.diagnostic_engine.run_diagnostics(
        is_first_run,
        &state.throttle_controller,
        &stream_stats,
        db_ok,
    );

    Json(response)
}

/// Query params for action details
#[derive(Debug, Deserialize)]
struct ActionQuery {
    id: Option<String>,
}

/// GET /api/selfcheck/actions - Get action details
async fn get_self_check_actions(
    State(state): State<SharedState>,
    Query(query): Query<ActionQuery>,
) -> impl IntoResponse {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    if let Some(action_id) = query.id {
        // Return single action details
        match state.diagnostic_engine.get_action_details(&action_id, os) {
            Some(details) => Json(serde_json::json!({
                "success": true,
                "action": details
            })),
            None => Json(serde_json::json!({
                "success": false,
                "error": format!("Action '{}' not found", action_id)
            })),
        }
    } else {
        // Return all available actions
        let actions = vec![
            state.diagnostic_engine.get_action_details("run_probe", os),
            state
                .diagnostic_engine
                .get_action_details("adjust_throttle", os),
            state
                .diagnostic_engine
                .get_action_details("check_storage", os),
            state
                .diagnostic_engine
                .get_action_details("fix_perms_esf_monitor", "macos"),
            state
                .diagnostic_engine
                .get_action_details("fix_perms_ebpf_monitor", "linux"),
            state
                .diagnostic_engine
                .get_action_details("fix_perms_etw_monitor", "windows"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        Json(serde_json::json!({
            "success": true,
            "actions": actions
        }))
    }
}

/// POST /api/selfcheck/probe - Run harmless probe
async fn run_self_check_probe(
    State(state): State<SharedState>,
    Json(spec): Json<Option<ProbeSpec>>,
) -> impl IntoResponse {
    let spec = spec.unwrap_or_default();

    // Run the probe
    let result = state.probe_runner.run(&spec).await;

    // Log result
    tracing::info!(
        probe_id = %result.probe_id,
        success = %result.success,
        duration_ms = %result.duration_ms,
        "Probe completed"
    );

    Json(serde_json::json!({
        "success": result.success,
        "probe": result
    }))
}

// ============================================================================
// Capture Control API
// ============================================================================

/// Capture profile request/response types
#[derive(Debug, Serialize, Deserialize)]
struct CaptureProfileResponse {
    success: bool,
    profile: String,
    description: String,
    enabled_sensors: Vec<String>,
    enabled_collectors: Vec<String>,
    global_event_rate: u32,
    global_byte_rate: u64,
}

#[derive(Debug, Deserialize)]
struct SetCaptureProfileRequest {
    profile: String,
}

#[derive(Debug, Serialize)]
struct SetCaptureProfileResponse {
    success: bool,
    profile: String,
    previous_profile: String,
    message: String,
}

/// GET /api/capture/profile - Get current capture profile
async fn get_capture_profile(State(state): State<SharedState>) -> impl IntoResponse {
    let profile = state.capture_profile.read().await;
    let config = state.throttle_controller.current_config();

    Json(CaptureProfileResponse {
        success: true,
        profile: profile.as_str().to_string(),
        description: profile.description().to_string(),
        enabled_sensors: config.enabled_sensors,
        enabled_collectors: config.enabled_collectors,
        global_event_rate: config.global_throttle.max_events_per_sec,
        global_byte_rate: config.global_throttle.max_bytes_per_sec,
    })
}

/// POST /api/capture/profile - Set capture profile
async fn set_capture_profile(
    State(state): State<SharedState>,
    Json(req): Json<SetCaptureProfileRequest>,
) -> impl IntoResponse {
    let new_profile = match CaptureProfile::from_str(&req.profile) {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SetCaptureProfileResponse {
                    success: false,
                    profile: req.profile,
                    previous_profile: String::new(),
                    message: "Invalid profile. Must be 'core', 'extended', or 'forensic'."
                        .to_string(),
                }),
            );
        }
    };

    let previous_profile = {
        let mut profile = state.capture_profile.write().await;
        let prev = *profile;
        *profile = new_profile;
        prev
    };

    // Update throttle controller configuration
    let new_config = ProfileConfig::for_profile(new_profile);
    state.throttle_controller.update_config(new_config);

    tracing::info!(
        "Capture profile changed: {} -> {}",
        previous_profile.as_str(),
        new_profile.as_str()
    );

    (
        StatusCode::OK,
        Json(SetCaptureProfileResponse {
            success: true,
            profile: new_profile.as_str().to_string(),
            previous_profile: previous_profile.as_str().to_string(),
            message: format!(
                "Profile changed from '{}' to '{}'. {}",
                previous_profile.as_str(),
                new_profile.as_str(),
                new_profile.description()
            ),
        }),
    )
}

/// GET /api/capture/profiles - List all available profiles
async fn list_capture_profiles() -> impl IntoResponse {
    let profiles: Vec<serde_json::Value> = [
        CaptureProfile::Core,
        CaptureProfile::Extended,
        CaptureProfile::Forensic,
    ]
    .iter()
    .map(|p| {
        let config = ProfileConfig::for_profile(*p);
        serde_json::json!({
            "id": p.as_str(),
            "description": p.description(),
            "sensors_count": config.enabled_sensors.len(),
            "collectors_count": config.enabled_collectors.len(),
            "global_event_rate": config.global_throttle.max_events_per_sec,
            "global_byte_rate": config.global_throttle.max_bytes_per_sec,
        })
    })
    .collect();

    Json(serde_json::json!({
        "success": true,
        "profiles": profiles
    }))
}

/// GET /api/visibility/throttle - Get throttle visibility state
async fn get_throttle_visibility(State(state): State<SharedState>) -> impl IntoResponse {
    let visibility = state.throttle_controller.get_visibility_state();
    Json(serde_json::json!({
        "success": true,
        "visibility": visibility
    }))
}

/// POST /api/visibility/throttle/reset - Reset throttle counters
async fn reset_throttle_counters(State(state): State<SharedState>) -> impl IntoResponse {
    state.throttle_controller.reset_counters();
    tracing::info!("Throttle counters reset");
    Json(serde_json::json!({
        "success": true,
        "message": "Throttle counters reset"
    }))
}

/// GET /api/capture/config - Get full capture configuration (for bundles)
async fn get_capture_config(State(state): State<SharedState>) -> impl IntoResponse {
    let snapshot = state.throttle_controller.create_config_snapshot();
    Json(serde_json::json!({
        "success": true,
        "config_snapshot": snapshot
    }))
}

/// Throttle decision test endpoint (for debugging/testing)
#[derive(Debug, Deserialize)]
struct TestThrottleRequest {
    stream_id: String,
    event_bytes: Option<usize>,
}

/// POST /api/capture/test-throttle - Test throttle decision (debugging)
async fn test_throttle_decision(
    State(state): State<SharedState>,
    Json(req): Json<TestThrottleRequest>,
) -> impl IntoResponse {
    let decision = state
        .throttle_controller
        .before_store(&req.stream_id, req.event_bytes.unwrap_or(100));

    let decision_str = match &decision {
        ThrottleDecision::Accept => "accept",
        ThrottleDecision::Drop { .. } => "drop",
        ThrottleDecision::Sample { .. } => "sample",
        ThrottleDecision::Defer => "defer",
    };

    Json(serde_json::json!({
        "success": true,
        "stream_id": req.stream_id,
        "decision": decision_str,
        "details": decision
    }))
}

// ============================================================================
// Health & UI
// ============================================================================

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "Attack Documentation Workbench",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn index() -> impl IntoResponse {
    // Redirect to the workbench UI
    axum::response::Redirect::permanent("/ui/workbench.html")
}

async fn api_docs() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Attack Documentation Workbench API</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #1a1a2e; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 4px; }
        .method { font-weight: bold; color: #16213e; }
        code { background: #e8e8e8; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🔬 Attack Documentation Workbench API</h1>
    <p>Capture, analyze, edit, and export attack documentation for detection engineering.</p>
    <p><a href="/ui/workbench.html">Open Workbench UI →</a></p>
    
    <h2>API Endpoints</h2>
    
    <h3>Documents</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/api/documents</code> - List all documents</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/documents</code> - Create new document</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/documents/:id</code> - Get document</div>
    <div class="endpoint"><span class="method">PUT</span> <code>/api/documents/:id/:section</code> - Update section</div>
    <div class="endpoint"><span class="method">DELETE</span> <code>/api/documents/:id</code> - Delete document</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/documents/:id/export</code> - Export document</div>
    
    <h3>Capture Sessions</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/api/session</code> - Get session status</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/session</code> - Control session (start/stop/pause/resume)</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/session/marker</code> - Add marker</div>
    
    <h3>Signals (Detection Pipeline)</h3>
    <div class="endpoint"><span class="method">POST</span> <code>/api/signals</code> - Ingest signals from locald</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/signals</code> - List signals (query: host, signal_type, severity, limit)</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/signals/:id</code> - Get signal by ID</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/signals/:id/explain</code> - Get explanation bundle for signal</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/signals/:id/narrative</code> - Get evidence-cited narrative for signal</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/signals/stats</code> - Get signal statistics</div>
    
    <h3>Narratives (Evidence-Cited Explanations)</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/api/narratives/:id/actions</code> - List user actions on narrative</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/narratives/:id/actions</code> - Record user action (pin/hide/verify)</div>
    
    <h3>Mission Mode (Discovery vs Mission)</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/api/mission</code> - Get current mode (Discovery/Mission)</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/mission</code> - Create new mission spec</div>
    <div class="endpoint"><span class="method">PUT</span> <code>/api/mission/active</code> - Set or clear active mission</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/missions</code> - List all mission specs</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/missions/:id</code> - Get mission spec by ID</div>
    <div class="endpoint"><span class="method">DELETE</span> <code>/api/missions/:id</code> - Delete mission spec</div>
    
    <h3>MITRE ATT&CK</h3>
    <div class="endpoint"><span class="method">POST</span> <code>/api/techniques/search</code> - Search techniques</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/techniques/:id</code> - Get technique details</div>
    
    <h3>Reports & Bundles</h3>
    <div class="endpoint"><span class="method">POST</span> <code>/api/report/pdf</code> - Generate PDF report from ExplanationResponse</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/export/bundle</code> - Export incident bundle (ZIP/JSON) for sharing</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/import/bundle</code> - Import incident bundle from file</div>
    
    <h3>App State & Verification</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/api/app/state</code> - Get application state (first-run status, verification state)</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/verify/load</code> - Load verification pack (synthetic data)</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/verify/reset</code> - Reset verification state and first-run marker</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/selfcheck</code> - Run self-check to detect real telemetry</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/setup/complete</code> - Complete first-run setup (mode, preset, focus)</div>
    
    <h3>Capture Control & Throttling</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/api/capture/profile</code> - Get current capture profile (core/extended/forensic)</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/capture/profile</code> - Set capture profile</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/capture/profiles</code> - List all available profiles</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/capture/config</code> - Get full capture configuration snapshot</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/capture/test-throttle</code> - Test throttle decision for debugging</div>
    <div class="endpoint"><span class="method">GET</span> <code>/api/visibility/throttle</code> - Get throttle visibility state (degraded, drops, etc.)</div>
    <div class="endpoint"><span class="method">POST</span> <code>/api/visibility/throttle/reset</code> - Reset throttle counters</div>
    
    <h3>Health</h3>
    <div class="endpoint"><span class="method">GET</span> <code>/health</code> - Health check</div>
</body>
</html>"#,
    )
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "edr_server=info".into()),
        )
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Get port from CLI args or environment
    let port: u16 = args
        .iter()
        .position(|a| a == "--port" || a == "-p")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("EDR_SERVER_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(3000);

    // Get telemetry root from CLI args or environment
    let telemetry_root: Option<std::path::PathBuf> = args
        .iter()
        .position(|a| a == "--telemetry-root" || a == "-t")
        .and_then(|i| args.get(i + 1))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var("EDR_TELEMETRY_ROOT")
                .ok()
                .map(std::path::PathBuf::from)
        });

    // Initialize database directory
    let data_dir = telemetry_root.unwrap_or_else(|| {
        dirs::data_local_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("attack-workbench")
    });
    std::fs::create_dir_all(&data_dir).expect("Failed to create data directory");

    let db_path = data_dir.join("workbench.db");
    tracing::info!("📁 Database: {:?}", db_path);
    tracing::info!("📡 Port: {}", port);

    let db = Database::open(&db_path).expect("Failed to open database");

    // Initialize throttle controller with default profile
    let default_profile = CaptureProfile::Core;
    let throttle_controller = Arc::new(ThrottleController::new(ProfileConfig::for_profile(
        default_profile,
    )));

    // Initialize diagnostic engine and probe runner
    let diagnostic_engine =
        DiagnosticEngine::new(data_dir.clone(), env!("CARGO_PKG_VERSION").to_string());
    let probe_runner = ProbeRunner::new();
    let start_time = chrono::Utc::now();

    let state = Arc::new(AppState {
        db,
        sessions: RwLock::new(std::collections::HashMap::new()),
        active_session: RwLock::new(None),
        data_dir: data_dir.clone(),
        verification_state: RwLock::new(VerificationState::default()),
        current_mode: RwLock::new(None),
        current_preset: RwLock::new(None),
        focus_minutes: RwLock::new(15),
        capture_profile: RwLock::new(default_profile),
        throttle_controller,
        diagnostic_engine,
        probe_runner,
        start_time,
    });

    // Log first-run status
    let is_first_run = verification_pack::is_first_run(&data_dir);
    tracing::info!("📋 First run: {}", is_first_run);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Serve static UI files
    let ui_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("ui");

    let app = Router::new()
        // UI
        .route("/", get(index))
        .route("/api", get(api_docs))
        .route("/health", get(health))
        .route("/api/health", get(health))
        // Documents API
        .route("/api/documents", get(list_documents).post(create_document))
        .route(
            "/api/documents/:id",
            get(get_document).delete(delete_document),
        )
        .route("/api/documents/:id/:section", put(update_document_section))
        .route("/api/documents/:id/export", post(export_document))
        // Session API
        .route(
            "/api/session",
            get(get_session_status).post(control_session),
        )
        .route("/api/session/marker", post(add_marker))
        // Signals API (Detection Pipeline)
        .route("/api/signals", get(list_signals).post(ingest_signals))
        .route("/api/signals/stats", get(signal_stats))
        .route("/api/signals/:id", get(get_signal))
        .route("/api/signals/:id/explain", get(get_signal_explanation))
        .route("/api/signals/:id/narrative", get(get_signal_narrative))
        // License API
        .route("/api/license/status", get(license_status_endpoint))
        .route("/api/license/install", post(license_install_endpoint))
        .route("/api/license/reload", post(license_reload_endpoint))
        // Pro: Diff API (requires Pro license entitlement)
        .route("/api/diff", get(diff_endpoint))
        .route("/api/runs", get(list_runs_endpoint))
        // Narrative Actions API
        .route(
            "/api/narratives/:id/actions",
            get(get_narrative_actions).post(create_narrative_action),
        )
        // Mission Mode API
        .route("/api/mission", get(get_mission_mode).post(create_mission))
        .route("/api/mission/active", put(set_active_mission))
        .route("/api/missions", get(list_missions))
        .route("/api/missions/:id", get(get_mission).delete(delete_mission))
        // Eval Metrics API
        .route("/api/eval/metrics", get(get_eval_metrics))
        // MITRE API
        .route("/api/techniques/search", post(search_mitre_techniques))
        .route("/api/techniques/:id", get(get_mitre_technique))
        // Report API (PDF generation)
        .route("/api/report/pdf", post(generate_pdf_report))
        // Bundle Export/Import API
        .route("/api/export/bundle", post(export_bundle))
        .route("/api/import/bundle", post(import_bundle_endpoint))
        .route(
            "/api/import/bundle/recompute",
            post(recompute_bundle_endpoint),
        )
        // Support Bundle API (One-click redacted pack for support)
        .route("/api/support/bundle", post(generate_support_bundle))
        // App State & Verification API
        .route("/api/app/state", get(get_app_state))
        .route("/api/verify/load", post(load_verification))
        .route("/api/verify/reset", post(reset_verification))
        .route(
            "/api/selfcheck",
            get(run_self_check_v2).post(run_self_check_legacy),
        )
        .route("/api/selfcheck/actions", get(get_self_check_actions))
        .route("/api/selfcheck/probe", post(run_self_check_probe))
        .route("/api/setup/complete", post(complete_setup))
        // Capture Control API
        .route(
            "/api/capture/profile",
            get(get_capture_profile).post(set_capture_profile),
        )
        .route("/api/capture/profiles", get(list_capture_profiles))
        .route("/api/capture/config", get(get_capture_config))
        .route("/api/capture/test-throttle", post(test_throttle_decision))
        .route("/api/visibility/throttle", get(get_throttle_visibility))
        .route(
            "/api/visibility/throttle/reset",
            post(reset_throttle_counters),
        )
        // Integration API endpoints (mounted separately due to different state)
        // These endpoints provide integration metadata and capabilities
        .route(
            "/api/integrations",
            get(integration_api::list_integrations_bridge),
        )
        .route(
            "/api/integrations/:id",
            get(integration_api::get_integration_bridge),
        )
        .route(
            "/api/integrations/:id/sample",
            get(integration_api::get_samples_bridge),
        )
        .route(
            "/api/capabilities",
            get(integration_api::get_capabilities_bridge),
        )
        // Static files
        .nest_service("/ui", ServeDir::new(&ui_dir))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    tracing::info!(
        "🚀 Attack Documentation Workbench running at http://{}",
        addr
    );

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl+c");
    tracing::info!("Shutting down...");
}
